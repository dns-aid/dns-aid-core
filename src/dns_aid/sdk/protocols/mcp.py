# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
MCP (Model Context Protocol) handler — modern Streamable HTTP transport.

Delegates the actual transport to the official MCP Python SDK
(``mcp.client.streamable_http.streamablehttp_client``), wrapped in a thin
dns-aid telemetry adapter and Layer 2 caller-identity injector. When the
target server signals incompatibility with the modern transport, the
handler transparently falls back to a plain JSON-RPC POST (the legacy
transport) so on-premise and pre-2025-03-26 servers continue to work.

The fallback decision is logged as a structured warning so operators can
track which targets need migration.
"""

from __future__ import annotations

import json
import os
import time
from typing import TYPE_CHECKING, Any, Literal

import httpx
import structlog

from dns_aid.sdk.auth._httpx_adapter import to_httpx_auth
from dns_aid.sdk.models import InvocationStatus
from dns_aid.sdk.protocols._mcp_telemetry import _make_telemetry_factory, _TelemetryCapture
from dns_aid.sdk.protocols.base import ProtocolHandler, RawResponse

if TYPE_CHECKING:
    from dns_aid.sdk.auth.base import AuthHandler


_logger = structlog.get_logger(__name__)

# Header used by dns-aid Layer 2 target middleware to identify the caller.
_CALLER_DOMAIN_HEADER = "X-DNS-AID-Caller-Domain"
_CALLER_DOMAIN_ENV_VAR = "DNS_AID_CALLER_DOMAIN"

# Detect whether the official MCP SDK is importable at module load time.
# Failure to import means the [mcp] extra is not installed; the handler
# surfaces a clear remediation message instead of crashing at first use.
try:
    from mcp import ClientSession

    # mcp 2.0.0 renamed McpError -> MCPError. mcp.types is unaffected by the 2.x
    # package split, so the names below resolve identically on both majors.
    try:  # mcp >= 1.28.1, < 2
        from mcp.shared.exceptions import McpError
    except ImportError:  # mcp >= 2
        # mypy resolves against whichever major is installed, so the other
        # branch is always unknown to it.
        from mcp.shared.exceptions import (  # type: ignore[attr-defined,no-redef]
            MCPError as McpError,
        )

    from mcp.types import (
        CallToolResult,
        ListToolsResult,
        TextContent,
    )

    # The client path does not carry over to mcp 2.x. Three separate changes:
    #
    #   1. streamablehttp_client -> streamable_http_client, and its
    #      headers/timeout/auth/httpx_client_factory arguments collapsed into a
    #      single `http_client`.
    #   2. It yields TransportStreams rather than the
    #      (read, write, get_session_id) tuple unpacked below.
    #   3. mcp.types renamed its camelCase fields to snake_case. The classes
    #      still import, which makes this easy to miss, but every field this
    #      module reads is gone: CallToolResult.isError and .structuredContent,
    #      ListToolsResult.nextCursor, Tool.inputSchema (used at lines ~182-209
    #      and ~340). Those are plain AttributeError at runtime.
    #
    # Note the `http_client` parameter is annotated httpx2.AsyncClient, but that
    # is advisory: httpx2 and httpx expose identical AsyncClient constructor
    # parameters and an httpx client is accepted, so the HTTP library is NOT the
    # obstacle and no port of this module's transport layer is required. The
    # blocker is (3), the field renames, which need a compatibility shim in
    # _extract_* and the call-result handling.
    #
    # pyproject caps mcp below 2.0.0 until that shim exists. This detection is
    # here so a forced 2.x install reports the real reason rather than failing
    # with an opaque AttributeError partway through an invocation.
    try:  # mcp >= 1.28.1, < 2
        from mcp.client.streamable_http import streamablehttp_client

        _MCP_SDK_AVAILABLE = True
        _MCP_IMPORT_ERROR: str | None = None
    except ImportError:  # mcp >= 2
        streamablehttp_client = None  # type: ignore[assignment]
        _MCP_SDK_AVAILABLE = False
        _MCP_IMPORT_ERROR = (
            "mcp 2.x is installed, but this client requires the 1.x API: "
            "mcp.types renamed its result fields to snake_case (isError, "
            "structuredContent, nextCursor, inputSchema) and the "
            "streamable-HTTP transport changed shape. dns-aid supports "
            "mcp >=1.28.1,<2.0.0 on the client path"
        )
except ImportError as exc:
    _MCP_SDK_AVAILABLE = False
    _MCP_IMPORT_ERROR = str(exc)


_TransportClass = Literal["transport_mismatch", "real_failure"]


def _classify_transport_failure(exc: BaseException) -> _TransportClass:
    """Decide whether *exc* indicates a transport-protocol mismatch (fallback eligible)
    or a real failure (auth/network/server) that should propagate as-is.

    Transport mismatch: target server does not speak modern Streamable HTTP.
    Triggers fallback to the legacy plain JSON-RPC POST path.

    Real failure: target accepted the modern transport but the operation
    itself failed for an orthogonal reason. No fallback — surface to caller.
    """
    # HTTP-level mismatch signals
    if isinstance(exc, httpx.HTTPStatusError):
        code = exc.response.status_code
        if code in (405, 406):
            return "transport_mismatch"
        return "real_failure"

    # ExceptionGroup may wrap inner causes (anyio raises these)
    if isinstance(exc, BaseExceptionGroup):  # type: ignore[has-type]
        for inner in exc.exceptions:
            if _classify_transport_failure(inner) == "transport_mismatch":
                return "transport_mismatch"
        return "real_failure"

    # MCP-level handshake refusal (server doesn't speak the protocol version we requested)
    if _MCP_SDK_AVAILABLE and isinstance(exc, McpError):
        # JSON-RPC -32601 = Method not found (e.g., server doesn't implement initialize)
        try:
            code = exc.error.code  # type: ignore[attr-defined]
            if code == -32601:
                return "transport_mismatch"
        except AttributeError:
            pass
        return "real_failure"

    # Treat connection-level rejection as transport mismatch ONLY when the modern
    # transport itself raised it during negotiation (server closed the connection
    # rather than completing the handshake). Generic ConnectError is a real failure.
    return "real_failure"


def _classify_failure_reason(exc: BaseException) -> str:
    """Human-readable fallback reason for the structured warning log."""
    if isinstance(exc, httpx.HTTPStatusError):
        return f"http_{exc.response.status_code}"
    if isinstance(exc, BaseExceptionGroup):  # type: ignore[has-type]
        for inner in exc.exceptions:
            return _classify_failure_reason(inner)
    if _MCP_SDK_AVAILABLE and isinstance(exc, McpError):
        return "initialize_refused"
    return type(exc).__name__


def _build_caller_headers() -> dict[str, str]:
    """Return the dns-aid metadata headers to attach to every MCP request.

    Currently only ``X-DNS-AID-Caller-Domain`` (Layer 2 caller identity).
    Returns an empty dict when ``DNS_AID_CALLER_DOMAIN`` is unset OR set to
    an empty string — the header is omitted entirely (NOT sent as empty
    value), per the spec acceptance scenarios.
    """
    caller_domain = os.environ.get(_CALLER_DOMAIN_ENV_VAR, "").strip()
    if not caller_domain:
        return {}
    return {_CALLER_DOMAIN_HEADER: caller_domain}


def _extract_call_tool_content(result: CallToolResult) -> Any:
    """Extract the meaningful payload from a CallToolResult.

    MCP servers return tool output as a list of typed content blocks. The
    convention dns-aid has historically followed is:
      - Take the first content block
      - If it's a TextContent, attempt JSON-decode the text; fall back to raw text
      - Otherwise return the raw content list

    Preserves backwards compatibility with the previous ``_extract_mcp_content``
    behavior that operated on dict-shaped JSON-RPC results.
    """
    content = result.content
    if not content:
        # Some tools may carry structured output instead of content blocks.
        if result.structuredContent is not None:
            return result.structuredContent
        return None

    first = content[0]
    if isinstance(first, TextContent):
        text = first.text or ""
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return text

    # Non-text content (image, resource, etc.) — return as serialised dict list.
    return [block.model_dump(mode="json") for block in content]


def _extract_list_tools_payload(result: ListToolsResult) -> dict[str, Any]:
    """Convert a typed ListToolsResult into the dict shape the SDK historically returned."""
    return {
        "tools": [
            {
                "name": tool.name,
                "description": tool.description or "",
                "inputSchema": tool.inputSchema,
            }
            for tool in result.tools
        ],
        "nextCursor": result.nextCursor,
    }


class MCPProtocolHandler(ProtocolHandler):
    """Handles MCP invocations over the modern Streamable HTTP transport.

    Falls back to the legacy plain JSON-RPC POST transport when the target
    server rejects the modern transport (HTTP 406, refused initialize,
    missing session-id support). The fallback is transparent to callers;
    the only observable difference is a structured warning log entry.
    """

    @property
    def protocol_name(self) -> str:
        return "mcp"

    async def invoke(
        self,
        client: httpx.AsyncClient,
        endpoint: str,
        method: str | None,
        arguments: dict[str, Any] | None,
        timeout: float,
        auth_handler: AuthHandler | None = None,
    ) -> RawResponse:
        """Send an MCP request via the modern Streamable HTTP transport.

        The ``client`` parameter (a shared httpx.AsyncClient from AgentClient)
        is intentionally NOT used by the modern transport — the official SDK
        owns its own client built by ``httpx_client_factory``. The shared
        client is reserved for the legacy fallback path so existing
        connection pooling continues to work there.
        """
        if not _MCP_SDK_AVAILABLE:
            return RawResponse(
                success=False,
                status=InvocationStatus.ERROR,
                error_type="ImportError",
                error_message=(
                    "The MCP streamable-HTTP transport is unavailable. If the "
                    "'mcp' package is not installed, run "
                    "`pip install 'dns-aid[mcp]'`; if it is installed, its "
                    "version is out of range (supported: mcp >=1.28.1,<2.0.0). "
                    f"Reason: {_MCP_IMPORT_ERROR}"
                ),
            )

        mcp_method = method or "tools/list"
        mcp_arguments = arguments or {}
        headers = _build_caller_headers()

        start = time.perf_counter()

        # ── Modern Streamable HTTP path ──────────────────────────────────
        try:
            return await self._invoke_via_streamable_http(
                endpoint=endpoint,
                mcp_method=mcp_method,
                mcp_arguments=mcp_arguments,
                timeout=timeout,
                auth_handler=auth_handler,
                headers=headers,
                start=start,
            )
        except (httpx.TimeoutException, httpx.ConnectError) as exc:
            elapsed = (time.perf_counter() - start) * 1000
            return _build_failure_response(exc, elapsed)
        except BaseException as exc:  # noqa: BLE001 - we classify and re-raise via fallback if not transport_mismatch
            classification = _classify_transport_failure(exc)
            if classification != "transport_mismatch":
                elapsed = (time.perf_counter() - start) * 1000
                return _build_failure_response(exc, elapsed)

            # ── Transparent fallback to legacy plain JSON-RPC POST ──────
            reason = _classify_failure_reason(exc)
            modern_attempt_ms = (time.perf_counter() - start) * 1000
            _logger.warning(
                "transport.legacy_fallback",
                endpoint=endpoint,
                reason=reason,
                latency_ms_modern_attempt=round(modern_attempt_ms, 2),
            )
            return await self._invoke_via_legacy_fallback(
                client=client,
                endpoint=endpoint,
                mcp_method=mcp_method,
                mcp_arguments=mcp_arguments,
                timeout=timeout,
                auth_handler=auth_handler,
                headers=headers,
            )

    # ── Modern path implementation ──────────────────────────────────────

    async def _invoke_via_streamable_http(
        self,
        *,
        endpoint: str,
        mcp_method: str,
        mcp_arguments: dict[str, Any],
        timeout: float,
        auth_handler: AuthHandler | None,
        headers: dict[str, str],
        start: float,
    ) -> RawResponse:
        capture = _TelemetryCapture()
        factory = _make_telemetry_factory(capture)
        auth = to_httpx_auth(auth_handler)

        async with (  # noqa: SIM117 - keeping streams open across the inner session is required by the SDK contract
            streamablehttp_client(
                endpoint,
                headers=headers if headers else None,
                timeout=timeout,
                httpx_client_factory=factory,
                auth=auth,
            ) as (read_stream, write_stream, _get_session_id),
            ClientSession(read_stream, write_stream) as session,
        ):
            await session.initialize()

            if mcp_method == "tools/list":
                list_result = await session.list_tools()
                data: Any = _extract_list_tools_payload(list_result)
                is_error = False
            elif mcp_method == "tools/call":
                name = mcp_arguments.get("name", "")
                tool_args = mcp_arguments.get("arguments", {})
                call_result = await session.call_tool(name, tool_args)
                data = _extract_call_tool_content(call_result)
                is_error = call_result.isError
            else:
                return RawResponse(
                    success=False,
                    status=InvocationStatus.ERROR,
                    error_type="UnsupportedMethod",
                    error_message=f"MCP method not supported by handler: {mcp_method}",
                )

        # Compute end-to-end latency from invoke entry, not from session start.
        invocation_latency_ms = (time.perf_counter() - start) * 1000

        if is_error:
            return RawResponse(
                success=False,
                status=InvocationStatus.ERROR,
                data=data,
                http_status_code=capture.http_status_code,
                error_type="ToolError",
                error_message=str(data) if data is not None else "tool returned isError=True",
                invocation_latency_ms=invocation_latency_ms,
                ttfb_ms=capture.ttfb_ms,
                response_size_bytes=capture.response_size_bytes,
                cost_units=capture.cost_units,
                cost_currency=capture.cost_currency,
                tls_version=capture.tls_version,
                headers=capture.headers,
            )

        return RawResponse(
            success=True,
            status=InvocationStatus.SUCCESS,
            data=data,
            http_status_code=capture.http_status_code,
            invocation_latency_ms=invocation_latency_ms,
            ttfb_ms=capture.ttfb_ms,
            response_size_bytes=capture.response_size_bytes,
            cost_units=capture.cost_units,
            cost_currency=capture.cost_currency,
            tls_version=capture.tls_version,
            headers=capture.headers,
        )

    # ── Legacy fallback path ────────────────────────────────────────────

    async def _invoke_via_legacy_fallback(
        self,
        *,
        client: httpx.AsyncClient,
        endpoint: str,
        mcp_method: str,
        mcp_arguments: dict[str, Any],
        timeout: float,
        auth_handler: AuthHandler | None,
        headers: dict[str, str],
    ) -> RawResponse:
        """Send a single plain JSON-RPC 2.0 POST to *endpoint* — the legacy MCP transport.

        This is the same code path the previous (pre-streamable) MCPProtocolHandler used,
        retained exclusively as the fallback for servers that do not speak the modern
        Streamable HTTP transport. The dns-aid caller-identity header is propagated
        the same way it is in the modern path so Layer 2 policy enforcement keeps
        working consistently across both transports.
        """
        rpc_request = {
            "jsonrpc": "2.0",
            "method": mcp_method,
            "params": mcp_arguments,
            "id": 1,
        }

        request_headers = {"Content-Type": "application/json"}
        request_headers.update(headers)  # invariant: caller-domain header propagates

        start = time.perf_counter()
        try:
            request = client.build_request(
                "POST",
                endpoint,
                json=rpc_request,
                headers=request_headers,
                timeout=timeout,
            )
            if auth_handler is not None:
                request = await auth_handler.apply(request)
            response = await client.send(request)
            ttfb_ms = (time.perf_counter() - start) * 1000
            invocation_latency_ms = ttfb_ms
        except httpx.TimeoutException as exc:
            elapsed = (time.perf_counter() - start) * 1000
            return _build_failure_response(exc, elapsed)
        except httpx.ConnectError as exc:
            elapsed = (time.perf_counter() - start) * 1000
            return _build_failure_response(exc, elapsed)
        except httpx.HTTPError as exc:
            elapsed = (time.perf_counter() - start) * 1000
            return _build_failure_response(exc, elapsed)

        cost_units = _parse_float_header(response.headers, "x-cost-units")
        cost_currency = response.headers.get("x-cost-currency")
        tls_version = _extract_tls_version(response)
        response_size_bytes = len(response.content)
        response_headers = {k.lower(): v for k, v in response.headers.items()}

        if response.status_code != 200:
            return RawResponse(
                success=False,
                status=InvocationStatus.ERROR,
                http_status_code=response.status_code,
                error_type="HTTPError",
                error_message=(
                    f"HTTP {response.status_code} from legacy fallback (modern transport "
                    f"already failed): {response.text[:200]}"
                ),
                invocation_latency_ms=invocation_latency_ms,
                ttfb_ms=ttfb_ms,
                response_size_bytes=response_size_bytes,
                cost_units=cost_units,
                cost_currency=cost_currency,
                tls_version=tls_version,
                headers=response_headers,
            )

        try:
            result = response.json()
        except json.JSONDecodeError as exc:
            return RawResponse(
                success=False,
                status=InvocationStatus.ERROR,
                http_status_code=200,
                error_type="JSONDecodeError",
                error_message=f"Invalid JSON response from legacy fallback: {exc}",
                invocation_latency_ms=invocation_latency_ms,
                ttfb_ms=ttfb_ms,
                response_size_bytes=response_size_bytes,
                tls_version=tls_version,
                headers=response_headers,
            )

        if "error" in result:
            rpc_error = result["error"]
            return RawResponse(
                success=False,
                status=InvocationStatus.ERROR,
                data=rpc_error,
                http_status_code=200,
                error_type="RPCError",
                error_message=rpc_error.get("message", str(rpc_error))
                if isinstance(rpc_error, dict)
                else str(rpc_error),
                invocation_latency_ms=invocation_latency_ms,
                ttfb_ms=ttfb_ms,
                response_size_bytes=response_size_bytes,
                cost_units=cost_units,
                cost_currency=cost_currency,
                tls_version=tls_version,
                headers=response_headers,
            )

        data = _extract_legacy_dict_content(result)
        return RawResponse(
            success=True,
            status=InvocationStatus.SUCCESS,
            data=data,
            http_status_code=200,
            invocation_latency_ms=invocation_latency_ms,
            ttfb_ms=ttfb_ms,
            response_size_bytes=response_size_bytes,
            cost_units=cost_units,
            cost_currency=cost_currency,
            tls_version=tls_version,
            headers=response_headers,
        )


# ── Helpers (module-private, retained for backward compatibility with tests) ──


def _build_failure_response(exc: BaseException, elapsed_ms: float) -> RawResponse:
    if isinstance(exc, httpx.TimeoutException):
        return RawResponse(
            success=False,
            status=InvocationStatus.TIMEOUT,
            error_type="TimeoutError",
            error_message=str(exc) or "Request timed out",
            invocation_latency_ms=elapsed_ms,
        )
    if isinstance(exc, httpx.ConnectError):
        return RawResponse(
            success=False,
            status=InvocationStatus.REFUSED,
            error_type="ConnectError",
            error_message=str(exc),
            invocation_latency_ms=elapsed_ms,
        )
    return RawResponse(
        success=False,
        status=InvocationStatus.ERROR,
        error_type=type(exc).__name__,
        error_message=str(exc),
        invocation_latency_ms=elapsed_ms,
    )


def _extract_legacy_dict_content(result: dict[str, Any]) -> Any:
    """Extract content from a legacy plain-JSON-RPC MCP result dict.

    Preserves the behavior of the pre-streamable transport for servers that
    still respond with the dict-shaped result.
    """
    rpc_result = result.get("result")
    if rpc_result is None:
        return None

    content = rpc_result.get("content") if isinstance(rpc_result, dict) else None
    if content and isinstance(content, list) and len(content) > 0:
        text = content[0].get("text", "") if isinstance(content[0], dict) else ""
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            return text

    return rpc_result


# Public alias retained for any external callers that imported this name.
_extract_mcp_content = _extract_legacy_dict_content


def _parse_float_header(headers: httpx.Headers, name: str) -> float | None:
    value = headers.get(name)
    if value is None:
        return None
    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def _extract_tls_version(response: httpx.Response) -> str | None:
    """Best-effort TLS version extraction from a completed httpx response."""
    try:
        extensions = response.extensions
        network_stream = extensions.get("network_stream") if extensions else None
        if network_stream is not None:
            ssl_object = network_stream.get_extra_info("ssl_object")
            if ssl_object is not None:
                return ssl_object.version()
        # Fallback: probe the underlying stream the way the previous impl did
        stream = response.stream
        if hasattr(stream, "_stream") and hasattr(stream._stream, "get_extra_info"):
            ssl_object = stream._stream.get_extra_info("ssl_object")
            if ssl_object:
                return ssl_object.version()
    except (AttributeError, KeyError):
        pass
    return None
