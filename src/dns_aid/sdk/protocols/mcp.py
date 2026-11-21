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
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any, Literal

import httpx
import structlog

from dns_aid.sdk.auth._httpx_adapter import to_httpx2_auth, to_httpx_auth
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
#
# Both mcp 1.x (>=1.30.0) and 2.x are supported. What 2.x changed on the
# client path, and where it is absorbed:
#
#   - McpError became MCPError (imported under the 1.x name below).
#   - streamablehttp_client(url, headers=, timeout=, auth=,
#     httpx_client_factory=) became streamable_http_client(url,
#     http_client=), yielding (read, write) instead of (read, write,
#     get_session_id). _streamablehttp_client_v2 keeps the 1.x call shape.
#   - The transport runs on httpx2, so the client has to be an
#     httpx2.AsyncClient (its SSE reader wraps httpx2 responses) and auth an
#     httpx2.Auth. _HTTP_LIB and _to_auth pick the matching library.
#   - mcp.types fields went snake_case (isError -> is_error, ...). _field
#     reads either spelling.
#   - An HTTP error status on a POST no longer raises HTTPStatusError; it
#     comes back as an MCPError. _classify_transport_failure looks at the
#     status the telemetry hook recorded instead.
_MCP_V2 = False
try:
    from mcp import ClientSession

    try:  # mcp >= 1.30.0, < 2
        from mcp.shared.exceptions import McpError
    except ImportError:  # mcp >= 2
        # mypy resolves against whichever major is installed, so the other
        # branch is always unknown to it.
        from mcp.shared.exceptions import (  # type: ignore[attr-defined,no-redef]
            MCPError as McpError,
        )

        _MCP_V2 = True

    from mcp.types import (
        CallToolResult,
        ListToolsResult,
        TextContent,
    )

    if _MCP_V2:
        import httpx2
        from mcp.client.streamable_http import (  # type: ignore[attr-defined]
            streamable_http_client,
        )
    else:
        from mcp.client.streamable_http import streamablehttp_client

    _MCP_SDK_AVAILABLE = True
    _MCP_IMPORT_ERROR: str | None = None
except ImportError as exc:
    _MCP_SDK_AVAILABLE = False
    _MCP_IMPORT_ERROR = str(exc)

# mcp 1.x's streamablehttp_client default for how long a response stream may
# stay idle; the 2.x shim below keeps it.
_SSE_READ_TIMEOUT = 300.0

if _MCP_V2:
    _HTTP_LIB: Any = httpx2
    _to_auth = to_httpx2_auth

    @asynccontextmanager
    async def _streamablehttp_client_v2(
        url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout: float = 30.0,
        httpx_client_factory: Any,
        auth: Any = None,
    ) -> AsyncIterator[tuple[Any, Any, Callable[[], str | None]]]:
        """mcp 1.x ``streamablehttp_client`` call shape on top of the 2.x transport."""
        client = httpx_client_factory(
            headers=headers,
            timeout=httpx2.Timeout(timeout, read=_SSE_READ_TIMEOUT),
            auth=auth,
        )
        # mypy checks this against the installed major; on 1.x the name exists
        # with a different signature, hence the ignore below.
        async with client, streamable_http_client(url, http_client=client) as streams:
            read_stream, write_stream = streams[0], streams[1]
            yield read_stream, write_stream, lambda: None

    streamablehttp_client = _streamablehttp_client_v2  # type: ignore[assignment,unused-ignore]
else:
    _HTTP_LIB = httpx
    _to_auth = to_httpx_auth


def _field(obj: Any, snake: str, camel: str) -> Any:
    """Read an mcp.types field under its 2.x (snake_case) or 1.x (camelCase) name."""
    return getattr(obj, snake) if hasattr(obj, snake) else getattr(obj, camel)


# Errors that mean the request never got an answer. httpx2 has its own
# hierarchy, so on mcp 2.x both are listed.
_TIMEOUT_ERRORS: tuple[type[BaseException], ...] = (httpx.TimeoutException,)
_CONNECT_ERRORS: tuple[type[BaseException], ...] = (httpx.ConnectError,)
if _MCP_V2:
    _TIMEOUT_ERRORS += (httpx2.TimeoutException,)
    _CONNECT_ERRORS += (httpx2.ConnectError,)

# Status codes that mean "this server does not speak Streamable HTTP".
_MISMATCH_STATUS = (405, 406)

_STATUS_ERRORS: tuple[type[BaseException], ...] = (httpx.HTTPStatusError,)
if _MCP_V2:
    _STATUS_ERRORS += (httpx2.HTTPStatusError,)


_TransportClass = Literal["transport_mismatch", "real_failure"]


def _classify_transport_failure(
    exc: BaseException, http_status: int | None = None
) -> _TransportClass:
    """Decide whether *exc* indicates a transport-protocol mismatch (fallback eligible)
    or a real failure (auth/network/server) that should propagate as-is.

    Transport mismatch: target server does not speak modern Streamable HTTP.
    Triggers fallback to the legacy plain JSON-RPC POST path.

    Real failure: target accepted the modern transport but the operation
    itself failed for an orthogonal reason. No fallback — surface to caller.

    *http_status* is the status of the last HTTP response the transport saw.
    mcp 2.x reports an error status on a POST as an MCPError rather than an
    HTTPStatusError, so for an MCPError it is the only place a 405/406 shows.
    """
    # HTTP-level mismatch signals
    if isinstance(exc, _STATUS_ERRORS):
        code = exc.response.status_code  # type: ignore[attr-defined]
        if code in _MISMATCH_STATUS:
            return "transport_mismatch"
        return "real_failure"

    # ExceptionGroup may wrap inner causes (anyio raises these)
    if isinstance(exc, BaseExceptionGroup):  # type: ignore[has-type]
        for inner in exc.exceptions:
            if _classify_transport_failure(inner, http_status) == "transport_mismatch":
                return "transport_mismatch"
        return "real_failure"

    # MCP-level handshake refusal (server doesn't speak the protocol version we requested)
    if _MCP_SDK_AVAILABLE and isinstance(exc, McpError):
        if http_status in _MISMATCH_STATUS:
            return "transport_mismatch"
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


def _classify_failure_reason(exc: BaseException, http_status: int | None = None) -> str:
    """Human-readable fallback reason for the structured warning log."""
    if isinstance(exc, _STATUS_ERRORS):
        return f"http_{exc.response.status_code}"  # type: ignore[attr-defined]
    if isinstance(exc, BaseExceptionGroup):  # type: ignore[has-type]
        for inner in exc.exceptions:
            return _classify_failure_reason(inner, http_status)
    if _MCP_SDK_AVAILABLE and isinstance(exc, McpError):
        if http_status in _MISMATCH_STATUS:
            return f"http_{http_status}"
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
        structured = _field(result, "structured_content", "structuredContent")
        if structured is not None:
            return structured
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
                "inputSchema": _field(tool, "input_schema", "inputSchema"),
            }
            for tool in result.tools
        ],
        "nextCursor": _field(result, "next_cursor", "nextCursor"),
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
                    "version is out of range (supported: mcp >=1.30.0,<3.0.0). "
                    f"Reason: {_MCP_IMPORT_ERROR}"
                ),
            )

        mcp_method = method or "tools/list"
        mcp_arguments = arguments or {}
        headers = _build_caller_headers()

        start = time.perf_counter()
        capture = _TelemetryCapture()

        # ── Modern Streamable HTTP path ──────────────────────────────────
        try:
            return await self._invoke_via_streamable_http(
                capture=capture,
                endpoint=endpoint,
                mcp_method=mcp_method,
                mcp_arguments=mcp_arguments,
                timeout=timeout,
                auth_handler=auth_handler,
                headers=headers,
                start=start,
            )
        except _TIMEOUT_ERRORS + _CONNECT_ERRORS as exc:
            elapsed = (time.perf_counter() - start) * 1000
            return _build_failure_response(exc, elapsed)
        except BaseException as exc:  # noqa: BLE001 - we classify and re-raise via fallback if not transport_mismatch
            status = capture.http_status_code
            classification = _classify_transport_failure(exc, status)
            if classification != "transport_mismatch":
                elapsed = (time.perf_counter() - start) * 1000
                return _build_failure_response(exc, elapsed)

            # ── Transparent fallback to legacy plain JSON-RPC POST ──────
            reason = _classify_failure_reason(exc, status)
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
        capture: _TelemetryCapture,
        endpoint: str,
        mcp_method: str,
        mcp_arguments: dict[str, Any],
        timeout: float,
        auth_handler: AuthHandler | None,
        headers: dict[str, str],
        start: float,
    ) -> RawResponse:
        factory = _make_telemetry_factory(capture, _HTTP_LIB)
        auth = _to_auth(auth_handler)

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
                is_error = bool(_field(call_result, "is_error", "isError"))
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
    # anyio task groups wrap a transport error raised inside the SDK
    if isinstance(exc, BaseExceptionGroup) and len(exc.exceptions) == 1:  # type: ignore[has-type]
        return _build_failure_response(exc.exceptions[0], elapsed_ms)
    if isinstance(exc, _TIMEOUT_ERRORS):
        return RawResponse(
            success=False,
            status=InvocationStatus.TIMEOUT,
            error_type="TimeoutError",
            error_message=str(exc) or "Request timed out",
            invocation_latency_ms=elapsed_ms,
        )
    if isinstance(exc, _CONNECT_ERRORS):
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
