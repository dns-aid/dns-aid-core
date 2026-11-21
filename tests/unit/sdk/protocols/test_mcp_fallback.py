# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for the MCP transport fallback decision logic.

The handler tries the modern Streamable HTTP transport first. On
"transport mismatch" failures (HTTP 405/406, refused initialize via
JSON-RPC -32601, BaseExceptionGroup wrapping any of the above) it
transparently falls back to the legacy plain JSON-RPC POST path. On
"real failures" (auth, network timeout, connection refused, server
errors, tool errors) it must NOT fall back — the failure propagates
to the caller as RawResponse(success=False).
"""

from __future__ import annotations

import json

import httpx
import pytest

from dns_aid.sdk.models import InvocationStatus
from dns_aid.sdk.protocols.mcp import (
    MCPProtocolHandler,
    _classify_failure_reason,
    _classify_transport_failure,
)


def _mcp_error(code: int, message: str) -> Exception:
    """An MCP error as the installed SDK raises it.

    mcp 1.x builds McpError from an ErrorData; 2.x renamed it MCPError and
    takes the code and message directly.
    """
    from mcp.types import ErrorData

    from dns_aid.sdk.protocols.mcp import _MCP_V2, McpError

    if _MCP_V2:
        return McpError(code, message)  # type: ignore[call-arg]
    return McpError(ErrorData(code=code, message=message))


@pytest.fixture
def handler() -> MCPProtocolHandler:
    return MCPProtocolHandler()


def _legacy_response(payload: dict | None = None) -> httpx.Response:
    body = payload or {
        "jsonrpc": "2.0",
        "result": {"content": [{"type": "text", "text": json.dumps({"ok": True})}]},
        "id": 1,
    }
    return httpx.Response(200, json=body)


def _make_legacy_client_with_capture(headers_capture: dict) -> httpx.AsyncClient:
    """Return an AsyncClient whose MockTransport captures the request headers."""

    def transport_fn(request: httpx.Request) -> httpx.Response:
        headers_capture.update(dict(request.headers))
        return _legacy_response()

    return httpx.AsyncClient(transport=httpx.MockTransport(transport_fn))


def _install_modern_failure(monkeypatch: pytest.MonkeyPatch, exc: BaseException) -> None:
    """Patch streamablehttp_client to raise *exc* on entry."""

    class _Raiser:
        async def __aenter__(self):
            raise exc

        async def __aexit__(self, *exc_info):
            return False

    monkeypatch.setattr(
        "dns_aid.sdk.protocols.mcp.streamablehttp_client",
        lambda *a, **k: _Raiser(),
    )


# ── Classification unit tests (no handler involvement) ───────────────────


def test_classify_http_406_is_transport_mismatch() -> None:
    exc = httpx.HTTPStatusError(
        "406",
        request=httpx.Request("POST", "https://x"),
        response=httpx.Response(406),
    )
    assert _classify_transport_failure(exc) == "transport_mismatch"


def test_classify_http_405_is_transport_mismatch() -> None:
    exc = httpx.HTTPStatusError(
        "405",
        request=httpx.Request("POST", "https://x"),
        response=httpx.Response(405),
    )
    assert _classify_transport_failure(exc) == "transport_mismatch"


def test_classify_http_500_is_real_failure() -> None:
    exc = httpx.HTTPStatusError(
        "500",
        request=httpx.Request("POST", "https://x"),
        response=httpx.Response(500),
    )
    assert _classify_transport_failure(exc) == "real_failure"


def test_classify_http_401_is_real_failure() -> None:
    exc = httpx.HTTPStatusError(
        "401",
        request=httpx.Request("POST", "https://x"),
        response=httpx.Response(401),
    )
    assert _classify_transport_failure(exc) == "real_failure"


def test_classify_connect_error_is_real_failure() -> None:
    assert _classify_transport_failure(httpx.ConnectError("nope")) == "real_failure"


def test_classify_timeout_is_real_failure() -> None:
    assert _classify_transport_failure(httpx.ReadTimeout("slow")) == "real_failure"


def test_classify_mcp_method_not_found_is_transport_mismatch() -> None:
    exc = _mcp_error(-32601, "Method not found")
    assert _classify_transport_failure(exc) == "transport_mismatch"


def test_classify_mcp_other_error_is_real_failure() -> None:
    exc = _mcp_error(-32000, "Server error")
    assert _classify_transport_failure(exc) == "real_failure"


def test_classify_exception_group_with_inner_transport_mismatch() -> None:
    inner_406 = httpx.HTTPStatusError(
        "406",
        request=httpx.Request("POST", "https://x"),
        response=httpx.Response(406),
    )
    group = BaseExceptionGroup("group", [inner_406])
    assert _classify_transport_failure(group) == "transport_mismatch"


def test_classify_failure_reason_http() -> None:
    exc = httpx.HTTPStatusError(
        "406",
        request=httpx.Request("POST", "https://x"),
        response=httpx.Response(406),
    )
    assert _classify_failure_reason(exc) == "http_406"


def test_classify_failure_reason_initialize_refused() -> None:
    exc = _mcp_error(-32601, "Method not found")
    assert _classify_failure_reason(exc) == "initialize_refused"


# ── Handler-level fallback behavior tests ────────────────────────────────


@pytest.mark.asyncio
async def test_fallback_fires_on_http_406(
    handler: MCPProtocolHandler, monkeypatch: pytest.MonkeyPatch, caplog
) -> None:
    _install_modern_failure(
        monkeypatch,
        httpx.HTTPStatusError(
            "modern transport rejected",
            request=httpx.Request("POST", "https://example.com/mcp"),
            response=httpx.Response(406),
        ),
    )

    headers_capture: dict = {}
    async with _make_legacy_client_with_capture(headers_capture) as client:
        raw = await handler.invoke(
            client=client,
            endpoint="https://example.com/mcp",
            method="tools/list",
            arguments=None,
            timeout=5.0,
        )

    assert raw.success is True
    assert raw.status == InvocationStatus.SUCCESS


@pytest.mark.asyncio
async def test_fallback_fires_on_initialize_refused(
    handler: MCPProtocolHandler, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_modern_failure(
        monkeypatch,
        _mcp_error(-32601, "Method not found"),
    )

    headers_capture: dict = {}
    async with _make_legacy_client_with_capture(headers_capture) as client:
        raw = await handler.invoke(
            client=client,
            endpoint="https://example.com/mcp",
            method="tools/list",
            arguments=None,
            timeout=5.0,
        )

    assert raw.success is True


@pytest.mark.asyncio
async def test_no_fallback_on_auth_failure(
    handler: MCPProtocolHandler, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_modern_failure(
        monkeypatch,
        httpx.HTTPStatusError(
            "401",
            request=httpx.Request("POST", "https://example.com/mcp"),
            response=httpx.Response(401),
        ),
    )

    # Legacy path response would succeed if invoked, so a successful raw
    # response means the fallback fired (which it must NOT for 401).
    fallback_invoked = {"called": False}

    def transport_fn(request: httpx.Request) -> httpx.Response:
        fallback_invoked["called"] = True
        return _legacy_response()

    async with httpx.AsyncClient(transport=httpx.MockTransport(transport_fn)) as client:
        raw = await handler.invoke(
            client=client,
            endpoint="https://example.com/mcp",
            method="tools/list",
            arguments=None,
            timeout=5.0,
        )

    assert fallback_invoked["called"] is False, "Fallback must NOT fire on 401"
    assert raw.success is False
    assert raw.status == InvocationStatus.ERROR
    assert "401" in (raw.error_message or "")


@pytest.mark.asyncio
async def test_no_fallback_on_network_timeout(
    handler: MCPProtocolHandler, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_modern_failure(monkeypatch, httpx.ReadTimeout("Read timed out"))

    fallback_invoked = {"called": False}

    def transport_fn(request: httpx.Request) -> httpx.Response:
        fallback_invoked["called"] = True
        return _legacy_response()

    async with httpx.AsyncClient(transport=httpx.MockTransport(transport_fn)) as client:
        raw = await handler.invoke(
            client=client,
            endpoint="https://example.com/mcp",
            method="tools/list",
            arguments=None,
            timeout=5.0,
        )

    assert fallback_invoked["called"] is False, "Fallback must NOT fire on timeout"
    assert raw.success is False
    assert raw.status == InvocationStatus.TIMEOUT
    assert raw.error_type == "TimeoutError"


@pytest.mark.asyncio
async def test_no_fallback_on_connect_error(
    handler: MCPProtocolHandler, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_modern_failure(monkeypatch, httpx.ConnectError("Connection refused"))

    fallback_invoked = {"called": False}

    def transport_fn(request: httpx.Request) -> httpx.Response:
        fallback_invoked["called"] = True
        return _legacy_response()

    async with httpx.AsyncClient(transport=httpx.MockTransport(transport_fn)) as client:
        raw = await handler.invoke(
            client=client,
            endpoint="https://example.com/mcp",
            method="tools/list",
            arguments=None,
            timeout=5.0,
        )

    assert fallback_invoked["called"] is False, "Fallback must NOT fire on ConnectError"
    assert raw.success is False
    assert raw.status == InvocationStatus.REFUSED


# ── US2: Caller-domain header propagated on the fallback path too ────────


@pytest.mark.asyncio
async def test_caller_domain_header_propagated_in_fallback(
    handler: MCPProtocolHandler,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DNS_AID_CALLER_DOMAIN", "fallback.example.com")
    _install_modern_failure(
        monkeypatch,
        httpx.HTTPStatusError(
            "406",
            request=httpx.Request("POST", "https://example.com/mcp"),
            response=httpx.Response(406),
        ),
    )

    headers_capture: dict = {}
    async with _make_legacy_client_with_capture(headers_capture) as client:
        await handler.invoke(
            client=client,
            endpoint="https://example.com/mcp",
            method="tools/list",
            arguments=None,
            timeout=5.0,
        )

    # httpx lowercases header keys
    assert headers_capture.get("x-dns-aid-caller-domain") == "fallback.example.com"


@pytest.mark.asyncio
async def test_no_caller_domain_header_in_fallback_when_env_unset(
    handler: MCPProtocolHandler,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DNS_AID_CALLER_DOMAIN", raising=False)
    _install_modern_failure(
        monkeypatch,
        httpx.HTTPStatusError(
            "406",
            request=httpx.Request("POST", "https://example.com/mcp"),
            response=httpx.Response(406),
        ),
    )

    headers_capture: dict = {}
    async with _make_legacy_client_with_capture(headers_capture) as client:
        await handler.invoke(
            client=client,
            endpoint="https://example.com/mcp",
            method="tools/list",
            arguments=None,
            timeout=5.0,
        )

    assert "x-dns-aid-caller-domain" not in headers_capture


# ── mcp 2.x reports an HTTP error status as an MCPError (#291) ───────────


@pytest.mark.parametrize("status", [405, 406])
def test_classify_mcp_error_after_mismatch_status_is_transport_mismatch(status: int) -> None:
    exc = _mcp_error(-32603, "Server returned an error response")
    assert _classify_transport_failure(exc, status) == "transport_mismatch"
    assert _classify_failure_reason(exc, status) == f"http_{status}"


@pytest.mark.parametrize("status", [None, 200, 401, 500])
def test_classify_mcp_error_after_other_status_is_real_failure(status: int | None) -> None:
    exc = _mcp_error(-32603, "Server returned an error response")
    assert _classify_transport_failure(exc, status) == "real_failure"


def test_classify_mcp_error_in_a_group_uses_the_status() -> None:
    group = BaseExceptionGroup("tg", [_mcp_error(-32603, "Server returned an error response")])
    assert _classify_transport_failure(group, 406) == "transport_mismatch"


def test_failure_response_unwraps_a_single_exception_group() -> None:
    from dns_aid.sdk.protocols.mcp import _build_failure_response

    group = BaseExceptionGroup("tg", [httpx.ConnectError("refused")])
    raw = _build_failure_response(group, 1.0)

    assert raw.status == InvocationStatus.REFUSED
    assert raw.error_type == "ConnectError"


def test_field_reads_either_spelling() -> None:
    from types import SimpleNamespace

    from dns_aid.sdk.protocols.mcp import _field

    assert _field(SimpleNamespace(is_error=True), "is_error", "isError") is True
    assert _field(SimpleNamespace(isError=True), "is_error", "isError") is True
