# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for the MCP transport error remediation messages (US3).

These tests verify that error paths surface clear, actionable messages
instead of opaque stack traces or HTTP 406 with no remediation hint.
"""

from __future__ import annotations

import httpx
import pytest

from dns_aid.sdk.models import InvocationStatus
from dns_aid.sdk.protocols.mcp import MCPProtocolHandler


@pytest.fixture
def handler() -> MCPProtocolHandler:
    return MCPProtocolHandler()


def _install_modern_failure(monkeypatch: pytest.MonkeyPatch, exc: BaseException) -> None:
    class _Raiser:
        async def __aenter__(self):
            raise exc

        async def __aexit__(self, *exc_info):
            return False

    monkeypatch.setattr(
        "dns_aid.sdk.protocols.mcp.streamablehttp_client",
        lambda *a, **k: _Raiser(),
    )


def _install_legacy_failure(transport_fn) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(transport_fn))


@pytest.mark.asyncio
async def test_missing_mcp_extra_returns_clear_remediation(
    handler: MCPProtocolHandler, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the [mcp] extra is not installed, surface a clear install message."""
    import dns_aid.sdk.protocols.mcp as mcp_module

    monkeypatch.setattr(mcp_module, "_MCP_SDK_AVAILABLE", False)
    monkeypatch.setattr(mcp_module, "_MCP_IMPORT_ERROR", "No module named 'mcp'")

    async with httpx.AsyncClient() as client:
        raw = await handler.invoke(
            client=client,
            endpoint="https://example.com/mcp",
            method="tools/list",
            arguments=None,
            timeout=5.0,
        )

    assert raw.success is False
    assert raw.status == InvocationStatus.ERROR
    assert raw.error_type == "ImportError"
    assert "dns-aid[mcp]" in (raw.error_message or "")
    # The underlying import error is echoed so a missing package and an
    # unsupported version are distinguishable from the message alone.
    assert "No module named 'mcp'" in (raw.error_message or "")


@pytest.mark.asyncio
async def test_unsupported_mcp_version_is_distinguishable_from_missing_package(
    handler: MCPProtocolHandler, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An installed-but-unsupported mcp must not be reported as a missing extra.

    mcp 2.x is importable but its streamable_http_client requires httpx2, so the
    handler marks the transport unavailable. Telling that user to install the
    [mcp] extra they already have sends them the wrong way; the message has to
    name the version range.
    """
    import dns_aid.sdk.protocols.mcp as mcp_module

    monkeypatch.setattr(mcp_module, "_MCP_SDK_AVAILABLE", False)
    monkeypatch.setattr(
        mcp_module,
        "_MCP_IMPORT_ERROR",
        "mcp 2.x is installed, but its streamable_http_client requires an httpx2.AsyncClient",
    )

    async with httpx.AsyncClient() as client:
        raw = await handler.invoke(
            client=client,
            endpoint="https://example.com/mcp",
            method="tools/list",
            arguments=None,
            timeout=5.0,
        )

    assert raw.success is False
    assert raw.error_type == "ImportError"
    message = raw.error_message or ""
    assert "mcp >=1.28.1,<2.0.0" in message, "the supported range must be stated"
    assert "httpx2" in message, "the actual blocker must reach the user"


@pytest.mark.asyncio
async def test_double_transport_failure_includes_legacy_context(
    handler: MCPProtocolHandler, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Modern path 406 + legacy path 406 → error names the legacy fallback context."""
    _install_modern_failure(
        monkeypatch,
        httpx.HTTPStatusError(
            "modern 406",
            request=httpx.Request("POST", "https://example.com/mcp"),
            response=httpx.Response(406),
        ),
    )

    def legacy_also_fails(request: httpx.Request) -> httpx.Response:
        return httpx.Response(406, text="legacy also rejected")

    async with _install_legacy_failure(legacy_also_fails) as client:
        raw = await handler.invoke(
            client=client,
            endpoint="https://example.com/mcp",
            method="tools/list",
            arguments=None,
            timeout=5.0,
        )

    assert raw.success is False
    assert raw.status == InvocationStatus.ERROR
    assert raw.http_status_code == 406
    msg = raw.error_message or ""
    # Message must indicate this came through the legacy fallback (modern already failed)
    assert "legacy fallback" in msg.lower()
    assert "406" in msg


@pytest.mark.asyncio
async def test_initialize_refused_classified_as_transport_mismatch(
    handler: MCPProtocolHandler, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A server that refuses initialize via -32601 should still try legacy fallback."""
    from mcp.shared.exceptions import McpError
    from mcp.types import ErrorData

    _install_modern_failure(
        monkeypatch,
        McpError(ErrorData(code=-32601, message="Method not found: initialize")),
    )

    def legacy_succeeds(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "jsonrpc": "2.0",
                "result": {"content": [{"type": "text", "text": '{"ok": true}'}]},
                "id": 1,
            },
        )

    async with _install_legacy_failure(legacy_succeeds) as client:
        raw = await handler.invoke(
            client=client,
            endpoint="https://example.com/mcp",
            method="tools/list",
            arguments=None,
            timeout=5.0,
        )

    assert raw.success is True


@pytest.mark.asyncio
async def test_auth_failure_clear_error(
    handler: MCPProtocolHandler, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A 401 from the modern path must NOT trigger fallback, must surface clearly."""
    _install_modern_failure(
        monkeypatch,
        httpx.HTTPStatusError(
            "401 Unauthorized",
            request=httpx.Request("POST", "https://example.com/mcp"),
            response=httpx.Response(401),
        ),
    )

    async with httpx.AsyncClient() as client:
        raw = await handler.invoke(
            client=client,
            endpoint="https://example.com/mcp",
            method="tools/list",
            arguments=None,
            timeout=5.0,
        )

    assert raw.success is False
    assert raw.status == InvocationStatus.ERROR
    msg = (raw.error_message or "").lower()
    # Must NOT suggest a transport remediation (auth ≠ transport problem)
    assert "transport" not in msg or "401" in msg
    # Must surface the underlying status
    assert "401" in (raw.error_message or "")


@pytest.mark.asyncio
async def test_unsupported_method_returns_clear_error(
    handler: MCPProtocolHandler, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unknown method passed to handler should surface a clear ERROR."""
    # Stub modern path so it succeeds (we want to exercise the method dispatch branch)
    from contextlib import asynccontextmanager
    from unittest.mock import AsyncMock, MagicMock

    @asynccontextmanager
    async def fake_streamable(*args, **kwargs):
        factory = kwargs.get("httpx_client_factory")
        if factory is not None:
            client = factory(headers=None, timeout=None, auth=None)
            await client.aclose()
        yield (MagicMock(), MagicMock(), lambda: "session-x")

    @asynccontextmanager
    async def fake_session(rs, ws):
        session = MagicMock()
        session.initialize = AsyncMock(return_value=MagicMock())
        yield session

    monkeypatch.setattr("dns_aid.sdk.protocols.mcp.streamablehttp_client", fake_streamable)
    monkeypatch.setattr("dns_aid.sdk.protocols.mcp.ClientSession", fake_session)

    async with httpx.AsyncClient() as client:
        raw = await handler.invoke(
            client=client,
            endpoint="https://example.com/mcp",
            method="unknown/weird-method",
            arguments=None,
            timeout=5.0,
        )

    assert raw.success is False
    assert raw.status == InvocationStatus.ERROR
    assert raw.error_type == "UnsupportedMethod"
    assert "unknown/weird-method" in (raw.error_message or "")
