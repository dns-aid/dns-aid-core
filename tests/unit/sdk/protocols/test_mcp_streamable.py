# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for the MCP Streamable HTTP transport (modern path).

These tests verify the handler's behavior when the modern Streamable HTTP
transport succeeds. For the legacy fallback path's behavior see
``tests/unit/sdk/test_mcp_handler.py``. For the fallback DECISION logic
see ``tests/unit/sdk/protocols/test_mcp_fallback.py``.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from dns_aid.sdk.models import InvocationStatus
from dns_aid.sdk.protocols.mcp import _CALLER_DOMAIN_HEADER, MCPProtocolHandler


def _build_call_tool_result(payload: Any, *, is_error: bool = False) -> Any:
    """Build a CallToolResult-like object matching what the official SDK returns."""
    from mcp.types import CallToolResult, TextContent

    text = json.dumps(payload) if not isinstance(payload, str) else payload
    return CallToolResult(
        content=[TextContent(type="text", text=text)],
        isError=is_error,
    )


def _build_list_tools_result(tool_names: list[str]) -> Any:
    """Build a ListToolsResult with the named tools (minimal schema)."""
    from mcp.types import ListToolsResult, Tool

    tools = [
        Tool(
            name=name,
            description=f"{name} tool",
            inputSchema={"type": "object", "properties": {}, "required": []},
        )
        for name in tool_names
    ]
    return ListToolsResult(tools=tools, nextCursor=None)


@pytest.fixture
def streamable_client_factory(monkeypatch: pytest.MonkeyPatch):
    """Returns a callable that installs a fake streamablehttp_client + ClientSession.

    Tests use this to inject the typed result they want the session to return,
    plus a hook to inspect the headers/auth that were passed.
    """
    captured: dict[str, Any] = {}

    def _install(
        *,
        call_tool_result: Any = None,
        list_tools_result: Any = None,
        on_initialize=None,
    ) -> dict[str, Any]:
        @asynccontextmanager
        async def fake_streamable(*args, **kwargs):
            captured["url"] = args[0] if args else kwargs.get("url")
            captured["headers"] = kwargs.get("headers")
            captured["auth"] = kwargs.get("auth")
            captured["timeout"] = kwargs.get("timeout")
            factory = kwargs.get("httpx_client_factory")
            captured["factory"] = factory
            # Simulate one HTTP request through the telemetry factory so
            # event hooks fire and capture signals.
            if factory is not None:
                client = factory(headers=kwargs.get("headers"), timeout=None, auth=None)
                request = httpx.Request("POST", captured["url"] or "https://example.com/mcp")
                response = httpx.Response(
                    200,
                    request=request,
                    headers={"x-cost-units": "0.05", "x-cost-currency": "USD"},
                    content=b'{"result":"ok"}',
                )
                # Trigger hooks manually since we are not actually sending
                for hook in client.event_hooks.get("request", []):
                    await hook(request)
                for hook in client.event_hooks.get("response", []):
                    await hook(response)
                await client.aclose()

            yield (MagicMock(), MagicMock(), lambda: "session-123")

        @asynccontextmanager
        async def fake_session(read_stream, write_stream):
            session = MagicMock()
            session.initialize = AsyncMock(
                return_value=on_initialize() if on_initialize else MagicMock()
            )
            session.call_tool = AsyncMock(return_value=call_tool_result)
            session.list_tools = AsyncMock(return_value=list_tools_result)
            yield session

        monkeypatch.setattr(
            "dns_aid.sdk.protocols.mcp.streamablehttp_client",
            fake_streamable,
        )
        monkeypatch.setattr(
            "dns_aid.sdk.protocols.mcp.ClientSession",
            fake_session,
        )
        return captured

    return _install


@pytest.fixture
def handler() -> MCPProtocolHandler:
    return MCPProtocolHandler()


# ── US1: Modern transport happy path ─────────────────────────────────────


@pytest.mark.asyncio
async def test_modern_transport_tools_call_happy_path(
    handler: MCPProtocolHandler, streamable_client_factory
) -> None:
    streamable_client_factory(
        call_tool_result=_build_call_tool_result({"result": "pong"}),
    )
    async with httpx.AsyncClient() as client:
        raw = await handler.invoke(
            client=client,
            endpoint="https://mcp.example.com/mcp",
            method="tools/call",
            arguments={"name": "ping", "arguments": {"host": "1.1.1.1"}},
            timeout=5.0,
        )

    assert raw.success is True
    assert raw.status == InvocationStatus.SUCCESS
    assert raw.data == {"result": "pong"}


@pytest.mark.asyncio
async def test_modern_transport_tools_list_happy_path(
    handler: MCPProtocolHandler, streamable_client_factory
) -> None:
    streamable_client_factory(
        list_tools_result=_build_list_tools_result(["ping", "traceroute"]),
    )
    async with httpx.AsyncClient() as client:
        raw = await handler.invoke(
            client=client,
            endpoint="https://mcp.example.com/mcp",
            method="tools/list",
            arguments=None,
            timeout=5.0,
        )

    assert raw.success is True
    assert isinstance(raw.data, dict)
    tools_payload = raw.data["tools"]
    assert [t["name"] for t in tools_payload] == ["ping", "traceroute"]


@pytest.mark.asyncio
async def test_telemetry_signals_populated_on_modern_path(
    handler: MCPProtocolHandler, streamable_client_factory
) -> None:
    streamable_client_factory(
        call_tool_result=_build_call_tool_result({"ok": True}),
    )
    async with httpx.AsyncClient() as client:
        raw = await handler.invoke(
            client=client,
            endpoint="https://mcp.example.com/mcp",
            method="tools/call",
            arguments={"name": "ping", "arguments": {}},
            timeout=5.0,
        )

    assert raw.invocation_latency_ms is not None
    assert raw.invocation_latency_ms > 0
    assert raw.ttfb_ms is not None
    assert raw.response_size_bytes is not None
    assert raw.response_size_bytes > 0
    assert raw.http_status_code == 200
    assert raw.headers is not None


@pytest.mark.asyncio
async def test_cost_headers_propagated_on_modern_path(
    handler: MCPProtocolHandler, streamable_client_factory
) -> None:
    streamable_client_factory(
        call_tool_result=_build_call_tool_result({"ok": True}),
    )
    async with httpx.AsyncClient() as client:
        raw = await handler.invoke(
            client=client,
            endpoint="https://mcp.example.com/mcp",
            method="tools/call",
            arguments={"name": "ping", "arguments": {}},
            timeout=5.0,
        )

    assert raw.cost_units == 0.05
    assert raw.cost_currency == "USD"


@pytest.mark.asyncio
async def test_concurrent_modern_invocations_correlate(
    handler: MCPProtocolHandler, streamable_client_factory
) -> None:
    """asyncio.gather of N invocations all complete with their expected results."""
    # Each invocation sees its own streamable_client_factory installation,
    # so we need a session-scoped fake that can return distinct results per call.
    # Use a counter-based mock.
    counter = {"n": 0}
    payloads = ["alpha", "beta", "gamma", "delta", "epsilon"]

    @asynccontextmanager
    async def fake_streamable(*args, **kwargs):
        factory = kwargs.get("httpx_client_factory")
        if factory is not None:
            client = factory(headers=kwargs.get("headers"), timeout=None, auth=None)
            request = httpx.Request("POST", args[0])
            response = httpx.Response(200, request=request, content=b"{}")
            for hook in client.event_hooks.get("request", []):
                await hook(request)
            for hook in client.event_hooks.get("response", []):
                await hook(response)
            await client.aclose()
        yield (MagicMock(), MagicMock(), lambda: f"session-{counter['n']}")

    @asynccontextmanager
    async def fake_session(rs, ws):
        session = MagicMock()
        session.initialize = AsyncMock(return_value=MagicMock())
        idx = counter["n"]
        counter["n"] += 1
        session.call_tool = AsyncMock(
            return_value=_build_call_tool_result({"index": idx, "payload": payloads[idx]})
        )
        yield session

    import dns_aid.sdk.protocols.mcp as mcp_module

    original_streamable = mcp_module.streamablehttp_client
    original_session = mcp_module.ClientSession
    mcp_module.streamablehttp_client = fake_streamable
    mcp_module.ClientSession = fake_session
    try:
        async with httpx.AsyncClient() as client:
            results = await asyncio.gather(
                *[
                    handler.invoke(
                        client=client,
                        endpoint="https://mcp.example.com/mcp",
                        method="tools/call",
                        arguments={"name": "ping", "arguments": {}},
                        timeout=5.0,
                    )
                    for _ in payloads
                ]
            )
    finally:
        mcp_module.streamablehttp_client = original_streamable
        mcp_module.ClientSession = original_session

    assert len(results) == len(payloads)
    indices = sorted(r.data["index"] for r in results)
    assert indices == [0, 1, 2, 3, 4]
    for r in results:
        assert r.success is True
    assert counter["n"] == len(payloads)


# ── US1: Tool error reported as failure ──────────────────────────────────


@pytest.mark.asyncio
async def test_tool_is_error_flag_marks_response_unsuccessful(
    handler: MCPProtocolHandler, streamable_client_factory
) -> None:
    streamable_client_factory(
        call_tool_result=_build_call_tool_result({"error": "tool failed"}, is_error=True),
    )
    async with httpx.AsyncClient() as client:
        raw = await handler.invoke(
            client=client,
            endpoint="https://mcp.example.com/mcp",
            method="tools/call",
            arguments={"name": "broken", "arguments": {}},
            timeout=5.0,
        )

    assert raw.success is False
    assert raw.status == InvocationStatus.ERROR
    assert raw.error_type == "ToolError"


# ── US2: Caller-identity header propagation ──────────────────────────────


@pytest.mark.asyncio
async def test_caller_domain_header_set_when_env_var_present(
    handler: MCPProtocolHandler,
    streamable_client_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DNS_AID_CALLER_DOMAIN", "test.example.com")
    captured = streamable_client_factory(
        call_tool_result=_build_call_tool_result({"ok": True}),
    )

    async with httpx.AsyncClient() as client:
        await handler.invoke(
            client=client,
            endpoint="https://mcp.example.com/mcp",
            method="tools/call",
            arguments={"name": "ping", "arguments": {}},
            timeout=5.0,
        )

    assert captured["headers"] is not None
    assert captured["headers"][_CALLER_DOMAIN_HEADER] == "test.example.com"


@pytest.mark.asyncio
async def test_caller_domain_header_omitted_when_env_var_unset(
    handler: MCPProtocolHandler,
    streamable_client_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DNS_AID_CALLER_DOMAIN", raising=False)
    captured = streamable_client_factory(
        call_tool_result=_build_call_tool_result({"ok": True}),
    )

    async with httpx.AsyncClient() as client:
        await handler.invoke(
            client=client,
            endpoint="https://mcp.example.com/mcp",
            method="tools/call",
            arguments={"name": "ping", "arguments": {}},
            timeout=5.0,
        )

    # Header omitted entirely (None or absent), NOT sent as empty string
    assert captured["headers"] is None or _CALLER_DOMAIN_HEADER not in captured["headers"]


@pytest.mark.asyncio
async def test_caller_domain_header_omitted_when_env_var_empty(
    handler: MCPProtocolHandler,
    streamable_client_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DNS_AID_CALLER_DOMAIN", "")
    captured = streamable_client_factory(
        call_tool_result=_build_call_tool_result({"ok": True}),
    )

    async with httpx.AsyncClient() as client:
        await handler.invoke(
            client=client,
            endpoint="https://mcp.example.com/mcp",
            method="tools/call",
            arguments={"name": "ping", "arguments": {}},
            timeout=5.0,
        )

    assert captured["headers"] is None or _CALLER_DOMAIN_HEADER not in captured["headers"]


@pytest.mark.asyncio
async def test_caller_domain_header_strips_whitespace(
    handler: MCPProtocolHandler,
    streamable_client_factory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DNS_AID_CALLER_DOMAIN", "  whitespace.example.com  ")
    captured = streamable_client_factory(
        call_tool_result=_build_call_tool_result({"ok": True}),
    )

    async with httpx.AsyncClient() as client:
        await handler.invoke(
            client=client,
            endpoint="https://mcp.example.com/mcp",
            method="tools/call",
            arguments={"name": "ping", "arguments": {}},
            timeout=5.0,
        )

    assert captured["headers"][_CALLER_DOMAIN_HEADER] == "whitespace.example.com"


# ── US1: Auth handler propagation ────────────────────────────────────────


@pytest.mark.asyncio
async def test_auth_handler_passed_through_as_httpx_auth(
    handler: MCPProtocolHandler, streamable_client_factory
) -> None:
    from dns_aid.sdk.auth.simple import BearerAuthHandler

    auth = BearerAuthHandler(token="test-token-abc")
    captured = streamable_client_factory(
        call_tool_result=_build_call_tool_result({"ok": True}),
    )

    async with httpx.AsyncClient() as client:
        await handler.invoke(
            client=client,
            endpoint="https://mcp.example.com/mcp",
            method="tools/call",
            arguments={"name": "ping", "arguments": {}},
            timeout=5.0,
            auth_handler=auth,
        )

    from dns_aid.sdk.protocols.mcp import _HTTP_LIB

    assert captured["auth"] is not None
    # httpx.Auth on mcp 1.x, httpx2.Auth on 2.x: each client only takes its own.
    assert isinstance(captured["auth"], _HTTP_LIB.Auth)


@pytest.mark.asyncio
async def test_no_auth_handler_passes_none_to_streamable_client(
    handler: MCPProtocolHandler, streamable_client_factory
) -> None:
    captured = streamable_client_factory(
        call_tool_result=_build_call_tool_result({"ok": True}),
    )

    async with httpx.AsyncClient() as client:
        await handler.invoke(
            client=client,
            endpoint="https://mcp.example.com/mcp",
            method="tools/call",
            arguments={"name": "ping", "arguments": {}},
            timeout=5.0,
            auth_handler=None,
        )

    assert captured["auth"] is None
