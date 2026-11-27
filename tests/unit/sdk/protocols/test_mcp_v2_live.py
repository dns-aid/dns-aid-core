# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""MCP client against a real mcp 2.x server over loopback (#291).

The other MCP tests stub ``streamablehttp_client``. These run the actual 2.x
transport (``streamable_http_client`` on an httpx2 client) against an in-process
server, so they cover what a stub cannot: that the 2.x shim hands the SDK a
client it can drive, SSE and JSON responses both decode, and the auth handler,
caller-domain header and telemetry hooks all see the real requests.

Skipped on mcp 1.x; CI runs them in the ``mcp-2x-client`` job.
"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from typing import Any

import httpx
import pytest

from dns_aid.sdk.models import InvocationStatus
from dns_aid.sdk.protocols.mcp import _MCP_V2, MCPProtocolHandler

pytestmark = pytest.mark.skipif(not _MCP_V2, reason="needs mcp 2.x")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class _HeaderRecorder:
    """ASGI wrapper that keeps the headers of every HTTP request it sees."""

    def __init__(self, app: Any) -> None:
        self.app = app
        self.requests: list[tuple[str, dict[str, str]]] = []

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
            self.requests.append((scope["method"], headers))
        await self.app(scope, receive, send)


def _serve(json_response: bool) -> Iterator[tuple[str, _HeaderRecorder]]:
    import uvicorn
    from mcp.server.mcpserver import MCPServer

    server = MCPServer("live-test")

    @server.tool()
    def echo(text: str) -> str:
        """Return the text unchanged."""
        return text

    @server.tool()
    def fail() -> str:
        """Always raise, so the result comes back with is_error set."""
        raise ValueError("boom")

    app = _HeaderRecorder(server.streamable_http_app(json_response=json_response))
    port = _free_port()
    uv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=uv.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not uv.started:
        if time.monotonic() > deadline:
            raise RuntimeError("uvicorn did not start")
        time.sleep(0.02)
    try:
        yield f"http://127.0.0.1:{port}/mcp", app
    finally:
        uv.should_exit = True
        thread.join(timeout=10)


@pytest.fixture(params=[False, True], ids=["sse", "json"])
def live_server(request: pytest.FixtureRequest) -> Iterator[tuple[str, _HeaderRecorder]]:
    yield from _serve(json_response=request.param)


async def _invoke(endpoint: str, method: str, arguments: Any = None, auth_handler: Any = None):
    # The shared client is only used by the legacy fallback; a request reaching
    # it means the modern path failed, so make that loud.
    def _no_fallback(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"legacy fallback was used: {request.method} {request.url}")

    async with httpx.AsyncClient(transport=httpx.MockTransport(_no_fallback)) as client:
        return await MCPProtocolHandler().invoke(
            client=client,
            endpoint=endpoint,
            method=method,
            arguments=arguments,
            timeout=10.0,
            auth_handler=auth_handler,
        )


@pytest.mark.asyncio
async def test_tools_list(live_server) -> None:
    endpoint, _ = live_server
    raw = await _invoke(endpoint, "tools/list")

    assert raw.success, raw.error_message
    tools = {t["name"]: t for t in raw.data["tools"]}
    assert set(tools) == {"echo", "fail"}
    assert tools["echo"]["inputSchema"]["properties"]["text"]["type"] == "string"
    assert raw.data["nextCursor"] is None
    assert raw.http_status_code == 200


@pytest.mark.asyncio
async def test_tools_call(live_server) -> None:
    endpoint, _ = live_server
    raw = await _invoke(endpoint, "tools/call", {"name": "echo", "arguments": {"text": "hello"}})

    assert raw.success, raw.error_message
    assert raw.status == InvocationStatus.SUCCESS
    assert raw.data == "hello"


@pytest.mark.asyncio
async def test_tool_error_marks_the_response_unsuccessful(live_server) -> None:
    endpoint, _ = live_server
    raw = await _invoke(endpoint, "tools/call", {"name": "fail", "arguments": {}})

    assert raw.success is False
    assert raw.error_type == "ToolError"
    # The server reports the failure without the exception text.
    assert "fail" in (raw.error_message or "")


@pytest.mark.asyncio
async def test_auth_and_caller_domain_reach_every_request(
    live_server, monkeypatch: pytest.MonkeyPatch
) -> None:
    from dns_aid.sdk.auth.simple import BearerAuthHandler

    endpoint, recorder = live_server
    monkeypatch.setenv("DNS_AID_CALLER_DOMAIN", "caller.example.com")

    raw = await _invoke(endpoint, "tools/list", auth_handler=BearerAuthHandler(token="t0ken"))

    assert raw.success, raw.error_message
    posts = [headers for method, headers in recorder.requests if method == "POST"]
    # initialize, notifications/initialized, tools/list
    assert len(posts) >= 3
    for headers in posts:
        assert headers.get("authorization") == "Bearer t0ken"
        assert headers.get("x-dns-aid-caller-domain") == "caller.example.com"


@pytest.mark.asyncio
async def test_unreachable_server_is_refused_not_an_error() -> None:
    raw = await _invoke(f"http://127.0.0.1:{_free_port()}/mcp", "tools/list")

    assert raw.status == InvocationStatus.REFUSED
    assert raw.error_type == "ConnectError"


async def _reject_with_406(scope: Any, receive: Any, send: Any) -> None:
    """A server that only speaks the legacy transport and refuses streamable HTTP."""
    if scope["type"] != "http":
        return
    await send({"type": "http.response.start", "status": 406, "headers": []})
    await send({"type": "http.response.body", "body": b""})


@pytest.fixture
def rejecting_server() -> Iterator[str]:
    import uvicorn

    port = _free_port()
    uv = uvicorn.Server(
        uvicorn.Config(_reject_with_406, host="127.0.0.1", port=port, log_level="error")
    )
    thread = threading.Thread(target=uv.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not uv.started:
        if time.monotonic() > deadline:
            raise RuntimeError("uvicorn did not start")
        time.sleep(0.02)
    try:
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        uv.should_exit = True
        thread.join(timeout=10)


@pytest.mark.asyncio
async def test_406_still_falls_back_to_the_legacy_transport(rejecting_server: str) -> None:
    """mcp 2.x turns a 406 into an MCPError, not an HTTPStatusError.

    The fallback has to recognise it from the recorded status instead, or every
    legacy-only server stops working on 2.x.
    """

    def legacy(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "legacy"}]}},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(legacy)) as client:
        raw = await MCPProtocolHandler().invoke(
            client=client,
            endpoint=rejecting_server,
            method="tools/list",
            arguments=None,
            timeout=10.0,
        )

    assert raw.success, raw.error_message
    assert raw.data == {"tools": [{"name": "legacy"}]}


@pytest.mark.asyncio
async def test_httpx2_auth_adapter_applies_the_handler() -> None:
    import httpx2

    from dns_aid.sdk.auth._httpx_adapter import to_httpx2_auth
    from dns_aid.sdk.auth.simple import BearerAuthHandler

    auth = to_httpx2_auth(BearerAuthHandler(token="abc"))
    assert isinstance(auth, httpx2.Auth)

    request = httpx2.Request("POST", "https://example.com/mcp")
    flow = auth.async_auth_flow(request)
    signed = await flow.__anext__()
    assert signed.headers["authorization"] == "Bearer abc"
    assert to_httpx2_auth(None) is None
