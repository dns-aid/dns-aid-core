# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""A failure after a completed handshake must never replay through the legacy path.

The fallback decides "transport mismatch" partly from the last HTTP status the
transport saw. That status is shared across every request in the session, so a
405 on the session-closing DELETE (which the spec allows when a server doesn't
let clients end sessions) or on the GET stream could make a JSON-RPC error from
``tools/call`` look like a mismatch. The legacy path would then send the same
``tools/call`` again: the tool runs twice and the caller sees the replay's
result instead of the real error.

The server here is a bare ASGI app speaking just enough streamable HTTP (JSON
responses), so the test runs the real transport on both mcp 1.x and 2.x.
"""

from __future__ import annotations

import json
import socket
import threading
import time
from collections.abc import Iterator
from typing import Any

import httpx
import pytest

from dns_aid.sdk.protocols.mcp import _MCP_SDK_AVAILABLE, MCPProtocolHandler

pytestmark = pytest.mark.skipif(not _MCP_SDK_AVAILABLE, reason="needs the mcp SDK")

_SESSION_ID = "sess-1"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class _ErrorAfterHandshake:
    """Completes initialize, fails tools/* with a JSON-RPC error, 405s GET and DELETE."""

    def __init__(self) -> None:
        self.methods: list[str] = []

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            return
        self.methods.append(scope["method"])
        if scope["method"] != "POST":
            await self._send(send, 405, b"")
            return

        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break
        request = json.loads(body)

        if "id" not in request:  # notifications/initialized
            await self._send(send, 202, b"")
            return
        if request["method"] == "initialize":
            result: dict[str, Any] = {
                "result": {
                    "protocolVersion": request["params"]["protocolVersion"],
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "no-replay", "version": "1"},
                }
            }
        else:
            result = {"error": {"code": -32603, "message": "tool exploded"}}
        payload = json.dumps({"jsonrpc": "2.0", "id": request["id"], **result}).encode()
        await self._send(send, 200, payload, json_body=True)

    @staticmethod
    async def _send(send: Any, status: int, body: bytes, *, json_body: bool = False) -> None:
        headers = [(b"mcp-session-id", _SESSION_ID.encode())]
        if json_body:
            headers.append((b"content-type", b"application/json"))
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})


@pytest.fixture
def server() -> Iterator[tuple[str, _ErrorAfterHandshake]]:
    import uvicorn

    app = _ErrorAfterHandshake()
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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "arguments"),
    [
        ("tools/call", {"name": "explode", "arguments": {}}),
        ("tools/list", None),
    ],
)
async def test_error_after_handshake_is_not_replayed_via_legacy(
    server: tuple[str, _ErrorAfterHandshake],
    method: str,
    arguments: dict[str, Any] | None,
) -> None:
    endpoint, app = server
    legacy_calls: list[str] = []

    def legacy(request: httpx.Request) -> httpx.Response:
        legacy_calls.append(json.loads(request.content)["method"])
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"replayed": True}})

    async with httpx.AsyncClient(transport=httpx.MockTransport(legacy)) as client:
        raw = await MCPProtocolHandler().invoke(
            client=client,
            endpoint=endpoint,
            method=method,
            arguments=arguments,
            timeout=10.0,
        )

    assert legacy_calls == []
    assert not raw.success
    assert "POST" in app.methods
