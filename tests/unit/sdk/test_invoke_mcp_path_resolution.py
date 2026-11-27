# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""AgentClient.invoke() resolves the MCP endpoint path (issue #248)."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from dns_aid.core.models import AgentRecord, Protocol
from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.client import AgentClient
from dns_aid.sdk.models import InvocationStatus
from dns_aid.sdk.protocols.base import RawResponse


def _agent(protocol: Protocol = Protocol.MCP, override: str | None = None) -> AgentRecord:
    return AgentRecord(
        name="chat",
        domain="example.com",
        protocol=protocol,
        target_host="mcp.example.com",
        port=443,
        endpoint_override=override,
        endpoint_source="dns_svcb",
    )


def _ok() -> RawResponse:
    return RawResponse(
        success=True,
        status=InvocationStatus.SUCCESS,
        data={"tools": []},
        http_status_code=200,
    )


async def _invoke_capture(agent: AgentRecord, agent_json: httpx.Response | None):
    """Run invoke() with a mocked handler; return (endpoint seen, result)."""

    def respond(request: httpx.Request) -> httpx.Response:
        if agent_json is None:
            raise httpx.ConnectError("no agent.json")
        return agent_json

    real_client = httpx.AsyncClient
    transport = httpx.MockTransport(respond)

    def factory(*a, **kw):
        kw["transport"] = transport
        return real_client(*a, **kw)

    async with AgentClient(config=SDKConfig(caller_id="t")) as client:
        handler = client._get_handler(agent.protocol.value)
        with (
            patch.object(handler, "invoke", AsyncMock(return_value=_ok())) as inv,
            patch("dns_aid.core.invoke.httpx.AsyncClient", side_effect=factory),
            patch(
                "dns_aid.utils.url_safety.validate_fetch_url_async",
                new=AsyncMock(side_effect=lambda url, **kw: url),
            ),
        ):
            result = await client.invoke(agent, method="tools/list")
    return inv.await_args.kwargs["endpoint"], result


@pytest.mark.asyncio
async def test_bare_endpoint_uses_agent_json_path() -> None:
    resp = httpx.Response(200, json={"endpoints": {"mcp": "/api/mcp"}})
    endpoint, result = await _invoke_capture(_agent(), resp)
    assert endpoint == "https://mcp.example.com:443/api/mcp"
    # telemetry keeps the discovered identity, not the resolved URL
    assert result.signal.agent_endpoint == "https://mcp.example.com:443"


@pytest.mark.asyncio
async def test_bare_endpoint_falls_back_to_mcp_convention() -> None:
    endpoint, result = await _invoke_capture(_agent(), None)
    assert endpoint == "https://mcp.example.com:443/mcp"
    assert result.success


@pytest.mark.asyncio
async def test_endpoint_with_path_is_unchanged() -> None:
    endpoint, _ = await _invoke_capture(_agent(override="https://mcp.example.com/rpc"), None)
    assert endpoint == "https://mcp.example.com/rpc"


@pytest.mark.asyncio
async def test_non_mcp_protocol_is_not_resolved() -> None:
    endpoint, _ = await _invoke_capture(_agent(Protocol.A2A), None)
    assert endpoint == "https://mcp.example.com:443"
