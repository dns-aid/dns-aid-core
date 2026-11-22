# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""The URL invoke() actually called is reported as resolved_endpoint (issue #293)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from dns_aid.core.models import AgentRecord, Protocol
from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.client import AgentClient
from dns_aid.sdk.models import InvocationSignal, InvocationStatus
from dns_aid.sdk.protocols.base import RawResponse
from dns_aid.sdk.telemetry.otel import (
    ATTR_AGENT_ENDPOINT,
    ATTR_AGENT_RESOLVED_ENDPOINT,
    TelemetryManager,
)


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


def _signal(resolved: str | None) -> InvocationSignal:
    return InvocationSignal(
        agent_fqdn="_chat._mcp._agents.example.com",
        agent_endpoint="https://user:secret@mcp.example.com:443",
        resolved_endpoint=resolved,
        protocol="mcp",
        invocation_latency_ms=12.0,
        status=InvocationStatus.SUCCESS,
    )


async def _invoke(agent: AgentRecord, agent_json: httpx.Response | None) -> InvocationSignal:
    def respond(request: httpx.Request) -> httpx.Response:
        if agent_json is None:
            raise httpx.ConnectError("no agent.json")
        return agent_json

    real_client = httpx.AsyncClient
    transport = httpx.MockTransport(respond)

    def factory(*a, **kw):
        kw["transport"] = transport
        return real_client(*a, **kw)

    ok = RawResponse(success=True, status=InvocationStatus.SUCCESS, data={}, http_status_code=200)
    async with AgentClient(config=SDKConfig(caller_id="t")) as client:
        handler = client._get_handler(agent.protocol.value)
        with (
            patch.object(handler, "invoke", AsyncMock(return_value=ok)),
            patch("dns_aid.core.invoke.httpx.AsyncClient", side_effect=factory),
            patch(
                "dns_aid.utils.url_safety.validate_fetch_url_async",
                new=AsyncMock(side_effect=lambda url, **kw: url),
            ),
        ):
            result = await client.invoke(agent, method="tools/list")
    return result.signal


@pytest.mark.asyncio
async def test_resolved_path_is_recorded_and_identity_kept() -> None:
    resp = httpx.Response(200, json={"endpoints": {"mcp": "/api/mcp"}})
    signal = await _invoke(_agent(), resp)
    assert signal.agent_endpoint == "https://mcp.example.com:443"
    assert signal.resolved_endpoint == "https://mcp.example.com:443/api/mcp"


@pytest.mark.asyncio
async def test_convention_guess_is_recorded() -> None:
    signal = await _invoke(_agent(), None)
    assert signal.resolved_endpoint == "https://mcp.example.com:443/mcp"


@pytest.mark.asyncio
async def test_omitted_when_endpoint_called_as_is() -> None:
    signal = await _invoke(_agent(override="https://mcp.example.com/rpc"), None)
    assert signal.resolved_endpoint is None


@pytest.mark.asyncio
async def test_omitted_for_non_mcp_protocol() -> None:
    signal = await _invoke(_agent(Protocol.A2A), None)
    assert signal.resolved_endpoint is None


def test_span_attribute_is_sanitized() -> None:
    attrs = TelemetryManager._build_span_end_attributes(
        _signal("https://user:secret@mcp.example.com:443/api/mcp")
    )
    assert attrs[ATTR_AGENT_RESOLVED_ENDPOINT] == "https://mcp.example.com:443/api/mcp"
    assert "secret" not in str(attrs)


def test_span_attribute_absent_when_not_resolved() -> None:
    attrs = TelemetryManager._build_span_attributes(_signal(None))
    assert ATTR_AGENT_RESOLVED_ENDPOINT not in attrs
    assert attrs[ATTR_AGENT_ENDPOINT] == "https://mcp.example.com:443"


def _pushed_payload(signal: InvocationSignal) -> dict:
    with patch("dns_aid.sdk.client.httpx.post") as post:
        post.return_value = MagicMock(status_code=202)
        AgentClient._push_signal_http_sync(signal, "https://api.test.io/signals")
    return post.call_args.kwargs["json"]


def test_push_payload_carries_sanitized_resolved_endpoint() -> None:
    payload = _pushed_payload(_signal("https://user:secret@mcp.example.com:443/api/mcp"))
    assert payload["resolved_endpoint"] == "https://mcp.example.com:443/api/mcp"


def test_push_payload_omits_resolved_endpoint_when_unset() -> None:
    payload = _pushed_payload(_signal(None))
    assert "resolved_endpoint" not in payload
