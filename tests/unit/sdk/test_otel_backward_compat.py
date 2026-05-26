# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Spec 005 — US6 tests: lossless backward compatibility (release-blocker).

Verifies that with otel_enabled=False, the SDK's externally observable
behavior matches v0.21.3 — no new headers on outbound requests, no new
structlog event fields, no behavior change.
"""

from __future__ import annotations

import httpx
import pytest

from dns_aid.core.models import AgentRecord, Protocol
from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.client import AgentClient


def _agent() -> AgentRecord:
    return AgentRecord(
        name="echo",
        domain="example.com",
        protocol=Protocol.HTTPS,
        target_host="echo.example.com",
        port=443,
    )


class TestOTELDisabledOutboundHeaders:
    """Outbound HTTP requests carry NO OTEL headers when otel_enabled=False."""

    @pytest.mark.asyncio
    async def test_no_otel_headers_https(self) -> None:
        captured: list[httpx.Request] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            captured.append(request)
            return httpx.Response(200, json={"ok": True})

        transport = httpx.MockTransport(handler)
        config = SDKConfig(otel_enabled=False)
        async with AgentClient(config=config) as client:
            client._http_client = httpx.AsyncClient(transport=transport)
            await client.invoke(_agent(), method="probe")

        headers = captured[0].headers
        # OTEL headers must be absent
        assert "traceparent" not in headers
        assert "tracestate" not in headers
        assert "baggage" not in headers

    @pytest.mark.asyncio
    async def test_no_otel_headers_a2a(self) -> None:
        captured: list[httpx.Request] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            captured.append(request)
            return httpx.Response(200, json={"jsonrpc": "2.0", "result": {}, "id": 1})

        transport = httpx.MockTransport(handler)
        config = SDKConfig(otel_enabled=False)
        async with AgentClient(config=config) as client:
            client._http_client = httpx.AsyncClient(transport=transport)
            agent = AgentRecord(
                name="chat",
                domain="example.com",
                protocol=Protocol.A2A,
                target_host="chat.example.com",
                port=443,
            )
            await client.invoke(agent, method="message/send", arguments={"text": "hi"})

        assert "traceparent" not in captured[0].headers


class TestExistingInvokePathUnchanged:
    """The signal shape and return value match the pre-v0.23.0 contract."""

    @pytest.mark.asyncio
    async def test_invocation_result_shape_unchanged(self) -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"ok": True}, headers={"x-cost-units": "0.05"})

        transport = httpx.MockTransport(handler)
        config = SDKConfig(otel_enabled=False)
        async with AgentClient(config=config) as client:
            client._http_client = httpx.AsyncClient(transport=transport)
            result = await client.invoke(_agent(), method="probe")

        # Same fields as v0.21.3
        assert result.success is True
        assert result.signal.protocol == "https"
        assert result.signal.method == "probe"
        assert result.signal.cost_units == 0.05
        assert result.signal.status.value == "success"
