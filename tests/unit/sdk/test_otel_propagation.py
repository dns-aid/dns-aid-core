# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Spec 005 — US2 tests: W3C Trace Context propagation.

Asserts that outbound MCP/A2A/HTTPS requests carry ``traceparent`` (and
``tracestate``/``baggage`` when applicable) when an OTEL span is active,
and that NO header is added when otel_enabled=False or no current span.
"""

from __future__ import annotations

import httpx
import pytest

from dns_aid.core.models import AgentRecord, Protocol
from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.client import AgentClient
from dns_aid.sdk.telemetry.otel import _otel_available
from dns_aid.sdk.telemetry.propagation import inject_otel_context

# OTEL feature tests — skip when opentelemetry isn't installed (FR-012:
# the SDK still works without it; that path is covered by
# test_otel_no_opentelemetry.py / test_otel_backward_compat.py).
pytestmark = pytest.mark.skipif(
    not _otel_available, reason="opentelemetry not installed ([otel] extra)"
)


def _agent(protocol: Protocol, name: str = "echo") -> AgentRecord:
    return AgentRecord(
        name=name,
        domain="example.com",
        protocol=protocol,
        target_host=f"{name}.example.com",
        port=443,
    )


def _ok_response() -> httpx.Response:
    return httpx.Response(200, json={"jsonrpc": "2.0", "result": {"ok": True}, "id": 1})


_TRACEPARENT_RE = r"^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$"


class TestTraceparentHTTPS:
    @pytest.mark.asyncio
    async def test_traceparent_injected_when_otel_enabled_and_span_active(self) -> None:
        captured: list[httpx.Request] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            captured.append(request)
            return _ok_response()

        transport = httpx.MockTransport(handler)
        config = SDKConfig(otel_enabled=True, otel_export_format="console")
        async with AgentClient(config=config) as client:
            client._http_client = httpx.AsyncClient(transport=transport)
            await client.invoke(_agent(Protocol.HTTPS), method="probe")

        assert len(captured) == 1
        traceparent = captured[0].headers.get("traceparent")
        assert traceparent is not None, "traceparent header missing"
        import re

        assert re.match(_TRACEPARENT_RE, traceparent), (
            f"traceparent {traceparent!r} does not match W3C format"
        )

    @pytest.mark.asyncio
    async def test_no_traceparent_when_otel_disabled(self) -> None:
        captured: list[httpx.Request] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            captured.append(request)
            return _ok_response()

        transport = httpx.MockTransport(handler)
        config = SDKConfig(otel_enabled=False)
        async with AgentClient(config=config) as client:
            client._http_client = httpx.AsyncClient(transport=transport)
            await client.invoke(_agent(Protocol.HTTPS), method="probe")

        assert "traceparent" not in captured[0].headers


class TestTraceparentA2A:
    @pytest.mark.asyncio
    async def test_traceparent_injected_on_a2a_message_send(self) -> None:
        captured: list[httpx.Request] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            captured.append(request)
            return _ok_response()

        transport = httpx.MockTransport(handler)
        config = SDKConfig(otel_enabled=True, otel_export_format="console")
        async with AgentClient(config=config) as client:
            client._http_client = httpx.AsyncClient(transport=transport)
            await client.invoke(
                _agent(Protocol.A2A), method="message/send", arguments={"text": "hi"}
            )

        traceparent = captured[0].headers.get("traceparent")
        assert traceparent is not None
        import re

        assert re.match(_TRACEPARENT_RE, traceparent)

    @pytest.mark.asyncio
    async def test_no_traceparent_a2a_when_disabled(self) -> None:
        captured: list[httpx.Request] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            captured.append(request)
            return _ok_response()

        transport = httpx.MockTransport(handler)
        config = SDKConfig(otel_enabled=False)
        async with AgentClient(config=config) as client:
            client._http_client = httpx.AsyncClient(transport=transport)
            await client.invoke(_agent(Protocol.A2A), method="message/send", arguments={})

        assert "traceparent" not in captured[0].headers


class TestPropagationFunctionContract:
    """Unit tests for inject_otel_context() in isolation."""

    @pytest.mark.asyncio
    async def test_no_op_when_no_current_span(self) -> None:
        request = httpx.Request("POST", "https://example.com/api")
        await inject_otel_context(request)
        assert "traceparent" not in request.headers

    @pytest.mark.asyncio
    async def test_injects_when_span_active(self) -> None:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider

        # Set up a real tracer provider so we can start a span.
        provider = TracerProvider(resource=Resource.create({"service.name": "test"}))
        trace._TRACER_PROVIDER_SET_ONCE._done = False  # type: ignore[attr-defined]
        trace.set_tracer_provider(provider)
        tracer = trace.get_tracer("test")

        request = httpx.Request("POST", "https://example.com/api")
        with tracer.start_as_current_span("test-span"):
            await inject_otel_context(request)
        assert "traceparent" in request.headers
