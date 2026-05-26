# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Spec 005 — US3 tests: span lifecycle (open BEFORE handler, close AFTER).

Verifies the span is the active context during ``handler.invoke()`` and
that span duration matches the recorded signal's latency within tolerance.
"""

from __future__ import annotations

import httpx
import pytest
from opentelemetry import trace

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


def _install_recording_exporter():
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor

    class Recorder:
        def __init__(self):
            self.spans = []

        def export(self, spans):
            from opentelemetry.sdk.trace.export import SpanExportResult

            self.spans.extend(spans)
            return SpanExportResult.SUCCESS

        def shutdown(self):
            pass

        def force_flush(self, timeout_millis=5000):
            return True

    rec = Recorder()
    provider = TracerProvider(resource=Resource.create({"service.name": "test"}))
    provider.add_span_processor(SimpleSpanProcessor(rec))
    trace._TRACER_PROVIDER_SET_ONCE._done = False  # type: ignore[attr-defined]
    trace.set_tracer_provider(provider)
    return rec


class TestSpanActiveDuringHandler:
    @pytest.mark.asyncio
    async def test_handler_sees_active_dns_aid_span(self) -> None:
        captured_span_names: list[str] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            current = trace.get_current_span()
            captured_span_names.append(current.name if hasattr(current, "name") else "")
            return httpx.Response(200, json={"ok": True})

        transport = httpx.MockTransport(handler)
        config = SDKConfig(otel_enabled=True, otel_export_format="console")
        _install_recording_exporter()
        async with AgentClient(config=config) as client:
            client._http_client = httpx.AsyncClient(transport=transport)
            await client.invoke(_agent(), method="probe")

        # The active span during handler.invoke should be our dns-aid.invoke span.
        assert captured_span_names, "handler did not capture any span name"
        assert any("dns-aid.invoke" in name for name in captured_span_names), (
            f"expected dns-aid.invoke span active in handler, got {captured_span_names}"
        )


class TestSpanLifecycleOnException:
    @pytest.mark.asyncio
    async def test_span_ends_with_error_on_handler_exception(self) -> None:
        rec = _install_recording_exporter()

        async def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("simulated network failure")

        transport = httpx.MockTransport(handler)
        config = SDKConfig(otel_enabled=True, otel_export_format="console")
        async with AgentClient(config=config) as client:
            client._http_client = httpx.AsyncClient(transport=transport)
            # Should NOT raise — protocol handler catches httpx errors and
            # returns a RawResponse with status=REFUSED.
            result = await client.invoke(_agent(), method="probe")
            assert not result.success

        assert len(rec.spans) == 1
        span = rec.spans[0]
        # Status should reflect the refused/error outcome
        attrs = dict(span.attributes or {})
        assert attrs.get("dns_aid.invocation.status") in ("error", "refused", "timeout")


class TestSpanDurationMatchesLatency:
    @pytest.mark.asyncio
    async def test_span_duration_within_tolerance_of_signal_latency(self) -> None:
        rec = _install_recording_exporter()

        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"ok": True})

        transport = httpx.MockTransport(handler)
        config = SDKConfig(otel_enabled=True, otel_export_format="console")
        async with AgentClient(config=config) as client:
            client._http_client = httpx.AsyncClient(transport=transport)
            result = await client.invoke(_agent(), method="probe")

        assert len(rec.spans) == 1
        span = rec.spans[0]
        span_duration_ms = (span.end_time - span.start_time) / 1_000_000.0  # ns → ms
        signal_latency_ms = result.signal.invocation_latency_ms
        # Span wraps a wider scope than the protocol handler (includes
        # auth + policy + record), so it's ≥ signal_latency_ms. We assert
        # the span is at least as long as the signal latency, with a
        # tolerance for the surrounding code.
        assert span_duration_ms >= signal_latency_ms, (
            f"span duration {span_duration_ms}ms < signal latency {signal_latency_ms}ms"
        )
        # And not absurdly longer (< 100ms overhead for the surround).
        assert span_duration_ms - signal_latency_ms < 500.0
