# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Spec 005 — US1 tests: spans + metrics emit on every invoke.

Also covers the CRITICAL hardening items:
- H1 (FR-019, FR-020) credential sanitization in span attributes
- H2 (FR-022) asyncio.CancelledError propagation
- H3 (FR-023, FR-024) flush on AgentClient close
- H4 (FR-025) rate-limited WARN logs
"""

from __future__ import annotations

import asyncio
import time
from typing import Any
from unittest.mock import patch

import httpx
import pytest

from dns_aid.core.models import AgentRecord, Protocol
from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.client import AgentClient
from dns_aid.sdk.telemetry.otel import (
    TelemetryManager,
    _OTELWarnRateLimiter,
    _sanitize_endpoint_url,
    _sanitize_error_message,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_https_response(
    content: bytes = b'{"ok": true}', status: int = 200
) -> httpx.Response:
    return httpx.Response(
        status_code=status, content=content, headers={"content-type": "application/json"}
    )


def _build_agent(
    name: str = "echo",
    domain: str = "example.com",
    target_host: str | None = None,
    port: int = 443,
) -> AgentRecord:
    return AgentRecord(
        name=name,
        domain=domain,
        protocol=Protocol.HTTPS,
        target_host=target_host or f"{name}.{domain}",
        port=port,
        capabilities=["echo"],
    )


class _RecordingExporter:
    """In-memory span exporter — captures spans for assertions."""

    def __init__(self) -> None:
        self.spans: list[Any] = []

    def export(self, spans):
        from opentelemetry.sdk.trace.export import SpanExportResult

        self.spans.extend(spans)
        return SpanExportResult.SUCCESS

    def shutdown(self):
        pass

    def force_flush(self, timeout_millis: int = 5000):
        return True


class _CountingMetricReader:
    """Captures metric counts across all reads (used for sampler tests)."""

    def __init__(self):
        self.data_point_count = 0


# ---------------------------------------------------------------------------
# Sanitization unit tests (H1 / SC-016)
# ---------------------------------------------------------------------------


class TestSanitizationHelpers:
    def test_sanitize_endpoint_url_strips_userinfo(self) -> None:
        out = _sanitize_endpoint_url("https://leaked-user:leaked-pass@host:443/path")
        assert out is not None
        assert "leaked-user" not in out
        assert "leaked-pass" not in out
        assert "host:443" in out

    def test_sanitize_endpoint_url_passthrough_when_clean(self) -> None:
        assert (
            _sanitize_endpoint_url("https://example.com:443/path") == "https://example.com:443/path"
        )

    def test_sanitize_endpoint_url_handles_none(self) -> None:
        assert _sanitize_endpoint_url(None) is None

    def test_sanitize_error_message_redacts_url_with_userinfo(self) -> None:
        msg = "Connection refused: https://leaked-user:leaked-pass@target.com:443/api"
        out = _sanitize_error_message(msg)
        assert out is not None
        assert "leaked-user" not in out
        assert "leaked-pass" not in out
        assert "target.com:443" in out

    def test_sanitize_error_message_passthrough_when_clean(self) -> None:
        msg = "Plain error message with no URL"
        assert _sanitize_error_message(msg) == msg

    def test_sanitize_error_message_handles_none(self) -> None:
        assert _sanitize_error_message(None) is None

    def test_sanitize_error_message_redacts_grpc_url(self) -> None:
        msg = "OTLP failed: grpc://user:pass@collector:4317"
        out = _sanitize_error_message(msg)
        assert out is not None
        assert "user:pass" not in out


# ---------------------------------------------------------------------------
# Rate-limiter unit tests (H4 / SC-019)
# ---------------------------------------------------------------------------


class TestWarnRateLimiter:
    """Test the rate-limiter directly via ``structlog.testing.capture_logs``,
    which captures structlog events regardless of how structlog is configured
    (avoids brittle caplog / capsys coupling)."""

    def test_first_event_emits_one_log(self) -> None:
        import structlog

        rl = _OTELWarnRateLimiter()
        with structlog.testing.capture_logs() as captured:
            rl.emit("sdk.otel_test_event", instance_id=42, detail="first")
        events = [e for e in captured if e.get("event") == "sdk.otel_test_event"]
        assert len(events) == 1

    def test_repeated_events_within_window_suppressed(self) -> None:
        import structlog

        rl = _OTELWarnRateLimiter()
        with structlog.testing.capture_logs() as captured:
            for _ in range(1000):
                rl.emit("sdk.otel_test_event", instance_id=42, detail="repeated")
        events = [e for e in captured if e.get("event") == "sdk.otel_test_event"]
        assert len(events) == 1, f"expected 1 emission, got {len(events)}"

    def test_window_expiry_emits_summary(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import structlog

        rl = _OTELWarnRateLimiter()
        t = [1000.0]

        def fake_monotonic() -> float:
            return t[0]

        monkeypatch.setattr(time, "monotonic", fake_monotonic)
        with structlog.testing.capture_logs() as captured:
            rl.emit("sdk.otel_x", instance_id=1)
            for _ in range(999):
                rl.emit("sdk.otel_x", instance_id=1)
            t[0] += 65.0
            rl.emit("sdk.otel_x", instance_id=1, detail="post-window")

        summaries = [e for e in captured if e.get("event") == "sdk.otel_warn_summary"]
        assert len(summaries) == 1
        assert summaries[0].get("suppressed_count") == 999


# ---------------------------------------------------------------------------
# Span + metric emission (SC-001) — uses RecordingExporter to capture spans
# ---------------------------------------------------------------------------


def _install_recording_exporter() -> _RecordingExporter:
    """Replace the OTEL exporter chain with a RecordingExporter for assertion."""
    from opentelemetry import trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor

    recording = _RecordingExporter()
    # Force a fresh global TracerProvider so our recording exporter receives spans.
    # Test fixture reset_otel_singleton clears any prior state.
    provider = TracerProvider(resource=Resource.create({"service.name": "test"}))
    provider.add_span_processor(SimpleSpanProcessor(recording))
    trace._TRACER_PROVIDER_SET_ONCE._done = False  # type: ignore[attr-defined]
    trace.set_tracer_provider(provider)
    return recording


class TestSpanEmission:
    @pytest.mark.asyncio
    async def test_one_invoke_produces_one_span_with_attributes(self) -> None:
        recording = _install_recording_exporter()

        async def handler(request: httpx.Request) -> httpx.Response:
            return _make_mock_https_response()

        transport = httpx.MockTransport(handler)
        config = SDKConfig(otel_enabled=True, otel_export_format="console")
        async with AgentClient(config=config) as client:
            client._http_client = httpx.AsyncClient(transport=transport)  # inject mock
            agent = _build_agent()
            await client.invoke(agent, method="tools/call", arguments={"name": "echo"})

        assert len(recording.spans) == 1, f"expected 1 span, got {len(recording.spans)}"
        span = recording.spans[0]
        assert "dns-aid.invoke" in span.name
        attrs = dict(span.attributes or {})
        assert attrs.get("dns_aid.agent.name") == "echo"
        assert attrs.get("dns_aid.agent.domain") == "example.com"
        assert attrs.get("dns_aid.agent.protocol") == "https"
        assert attrs.get("dns_aid.invocation.method") == "tools/call"
        assert attrs.get("dns_aid.invocation.status") == "success"
        assert "dns_aid.invocation.latency_ms" in attrs


# ---------------------------------------------------------------------------
# Credential sanitization end-to-end (SC-016) — release-blocker H1
# ---------------------------------------------------------------------------


class TestCredentialSanitizationEndToEnd:
    @pytest.mark.asyncio
    async def test_endpoint_with_userinfo_does_not_leak_to_span(self) -> None:
        recording = _install_recording_exporter()

        async def handler(request: httpx.Request) -> httpx.Response:
            return _make_mock_https_response()

        transport = httpx.MockTransport(handler)
        config = SDKConfig(otel_enabled=True, otel_export_format="console")
        async with AgentClient(config=config) as client:
            client._http_client = httpx.AsyncClient(transport=transport)
            # Build an AgentRecord with a credentialed endpoint URL via override.
            agent = AgentRecord(
                name="leaked",
                domain="example.com",
                protocol=Protocol.HTTPS,
                target_host="leaked.example.com",
                port=443,
                endpoint_override="https://leaked-user:leaked-pass@leaked.example.com:443/api",
            )
            await client.invoke(agent, method="probe")

        assert len(recording.spans) == 1
        span = recording.spans[0]
        attrs = dict(span.attributes or {})
        endpoint = attrs.get("dns_aid.agent.endpoint", "")
        assert "leaked-user" not in str(endpoint), f"credential leaked into span: {endpoint}"
        assert "leaked-pass" not in str(endpoint), f"credential leaked into span: {endpoint}"


# ---------------------------------------------------------------------------
# CancelledError propagation (SC-017) — release-blocker H2
# ---------------------------------------------------------------------------


class TestCancelledErrorPropagation:
    @pytest.mark.asyncio
    async def test_cancelled_error_propagates_unchanged(self) -> None:
        recording = _install_recording_exporter()

        async def handler(request: httpx.Request) -> httpx.Response:
            # Simulate cancellation mid-invoke
            raise asyncio.CancelledError()

        transport = httpx.MockTransport(handler)
        config = SDKConfig(otel_enabled=True, otel_export_format="console")
        async with AgentClient(config=config) as client:
            client._http_client = httpx.AsyncClient(transport=transport)
            agent = _build_agent()
            with pytest.raises(asyncio.CancelledError):
                await client.invoke(agent, method="probe")

        # Span must have been ended on cancellation (no leak)
        assert len(recording.spans) == 1, "span should be ended even on cancellation"


# ---------------------------------------------------------------------------
# Flush on AgentClient close (SC-018) — release-blocker H3
# ---------------------------------------------------------------------------


class TestFlushOnClose:
    @pytest.mark.asyncio
    async def test_aexit_calls_otel_force_flush(self) -> None:
        flush_called: list[bool] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            return _make_mock_https_response()

        transport = httpx.MockTransport(handler)
        config = SDKConfig(otel_enabled=True, otel_export_format="console")

        # Pre-create the singleton so we can patch its force_flush.
        mgr = TelemetryManager.get_or_create(config)
        original_flush = mgr.force_flush

        def tracked_flush(timeout_millis: int = 5000) -> bool:
            flush_called.append(True)
            return original_flush(timeout_millis)

        with patch.object(mgr, "force_flush", side_effect=tracked_flush):
            async with AgentClient(config=config) as client:
                client._http_client = httpx.AsyncClient(transport=transport)
                agent = _build_agent()
                await client.invoke(agent, method="probe")
            # __aexit__ should have called force_flush before returning
            assert flush_called, "AgentClient.__aexit__ did not call OTEL force_flush"


# ---------------------------------------------------------------------------
# Backward compatibility — otel_enabled=False (US6 SC-007)
# ---------------------------------------------------------------------------


class TestOTELDisabledNoBehaviorChange:
    @pytest.mark.asyncio
    async def test_no_traceparent_when_otel_disabled(self) -> None:
        captured: list[httpx.Request] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            captured.append(request)
            return _make_mock_https_response()

        transport = httpx.MockTransport(handler)
        config = SDKConfig(otel_enabled=False)  # default
        async with AgentClient(config=config) as client:
            client._http_client = httpx.AsyncClient(transport=transport)
            agent = _build_agent()
            await client.invoke(agent, method="probe")

        assert "traceparent" not in captured[0].headers
        assert "tracestate" not in captured[0].headers


# ---------------------------------------------------------------------------
# OTEL flush works even when collector is unreachable (SC-008)
# ---------------------------------------------------------------------------


class TestUnreachableCollector:
    @pytest.mark.asyncio
    async def test_invoke_succeeds_with_bogus_otel_endpoint(self) -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            return _make_mock_https_response()

        transport = httpx.MockTransport(handler)
        config = SDKConfig(
            otel_enabled=True,
            otel_export_format="otlp",
            otel_endpoint="grpc://localhost:0",  # unreachable
        )
        async with AgentClient(config=config) as client:
            client._http_client = httpx.AsyncClient(transport=transport)
            agent = _build_agent()
            # 5 invokes — none should raise despite the unreachable collector.
            for _ in range(5):
                result = await client.invoke(agent, method="probe")
                assert result.success
