# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Spec 005 — US4 tests: structlog trace correlation.

Verifies the always-on ``otel_trace_processor`` injects ``trace_id`` and
``span_id`` into structlog events when an OTEL span is active, and adds
nothing when no span is active.
"""

from __future__ import annotations

from dns_aid.utils.logging import otel_trace_processor


class TestOTELTraceProcessor:
    def test_no_fields_when_no_active_span(self) -> None:
        event_dict = {"event": "test.event", "agent": "echo"}
        out = otel_trace_processor(None, "info", event_dict)
        assert "trace_id" not in out
        assert "span_id" not in out
        assert out["agent"] == "echo"  # original fields preserved

    def test_injects_fields_when_span_active(self) -> None:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider

        provider = TracerProvider(resource=Resource.create({"service.name": "test"}))
        trace._TRACER_PROVIDER_SET_ONCE._done = False  # type: ignore[attr-defined]
        trace.set_tracer_provider(provider)
        tracer = trace.get_tracer("test")

        event_dict = {"event": "test.event"}
        with tracer.start_as_current_span("test-span") as span:
            out = otel_trace_processor(None, "info", event_dict)
            ctx = span.get_span_context()
            assert out["trace_id"] == format(ctx.trace_id, "032x")
            assert out["span_id"] == format(ctx.span_id, "016x")

    def test_never_breaks_logging_on_processor_exception(self) -> None:
        # Pass a non-dict to trigger an unexpected branch — must not raise.
        # The processor returns the input unchanged on any failure.
        from unittest.mock import patch

        event_dict = {"event": "test"}
        with patch("dns_aid.utils.logging._otel_trace") as mocked:
            mocked.get_current_span.side_effect = RuntimeError("simulated OTEL bug")
            out = otel_trace_processor(None, "info", event_dict)
            assert out == event_dict

    def test_short_circuits_when_otel_unavailable(self) -> None:
        from unittest.mock import patch

        event_dict = {"event": "test"}
        with patch("dns_aid.utils.logging._otel_available", False):
            out = otel_trace_processor(None, "info", event_dict)
            assert "trace_id" not in out
            assert "span_id" not in out
