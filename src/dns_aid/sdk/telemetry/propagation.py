# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""W3C Trace Context propagation for outbound HTTP requests (spec 005).

This module provides ``inject_otel_context()``, a single function reused by
all three protocol handlers (MCP, A2A, HTTPS) as an httpx ``event_hooks``
callback. It injects ``traceparent`` (and ``tracestate`` / ``baggage``
when applicable) into the outbound request headers immediately before the
request is sent, using the OTEL SDK's default propagator chain configured
via ``OTEL_PROPAGATORS`` env var.

Behaviour per contracts/propagation.md:

- No-op when ``opentelemetry`` is not installed.
- No-op when no current OTEL span is active.
- Defensive try/except — any propagator failure is logged via the
  rate-limiter and the request continues unmodified.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog

from dns_aid.sdk.telemetry.otel import _otel_warn_rate_limited

if TYPE_CHECKING:
    import httpx

logger = structlog.get_logger(__name__)

# Cached availability check — same idiom as telemetry/otel.py.
_otel_available = False
try:
    from opentelemetry import propagate, trace  # noqa: F401

    _otel_available = True
except ImportError:
    # opentelemetry is an optional dependency ([otel] extra). When absent,
    # inject_otel_context() below becomes a no-op — propagation is simply
    # not performed (FR-006 / FR-012).
    _otel_available = False


async def inject_otel_context(request: httpx.Request) -> None:
    """Inject W3C Trace Context headers into *request* if a span is active.

    Suitable for use as an httpx ``event_hooks["request"]`` callback.

    No-op when:
        - opentelemetry is not installed
        - no current span exists (``INVALID_SPAN``)
        - propagate.inject() raises (defensive — request continues)
    """
    if not _otel_available:
        return
    try:
        current_span = trace.get_current_span()
        ctx = current_span.get_span_context()
        if ctx.trace_id == 0:
            # No real span — propagator's inject() would be a no-op anyway,
            # but skipping the call saves ~µs in the hot path.
            return
        # propagate.inject() writes traceparent + tracestate (and baggage
        # when the baggage propagator is in OTEL_PROPAGATORS).
        propagate.inject(request.headers)
    except Exception as exc:
        # Never break the request because of propagation.
        _otel_warn_rate_limited(
            "sdk.otel_propagation_failed",
            instance_id=0,
            error=type(exc).__name__,
            detail=str(exc)[:200],
        )
