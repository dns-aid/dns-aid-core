# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Logging configuration for DNS-AID.

Uses structlog for structured logging with configurable output levels.
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Any

import structlog

# Spec 005 — OTEL trace correlation processor (US4 / FR-007).
# Cached availability check at module import — ~10 ns short-circuit when
# opentelemetry is not installed, so the always-on processor adds no
# observable cost to integrators who never use OTEL.
_otel_available = False
try:
    from opentelemetry import trace as _otel_trace

    _otel_available = True
except ImportError:
    _otel_trace = None  # type: ignore[assignment]


def otel_trace_processor(
    _logger: Any, _method_name: str, event_dict: dict[str, Any]
) -> dict[str, Any]:
    """Inject ``trace_id`` and ``span_id`` into structlog events when an OTEL
    span is active in the current context.

    Always-on per design-decisions.md Q5 — supports integrators with their
    own OTEL setup even when DNS-AID's own ``otel_enabled`` is False.

    Defensive: any failure returns ``event_dict`` unchanged. Logging must
    never break because of OTEL.
    """
    if not _otel_available or _otel_trace is None:
        return event_dict
    try:
        span = _otel_trace.get_current_span()
        ctx = span.get_span_context()
        if ctx.trace_id != 0:
            event_dict["trace_id"] = format(ctx.trace_id, "032x")
            event_dict["span_id"] = format(ctx.span_id, "016x")
    except Exception:
        # Logging must never break for any reason.
        pass
    return event_dict


def configure_logging(
    level: str = "INFO",
    json_output: bool = False,
) -> None:
    """
    Configure logging for DNS-AID.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR)
        json_output: If True, output logs as JSON
    """
    # Get level from environment or parameter
    level = os.environ.get("DNS_AID_LOG_LEVEL", level).upper()

    # Configure standard logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stderr,
        level=getattr(logging, level, logging.INFO),
    )

    # Configure structlog
    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S"),
        otel_trace_processor,  # spec 005 / US4 — always-on; ~100 ns when no span
    ]

    if json_output:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=True))

    structlog.configure(
        processors=processors,  # type: ignore[arg-type]
        wrapper_class=structlog.make_filtering_bound_logger(getattr(logging, level, logging.INFO)),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def silence_logging() -> None:
    """Silence all logging (for CLI in quiet mode)."""
    logging.disable(logging.CRITICAL)
    # Use CRITICAL level which is the highest valid level
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL),
    )
