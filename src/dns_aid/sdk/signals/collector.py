# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
In-memory signal collector.

Captures InvocationSignal objects and provides basic querying.
Phase B adds database persistence via SignalStore.
"""

from __future__ import annotations

import statistics
from datetime import UTC, datetime

import structlog

from dns_aid.sdk.models import (
    AgentScorecard,
    InvocationSignal,
    InvocationStatus,
)
from dns_aid.sdk.protocols.base import RawResponse

logger = structlog.get_logger(__name__)


class SignalCollector:
    """Collects invocation signals in memory and computes scorecards."""

    def __init__(self, *, console: bool = False, caller_id: str | None = None) -> None:
        self._signals: list[InvocationSignal] = []
        self._console = console
        self._caller_id = caller_id

    def record(
        self,
        *,
        agent_fqdn: str,
        agent_endpoint: str,
        protocol: str,
        method: str | None,
        raw: RawResponse,
        discovery_latency_ms: float = 0.0,
        dnssec_validated: bool = False,
        auth_type: str | None = None,
        auth_applied: bool = False,
        resolved_endpoint: str | None = None,
    ) -> InvocationSignal:
        """
        Enrich a RawResponse into a full InvocationSignal and store it.

        Returns the created signal.
        """
        total_latency_ms = discovery_latency_ms + raw.invocation_latency_ms

        signal = InvocationSignal(
            agent_fqdn=agent_fqdn,
            agent_endpoint=agent_endpoint,
            resolved_endpoint=resolved_endpoint,
            protocol=protocol,
            method=method,
            discovery_latency_ms=discovery_latency_ms,
            invocation_latency_ms=raw.invocation_latency_ms,
            total_latency_ms=total_latency_ms,
            ttfb_ms=raw.ttfb_ms,
            status=raw.status,
            error_type=raw.error_type,
            error_message=raw.error_message,
            http_status_code=raw.http_status_code,
            cost_units=raw.cost_units,
            cost_currency=raw.cost_currency,
            response_size_bytes=raw.response_size_bytes,
            dnssec_validated=dnssec_validated,
            tls_version=raw.tls_version,
            auth_type=auth_type,
            auth_applied=auth_applied,
            caller_id=self._caller_id,
        )

        self._signals.append(signal)

        if self._console:
            logger.info(
                "sdk.signal",
                agent_fqdn=signal.agent_fqdn,
                method=signal.method,
                status=signal.status.value,
                latency_ms=round(signal.invocation_latency_ms, 2),
                cost=signal.cost_units,
            )

        return signal

    @property
    def signals(self) -> list[InvocationSignal]:
        """Return all collected signals."""
        return list(self._signals)

    def signals_for(self, agent_fqdn: str) -> list[InvocationSignal]:
        """Return signals for a specific agent."""
        return [s for s in self._signals if s.agent_fqdn == agent_fqdn]

    def scorecard(self, agent_fqdn: str) -> AgentScorecard:
        """Compute an aggregated scorecard for a single agent."""
        agent_signals = self.signals_for(agent_fqdn)
        return _compute_scorecard(agent_fqdn, agent_signals)

    def clear(self) -> None:
        """Clear all collected signals."""
        self._signals.clear()


def _compute_scorecard(agent_fqdn: str, signals: list[InvocationSignal]) -> AgentScorecard:
    """Compute aggregated metrics from a list of signals."""
    if not signals:
        return AgentScorecard(agent_fqdn=agent_fqdn)

    total = len(signals)
    success_count = sum(1 for s in signals if s.status == InvocationStatus.SUCCESS)
    error_count = sum(
        1 for s in signals if s.status in (InvocationStatus.ERROR, InvocationStatus.REFUSED)
    )
    timeout_count = sum(1 for s in signals if s.status == InvocationStatus.TIMEOUT)

    latencies = [s.invocation_latency_ms for s in signals]
    sorted_latencies = sorted(latencies)
    costs = [s.cost_units for s in signals if s.cost_units is not None]

    success_rate = (success_count / total) * 100 if total > 0 else 0.0
    error_rate = ((error_count + timeout_count) / total) * 100 if total > 0 else 0.0

    avg_latency = statistics.mean(latencies) if latencies else 0.0

    timestamps = [s.timestamp for s in signals]

    # Composite score: weighted average of reliability, latency, cost, freshness
    reliability_score = success_rate
    latency_score = max(0.0, 100 * (1 - avg_latency / 5000))
    cost_score = 100.0  # Default if no cost data
    if costs:
        max_cost = max(costs) if max(costs) > 0 else 1.0
        avg_cost = statistics.mean(costs)
        cost_score = max(0.0, 100 * (1 - avg_cost / max_cost)) if max_cost > 0 else 100.0

    freshness_score = 100.0
    if timestamps:
        most_recent = max(timestamps)
        age_hours = (datetime.now(UTC) - most_recent).total_seconds() / 3600
        freshness_score = max(0.0, 100 * (1 - age_hours / (24 * 7)))

    composite = (
        0.40 * reliability_score + 0.30 * latency_score + 0.15 * cost_score + 0.15 * freshness_score
    )

    return AgentScorecard(
        agent_fqdn=agent_fqdn,
        total_invocations=total,
        success_count=success_count,
        error_count=error_count,
        timeout_count=timeout_count,
        success_rate=success_rate,
        error_rate=error_rate,
        avg_latency_ms=avg_latency,
        p50_latency_ms=_percentile(sorted_latencies, 50),
        p95_latency_ms=_percentile(sorted_latencies, 95),
        p99_latency_ms=_percentile(sorted_latencies, 99),
        min_latency_ms=min(latencies),
        max_latency_ms=max(latencies),
        total_cost_units=sum(costs) if costs else 0.0,
        avg_cost_units=statistics.mean(costs) if costs else 0.0,
        composite_score=round(composite, 2),
        first_seen=min(timestamps) if timestamps else None,
        last_seen=max(timestamps) if timestamps else None,
    )


def _percentile(sorted_data: list[float], p: int) -> float:
    """Compute the p-th percentile of a sorted list."""
    if not sorted_data:
        return 0.0
    k = (len(sorted_data) - 1) * (p / 100)
    f = int(k)
    c = f + 1
    if c >= len(sorted_data):
        return sorted_data[-1]
    return sorted_data[f] + (k - f) * (sorted_data[c] - sorted_data[f])
