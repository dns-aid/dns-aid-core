# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
SDK telemetry models.

Defines the core data structures for invocation signals, results,
and aggregated scorecards.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class InvocationStatus(StrEnum):
    """Outcome of an agent invocation."""

    SUCCESS = "success"
    ERROR = "error"
    TIMEOUT = "timeout"
    REFUSED = "refused"


class InvocationSignal(BaseModel):
    """Per-call telemetry signal captured during an agent invocation."""

    model_config = ConfigDict(frozen=False)

    # Identity
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    # Agent identification
    agent_fqdn: str
    agent_endpoint: str
    # URL actually called, when invoke() resolved a different one from
    # agent_endpoint (e.g. the MCP path from agent.json or the /mcp
    # convention). None when the discovered endpoint was called as-is.
    resolved_endpoint: str | None = None
    protocol: str
    method: str | None = None

    # Timing (milliseconds)
    discovery_latency_ms: float = 0.0
    invocation_latency_ms: float
    total_latency_ms: float = 0.0
    ttfb_ms: float | None = None

    # Outcome
    status: InvocationStatus
    error_type: str | None = None
    error_message: str | None = None
    http_status_code: int | None = None

    # Cost
    cost_units: float | None = None
    cost_currency: str | None = None

    # Quality
    response_size_bytes: int | None = None
    dnssec_validated: bool = False
    tls_version: str | None = None

    # Auth
    auth_type: str | None = None
    auth_applied: bool = False

    # Caller context
    caller_id: str | None = None

    # Policy enforcement (Phase 6 §3.20)
    policy_enforced: bool = False
    policy_mode: str | None = None  # "disabled" | "permissive" | "strict"
    policy_result: str | None = None  # "allowed" | "denied" | "warning"
    policy_violations: list[str] | None = None  # ["rule:detail", ...]
    policy_version: str | None = None  # version from PolicyDocument
    policy_fetch_time_ms: float | None = None  # HTTP fetch latency for policy_uri
    target_policy_result: str | None = None  # "allowed" | "denied" | "no-policy"


class InvocationResult(BaseModel):
    """Result of an SDK invocation — wraps the response payload and signal."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    success: bool
    data: dict | str | list | None = None
    signal: InvocationSignal


class AgentScorecard(BaseModel):
    """Aggregated performance scorecard for a single agent."""

    agent_fqdn: str
    total_invocations: int = 0
    success_count: int = 0
    error_count: int = 0
    timeout_count: int = 0

    # Rates (0-100)
    success_rate: float = 0.0
    error_rate: float = 0.0

    # Timing
    avg_latency_ms: float = 0.0
    p50_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0
    min_latency_ms: float = 0.0
    max_latency_ms: float = 0.0

    # Cost
    total_cost_units: float = 0.0
    avg_cost_units: float = 0.0

    # Composite score (0-100)
    composite_score: float = 0.0

    # Time window
    first_seen: datetime | None = None
    last_seen: datetime | None = None
