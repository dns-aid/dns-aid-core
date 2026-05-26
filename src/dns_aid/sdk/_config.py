# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
SDK configuration.

Configures the AgentClient behavior including timeouts, exporters, and caller identity.
"""

from __future__ import annotations

import functools
import os
import warnings

from pydantic import BaseModel, Field, field_validator

# Spec 005 — supported sampler names (subset of OTEL Python SDK built-ins
# we intentionally expose; rejecting unknown values prevents typo footguns).
_SUPPORTED_OTEL_SAMPLERS = frozenset(
    {
        "always_on",
        "always_off",
        "traceidratio",
        "parentbased_always_on",
        "parentbased_always_off",
        "parentbased_traceidratio",
    }
)

# Spec 005 — opt-in high-cardinality metric labels (per contracts/metrics.md).
_SUPPORTED_OTEL_METRIC_LABELS = frozenset({"fqdn", "caller", "tool"})


class SDKConfig(BaseModel):
    """Configuration for the DNS-AID SDK."""

    # HTTP client settings
    timeout_seconds: float = Field(
        default=30.0,
        description="Default timeout for agent invocations in seconds.",
    )
    max_retries: int = Field(
        default=0,
        description="Max retry attempts on transient failures.",
    )

    # Caller identity (optional, added to signals)
    caller_id: str | None = Field(
        default=None,
        description="Identifier for the calling agent/service.",
    )

    # OTEL settings
    otel_enabled: bool = Field(
        default=False,
        description="Enable OpenTelemetry export.",
    )
    otel_endpoint: str | None = Field(
        default=None,
        description="OTLP endpoint URL.",
    )
    otel_export_format: str = Field(
        default="otlp",
        description="Export format: otlp, console, or noop.",
    )

    # Spec 005 — production-grade OTEL fields (v0.23.0)
    otel_sampler: str | None = Field(
        default=None,
        description=(
            "OpenTelemetry sampler name. Supported: always_on, always_off, "
            "traceidratio, parentbased_always_on, parentbased_always_off, "
            "parentbased_traceidratio. None = OTEL SDK default "
            "(parentbased_always_on). Overridden by OTEL_TRACES_SAMPLER env "
            "var if set (FR-010)."
        ),
    )
    otel_environment: str | None = Field(
        default=None,
        max_length=64,
        description=(
            "Populates the OTEL ``deployment.environment`` resource attribute "
            "when set. Free-form string. Overridden by user-set value in "
            "OTEL_RESOURCE_ATTRIBUTES env var (FR-014)."
        ),
    )
    otel_metric_labels: list[str] = Field(
        default_factory=list,
        description=(
            "Opt-in high-cardinality labels for metric instruments. Each "
            "element must be one of: 'fqdn', 'caller', 'tool'. Default empty "
            "keeps the low-cardinality label set (protocol, status). See "
            "specs/005-otel-production/contracts/metrics.md for the "
            "cardinality cost discussion (FR-014)."
        ),
    )

    @field_validator("otel_sampler")
    @classmethod
    def _validate_otel_sampler(cls, v: str | None) -> str | None:
        # None is fine; means "use OTEL SDK default"
        if v is None:
            return v
        if v not in _SUPPORTED_OTEL_SAMPLERS:
            supported = ", ".join(sorted(_SUPPORTED_OTEL_SAMPLERS))
            raise ValueError(
                f"otel_sampler {v!r} is not supported (FR-010b). Supported values: {supported}"
            )
        return v

    @field_validator("otel_environment")
    @classmethod
    def _validate_otel_environment(cls, v: str | None) -> str | None:
        if v is None:
            return v
        stripped = v.strip()
        if stripped != v:
            raise ValueError("otel_environment must not have leading/trailing whitespace")
        return v

    @field_validator("otel_metric_labels")
    @classmethod
    def _validate_otel_metric_labels(cls, v: list[str]) -> list[str]:
        # Reject duplicates and unknown values.
        if len(v) != len(set(v)):
            raise ValueError("otel_metric_labels must not contain duplicates")
        for item in v:
            if item not in _SUPPORTED_OTEL_METRIC_LABELS:
                supported = ", ".join(sorted(_SUPPORTED_OTEL_METRIC_LABELS))
                raise ValueError(
                    f"otel_metric_labels element {item!r} is not supported. "
                    f"Supported values: {supported}"
                )
        return v

    # HTTP push (fire-and-forget POST to telemetry API)
    http_push_url: str | None = Field(
        default=None,
        description="Full URL to POST signals to "
        "(e.g., https://directory.example.com/api/v1/telemetry/signals). "
        "When unset, signals are pushed to "
        "``{resolved_directory_url}/api/v1/telemetry/signals`` if a directory URL is configured. "
        "Set this only to override the derived path.",
    )

    # Console logging
    console_signals: bool = Field(
        default=False,
        description="Print signals to console/log for debugging.",
    )

    # Directory backend (canonical name; drives fetch_rankings, search, and signal push).
    directory_api_url: str | None = Field(
        default=None,
        description="Base URL of the DNS-AID directory backend "
        "(e.g., https://directory.example.com). "
        "Drives ``AgentClient.search()``, ``AgentClient.fetch_rankings()``, and the signal-push "
        "default destination. ``None`` keeps the SDK in DNS-substrate-only mode with no directory "
        "dependency.",
    )

    # Deprecated alias for directory_api_url. Honored for one minor release.
    telemetry_api_url: str | None = Field(
        default=None,
        description="**DEPRECATED**: alias for ``directory_api_url``. Honored for one minor release; "
        "set ``directory_api_url`` instead. When both are set, ``directory_api_url`` wins and a "
        "one-time DeprecationWarning is emitted on first resolution.",
    )

    # Policy enforcement (Phase 6)
    policy_mode: str = Field(
        default="permissive",
        description="Policy enforcement mode: disabled | permissive | strict.",
    )
    policy_cache_ttl: int = Field(
        default=300,
        description="Policy document cache TTL in seconds.",
    )
    caller_domain: str | None = Field(
        default=None,
        description="Caller's domain for policy allowed/blocked_caller_domains matching.",
    )

    # Circuit breaker (Phase 6.6)
    circuit_breaker_enabled: bool = Field(
        default=False,
        description="Enable agent-aware circuit breaker for cascading failure protection.",
    )
    circuit_breaker_threshold: int = Field(
        default=5,
        ge=1,
        description="Consecutive failures before opening the circuit.",
    )
    circuit_breaker_cooldown: float = Field(
        default=60.0,
        ge=1.0,
        description="Seconds before an open circuit transitions to half-open.",
    )
    credential_provider_timeout: float = Field(
        default=30.0,
        gt=0.0,
        description=(
            "Maximum seconds the SDK will wait for a ``credential_provider`` callback "
            "to complete before raising ``CredentialProviderError``. Separate from "
            "``timeout_seconds`` (the HTTP transport timeout) because credential "
            "resolution and the HTTP call are independent operations. Set via env: "
            "``DNS_AID_CREDENTIAL_PROVIDER_TIMEOUT``."
        ),
    )

    @property
    def resolved_directory_url(self) -> str | None:
        """
        Single source of truth for the directory backend base URL.

        Resolution order: ``directory_api_url`` (canonical) → ``telemetry_api_url`` (deprecated).
        When the deprecated alias is the active source, a single ``DeprecationWarning`` is emitted
        per process the first time this property is accessed.

        Returns:
            The resolved directory base URL, or ``None`` if neither field is set.
        """
        if self.directory_api_url is not None:
            return self.directory_api_url
        if self.telemetry_api_url is not None:
            _warn_telemetry_alias_once()
            return self.telemetry_api_url
        return None

    @classmethod
    def from_env(cls) -> SDKConfig:
        """Build config from environment variables."""
        return cls(
            timeout_seconds=float(os.getenv("DNS_AID_SDK_TIMEOUT", "30")),
            max_retries=int(os.getenv("DNS_AID_SDK_MAX_RETRIES", "0")),
            caller_id=os.getenv("DNS_AID_SDK_CALLER_ID"),
            http_push_url=os.getenv("DNS_AID_SDK_HTTP_PUSH_URL"),
            otel_enabled=os.getenv("DNS_AID_SDK_OTEL_ENABLED", "").lower() == "true",
            otel_endpoint=os.getenv("DNS_AID_SDK_OTEL_ENDPOINT"),
            otel_export_format=os.getenv("DNS_AID_SDK_OTEL_EXPORT_FORMAT", "otlp"),
            otel_sampler=os.getenv("DNS_AID_SDK_OTEL_SAMPLER") or None,
            otel_environment=os.getenv("DNS_AID_SDK_OTEL_ENVIRONMENT") or None,
            otel_metric_labels=_parse_otel_metric_labels_env(
                os.getenv("DNS_AID_SDK_OTEL_METRIC_LABELS", "")
            ),
            console_signals=os.getenv("DNS_AID_SDK_CONSOLE_SIGNALS", "").lower() == "true",
            directory_api_url=os.getenv("DNS_AID_SDK_DIRECTORY_API_URL"),
            telemetry_api_url=os.getenv("DNS_AID_SDK_TELEMETRY_API_URL"),
            policy_mode=os.getenv("DNS_AID_POLICY_MODE", "permissive"),
            policy_cache_ttl=int(os.getenv("DNS_AID_POLICY_CACHE_TTL", "300")),
            caller_domain=os.getenv("DNS_AID_CALLER_DOMAIN"),
            circuit_breaker_enabled=os.getenv("DNS_AID_CIRCUIT_BREAKER", "").lower() == "true",
            circuit_breaker_threshold=int(os.getenv("DNS_AID_CIRCUIT_BREAKER_THRESHOLD", "5")),
            circuit_breaker_cooldown=float(os.getenv("DNS_AID_CIRCUIT_BREAKER_COOLDOWN", "60")),
            credential_provider_timeout=float(
                os.getenv("DNS_AID_CREDENTIAL_PROVIDER_TIMEOUT", "30")
            ),
        )


def _parse_otel_metric_labels_env(raw: str) -> list[str]:
    """Parse comma-separated ``DNS_AID_SDK_OTEL_METRIC_LABELS`` env var.

    Returns an empty list when raw is empty/whitespace. Validation of element
    membership is delegated to the SDKConfig validator.
    """
    if not raw or not raw.strip():
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


@functools.cache
def _warn_telemetry_alias_once() -> None:
    """
    Emit a single ``DeprecationWarning`` per process when the legacy alias is active.

    Idempotency is delegated to :func:`functools.cache`: subsequent calls are no-ops
    until ``_warn_telemetry_alias_once.cache_clear()`` is invoked (used by tests).
    """
    warnings.warn(
        "SDKConfig.telemetry_api_url is deprecated; use directory_api_url instead. "
        "The alias will be removed in a future minor release.",
        DeprecationWarning,
        stacklevel=3,
    )
