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

from pydantic import BaseModel, Field


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
