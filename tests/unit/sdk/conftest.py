# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Shared fixtures for SDK tests."""

from __future__ import annotations

import httpx
import pytest

from dns_aid.core.models import AgentRecord, Protocol
from dns_aid.sdk._config import SDKConfig


@pytest.fixture(autouse=True)
def reset_otel_singleton():
    """Reset OTEL global state before AND after every test.

    Spec 005 hardening H5 / FR-026 — eliminates per-test cleanup burden and
    prevents flaky failures from singleton state leaking across tests when
    they run in random order.

    Resets:
    - ``TelemetryManager`` singleton (our SDK)
    - OTEL global ``TracerProvider`` and ``MeterProvider`` (so each test
      starts from the proxy/default — tests that install a custom provider
      must do so explicitly)
    - ``_OTELWarnRateLimiter`` state (so a previous test's suppressed-event
      counter doesn't leak)
    """
    from dns_aid.sdk.telemetry.otel import TelemetryManager

    def _reset_otel_globals() -> None:
        try:
            from opentelemetry import metrics, trace

            # Force OTEL to allow re-setting the provider. This is an
            # internal flag but is the only practical way to reset between
            # tests; OTEL itself does not expose a public reset.
            if hasattr(trace, "_TRACER_PROVIDER_SET_ONCE"):
                trace._TRACER_PROVIDER_SET_ONCE._done = False  # type: ignore[attr-defined]
            if hasattr(metrics, "_METER_PROVIDER_SET_ONCE"):
                metrics._METER_PROVIDER_SET_ONCE._done = False  # type: ignore[attr-defined]

            # Replace the global with a fresh ProxyTracerProvider so
            # ``_is_default_tracer_provider()`` returns True at test start.
            from opentelemetry.trace import ProxyTracerProvider

            trace._TRACER_PROVIDER = ProxyTracerProvider()  # type: ignore[attr-defined]
        except (ImportError, AttributeError):
            # opentelemetry absent or its internal attrs moved — nothing to
            # reset in that case; the OTEL tests skip via pytestmark anyway.
            pass

    _reset_otel_globals()
    TelemetryManager.reset()
    yield
    TelemetryManager.reset()
    _reset_otel_globals()


class _ModernTransportRejected:
    """Async context manager whose __aenter__ raises HTTP 406."""

    async def __aenter__(self):  # type: ignore[no-untyped-def]
        raise httpx.HTTPStatusError(
            "modern transport rejected (simulated 406)",
            request=httpx.Request("POST", "https://example.com/mcp"),
            response=httpx.Response(406),
        )

    async def __aexit__(self, *exc):  # type: ignore[no-untyped-def]
        return False


@pytest.fixture
def force_legacy_mcp_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the MCP handler to take the legacy fallback path on every call.

    Patches ``streamablehttp_client`` in ``dns_aid.sdk.protocols.mcp`` so
    that any attempt to use the modern Streamable HTTP transport raises
    HTTP 406 — which the handler classifies as a transport mismatch and
    falls back to the legacy plain JSON-RPC POST path.

    Use this fixture in any test that mocks MCP behavior with
    ``httpx.MockTransport`` (which simulates the legacy POST path), so the
    test continues to verify the legacy semantic now that it is reached
    via fallback rather than as the primary transport.
    """
    monkeypatch.setattr(
        "dns_aid.sdk.protocols.mcp.streamablehttp_client",
        lambda *args, **kwargs: _ModernTransportRejected(),
    )


@pytest.fixture
def sdk_config() -> SDKConfig:
    """Default SDK config for testing."""
    return SDKConfig(
        timeout_seconds=5.0,
        caller_id="test-caller",
        console_signals=False,
    )


@pytest.fixture
def sample_mcp_agent() -> AgentRecord:
    """A sample MCP agent record for testing."""
    return AgentRecord(
        name="network",
        domain="example.com",
        protocol=Protocol.MCP,
        target_host="mcp.example.com",
        port=443,
        capabilities=["ipam", "dns"],
        version="1.0.0",
    )


@pytest.fixture
def sample_a2a_agent() -> AgentRecord:
    """A sample A2A agent record for testing."""
    return AgentRecord(
        name="chat",
        domain="example.com",
        protocol=Protocol.A2A,
        target_host="a2a.example.com",
        port=443,
        capabilities=["conversation"],
        version="1.0.0",
    )
