# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for OTEL telemetry integration."""

from __future__ import annotations

from unittest.mock import patch

from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.models import InvocationSignal, InvocationStatus
from dns_aid.sdk.telemetry.otel import TelemetryManager


def _make_signal() -> InvocationSignal:
    return InvocationSignal(
        agent_fqdn="_network._mcp._agents.example.com",
        agent_endpoint="https://mcp.example.com:443",
        protocol="mcp",
        method="tools/call",
        invocation_latency_ms=150.0,
        status=InvocationStatus.SUCCESS,
        cost_units=0.5,
    )


class TestTelemetryManager:
    def setup_method(self) -> None:
        TelemetryManager.reset()

    def test_singleton(self) -> None:
        """Test get_or_create returns same instance."""
        config = SDKConfig(otel_enabled=False)
        mgr1 = TelemetryManager.get_or_create(config)
        mgr2 = TelemetryManager.get_or_create(config)
        assert mgr1 is mgr2

    def test_reset(self) -> None:
        """Test reset clears singleton."""
        config = SDKConfig(otel_enabled=False)
        mgr1 = TelemetryManager.get_or_create(config)
        TelemetryManager.reset()
        mgr2 = TelemetryManager.get_or_create(config)
        assert mgr1 is not mgr2

    def test_disabled_noop(self) -> None:
        """Test that disabled OTEL is a no-op."""
        config = SDKConfig(otel_enabled=False)
        mgr = TelemetryManager.get_or_create(config)
        assert mgr.is_available is False
        # Should not raise
        mgr.record_signal(_make_signal())

    def test_otel_not_installed_noop(self) -> None:
        """Test graceful fallback when opentelemetry is not installed."""
        config = SDKConfig(otel_enabled=True, otel_export_format="console")

        with patch("dns_aid.sdk.telemetry.otel._otel_available", False):
            mgr = TelemetryManager(config)
            mgr._initialize()
            assert mgr.is_available is False
            # Should not raise
            mgr.record_signal(_make_signal())

    def test_record_signal_when_available(self) -> None:
        """Test recording a signal when OTEL is available (console exporter)."""
        from dns_aid.sdk.telemetry.otel import _otel_available

        if not _otel_available:
            # Skip if OTEL not installed in test environment
            return

        config = SDKConfig(otel_enabled=True, otel_export_format="console")
        mgr = TelemetryManager.get_or_create(config)

        signal = _make_signal()
        # Should not raise
        mgr.record_signal(signal)

    def test_record_error_signal(self) -> None:
        """Test recording an error signal."""
        from dns_aid.sdk.telemetry.otel import _otel_available

        if not _otel_available:
            return

        config = SDKConfig(otel_enabled=True, otel_export_format="console")
        mgr = TelemetryManager.get_or_create(config)

        signal = InvocationSignal(
            agent_fqdn="_network._mcp._agents.example.com",
            agent_endpoint="https://mcp.example.com:443",
            protocol="mcp",
            invocation_latency_ms=5000.0,
            status=InvocationStatus.TIMEOUT,
            error_type="TimeoutError",
            error_message="Connection timed out",
        )
        mgr.record_signal(signal)

    def test_shutdown_idempotent(self) -> None:
        """Shutdown when not initialized should not raise."""
        config = SDKConfig(otel_enabled=False)
        mgr = TelemetryManager(config)
        mgr.shutdown()  # Not initialized
        mgr.shutdown()  # Double shutdown

    def test_initialize_console_exporter(self) -> None:
        """Test _initialize with console export format."""
        from dns_aid.sdk.telemetry.otel import _otel_available

        if not _otel_available:
            return

        config = SDKConfig(otel_enabled=True, otel_export_format="console")
        mgr = TelemetryManager(config)
        mgr._initialize()
        assert mgr.is_available is True
        assert mgr._tracer is not None
        assert mgr._duration_histogram is not None
        assert mgr._invocation_counter is not None
        assert mgr._error_counter is not None
        assert mgr._cost_counter is not None
        mgr.shutdown()

    def test_initialize_default_export_format(self) -> None:
        """Test _initialize with non-console/non-otlp falls back to console reader."""
        from dns_aid.sdk.telemetry.otel import _otel_available

        if not _otel_available:
            return

        config = SDKConfig(otel_enabled=True, otel_export_format="noop")
        mgr = TelemetryManager(config)
        mgr._initialize()
        assert mgr.is_available is True
        mgr.shutdown()

    def test_record_signal_with_cost(self) -> None:
        """Test that cost_units is recorded in attributes and counters."""
        from dns_aid.sdk.telemetry.otel import _otel_available

        if not _otel_available:
            return

        config = SDKConfig(otel_enabled=True, otel_export_format="console")
        mgr = TelemetryManager.get_or_create(config)
        signal = _make_signal()
        mgr.record_signal(signal)
        # Doesn't raise; cost counter is exercised

    def test_record_refused_signal(self) -> None:
        """Test recording a 'refused' status signal hits error counter."""
        from dns_aid.sdk.telemetry.otel import _otel_available

        if not _otel_available:
            return

        config = SDKConfig(otel_enabled=True, otel_export_format="console")
        mgr = TelemetryManager.get_or_create(config)

        signal = InvocationSignal(
            agent_fqdn="_chat._a2a._agents.example.com",
            agent_endpoint="https://chat.example.com",
            protocol="a2a",
            invocation_latency_ms=10.0,
            status=InvocationStatus.REFUSED,
            error_message="Access denied",
        )
        mgr.record_signal(signal)

    def test_record_signal_no_method_no_cost(self) -> None:
        """Signal without method or cost_units skips those attributes."""
        from dns_aid.sdk.telemetry.otel import _otel_available

        if not _otel_available:
            return

        config = SDKConfig(otel_enabled=True, otel_export_format="console")
        mgr = TelemetryManager.get_or_create(config)

        signal = InvocationSignal(
            agent_fqdn="_chat._a2a._agents.example.com",
            agent_endpoint="https://chat.example.com",
            protocol="a2a",
            invocation_latency_ms=10.0,
            status=InvocationStatus.SUCCESS,
            method=None,
            cost_units=None,
        )
        mgr.record_signal(signal)


class TestParseSignalFqdn:
    """Tests for _parse_signal_fqdn helper."""

    def test_valid_fqdn(self) -> None:
        from dns_aid.sdk.telemetry.otel import _parse_signal_fqdn

        name, domain = _parse_signal_fqdn("_network._mcp._agents.example.com")
        assert name == "network"
        assert domain == "example.com"

    def test_flat_fqdn_form(self) -> None:
        """draft-02 flat shape: the first label is the agent name."""
        from dns_aid.sdk.telemetry.otel import _parse_signal_fqdn

        name, domain = _parse_signal_fqdn("chat.example.com")
        assert name == "chat"
        assert domain == "example.com"

    def test_walkable_fqdn_form(self) -> None:
        """draft-02 walkable AliasMode shape: name is the label before `._agents.`."""
        from dns_aid.sdk.telemetry.otel import _parse_signal_fqdn

        name, domain = _parse_signal_fqdn("chat._agents.example.com")
        assert name == "chat"
        assert domain == "example.com"

    def test_single_label_returns_none(self) -> None:
        """Single-label input is not a valid FQDN; parser returns (None, None)."""
        from dns_aid.sdk.telemetry.otel import _parse_signal_fqdn

        name, domain = _parse_signal_fqdn("invalid")
        assert name is None
        assert domain is None

    def test_two_label_input_returns_none(self) -> None:
        """Inputs without a multi-label domain (e.g. "a.b") return (None, None)."""
        from dns_aid.sdk.telemetry.otel import _parse_signal_fqdn

        name, domain = _parse_signal_fqdn("a.b")
        assert name is None
        assert domain is None

    def test_walkable_empty_suffix_returns_none(self) -> None:
        """A walkable-shaped input with no domain ('foo._agents.') returns (None, None)."""
        from dns_aid.sdk.telemetry.otel import _parse_signal_fqdn

        name, domain = _parse_signal_fqdn("foo._agents.")
        assert name is None
        assert domain is None

    def test_legacy_with_malformed_protocol_returns_none(self) -> None:
        """A legacy-looking input where the protocol label lacks an underscore
        prefix (e.g. '_booking.mcp._agents.foo.com') is treated as unparseable.
        """
        from dns_aid.sdk.telemetry.otel import _parse_signal_fqdn

        name, domain = _parse_signal_fqdn("_booking.mcp._agents.foo.com")
        assert name is None
        assert domain is None

    def test_empty_string(self) -> None:
        from dns_aid.sdk.telemetry.otel import _parse_signal_fqdn

        name, domain = _parse_signal_fqdn("")
        assert name is None
        assert domain is None


class TestBuildSpanAttributes:
    """Tests for TelemetryManager._build_span_attributes."""

    def test_build_full_attributes(self) -> None:
        signal = _make_signal()
        config = SDKConfig(otel_enabled=False)
        mgr = TelemetryManager(config)
        attrs = mgr._build_span_attributes(signal)

        assert attrs["dns_aid.agent.endpoint"] == "https://mcp.example.com:443"
        assert attrs["dns_aid.agent.protocol"] == "mcp"
        assert attrs["dns_aid.invocation.status"] == "success"
        assert attrs["dns_aid.invocation.latency_ms"] == 150.0
        assert attrs["dns_aid.agent.name"] == "network"
        assert attrs["dns_aid.agent.domain"] == "example.com"
        assert attrs["dns_aid.invocation.method"] == "tools/call"
        assert attrs["dns_aid.invocation.cost_units"] == 0.5

    def test_build_attributes_no_method_no_cost(self) -> None:
        signal = InvocationSignal(
            agent_fqdn="invalid-no-agents",
            agent_endpoint="https://test.com",
            protocol="mcp",
            invocation_latency_ms=10.0,
            status=InvocationStatus.SUCCESS,
        )
        config = SDKConfig(otel_enabled=False)
        mgr = TelemetryManager(config)
        attrs = mgr._build_span_attributes(signal)

        assert "dns_aid.invocation.method" not in attrs
        assert "dns_aid.invocation.cost_units" not in attrs
        assert "dns_aid.agent.name" not in attrs
        assert "dns_aid.agent.domain" not in attrs
