# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Spec 005 — US6 tests: SDK functions without opentelemetry installed.

These tests can only fully verify FR-012 in a CI environment with
opentelemetry actually uninstalled. In a normal dev environment we
simulate the missing dep by monkey-patching the cached availability
flags. The dedicated CI matrix entry runs the full suite without
opentelemetry to catch import-time regressions.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from dns_aid.sdk._config import SDKConfig


class TestImportSucceedsWithoutOpenTelemetry:
    def test_sdk_client_importable_with_otel_unavailable(self) -> None:
        """Simulate otel unavailable; verify the SDK still works."""
        # We can't actually uninstall opentelemetry in this process, but
        # we can flip the cached availability flag and verify the no-op
        # paths work.
        from dns_aid.sdk.telemetry import otel as otel_mod
        from dns_aid.sdk.telemetry import propagation as prop_mod
        from dns_aid.utils import logging as log_mod

        # Flip all cached flags off.
        with (
            patch.object(otel_mod, "_otel_available", False),
            patch.object(prop_mod, "_otel_available", False),
            patch.object(log_mod, "_otel_available", False),
        ):
            # TelemetryManager construction must not raise.
            mgr = otel_mod.TelemetryManager(SDKConfig(otel_enabled=True))
            mgr._initialize()
            assert mgr.is_available is False
            # Methods must be no-ops.
            from dns_aid.sdk.models import InvocationSignal, InvocationStatus

            sig = InvocationSignal(
                agent_fqdn="_t._mcp._agents.example.com",
                agent_endpoint="https://t.example.com",
                protocol="mcp",
                invocation_latency_ms=1.0,
                status=InvocationStatus.SUCCESS,
            )
            mgr.record_signal(sig)
            mgr.shutdown()

    @pytest.mark.asyncio
    async def test_propagation_is_noop_when_otel_unavailable(self) -> None:
        import httpx

        from dns_aid.sdk.telemetry import propagation as prop_mod

        request = httpx.Request("POST", "https://example.com/api")
        with patch.object(prop_mod, "_otel_available", False):
            await prop_mod.inject_otel_context(request)
        assert "traceparent" not in request.headers


class TestOTELEnabledButUnavailable:
    def test_warn_emitted_when_otel_enabled_but_unavailable(self) -> None:
        """structlog logs are captured via structlog.testing.capture_logs.

        Robust against other tests reconfiguring structlog output (which
        breaks both ``caplog`` and ``capsys``).
        """
        import structlog

        from dns_aid.sdk.telemetry import otel as otel_mod

        with patch.object(otel_mod, "_otel_available", False):
            with structlog.testing.capture_logs() as captured:
                mgr = otel_mod.TelemetryManager(SDKConfig(otel_enabled=True))
                mgr._initialize()

        events = [e for e in captured if e.get("event") == "sdk.otel_unavailable"]
        assert len(events) == 1, f"expected 1 sdk.otel_unavailable event, got: {captured}"
