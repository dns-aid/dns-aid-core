# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Shared fixtures for utils tests."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def reset_otel_singleton():
    """Reset the OTEL ``TelemetryManager`` singleton before AND after every test.

    Spec 005 hardening H5 / FR-026 — utility tests (e.g., logging) may
    inadvertently leak OTEL singleton state otherwise.
    """
    try:
        from dns_aid.sdk.telemetry.otel import TelemetryManager

        TelemetryManager.reset()
        yield
        TelemetryManager.reset()
    except ImportError:
        # OTEL not installed in this environment — nothing to reset.
        yield
