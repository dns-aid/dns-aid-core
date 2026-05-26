# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Spec 005 — US5 tests: configurable sampling + provider safety.

Verifies that:
- The SDK does not clobber an integrator's pre-set TracerProvider (FR-008)
- Sampler resolution honors the documented precedence (FR-010)
- Unknown sampler names raise ValueError at SDKConfig construction (FR-010b)
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.telemetry.otel import (
    TelemetryManager,
    _is_default_tracer_provider,
    _otel_available,
    _resolve_sampler,
)

# OTEL feature tests — skip when opentelemetry isn't installed (FR-012).
pytestmark = pytest.mark.skipif(
    not _otel_available, reason="opentelemetry not installed ([otel] extra)"
)


class TestSamplerValidation:
    def test_unknown_sampler_raises_at_construction(self) -> None:
        with pytest.raises((ValueError, ValidationError)) as exc_info:
            SDKConfig(otel_sampler="bogus_sampler_name")
        # Error message should list the supported samplers
        msg = str(exc_info.value)
        assert "always_on" in msg or "supported" in msg.lower()

    def test_each_supported_sampler_accepted(self) -> None:
        for name in (
            "always_on",
            "always_off",
            "traceidratio",
            "parentbased_always_on",
            "parentbased_always_off",
            "parentbased_traceidratio",
        ):
            config = SDKConfig(otel_sampler=name)
            assert config.otel_sampler == name

    def test_none_is_valid_sampler(self) -> None:
        config = SDKConfig(otel_sampler=None)
        assert config.otel_sampler is None


class TestMetricLabelsValidation:
    def test_unknown_metric_label_raises(self) -> None:
        with pytest.raises((ValueError, ValidationError)):
            SDKConfig(otel_metric_labels=["fqdn", "unknown_label"])

    def test_duplicate_metric_labels_rejected(self) -> None:
        with pytest.raises((ValueError, ValidationError)):
            SDKConfig(otel_metric_labels=["fqdn", "fqdn"])

    def test_empty_list_is_default(self) -> None:
        config = SDKConfig()
        assert config.otel_metric_labels == []


class TestSamplerResolution:
    def test_resolve_sampler_none_when_no_config(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OTEL_TRACES_SAMPLER", raising=False)
        monkeypatch.delenv("DNS_AID_SDK_OTEL_SAMPLER", raising=False)
        config = SDKConfig()
        sampler = _resolve_sampler(config)
        assert sampler is None  # let OTEL SDK use default

    def test_otel_traces_sampler_env_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # Standard OTEL env var present → we defer to OTEL SDK's own parsing
        # by returning None (TracerProvider() reads OTEL_TRACES_SAMPLER itself).
        monkeypatch.setenv("OTEL_TRACES_SAMPLER", "always_off")
        monkeypatch.delenv("DNS_AID_SDK_OTEL_SAMPLER", raising=False)
        config = SDKConfig(otel_sampler="always_on")  # SDK config should be ignored
        sampler = _resolve_sampler(config)
        assert sampler is None  # defer to OTEL SDK env handling

    def test_dns_aid_env_var_used_when_otel_env_absent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("OTEL_TRACES_SAMPLER", raising=False)
        monkeypatch.setenv("DNS_AID_SDK_OTEL_SAMPLER", "always_off")
        config = SDKConfig()
        sampler = _resolve_sampler(config)
        assert sampler is not None
        # always_off has a specific class
        from opentelemetry.sdk.trace.sampling import ALWAYS_OFF as _AO

        assert sampler is _AO

    def test_config_field_used_when_envs_absent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OTEL_TRACES_SAMPLER", raising=False)
        monkeypatch.delenv("DNS_AID_SDK_OTEL_SAMPLER", raising=False)
        config = SDKConfig(otel_sampler="always_off")
        sampler = _resolve_sampler(config)
        from opentelemetry.sdk.trace.sampling import ALWAYS_OFF as _AO

        assert sampler is _AO


class TestOTLPExporterURLScheme:
    """Regression test for the URL-scheme handling that prevents the
    confusing ``SSL_ERROR_SSL: WRONG_VERSION_NUMBER`` failure when a
    plaintext endpoint is passed without scheme guidance.

    Pinned via real integration test against Jaeger 1.76.0 — see
    ``examples/integration_otel_collector/`` for the live demo.
    """

    def test_http_scheme_strips_and_marks_insecure(self) -> None:
        cfg = SDKConfig(otel_endpoint="http://localhost:4317")
        kw = TelemetryManager(cfg)._otlp_exporter_kwargs()
        assert kw == {"endpoint": "localhost:4317", "insecure": True}

    def test_https_scheme_strips_and_marks_tls(self) -> None:
        cfg = SDKConfig(otel_endpoint="https://collector.example.com:443")
        kw = TelemetryManager(cfg)._otlp_exporter_kwargs()
        assert kw == {"endpoint": "collector.example.com:443", "insecure": False}

    def test_grpc_scheme_treated_as_plaintext_alias(self) -> None:
        # `grpc://` is a legacy alias for `http://` in OTEL ecosystem tutorials.
        cfg = SDKConfig(otel_endpoint="grpc://localhost:4317")
        kw = TelemetryManager(cfg)._otlp_exporter_kwargs()
        assert kw == {"endpoint": "localhost:4317", "insecure": True}

    def test_grpcs_scheme_treated_as_tls_alias(self) -> None:
        cfg = SDKConfig(otel_endpoint="grpcs://collector:443")
        kw = TelemetryManager(cfg)._otlp_exporter_kwargs()
        assert kw == {"endpoint": "collector:443", "insecure": False}

    def test_bare_endpoint_passes_through(self) -> None:
        # No scheme → OTEL SDK default behavior applies (TLS unless
        # OTEL_EXPORTER_OTLP_INSECURE env var says otherwise).
        cfg = SDKConfig(otel_endpoint="bare-host:4317")
        kw = TelemetryManager(cfg)._otlp_exporter_kwargs()
        assert "insecure" not in kw
        assert kw == {"endpoint": "bare-host:4317"}

    def test_none_endpoint_returns_empty(self) -> None:
        cfg = SDKConfig(otel_endpoint=None)
        kw = TelemetryManager(cfg)._otlp_exporter_kwargs()
        assert kw == {}


class TestProviderJoin:
    def test_default_provider_is_default(self) -> None:
        # Fresh state — fixture has reset; OTEL has its default proxy provider.
        assert _is_default_tracer_provider() is True

    def test_does_not_clobber_when_user_set_provider(self) -> None:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider

        user_provider = TracerProvider(resource=Resource.create({"service.name": "user-app"}))
        trace._TRACER_PROVIDER_SET_ONCE._done = False  # type: ignore[attr-defined]
        trace.set_tracer_provider(user_provider)

        # Constructing TelemetryManager should NOT call set_tracer_provider
        # since the user has already set one.
        config = SDKConfig(otel_enabled=True, otel_export_format="console")
        TelemetryManager.get_or_create(config)
        # The user's provider must still be in place.
        assert trace.get_tracer_provider() is user_provider
