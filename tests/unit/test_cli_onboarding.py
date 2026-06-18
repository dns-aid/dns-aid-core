# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for CLI onboarding: backends registry, _get_backend(), doctor, init."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from dns_aid.cli.backends import ALL_BACKEND_NAMES, BACKEND_REGISTRY, detect_backend
from dns_aid.cli.main import app

runner = CliRunner()


# ── Backend Registry ───────────────────────────────────────────────


class TestBackendRegistry:
    def test_all_backends_present(self):
        assert set(ALL_BACKEND_NAMES) == {
            "route53",
            "cloud-dns",
            "cloudflare",
            "ns1",
            "infoblox",
            "nios",
            "akamai-edgedns",
            "ddns",
            "mock",
        }

    def test_env_based_backends_have_required_env(self):
        for name in ("cloudflare", "infoblox", "nios", "ddns"):
            info = BACKEND_REGISTRY[name]
            assert info.required_env, f"{name} should have required_env"

    def test_route53_uses_boto3_credential_chain(self):
        """Route 53 has no required_env — boto3 resolves credentials itself."""
        assert not BACKEND_REGISTRY["route53"].required_env

    def test_mock_has_no_required_env(self):
        assert not BACKEND_REGISTRY["mock"].required_env

    def test_all_have_display_name(self):
        for name, info in BACKEND_REGISTRY.items():
            assert info.display_name, f"{name} missing display_name"


# ── detect_backend() ──────────────────────────────────────────────


class TestDetectBackend:
    _NO_BOTO3 = "dns_aid.cli.backends._has_boto3_credentials"

    def test_no_env_returns_none(self):
        with patch.dict(os.environ, {}, clear=True), patch(self._NO_BOTO3, return_value=False):
            assert detect_backend() is None

    def test_detects_route53_via_boto3(self):
        """Route 53 detected via boto3 credential chain, not env vars."""
        with patch.dict(os.environ, {}, clear=True), patch(self._NO_BOTO3, return_value=True):
            assert detect_backend() == "route53"

    def test_detects_cloudflare(self):
        env = {"CLOUDFLARE_API_TOKEN": "cf-token"}
        with patch.dict(os.environ, env, clear=True), patch(self._NO_BOTO3, return_value=False):
            assert detect_backend() == "cloudflare"

    def test_detects_infoblox(self):
        env = {"INFOBLOX_API_KEY": "ib-key"}
        with patch.dict(os.environ, env, clear=True), patch(self._NO_BOTO3, return_value=False):
            assert detect_backend() == "infoblox"

    def test_detects_ddns(self):
        env = {"DDNS_SERVER": "ns1.example.com"}
        with patch.dict(os.environ, env, clear=True), patch(self._NO_BOTO3, return_value=False):
            assert detect_backend() == "ddns"

    def test_multiple_raises(self):
        env = {"CLOUDFLARE_API_TOKEN": "cf-token"}
        with patch.dict(os.environ, env, clear=True), patch(self._NO_BOTO3, return_value=True):
            with pytest.raises(ValueError, match="Multiple backends"):
                detect_backend()


# ── _get_backend() (improved) ─────────────────────────────────────


class TestGetBackendImproved:
    def test_env_var_detection(self):
        """DNS_AID_BACKEND env var is respected."""
        env = {"DNS_AID_BACKEND": "mock"}
        with patch.dict(os.environ, env, clear=True):
            result = runner.invoke(app, ["list", "example.com"])
            # mock backend doesn't need credentials; it will run but find no records
            assert result.exit_code == 0

    def test_explicit_backend_mock(self):
        result = runner.invoke(app, ["list", "--backend", "mock", "example.com"])
        assert result.exit_code == 0

    def test_unknown_backend_error(self):
        result = runner.invoke(app, ["list", "--backend", "nonexistent", "example.com"])
        assert result.exit_code != 0
        assert "Unknown backend" in result.output or "Unknown backend" in (result.stderr or "")

    def test_missing_env_vars_shows_guidance(self):
        """When backend is set but creds are missing, show actionable help."""
        env = {"DNS_AID_BACKEND": "route53"}
        with patch.dict(os.environ, env, clear=True):
            # Patch out boto3 import to not fail on ImportError first
            with patch.dict("sys.modules", {"boto3": None}):
                result = runner.invoke(app, ["list", "example.com"])
                assert result.exit_code != 0

    def test_no_backend_configured_shows_init_hint(self):
        """When nothing is configured, suggest dns-aid init."""
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("dns_aid.cli.backends._has_boto3_credentials", return_value=False),
            patch("dns_aid.cli.backends.detect_backend", return_value=None),
        ):
            result = runner.invoke(app, ["list", "example.com"])
            assert result.exit_code != 0
            assert "init" in result.output or "init" in (result.stderr or "")

    def test_auto_detect_mock_env(self):
        """Mock via DNS_AID_BACKEND works end to end."""
        env = {"DNS_AID_BACKEND": "mock"}
        with patch.dict(os.environ, env, clear=True):
            result = runner.invoke(app, ["list", "example.com"])
            assert result.exit_code == 0


# ── dns-aid doctor ─────────────────────────────────────────────────


class TestDoctor:
    def test_doctor_runs(self):
        result = runner.invoke(app, ["doctor"])
        assert result.exit_code == 0
        assert "Core" in result.output
        assert "dns-aid" in result.output

    def test_doctor_shows_python_version(self):
        result = runner.invoke(app, ["doctor"])
        assert "Python" in result.output

    def test_doctor_shows_summary(self):
        result = runner.invoke(app, ["doctor"])
        assert "Result:" in result.output


class TestDoctorAPI:
    """Tests for the structured dns_aid.doctor Python API."""

    def test_run_checks_returns_report(self):
        from dns_aid.doctor import DiagnosticReport, run_checks

        report = run_checks()
        assert isinstance(report, DiagnosticReport)
        assert report.version
        assert "Core" in report.sections
        assert "DNS" in report.sections
        assert "Backends" in report.sections

    def test_report_counts(self):
        from dns_aid.doctor import run_checks

        report = run_checks()
        assert report.pass_count >= 1
        assert report.pass_count + report.fail_count + report.warn_count > 0

    def test_report_to_dict(self):
        from dns_aid.doctor import run_checks

        report = run_checks()
        d = report.to_dict()
        assert "version" in d
        assert "sections" in d
        assert "pass_count" in d
        assert "fail_count" in d
        assert "warn_count" in d
        assert isinstance(d["sections"], dict)

    def test_check_results_have_status(self):
        from dns_aid.doctor import run_checks

        report = run_checks()
        for _section, checks in report.sections.items():
            for check in checks:
                assert check.status in ("pass", "fail", "warn")
                assert check.label


# ── dns-aid init ───────────────────────────────────────────────────


class TestInit:
    def test_init_help(self):
        result = runner.invoke(app, ["init", "--help"])
        assert result.exit_code == 0
        assert "wizard" in result.output.lower() or "setup" in result.output.lower()

    def test_init_discover_quickstart(self):
        """Choosing option 0 (discover-only) shows quickstart."""
        result = runner.invoke(app, ["init"], input="0\nn\n")
        assert result.exit_code == 0
        assert "discover" in result.output.lower()
