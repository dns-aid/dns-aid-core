# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for ``dns_aid.doctor`` internals — fully mocked, no network."""

from __future__ import annotations

import logging
import types

import pytest

import dns_aid.doctor as doctor_mod
from dns_aid.cli.backends import BACKEND_REGISTRY
from dns_aid.doctor import (
    _check_backends,
    _check_core,
    _check_dns,
    _check_dotenv,
    _check_optional,
    _get_module_version,
    _suppress_logs,
    run_checks,
)

AKAMAI_ENV = [
    "AKAMAI_HOST",
    "AKAMAI_CLIENT_TOKEN",
    "AKAMAI_CLIENT_SECRET",
    "AKAMAI_ACCESS_TOKEN",
]


class _FakeResponse:
    def __init__(self, status_code: int = 200, latest: str = "0.0.0"):
        self.status_code = status_code
        self._latest = latest

    def json(self) -> dict:
        return {"info": {"version": self._latest}}


def _raise_network_error(*args, **kwargs):
    raise OSError("network unreachable")


def _raise_import_error(*args, **kwargs):
    raise ImportError("nope")


def _by_label(results) -> dict:
    return {r.label: r for r in results}


# ── _check_core ────────────────────────────────────────────────────


class TestCheckCore:
    def test_update_available(self, monkeypatch):
        monkeypatch.setattr("httpx.get", lambda *a, **k: _FakeResponse(200, "999.0.0"))
        results = _check_core("0.1.0")
        assert results[0].status == "fail"
        assert results[0].label == "dns-aid"
        assert "999.0.0" in results[0].detail
        assert "upgrade" in results[0].detail

    def test_up_to_date(self, monkeypatch):
        monkeypatch.setattr("httpx.get", lambda *a, **k: _FakeResponse(200, "1.0.0"))
        results = _check_core("1.0.0")
        assert results[0].status == "pass"
        assert "(latest)" in results[0].detail

    def test_pypi_non_200_reports_version_only(self, monkeypatch):
        monkeypatch.setattr("httpx.get", lambda *a, **k: _FakeResponse(500))
        results = _check_core("1.2.3")
        assert results[0].status == "pass"
        assert results[0].detail == "1.2.3"

    def test_pypi_network_error_reports_version_only(self, monkeypatch):
        monkeypatch.setattr("httpx.get", _raise_network_error)
        results = _check_core("1.2.3")
        assert results[0].status == "pass"
        assert results[0].detail == "1.2.3"

    def test_python_version_reported(self, monkeypatch):
        monkeypatch.setattr("httpx.get", _raise_network_error)
        results = _check_core("1.2.3")
        assert _by_label(results)["Python"].status == "pass"

    def test_missing_dependency_fails(self, monkeypatch):
        monkeypatch.setattr("httpx.get", _raise_network_error)
        monkeypatch.setattr(doctor_mod, "_get_module_version", _raise_import_error)
        results = _check_core("1.2.3")
        fails = [r for r in results if r.status == "fail"]
        assert len(fails) == 6  # all listed deps
        assert all(r.detail == "not installed" for r in fails)


# ── _get_module_version ────────────────────────────────────────────


class TestGetModuleVersion:
    def test_callable_version_attribute(self, monkeypatch):
        fake_mod = types.SimpleNamespace(version=lambda: "9.9.9")
        fake_importlib = types.SimpleNamespace(import_module=lambda name: fake_mod)
        monkeypatch.setattr(doctor_mod, "importlib", fake_importlib)
        assert _get_module_version("whatever") == "9.9.9"

    def test_metadata_fallback(self, monkeypatch):
        fake_mod = types.SimpleNamespace()
        fake_importlib = types.SimpleNamespace(import_module=lambda name: fake_mod)
        monkeypatch.setattr(doctor_mod, "importlib", fake_importlib)
        ver = _get_module_version("whatever", "pytest")
        assert ver  # resolved via importlib.metadata

    def test_no_version_no_dist_returns_empty(self, monkeypatch):
        fake_mod = types.SimpleNamespace()
        fake_importlib = types.SimpleNamespace(import_module=lambda name: fake_mod)
        monkeypatch.setattr(doctor_mod, "importlib", fake_importlib)
        assert _get_module_version("whatever") == ""


# ── _suppress_logs ─────────────────────────────────────────────────


class TestSuppressLogs:
    def test_restores_logging_after_exit(self):
        with _suppress_logs():
            logging.getLogger("dns_aid.test").error("suppressed")
        assert logging.root.manager.disable == logging.NOTSET

    def test_no_previous_factory_resets_defaults(self, monkeypatch):
        monkeypatch.setattr("structlog.get_config", lambda: {})
        with _suppress_logs():
            pass
        assert logging.root.manager.disable == logging.NOTSET


# ── _check_dns ─────────────────────────────────────────────────────


class TestCheckDns:
    @pytest.fixture(autouse=True)
    def _no_doctor_domain(self, monkeypatch):
        monkeypatch.delenv("DNS_AID_DOCTOR_DOMAIN", raising=False)

    def test_resolution_failure_short_circuits(self, monkeypatch):
        monkeypatch.setattr("dns.resolver.resolve", _raise_network_error)
        results = _check_dns()
        assert len(results) == 1
        assert results[0].status == "fail"
        assert results[0].label == "Resolution"
        assert "network unreachable" in results[0].detail

    def test_svcb_unsupported_warns(self, monkeypatch):
        monkeypatch.setattr("dns.resolver.resolve", lambda *a, **k: None)
        monkeypatch.setattr("dns.rdatatype.from_text", _raise_import_error)
        results = _check_dns()
        checks = _by_label(results)
        assert checks["SVCB support"].status == "warn"

    def test_no_domain_warns(self, monkeypatch):
        monkeypatch.setattr("dns.resolver.resolve", lambda *a, **k: None)
        results = _check_dns()
        checks = _by_label(results)
        assert checks["Agent discovery"].status == "warn"
        assert "no domain specified" in checks["Agent discovery"].detail

    def test_discovery_finds_agents(self, monkeypatch):
        monkeypatch.setattr("dns.resolver.resolve", lambda *a, **k: None)

        async def fake_read(domain):
            return ["agent-one", "agent-two"]

        monkeypatch.setattr("dns_aid.core.indexer.read_index_via_dns", fake_read)
        results = _check_dns(domain="agents.example.com")
        checks = _by_label(results)
        assert checks["Agent discovery"].status == "pass"
        assert "2 agent(s)" in checks["Agent discovery"].detail
        assert "agents.example.com" in checks["Agent discovery"].detail

    def test_discovery_empty_index_warns(self, monkeypatch):
        monkeypatch.setattr("dns.resolver.resolve", lambda *a, **k: None)

        async def fake_read(domain):
            return []

        monkeypatch.setattr("dns_aid.core.indexer.read_index_via_dns", fake_read)
        results = _check_dns(domain="agents.example.com")
        checks = _by_label(results)
        assert checks["Agent discovery"].status == "warn"
        assert "no agents indexed" in checks["Agent discovery"].detail

    def test_discovery_query_error_warns(self, monkeypatch):
        monkeypatch.setattr("dns.resolver.resolve", lambda *a, **k: None)

        async def fake_read(domain):
            raise RuntimeError("SERVFAIL")

        monkeypatch.setattr("dns_aid.core.indexer.read_index_via_dns", fake_read)
        results = _check_dns(domain="agents.example.com")
        checks = _by_label(results)
        assert checks["Agent discovery"].status == "warn"
        assert "TXT index query failed" in checks["Agent discovery"].detail

    def test_domain_from_env_var(self, monkeypatch):
        monkeypatch.setattr("dns.resolver.resolve", lambda *a, **k: None)
        monkeypatch.setenv("DNS_AID_DOCTOR_DOMAIN", "env.example.com")

        async def fake_read(domain):
            return [f"agent@{domain}"]

        monkeypatch.setattr("dns_aid.core.indexer.read_index_via_dns", fake_read)
        results = _check_dns()
        checks = _by_label(results)
        assert checks["Agent discovery"].status == "pass"
        assert "env.example.com" in checks["Agent discovery"].detail


# ── _check_backends ────────────────────────────────────────────────


class TestCheckBackends:
    @pytest.fixture(autouse=True)
    def _no_ambient_creds(self, monkeypatch):
        monkeypatch.setattr("dns_aid.cli.backends._has_boto3_credentials", lambda: False)
        for var in AKAMAI_ENV:
            monkeypatch.delenv(var, raising=False)

    def test_missing_optional_deps_fail(self, monkeypatch):
        fake_importlib = types.SimpleNamespace(import_module=_raise_import_error)
        monkeypatch.setattr(doctor_mod, "importlib", fake_importlib)
        checks = _by_label(_check_backends())
        for name in ("route53", "cloudflare", "infoblox", "nios", "akamai-edgedns", "ddns"):
            info = BACKEND_REGISTRY[name]
            assert checks[info.display_name].status == "fail"
            assert f'pip install "dns-aid[{info.optional_dep}]"' in checks[info.display_name].detail

    def test_route53_with_credentials(self, monkeypatch):
        monkeypatch.setattr("dns_aid.cli.backends._has_boto3_credentials", lambda: True)
        checks = _by_label(_check_backends())
        assert checks["AWS Route 53"].status == "pass"
        assert "credentials configured" in checks["AWS Route 53"].detail

    def test_route53_without_credentials(self):
        checks = _by_label(_check_backends())
        assert checks["AWS Route 53"].status == "warn"
        assert "no AWS credentials" in checks["AWS Route 53"].detail

    def test_akamai_partial_env_fails(self, monkeypatch):
        monkeypatch.setenv("AKAMAI_HOST", "akab-x.luna.akamaiapis.net")
        monkeypatch.setenv("AKAMAI_EDGERC", "definitely-missing-edgerc")
        checks = _by_label(_check_backends())
        result = checks["Akamai Edge DNS"]
        assert result.status == "fail"
        assert "partial credentials" in result.detail
        assert "AKAMAI_CLIENT_TOKEN" in result.detail

    def test_akamai_all_env_passes(self, monkeypatch):
        for var in AKAMAI_ENV:
            monkeypatch.setenv(var, "value")
        checks = _by_label(_check_backends())
        result = checks["Akamai Edge DNS"]
        assert result.status == "pass"
        assert "env vars" in result.detail

    def test_akamai_edgerc_file_passes(self, monkeypatch, tmp_path):
        edgerc = tmp_path / "edgerc"
        edgerc.write_text("[default]\n")
        monkeypatch.setenv("AKAMAI_EDGERC", str(edgerc))
        checks = _by_label(_check_backends())
        result = checks["Akamai Edge DNS"]
        assert result.status == "pass"
        assert ".edgerc" in result.detail

    def test_akamai_no_credentials_warns(self, monkeypatch, tmp_path):
        monkeypatch.setenv("AKAMAI_EDGERC", str(tmp_path / "missing-edgerc"))
        checks = _by_label(_check_backends())
        result = checks["Akamai Edge DNS"]
        assert result.status == "warn"
        assert "no credentials found" in result.detail

    def test_env_backend_credentials_configured(self, monkeypatch):
        monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "cf-token")
        checks = _by_label(_check_backends())
        assert checks["Cloudflare DNS"].status == "pass"
        assert checks["Cloudflare DNS"].detail == "credentials configured"

    def test_env_backend_missing_credentials_warns(self, monkeypatch):
        monkeypatch.delenv("NS1_API_KEY", raising=False)
        checks = _by_label(_check_backends())
        assert checks["NS1 (IBM)"].status == "warn"
        assert "NS1_API_KEY" in checks["NS1 (IBM)"].detail


# ── _check_optional ────────────────────────────────────────────────


class TestCheckOptional:
    def test_all_available(self, monkeypatch):
        fake_importlib = types.SimpleNamespace(import_module=lambda n: types.ModuleType(n))
        monkeypatch.setattr(doctor_mod, "importlib", fake_importlib)
        results = _check_optional()
        assert len(results) == 3
        assert all(r.status == "pass" for r in results)

    def test_none_available(self, monkeypatch):
        fake_importlib = types.SimpleNamespace(import_module=_raise_import_error)
        monkeypatch.setattr(doctor_mod, "importlib", fake_importlib)
        results = _check_optional()
        assert len(results) == 3
        assert all(r.status == "warn" for r in results)
        assert any("pip install" in r.detail for r in results)


# ── _check_dotenv ──────────────────────────────────────────────────


class TestCheckDotenv:
    def test_env_file_with_backend_set(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("FOO=bar\n# comment\n\nBAR=baz\n")
        monkeypatch.setenv("DNS_AID_BACKEND", "mock")
        checks = _by_label(_check_dotenv())
        assert checks[".env file"].status == "pass"
        assert "2 variable(s) set" in checks[".env file"].detail
        assert checks["DNS_AID_BACKEND"].status == "pass"
        assert checks["DNS_AID_BACKEND"].detail == "mock"

    def test_env_file_without_backend_warns(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("FOO=bar\n")
        monkeypatch.delenv("DNS_AID_BACKEND", raising=False)
        checks = _by_label(_check_dotenv())
        assert checks[".env file"].status == "pass"
        assert checks["DNS_AID_BACKEND"].status == "warn"

    def test_no_env_file_warns(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        results = _check_dotenv()
        assert len(results) == 1
        assert results[0].status == "warn"
        assert "not found" in results[0].detail


# ── run_checks (integration, mocked) ───────────────────────────────


class TestRunChecksMocked:
    def test_run_checks_with_domain(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr("httpx.get", _raise_network_error)
        monkeypatch.setattr("dns.resolver.resolve", lambda *a, **k: None)
        monkeypatch.setattr("dns_aid.cli.backends._has_boto3_credentials", lambda: False)

        async def fake_read(domain):
            return ["entry"]

        monkeypatch.setattr("dns_aid.core.indexer.read_index_via_dns", fake_read)

        report = run_checks(domain="agents.example.com")
        assert set(report.sections) == {
            "Core",
            "DNS",
            "Backends",
            "Optional Features",
            "Configuration",
        }
        dns_checks = _by_label(report.sections["DNS"])
        assert dns_checks["Agent discovery"].status == "pass"
        assert "agents.example.com" in dns_checks["Agent discovery"].detail

        d = report.to_dict()
        assert d["pass_count"] == report.pass_count
        assert d["fail_count"] == report.fail_count
        assert d["warn_count"] == report.warn_count
