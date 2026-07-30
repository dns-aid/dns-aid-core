# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for the centralised backend factory (create_backend)."""

from __future__ import annotations

import importlib
import sys
from unittest.mock import patch

import pytest

from dns_aid.backends import VALID_BACKEND_NAMES, create_backend
from dns_aid.backends.base import DNSBackend

# ---------------------------------------------------------------------------
# Basic contract
# ---------------------------------------------------------------------------


class TestValidBackendNames:
    """VALID_BACKEND_NAMES is a frozenset with all expected entries."""

    def test_is_frozenset(self):
        assert isinstance(VALID_BACKEND_NAMES, frozenset)

    def test_contains_all_backends(self):
        expected = {
            "route53",
            "cloudflare",
            "cloud-dns",
            "ns1",
            "infoblox",
            "nios",
            "akamai-edgedns",
            "ddns",
            "mock",
        }
        assert expected == VALID_BACKEND_NAMES


# ---------------------------------------------------------------------------
# create_backend — happy paths
# ---------------------------------------------------------------------------


class TestCreateBackendHappyPath:
    """create_backend returns a DNSBackend subclass for every known name."""

    def test_mock_backend(self):
        backend = create_backend("mock")
        assert isinstance(backend, DNSBackend)
        assert backend.name == "mock"

    def test_mock_backend_case_insensitive(self):
        backend = create_backend("Mock")
        assert isinstance(backend, DNSBackend)

    def test_mock_backend_with_whitespace(self):
        backend = create_backend("  mock  ")
        assert isinstance(backend, DNSBackend)

    @pytest.mark.parametrize("name", sorted(VALID_BACKEND_NAMES - {"mock"}))
    def test_real_backends_return_dns_backend(self, name: str):
        """Each real backend should either succeed or raise ImportError (missing dep)."""
        try:
            backend = create_backend(name)
            assert isinstance(backend, DNSBackend)
        except (ImportError, ValueError, OSError):
            # ImportError = optional dep missing (e.g. boto3)
            # ValueError/OSError = missing credentials / config, acceptable
            pass


# ---------------------------------------------------------------------------
# create_backend — error paths
# ---------------------------------------------------------------------------


class TestCreateBackendErrors:
    """create_backend raises clear errors for invalid inputs."""

    def test_unknown_name_raises_value_error(self):
        with pytest.raises(ValueError, match="Unknown backend: 'nonexistent'"):
            create_backend("nonexistent")

    def test_empty_string_raises_value_error(self):
        with pytest.raises(ValueError, match="Unknown backend"):
            create_backend("")

    def test_missing_dependency_raises_import_error(self):
        """Simulate a missing optional dependency."""
        with patch(
            "importlib.import_module",
            side_effect=ImportError("No module named 'boto3'"),
        ):
            with pytest.raises(ImportError, match="boto3"):
                create_backend("route53")


# ---------------------------------------------------------------------------
# Eager convenience re-exports — missing optional deps are swallowed
# ---------------------------------------------------------------------------

_OPTIONAL_BACKEND_MODULES = [
    ("dns_aid.backends.route53", "Route53Backend"),
    ("dns_aid.backends.infoblox", "InfobloxBackend"),
    ("dns_aid.backends.ddns", "DDNSBackend"),
    ("dns_aid.backends.cloudflare", "CloudflareBackend"),
    ("dns_aid.backends.cloud_dns", "CloudDNSBackend"),
    ("dns_aid.backends.ns1", "NS1Backend"),
    ("dns_aid.backends.akamai_edgedns", "AkamaiEdgeDNSBackend"),
]


class TestOptionalReExports:
    """The eager re-export block must swallow ImportError for every backend."""

    def test_all_optional_backends_missing(self):
        """Re-import the package with every optional backend module blocked."""
        real_pkg = sys.modules["dns_aid.backends"]
        try:
            with patch.dict(sys.modules):
                for module_path, _ in _OPTIONAL_BACKEND_MODULES:
                    # A None entry makes `import <name>` raise ImportError.
                    sys.modules[module_path] = None  # type: ignore[assignment]
                sys.modules.pop("dns_aid.backends", None)

                fresh = importlib.import_module("dns_aid.backends")

                for _, class_name in _OPTIONAL_BACKEND_MODULES:
                    assert class_name not in fresh.__all__
                    assert not hasattr(fresh, class_name)
                # Core exports survive
                assert "MockBackend" in fresh.__all__
                assert "DNSBackend" in fresh.__all__
                assert fresh.VALID_BACKEND_NAMES == VALID_BACKEND_NAMES
                # Factory still works for backends without optional deps
                assert fresh.create_backend("mock").name == "mock"
        finally:
            # patch.dict restored sys.modules; also restore the attribute on
            # the parent package, which the fresh import overwrote.
            sys.modules["dns_aid.backends"] = real_pkg
            import dns_aid

            dns_aid.backends = real_pkg

    def test_all_optional_backends_present_are_exported(self):
        """With the full dev environment, every optional backend is re-exported."""
        import dns_aid.backends as pkg

        for _, class_name in _OPTIONAL_BACKEND_MODULES:
            assert class_name in pkg.__all__
            assert hasattr(pkg, class_name)
