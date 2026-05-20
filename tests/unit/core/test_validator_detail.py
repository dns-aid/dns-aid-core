# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for DNSSECDetail, TLSDetail models and validator detail extraction."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import dns.flags
import dns.resolver

from dns_aid.core.models import DNSSECDetail, TLSDetail, VerifyResult
from dns_aid.core.validator import (
    _ALGORITHM_STRENGTH,
    _DNSSEC_ALGORITHM_MAP,
    _check_dnssec_detail,
    _check_tls,
)

# =============================================================================
# DNSSECDetail model tests
# =============================================================================


class TestDNSSECDetail:
    """Test DNSSECDetail model creation with various inputs."""

    def test_default_values(self) -> None:
        detail = DNSSECDetail()
        assert detail.validated is False
        assert detail.algorithm is None
        assert detail.algorithm_strength is None
        assert detail.chain_complete is False
        assert detail.chain_depth == 0
        assert detail.nsec3_present is False
        assert detail.key_rotation_days is None
        assert detail.ad_flag is False

    def test_fully_populated(self) -> None:
        detail = DNSSECDetail(
            validated=True,
            algorithm="ECDSAP256SHA256",
            algorithm_strength="strong",
            chain_complete=True,
            chain_depth=3,
            nsec3_present=True,
            key_rotation_days=90,
            ad_flag=True,
        )
        assert detail.validated is True
        assert detail.algorithm == "ECDSAP256SHA256"
        assert detail.algorithm_strength == "strong"
        assert detail.chain_complete is True
        assert detail.chain_depth == 3
        assert detail.nsec3_present is True
        assert detail.key_rotation_days == 90
        assert detail.ad_flag is True

    def test_weak_algorithm(self) -> None:
        detail = DNSSECDetail(
            validated=True,
            algorithm="RSASHA1",
            algorithm_strength="weak",
        )
        assert detail.algorithm_strength == "weak"

    def test_acceptable_algorithm(self) -> None:
        detail = DNSSECDetail(
            validated=True,
            algorithm="RSASHA256",
            algorithm_strength="acceptable",
        )
        assert detail.algorithm_strength == "acceptable"


# =============================================================================
# TLSDetail model tests
# =============================================================================


class TestTLSDetail:
    """Test TLSDetail model creation with various inputs."""

    def test_default_values(self) -> None:
        detail = TLSDetail()
        assert detail.connected is False
        assert detail.tls_version is None
        assert detail.cipher_suite is None
        assert detail.cert_valid is False
        assert detail.cert_days_remaining is None
        assert detail.hsts_enabled is False
        assert detail.hsts_max_age is None

    def test_fully_populated(self) -> None:
        detail = TLSDetail(
            connected=True,
            tls_version="TLSv1.3",
            cipher_suite="TLS_AES_256_GCM_SHA384",
            cert_valid=True,
            cert_days_remaining=365,
            hsts_enabled=True,
            hsts_max_age=31536000,
        )
        assert detail.connected is True
        assert detail.tls_version == "TLSv1.3"
        assert detail.cipher_suite == "TLS_AES_256_GCM_SHA384"
        assert detail.cert_valid is True
        assert detail.cert_days_remaining == 365
        assert detail.hsts_enabled is True
        assert detail.hsts_max_age == 31536000

    def test_tls_12(self) -> None:
        detail = TLSDetail(
            connected=True,
            tls_version="TLSv1.2",
            cert_valid=True,
        )
        assert detail.tls_version == "TLSv1.2"

    def test_expired_cert(self) -> None:
        detail = TLSDetail(
            connected=True,
            cert_valid=False,
            cert_days_remaining=-5,
        )
        assert detail.cert_valid is False
        assert detail.cert_days_remaining == -5


# =============================================================================
# VerifyResult integration tests
# =============================================================================


class TestVerifyResultDetail:
    """Test that VerifyResult includes the new detail fields."""

    def test_default_detail_fields(self) -> None:
        result = VerifyResult(fqdn="_test._mcp._agents.example.com")
        assert isinstance(result.dnssec_detail, DNSSECDetail)
        assert isinstance(result.tls_detail, TLSDetail)
        assert result.dnssec_detail.validated is False
        assert result.tls_detail.connected is False

    def test_custom_detail_fields(self) -> None:
        dnssec = DNSSECDetail(validated=True, algorithm="ED25519", ad_flag=True)
        tls = TLSDetail(connected=True, tls_version="TLSv1.3")
        result = VerifyResult(
            fqdn="_test._mcp._agents.example.com",
            dnssec_detail=dnssec,
            tls_detail=tls,
        )
        assert result.dnssec_detail.algorithm == "ED25519"
        assert result.tls_detail.tls_version == "TLSv1.3"


# =============================================================================
# Algorithm mapping tests
# =============================================================================


class TestAlgorithmMaps:
    """Test DNSSEC algorithm mapping and strength classification."""

    def test_known_algorithms(self) -> None:
        assert _DNSSEC_ALGORITHM_MAP[13] == "ECDSAP256SHA256"
        assert _DNSSEC_ALGORITHM_MAP[15] == "ED25519"
        assert _DNSSEC_ALGORITHM_MAP[8] == "RSASHA256"

    def test_strong_algorithms(self) -> None:
        for alg in ("ECDSAP256SHA256", "ECDSAP384SHA384", "ED25519", "ED448"):
            assert _ALGORITHM_STRENGTH[alg] == "strong"

    def test_weak_algorithms(self) -> None:
        for alg in ("RSAMD5", "DSA", "RSASHA1"):
            assert _ALGORITHM_STRENGTH[alg] == "weak"

    def test_acceptable_algorithms(self) -> None:
        for alg in ("RSASHA256", "RSASHA512"):
            assert _ALGORITHM_STRENGTH[alg] == "acceptable"


# =============================================================================
# _check_dnssec_detail tests (mocked DNS)
# =============================================================================


class TestCheckDnssecDetail:
    """Test DNSSEC detail extraction with mocked DNS responses."""

    async def test_ad_flag_set(self) -> None:
        """When AD flag is set, validated should be True."""
        mock_answer = MagicMock()
        mock_answer.response = MagicMock()
        mock_answer.response.flags = dns.flags.AD | dns.flags.QR

        with patch("dns_aid.core.validator.dns.asyncresolver.Resolver") as MockResolver:
            resolver_instance = MockResolver.return_value
            resolver_instance.use_edns = MagicMock()

            # SVCB query returns answer with AD flag
            resolver_instance.resolve = AsyncMock(return_value=mock_answer)

            # Make DNSKEY/NSEC3PARAM/DS queries fail (not found)
            async def side_effect(name: str, rdtype: str) -> MagicMock:
                if rdtype == "SVCB":
                    return mock_answer
                raise dns.resolver.NXDOMAIN()

            resolver_instance.resolve = AsyncMock(side_effect=side_effect)

            detail = await _check_dnssec_detail("_test._mcp._agents.example.com")
            assert detail.ad_flag is True
            assert detail.validated is True

    async def test_no_ad_flag(self) -> None:
        """When AD flag is not set, validated should be False."""
        mock_answer = MagicMock()
        mock_answer.response = MagicMock()
        mock_answer.response.flags = dns.flags.QR  # No AD flag

        with patch("dns_aid.core.validator.dns.asyncresolver.Resolver") as MockResolver:
            resolver_instance = MockResolver.return_value
            resolver_instance.use_edns = MagicMock()

            async def side_effect(name: str, rdtype: str) -> MagicMock:
                if rdtype == "SVCB":
                    return mock_answer
                raise dns.resolver.NXDOMAIN()

            resolver_instance.resolve = AsyncMock(side_effect=side_effect)

            detail = await _check_dnssec_detail("_test._mcp._agents.example.com")
            assert detail.ad_flag is False
            assert detail.validated is False

    async def test_algorithm_extraction(self) -> None:
        """DNSKEY algorithm should be extracted and mapped."""
        mock_svcb_answer = MagicMock()
        mock_svcb_answer.response = MagicMock()
        mock_svcb_answer.response.flags = dns.flags.AD | dns.flags.QR

        mock_dnskey_rdata = MagicMock()
        mock_dnskey_rdata.algorithm = 13  # ECDSAP256SHA256

        mock_dnskey_answer = MagicMock()
        mock_dnskey_answer.__iter__ = MagicMock(return_value=iter([mock_dnskey_rdata]))

        with patch("dns_aid.core.validator.dns.asyncresolver.Resolver") as MockResolver:
            resolver_instance = MockResolver.return_value
            resolver_instance.use_edns = MagicMock()

            async def side_effect(name: str, rdtype: str) -> MagicMock:
                if rdtype == "SVCB":
                    return mock_svcb_answer
                if rdtype == "DNSKEY":
                    return mock_dnskey_answer
                raise dns.resolver.NXDOMAIN()

            resolver_instance.resolve = AsyncMock(side_effect=side_effect)

            detail = await _check_dnssec_detail("_test._mcp._agents.example.com")
            assert detail.algorithm == "ECDSAP256SHA256"
            assert detail.algorithm_strength == "strong"

    async def test_resolver_failure_returns_empty_detail(self) -> None:
        """On total resolver failure, return default empty detail."""
        with patch("dns_aid.core.validator.dns.asyncresolver.Resolver") as MockResolver:
            resolver_instance = MockResolver.return_value
            resolver_instance.use_edns = MagicMock()
            resolver_instance.resolve = AsyncMock(side_effect=Exception("resolver error"))

            detail = await _check_dnssec_detail("_test._mcp._agents.example.com")
            assert detail.validated is False
            assert detail.algorithm is None


# =============================================================================
# _check_tls tests (mocked)
# =============================================================================


class TestCheckTls:
    """Test TLS detail extraction with mocked connections."""

    async def test_connection_failure(self) -> None:
        """On connection failure, return default empty detail."""
        with patch(
            "dns_aid.core.validator.asyncio.open_connection",
            side_effect=ConnectionRefusedError("refused"),
        ):
            detail = await _check_tls("example.com", 443)
            assert detail.connected is False
            assert detail.tls_version is None

    async def test_successful_connection(self) -> None:
        """Extract TLS version and cipher from successful connection."""
        mock_ssl_object = MagicMock()
        mock_ssl_object.version.return_value = "TLSv1.3"
        mock_ssl_object.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssl_object.getpeercert.return_value = {
            "notAfter": "Jan 01 00:00:00 2027 GMT",
        }

        mock_writer = MagicMock()
        mock_writer.get_extra_info = MagicMock(return_value=mock_ssl_object)
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        mock_reader = MagicMock()

        with (
            patch(
                "dns_aid.core.validator.asyncio.open_connection",
                new_callable=AsyncMock,
                return_value=(mock_reader, mock_writer),
            ),
            patch("dns_aid.core.validator.asyncio.wait_for") as mock_wait_for,
            patch("dns_aid.core.validator.httpx.AsyncClient") as MockClient,
        ):
            mock_wait_for.return_value = (mock_reader, mock_writer)

            # Mock HSTS check
            mock_response = MagicMock()
            mock_response.headers = {"strict-transport-security": "max-age=31536000"}
            mock_client_instance = AsyncMock()
            mock_client_instance.head = AsyncMock(return_value=mock_response)
            mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
            mock_client_instance.__aexit__ = AsyncMock(return_value=None)
            MockClient.return_value = mock_client_instance

            detail = await _check_tls("example.com", 443)
            assert detail.connected is True
            assert detail.tls_version == "TLSv1.3"
            assert detail.cipher_suite == "TLS_AES_256_GCM_SHA384"
            assert detail.cert_valid is True
            assert detail.hsts_enabled is True
            assert detail.hsts_max_age == 31536000

    async def test_timeout_returns_empty(self) -> None:
        """On timeout, return default empty detail."""

        with patch(
            "dns_aid.core.validator.asyncio.wait_for",
            side_effect=TimeoutError(),
        ):
            detail = await _check_tls("example.com", 443)
            assert detail.connected is False
