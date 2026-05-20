# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for DNS-AID validator module."""

from unittest.mock import AsyncMock, MagicMock, patch

import dns.flags
import dns.resolver
import httpx
import pytest

from dns_aid.core.validator import (
    _check_dane,
    _check_dnssec,
    _check_endpoint,
    _check_svcb_record,
    verify,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_svcb_rdata():
    """Create a mock SVCB rdata object."""
    rdata = MagicMock()
    rdata.target = MagicMock()
    rdata.target.__str__ = MagicMock(return_value="agent.example.com.")
    rdata.priority = 1
    rdata.params = {}
    return rdata


@pytest.fixture
def mock_svcb_rdata_with_port():
    """Create a mock SVCB rdata with port param."""
    rdata = MagicMock()
    rdata.target = MagicMock()
    rdata.target.__str__ = MagicMock(return_value="agent.example.com.")
    rdata.priority = 1
    # Port param key is 3 in SVCB
    port_param = MagicMock()
    port_param.port = 8443
    rdata.params = {3: port_param}
    return rdata


@pytest.fixture
def mock_tlsa_rdata():
    """Create a mock TLSA rdata object."""
    rdata = MagicMock()
    rdata.usage = 3  # DANE-EE
    rdata.selector = 1  # SPKI
    rdata.mtype = 1  # SHA-256
    return rdata


# =============================================================================
# Tests for _check_svcb_record()
# =============================================================================


class TestCheckSvcbRecord:
    """Tests for _check_svcb_record function."""

    @pytest.mark.asyncio
    async def test_svcb_record_found(self, mock_svcb_rdata):
        """Test successful SVCB record lookup."""
        mock_answers = MagicMock()
        mock_answers.__iter__ = MagicMock(return_value=iter([mock_svcb_rdata]))

        with patch("dns_aid.core.validator.dns.asyncresolver.Resolver") as mock_resolver:
            resolver_instance = MagicMock()
            resolver_instance.resolve = AsyncMock(return_value=mock_answers)
            mock_resolver.return_value = resolver_instance

            result = await _check_svcb_record("_agent._mcp._agents.example.com")

            assert result is not None
            assert result["target"] == "agent.example.com"
            assert result["port"] == 443  # Default
            assert result["valid"] is True
            assert result["priority"] == 1

    @pytest.mark.asyncio
    async def test_svcb_with_custom_port(self, mock_svcb_rdata_with_port):
        """Test SVCB record with port parameter."""
        mock_answers = MagicMock()
        mock_answers.__iter__ = MagicMock(return_value=iter([mock_svcb_rdata_with_port]))

        with patch("dns_aid.core.validator.dns.asyncresolver.Resolver") as mock_resolver:
            resolver_instance = MagicMock()
            resolver_instance.resolve = AsyncMock(return_value=mock_answers)
            mock_resolver.return_value = resolver_instance

            result = await _check_svcb_record("_agent._mcp._agents.example.com")

            assert result is not None
            assert result["port"] == 8443

    @pytest.mark.asyncio
    async def test_svcb_fallback_to_https(self, mock_svcb_rdata):
        """Test fallback to HTTPS record when SVCB not found."""
        mock_answers = MagicMock()
        mock_answers.__iter__ = MagicMock(return_value=iter([mock_svcb_rdata]))

        with patch("dns_aid.core.validator.dns.asyncresolver.Resolver") as mock_resolver:
            resolver_instance = MagicMock()
            # First call (SVCB) raises NoAnswer, second call (HTTPS) succeeds
            resolver_instance.resolve = AsyncMock(
                side_effect=[dns.resolver.NoAnswer(), mock_answers]
            )
            mock_resolver.return_value = resolver_instance

            result = await _check_svcb_record("_agent._mcp._agents.example.com")

            assert result is not None
            assert result["target"] == "agent.example.com"

    @pytest.mark.asyncio
    async def test_svcb_nxdomain(self):
        """Test NXDOMAIN response."""
        with patch("dns_aid.core.validator.dns.asyncresolver.Resolver") as mock_resolver:
            resolver_instance = MagicMock()
            resolver_instance.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())
            mock_resolver.return_value = resolver_instance

            result = await _check_svcb_record("_nonexistent._mcp._agents.example.com")

            assert result is None

    @pytest.mark.asyncio
    async def test_svcb_no_answer_both_types(self):
        """Test NoAnswer for both SVCB and HTTPS."""
        with patch("dns_aid.core.validator.dns.asyncresolver.Resolver") as mock_resolver:
            resolver_instance = MagicMock()
            resolver_instance.resolve = AsyncMock(
                side_effect=[dns.resolver.NoAnswer(), dns.resolver.NoAnswer()]
            )
            mock_resolver.return_value = resolver_instance

            result = await _check_svcb_record("_agent._mcp._agents.example.com")

            assert result is None

    @pytest.mark.asyncio
    async def test_svcb_invalid_target(self):
        """Test SVCB with empty/invalid target."""
        rdata = MagicMock()
        rdata.target = MagicMock()
        rdata.target.__str__ = MagicMock(return_value=".")
        rdata.priority = 0
        rdata.params = {}

        mock_answers = MagicMock()
        mock_answers.__iter__ = MagicMock(return_value=iter([rdata]))

        with patch("dns_aid.core.validator.dns.asyncresolver.Resolver") as mock_resolver:
            resolver_instance = MagicMock()
            resolver_instance.resolve = AsyncMock(return_value=mock_answers)
            mock_resolver.return_value = resolver_instance

            result = await _check_svcb_record("_agent._mcp._agents.example.com")

            assert result is not None
            assert result["valid"] is False


# =============================================================================
# Tests for _check_dnssec()
# =============================================================================


class TestCheckDnssec:
    """Tests for _check_dnssec function."""

    @pytest.mark.asyncio
    async def test_dnssec_ad_flag_set(self):
        """Test DNSSEC validation with AD flag."""
        mock_response = MagicMock()
        mock_response.flags = dns.flags.AD  # Authenticated Data flag

        mock_answer = MagicMock()
        mock_answer.response = mock_response

        with patch("dns_aid.core.validator.dns.asyncresolver.Resolver") as mock_resolver:
            resolver_instance = MagicMock()
            resolver_instance.use_edns = MagicMock()
            resolver_instance.resolve = AsyncMock(return_value=mock_answer)
            mock_resolver.return_value = resolver_instance

            result = await _check_dnssec("_agent._mcp._agents.example.com")

            assert result is True

    @pytest.mark.asyncio
    async def test_dnssec_no_ad_flag(self):
        """Test DNSSEC check without AD flag."""
        mock_response = MagicMock()
        mock_response.flags = 0  # No AD flag

        mock_answer = MagicMock()
        mock_answer.response = mock_response

        with patch("dns_aid.core.validator.dns.asyncresolver.Resolver") as mock_resolver:
            resolver_instance = MagicMock()
            resolver_instance.use_edns = MagicMock()
            resolver_instance.resolve = AsyncMock(return_value=mock_answer)
            mock_resolver.return_value = resolver_instance

            result = await _check_dnssec("_agent._mcp._agents.example.com")

            assert result is False

    @pytest.mark.asyncio
    async def test_dnssec_fallback_to_txt(self):
        """Test DNSSEC check falls back to TXT record."""
        mock_response = MagicMock()
        mock_response.flags = dns.flags.AD

        mock_answer = MagicMock()
        mock_answer.response = mock_response

        with patch("dns_aid.core.validator.dns.asyncresolver.Resolver") as mock_resolver:
            resolver_instance = MagicMock()
            resolver_instance.use_edns = MagicMock()
            # First call (SVCB) raises NoAnswer, second call (TXT) succeeds
            resolver_instance.resolve = AsyncMock(
                side_effect=[dns.resolver.NoAnswer(), mock_answer]
            )
            mock_resolver.return_value = resolver_instance

            result = await _check_dnssec("_agent._mcp._agents.example.com")

            assert result is True

    @pytest.mark.asyncio
    async def test_dnssec_resolver_error(self):
        """Test DNSSEC check handles resolver errors."""
        with patch("dns_aid.core.validator.dns.asyncresolver.Resolver") as mock_resolver:
            resolver_instance = MagicMock()
            resolver_instance.use_edns = MagicMock()
            resolver_instance.resolve = AsyncMock(side_effect=Exception("DNS error"))
            mock_resolver.return_value = resolver_instance

            result = await _check_dnssec("_agent._mcp._agents.example.com")

            assert result is False


# =============================================================================
# Tests for _check_dane()
# =============================================================================


class TestCheckDane:
    """Tests for _check_dane function."""

    @pytest.mark.asyncio
    async def test_dane_tlsa_found(self, mock_tlsa_rdata):
        """Test TLSA record found."""
        mock_answers = MagicMock()
        mock_answers.__iter__ = MagicMock(return_value=iter([mock_tlsa_rdata]))

        with patch("dns_aid.core.validator.dns.asyncresolver.Resolver") as mock_resolver:
            resolver_instance = MagicMock()
            resolver_instance.resolve = AsyncMock(return_value=mock_answers)
            mock_resolver.return_value = resolver_instance

            result = await _check_dane("agent.example.com", 443)

            assert result is True

    @pytest.mark.asyncio
    async def test_dane_no_tlsa_nxdomain(self):
        """Test no TLSA record - NXDOMAIN."""
        with patch("dns_aid.core.validator.dns.asyncresolver.Resolver") as mock_resolver:
            resolver_instance = MagicMock()
            resolver_instance.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())
            mock_resolver.return_value = resolver_instance

            result = await _check_dane("agent.example.com", 443)

            assert result is None

    @pytest.mark.asyncio
    async def test_dane_no_tlsa_no_answer(self):
        """Test no TLSA record - NoAnswer."""
        with patch("dns_aid.core.validator.dns.asyncresolver.Resolver") as mock_resolver:
            resolver_instance = MagicMock()
            resolver_instance.resolve = AsyncMock(side_effect=dns.resolver.NoAnswer())
            mock_resolver.return_value = resolver_instance

            result = await _check_dane("agent.example.com", 443)

            assert result is None

    @pytest.mark.asyncio
    async def test_dane_custom_port(self, mock_tlsa_rdata):
        """Test TLSA lookup with custom port."""
        mock_answers = MagicMock()
        mock_answers.__iter__ = MagicMock(return_value=iter([mock_tlsa_rdata]))

        with patch("dns_aid.core.validator.dns.asyncresolver.Resolver") as mock_resolver:
            resolver_instance = MagicMock()
            resolver_instance.resolve = AsyncMock(return_value=mock_answers)
            mock_resolver.return_value = resolver_instance

            result = await _check_dane("agent.example.com", 8443)

            # Verify the TLSA FQDN format
            resolver_instance.resolve.assert_called_once()
            call_args = resolver_instance.resolve.call_args[0]
            assert call_args[0] == "_8443._tcp.agent.example.com"
            assert result is True


# =============================================================================
# Tests for _check_endpoint()
# =============================================================================


class TestCheckEndpoint:
    """Tests for _check_endpoint function."""

    @pytest.mark.asyncio
    async def test_endpoint_reachable(self):
        """Test reachable endpoint."""
        mock_response = MagicMock()
        mock_response.status_code = 200

        with patch("dns_aid.core.validator.httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_response)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            result = await _check_endpoint("agent.example.com", 443)

            assert result["reachable"] is True
            assert "latency_ms" in result
            assert result["status_code"] == 200

    @pytest.mark.asyncio
    async def test_endpoint_4xx_is_reachable(self):
        """Test 4xx response still counts as reachable."""
        mock_response = MagicMock()
        mock_response.status_code = 404

        with patch("dns_aid.core.validator.httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_response)
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            result = await _check_endpoint("agent.example.com", 443)

            assert result["reachable"] is True

    @pytest.mark.asyncio
    async def test_endpoint_5xx_tries_next_path(self):
        """Test 5xx response tries next path."""
        mock_response_500 = MagicMock()
        mock_response_500.status_code = 500

        mock_response_200 = MagicMock()
        mock_response_200.status_code = 200

        with patch("dns_aid.core.validator.httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            # First path returns 500, second returns 200
            mock_instance.get = AsyncMock(side_effect=[mock_response_500, mock_response_200])
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            result = await _check_endpoint("agent.example.com", 443)

            assert result["reachable"] is True
            assert mock_instance.get.call_count == 2

    @pytest.mark.asyncio
    async def test_endpoint_connection_refused(self):
        """Test connection refused."""
        with patch("dns_aid.core.validator.httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            result = await _check_endpoint("agent.example.com", 443)

            assert result["reachable"] is False

    @pytest.mark.asyncio
    async def test_endpoint_timeout(self):
        """Test endpoint timeout."""
        with patch("dns_aid.core.validator.httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(side_effect=httpx.TimeoutException("Timeout"))
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            result = await _check_endpoint("agent.example.com", 443)

            assert result["reachable"] is False


# =============================================================================
# Tests for verify() - Main entry point
# =============================================================================


class TestVerify:
    """Tests for main verify function."""

    @pytest.mark.asyncio
    async def test_verify_all_checks_pass(self):
        """Test verify with all checks passing."""
        from dns_aid.core.models import DNSSECDetail, TLSDetail

        with (
            patch("dns_aid.core.validator._check_svcb_record") as mock_svcb,
            patch("dns_aid.core.validator._check_dnssec_detail") as mock_dnssec_detail,
            patch("dns_aid.core.validator._check_dane") as mock_dane,
            patch("dns_aid.core.validator._check_endpoint") as mock_endpoint,
            patch("dns_aid.core.validator._check_tls") as mock_tls,
        ):
            mock_svcb.return_value = {
                "target": "agent.example.com",
                "port": 443,
                "valid": True,
            }
            mock_dnssec_detail.return_value = DNSSECDetail(
                validated=True,
                algorithm="ECDSAP256SHA256",
                algorithm_strength="strong",
                ad_flag=True,
            )
            mock_dane.return_value = True
            mock_endpoint.return_value = {"reachable": True, "latency_ms": 50.0}
            mock_tls.return_value = TLSDetail(connected=True, tls_version="TLSv1.3")

            result = await verify("_agent._mcp._agents.example.com")

            assert result.record_exists is True
            assert result.svcb_valid is True
            assert result.dnssec_valid is True
            assert result.dane_valid is True
            assert result.endpoint_reachable is True
            assert result.endpoint_latency_ms == 50.0
            assert result.security_score > 0

    @pytest.mark.asyncio
    async def test_verify_missing_svcb(self):
        """Test verify when SVCB record not found."""
        from dns_aid.core.models import DNSSECDetail

        with (
            patch("dns_aid.core.validator._check_svcb_record") as mock_svcb,
            patch("dns_aid.core.validator._check_dnssec_detail") as mock_dnssec_detail,
            patch("dns_aid.core.validator._check_tls"),
        ):
            mock_svcb.return_value = None
            mock_dnssec_detail.return_value = DNSSECDetail(validated=False)

            result = await verify("_agent._mcp._agents.example.com")

            assert result.record_exists is False
            assert result.svcb_valid is False

    @pytest.mark.asyncio
    async def test_verify_no_dnssec(self):
        """Test verify when DNSSEC not validated."""
        from dns_aid.core.models import DNSSECDetail, TLSDetail

        with (
            patch("dns_aid.core.validator._check_svcb_record") as mock_svcb,
            patch("dns_aid.core.validator._check_dnssec_detail") as mock_dnssec_detail,
            patch("dns_aid.core.validator._check_dane") as mock_dane,
            patch("dns_aid.core.validator._check_endpoint") as mock_endpoint,
            patch("dns_aid.core.validator._check_tls") as mock_tls,
        ):
            mock_svcb.return_value = {
                "target": "agent.example.com",
                "port": 443,
                "valid": True,
            }
            mock_dnssec_detail.return_value = DNSSECDetail(validated=False)
            mock_dane.return_value = None
            mock_endpoint.return_value = {"reachable": True, "latency_ms": 50.0}
            mock_tls.return_value = TLSDetail()

            result = await verify("_agent._mcp._agents.example.com")

            assert result.record_exists is True
            assert result.dnssec_valid is False

    @pytest.mark.asyncio
    async def test_verify_endpoint_unreachable(self):
        """Test verify when endpoint is unreachable."""
        from dns_aid.core.models import DNSSECDetail, TLSDetail

        with (
            patch("dns_aid.core.validator._check_svcb_record") as mock_svcb,
            patch("dns_aid.core.validator._check_dnssec_detail") as mock_dnssec_detail,
            patch("dns_aid.core.validator._check_dane") as mock_dane,
            patch("dns_aid.core.validator._check_endpoint") as mock_endpoint,
            patch("dns_aid.core.validator._check_tls") as mock_tls,
        ):
            mock_svcb.return_value = {
                "target": "agent.example.com",
                "port": 443,
                "valid": True,
            }
            mock_dnssec_detail.return_value = DNSSECDetail(validated=True, ad_flag=True)
            mock_dane.return_value = None
            mock_endpoint.return_value = {"reachable": False}
            mock_tls.return_value = TLSDetail()

            result = await verify("_agent._mcp._agents.example.com")

            assert result.endpoint_reachable is False
            assert result.endpoint_latency_ms is None


# =============================================================================
# Additional coverage tests
# =============================================================================


class TestCheckDaneVerifyCert:
    """Tests for _check_dane with verify_cert=True paths."""

    @pytest.mark.asyncio
    async def test_dane_verify_cert_match(self, mock_tlsa_rdata):
        """DANE with verify_cert=True + cert match → True."""
        mock_answers = MagicMock()
        mock_answers.__iter__ = MagicMock(return_value=iter([mock_tlsa_rdata]))

        with (
            patch("dns_aid.core.validator.dns.asyncresolver.Resolver") as mock_resolver,
            patch(
                "dns_aid.core.validator._match_dane_cert",
                new_callable=AsyncMock,
                return_value=True,
            ),
        ):
            resolver_instance = MagicMock()
            resolver_instance.resolve = AsyncMock(return_value=mock_answers)
            mock_resolver.return_value = resolver_instance

            result = await _check_dane("agent.example.com", 443, verify_cert=True)
            assert result is True

    @pytest.mark.asyncio
    async def test_dane_verify_cert_mismatch(self, mock_tlsa_rdata):
        """DANE with verify_cert=True + cert mismatch → False."""
        mock_answers = MagicMock()
        mock_answers.__iter__ = MagicMock(return_value=iter([mock_tlsa_rdata]))

        with (
            patch("dns_aid.core.validator.dns.asyncresolver.Resolver") as mock_resolver,
            patch(
                "dns_aid.core.validator._match_dane_cert",
                new_callable=AsyncMock,
                return_value=False,
            ),
        ):
            resolver_instance = MagicMock()
            resolver_instance.resolve = AsyncMock(return_value=mock_answers)
            mock_resolver.return_value = resolver_instance

            result = await _check_dane("agent.example.com", 443, verify_cert=True)
            assert result is False

    @pytest.mark.asyncio
    async def test_dane_query_failed(self):
        """Generic exception during TLSA query → None."""
        with patch("dns_aid.core.validator.dns.asyncresolver.Resolver") as mock_resolver:
            resolver_instance = MagicMock()
            resolver_instance.resolve = AsyncMock(side_effect=Exception("network error"))
            mock_resolver.return_value = resolver_instance

            result = await _check_dane("agent.example.com", 443)
            assert result is None


class TestCheckDnssecTxtFallback:
    """Tests for DNSSEC TXT fallback paths."""

    @pytest.mark.asyncio
    async def test_dnssec_txt_fallback_no_ad(self):
        """TXT fallback where AD flag is NOT set → False."""
        mock_response = MagicMock()
        mock_response.flags = 0  # No AD flag

        mock_answer = MagicMock()
        mock_answer.response = mock_response

        with patch("dns_aid.core.validator.dns.asyncresolver.Resolver") as mock_resolver:
            resolver_instance = MagicMock()
            resolver_instance.use_edns = MagicMock()
            # SVCB → NoAnswer, TXT → answer without AD
            resolver_instance.resolve = AsyncMock(
                side_effect=[dns.resolver.NoAnswer(), mock_answer]
            )
            mock_resolver.return_value = resolver_instance

            result = await _check_dnssec("_agent._mcp._agents.example.com")
            assert result is False

    @pytest.mark.asyncio
    async def test_dnssec_txt_fallback_exception(self):
        """TXT fallback raises exception → False."""
        with patch("dns_aid.core.validator.dns.asyncresolver.Resolver") as mock_resolver:
            resolver_instance = MagicMock()
            resolver_instance.use_edns = MagicMock()
            # SVCB → NoAnswer, TXT → Exception
            resolver_instance.resolve = AsyncMock(
                side_effect=[dns.resolver.NoAnswer(), Exception("TXT fail")]
            )
            mock_resolver.return_value = resolver_instance

            result = await _check_dnssec("_agent._mcp._agents.example.com")
            assert result is False


class TestCheckEndpointErrors:
    """Tests for _check_endpoint error paths."""

    @pytest.mark.asyncio
    async def test_endpoint_generic_error(self):
        """Generic Exception during endpoint check → not reachable."""
        with patch("dns_aid.core.validator.httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(side_effect=Exception("unexpected"))
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=None)
            mock_client.return_value = mock_instance

            result = await _check_endpoint("agent.example.com", 443)
            assert result["reachable"] is False
