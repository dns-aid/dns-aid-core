# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Mock integration tests — Tier A (always runs in CI, no credentials needed).

Exercises full publish → discover → verify flows with mocked DNS/HTTP.
The MockDNSBridge (from conftest.py) translates MockBackend's in-memory
records into dnspython and httpx mock responses.
"""

from __future__ import annotations

import base64
import hashlib
import json

import pytest

import dns_aid
from dns_aid import DNSSECError
from dns_aid.backends.mock import MockBackend
from tests.integration.conftest import MockDNSBridge

# ── Scenario A: Full Lifecycle ─────────────────────────────────────────


class TestFullLifecycle:
    """Publish → discover → verify → unpublish → verify-gone."""

    async def test_full_publish_discover_verify_unpublish(
        self,
        mock_backend: MockBackend,
        dns_bridge: MockDNSBridge,
    ):
        # 1. Publish
        result = await dns_aid.publish(
            name="network",
            domain="example.com",
            protocol="mcp",
            endpoint="mcp.example.com",
            capabilities=["ipam", "dns"],
            backend=mock_backend,
        )
        assert result.success

        # 2. Configure bridge for discover/verify
        dns_bridge.set_endpoint_reachable("mcp.example.com")

        with dns_bridge.patch_all():
            # 3. Discover
            discovery = await dns_aid.discover(
                "example.com",
                protocol="mcp",
                name="network",
                enrich_endpoints=False,
            )
            assert discovery.count == 1
            agent = discovery.agents[0]
            assert agent.name == "network"
            assert agent.target_host == "mcp.example.com"
            assert agent.capabilities == ["ipam", "dns"]
            assert agent.capability_source == "txt_fallback"

            # 4. Verify
            verify = await dns_aid.verify(agent.fqdn)
            assert verify.record_exists
            assert verify.svcb_valid
            assert verify.endpoint_reachable
            # record(20) + svcb(20) + endpoint(15) = 55
            assert verify.security_score >= 55

        # 5. Unpublish
        await dns_aid.unpublish(
            name="network",
            domain="example.com",
            protocol="mcp",
            backend=mock_backend,
        )

        # 6. Verify gone
        with dns_bridge.patch_all():
            verify = await dns_aid.verify(agent.fqdn)
            assert not verify.record_exists
            assert verify.security_score == 0


# ── Scenario B: Multi-Protocol ─────────────────────────────────────────


class TestMultiProtocol:
    """Publish MCP + A2A agents, discover each by protocol."""

    async def test_discover_mcp_agent(
        self,
        mock_backend: MockBackend,
        dns_bridge: MockDNSBridge,
    ):
        await dns_aid.publish(
            name="network",
            domain="example.com",
            protocol="mcp",
            endpoint="mcp.example.com",
            capabilities=["ipam"],
            backend=mock_backend,
        )
        await dns_aid.publish(
            name="chat",
            domain="example.com",
            protocol="a2a",
            endpoint="chat.example.com",
            capabilities=["assistant"],
            backend=mock_backend,
        )

        with dns_bridge.patch_all():
            result = await dns_aid.discover(
                "example.com",
                protocol="mcp",
                name="network",
                enrich_endpoints=False,
            )
            assert result.count == 1
            assert result.agents[0].protocol.value == "mcp"
            assert result.agents[0].name == "network"

    async def test_discover_a2a_agent(
        self,
        mock_backend: MockBackend,
        dns_bridge: MockDNSBridge,
    ):
        await dns_aid.publish(
            name="chat",
            domain="example.com",
            protocol="a2a",
            endpoint="chat.example.com",
            capabilities=["assistant"],
            backend=mock_backend,
        )

        with dns_bridge.patch_all():
            result = await dns_aid.discover(
                "example.com",
                protocol="a2a",
                name="chat",
                enrich_endpoints=False,
            )
            assert result.count == 1
            assert result.agents[0].protocol.value == "a2a"
            assert result.agents[0].name == "chat"


# ── Scenario C: Capability Document ────────────────────────────────────


class TestCapabilityDocumentFlow:
    """Cap URI enrichment, SHA-256 match, SHA-256 mismatch → TXT fallback."""

    @pytest.fixture
    def cap_data(self) -> dict:
        return {
            "capabilities": ["travel", "booking", "calendar"],
            "version": "2.0.0",
            "description": "Travel booking agent",
        }

    @pytest.fixture
    def cap_uri(self) -> str:
        return "https://cap.example.com/agent-cap.json"

    async def test_cap_uri_enrichment(
        self,
        mock_backend: MockBackend,
        dns_bridge: MockDNSBridge,
        cap_data: dict,
        cap_uri: str,
    ):
        """Cap URI present → capabilities come from the document, not TXT."""
        await dns_aid.publish(
            name="travel",
            domain="example.com",
            protocol="mcp",
            endpoint="mcp.example.com",
            capabilities=["fallback-cap"],
            cap_uri=cap_uri,
            backend=mock_backend,
        )

        dns_bridge.set_cap_document(cap_uri, cap_data)

        with dns_bridge.patch_all():
            result = await dns_aid.discover(
                "example.com",
                protocol="mcp",
                name="travel",
                enrich_endpoints=False,
            )
            assert result.count == 1
            agent = result.agents[0]
            assert agent.capability_source == "cap_uri"
            assert "travel" in agent.capabilities
            assert "booking" in agent.capabilities

    async def test_cap_sha256_match(
        self,
        mock_backend: MockBackend,
        dns_bridge: MockDNSBridge,
        cap_data: dict,
        cap_uri: str,
    ):
        """Matching cap_sha256 → capabilities accepted."""
        # Compute the actual SHA-256 of the serialized JSON bytes
        raw_bytes = json.dumps(cap_data, separators=(",", ":"), sort_keys=True).encode()
        expected_sha256 = (
            base64.urlsafe_b64encode(hashlib.sha256(raw_bytes).digest())
            .rstrip(b"=")
            .decode("ascii")
        )

        await dns_aid.publish(
            name="travel",
            domain="example.com",
            protocol="mcp",
            endpoint="mcp.example.com",
            capabilities=["fallback-cap"],
            cap_uri=cap_uri,
            cap_sha256=expected_sha256,
            backend=mock_backend,
        )

        dns_bridge.set_cap_document(cap_uri, cap_data)

        with dns_bridge.patch_all():
            result = await dns_aid.discover(
                "example.com",
                protocol="mcp",
                name="travel",
                enrich_endpoints=False,
            )
            agent = result.agents[0]
            assert agent.capability_source == "cap_uri"
            assert agent.capabilities == ["travel", "booking", "calendar"]

    async def test_cap_sha256_mismatch_falls_back_to_txt(
        self,
        mock_backend: MockBackend,
        dns_bridge: MockDNSBridge,
        cap_data: dict,
        cap_uri: str,
    ):
        """Wrong cap_sha256 → cap doc rejected → falls back to TXT capabilities."""
        await dns_aid.publish(
            name="travel",
            domain="example.com",
            protocol="mcp",
            endpoint="mcp.example.com",
            capabilities=["fallback-cap"],
            cap_uri=cap_uri,
            cap_sha256="WRONG_HASH_VALUE",
            backend=mock_backend,
        )

        dns_bridge.set_cap_document(cap_uri, cap_data)

        with dns_bridge.patch_all():
            result = await dns_aid.discover(
                "example.com",
                protocol="mcp",
                name="travel",
                enrich_endpoints=False,
            )
            agent = result.agents[0]
            # SHA-256 mismatch → cap doc rejected → TXT fallback
            assert agent.capability_source == "txt_fallback"
            assert agent.capabilities == ["fallback-cap"]


# ── Scenario D: HTTP Index Discovery ───────────────────────────────────


class TestHttpIndexDiscovery:
    """Discover via HTTP index (use_http_index=True)."""

    async def test_http_index_discovery(
        self,
        mock_backend: MockBackend,
        dns_bridge: MockDNSBridge,
    ):
        # Publish the agent so DNS SVCB resolution works
        await dns_aid.publish(
            name="network",
            domain="example.com",
            protocol="mcp",
            endpoint="mcp.example.com",
            capabilities=["ipam", "dns"],
            backend=mock_backend,
        )

        # Register HTTP index data (stakeholder JSON format)
        dns_bridge.set_http_index(
            "example.com",
            {
                "agents": {
                    "network": {
                        "location": {
                            "fqdn": "_network._mcp._agents.example.com",
                            "endpoint": "https://mcp.example.com/mcp",
                        },
                        "model-card": {
                            "description": "Network management agent",
                        },
                        "capability": {
                            "modality": "text",
                            "protocols": ["mcp"],
                        },
                    }
                }
            },
        )

        with dns_bridge.patch_all():
            result = await dns_aid.discover(
                "example.com",
                protocol="mcp",
                use_http_index=True,
                enrich_endpoints=False,
            )
            assert result.count >= 1
            agent = result.agents[0]
            assert agent.name == "network"
            assert agent.target_host == "mcp.example.com"


# ── Scenario E: Security Scoring ───────────────────────────────────────


class TestSecurityScoring:
    """Verify security_score under different conditions."""

    async def test_excellent_score(
        self,
        mock_backend: MockBackend,
        dns_bridge: MockDNSBridge,
    ):
        """All checks pass → score 100 (Excellent)."""
        await dns_aid.publish(
            name="secure",
            domain="example.com",
            protocol="mcp",
            endpoint="mcp.example.com",
            capabilities=["ipam"],
            backend=mock_backend,
        )

        dns_bridge.enable_dnssec("example.com")
        dns_bridge.add_tlsa_record("mcp.example.com", 443)
        dns_bridge.set_endpoint_reachable("mcp.example.com")

        with dns_bridge.patch_all():
            verify = await dns_aid.verify("_secure._mcp._agents.example.com")
            assert verify.record_exists
            assert verify.svcb_valid
            assert verify.dnssec_valid
            assert verify.dane_valid
            assert verify.endpoint_reachable
            assert verify.security_score == 100
            assert verify.security_rating == "Excellent"

    async def test_poor_score(
        self,
        mock_backend: MockBackend,
        dns_bridge: MockDNSBridge,
    ):
        """Record + SVCB only, no DNSSEC/DANE/endpoint → score 40 (Poor)."""
        await dns_aid.publish(
            name="basic",
            domain="example.com",
            protocol="mcp",
            endpoint="mcp.example.com",
            capabilities=["ipam"],
            backend=mock_backend,
        )

        with dns_bridge.patch_all():
            verify = await dns_aid.verify("_basic._mcp._agents.example.com")
            assert verify.record_exists
            assert verify.svcb_valid
            assert not verify.dnssec_valid
            assert not verify.endpoint_reachable
            assert verify.security_score == 40
            assert verify.security_rating == "Poor"

    async def test_nonexistent_agent_score(
        self,
        mock_backend: MockBackend,
        dns_bridge: MockDNSBridge,
    ):
        """Agent doesn't exist → score 0."""
        with dns_bridge.patch_all():
            verify = await dns_aid.verify("_ghost._mcp._agents.example.com")
            assert not verify.record_exists
            assert verify.security_score == 0


# ── Scenario F: DNS-AID Params Roundtrip ───────────────────────────────


class TestDnsaidParamsRoundtrip:
    """Publish with DNS-AID custom params → discover retrieves them."""

    async def test_full_dnsaid_params(
        self,
        mock_backend: MockBackend,
        dns_bridge: MockDNSBridge,
    ):
        """All 6 DNS-AID params round-trip through SVCB keyNNNNN encoding."""
        await dns_aid.publish(
            name="rich",
            domain="example.com",
            protocol="mcp",
            endpoint="mcp.example.com",
            capabilities=["ipam"],
            cap_uri="https://cap.example.com/rich.json",
            cap_sha256="abc123",
            bap=["mcp", "a2a"],
            policy_uri="https://example.com/policy",
            realm="demo",
            backend=mock_backend,
        )

        # Cap document not set → cap_fetcher returns None → TXT fallback
        with dns_bridge.patch_all():
            result = await dns_aid.discover(
                "example.com",
                protocol="mcp",
                name="rich",
                enrich_endpoints=False,
            )
            agent = result.agents[0]
            assert agent.cap_uri == "https://cap.example.com/rich.json"
            assert agent.cap_sha256 == "abc123"
            assert agent.bap == ["mcp", "a2a"]
            assert agent.policy_uri == "https://example.com/policy"
            assert agent.realm == "demo"

    async def test_partial_dnsaid_params(
        self,
        mock_backend: MockBackend,
        dns_bridge: MockDNSBridge,
    ):
        """Only cap_uri + realm → other params absent."""
        await dns_aid.publish(
            name="partial",
            domain="example.com",
            protocol="mcp",
            endpoint="mcp.example.com",
            capabilities=["dns"],
            cap_uri="https://cap.example.com/partial.json",
            realm="staging",
            backend=mock_backend,
        )

        with dns_bridge.patch_all():
            result = await dns_aid.discover(
                "example.com",
                protocol="mcp",
                name="partial",
                enrich_endpoints=False,
            )
            agent = result.agents[0]
            assert agent.cap_uri == "https://cap.example.com/partial.json"
            assert agent.realm == "staging"
            assert agent.cap_sha256 is None
            assert agent.bap == []
            assert agent.policy_uri is None


# ── Scenario G: Unpublish Negative ─────────────────────────────────────


class TestUnpublishNegative:
    """Unpublish makes agent undiscoverable."""

    async def test_unpublish_makes_agent_undiscoverable(
        self,
        mock_backend: MockBackend,
        dns_bridge: MockDNSBridge,
    ):
        # Publish
        await dns_aid.publish(
            name="temp",
            domain="example.com",
            protocol="mcp",
            endpoint="mcp.example.com",
            capabilities=["ipam"],
            backend=mock_backend,
        )

        # Confirm discoverable
        with dns_bridge.patch_all():
            result = await dns_aid.discover(
                "example.com",
                protocol="mcp",
                name="temp",
                enrich_endpoints=False,
            )
            assert result.count == 1

        # Unpublish
        await dns_aid.unpublish(
            name="temp",
            domain="example.com",
            protocol="mcp",
            backend=mock_backend,
        )

        # Confirm undiscoverable
        with dns_bridge.patch_all():
            result = await dns_aid.discover(
                "example.com",
                protocol="mcp",
                name="temp",
                enrich_endpoints=False,
            )
            assert result.count == 0


# ── Scenario H: DNSSEC Enforcement ────────────────────────────────────


class TestDNSSECEnforcement:
    """require_dnssec=True raises DNSSECError when AD flag is absent."""

    async def test_require_dnssec_raises_when_unsigned(
        self,
        mock_backend: MockBackend,
        dns_bridge: MockDNSBridge,
    ):
        """Publish without DNSSEC → discover(require_dnssec=True) → DNSSECError."""
        await dns_aid.publish(
            name="unsigned",
            domain="example.com",
            protocol="mcp",
            endpoint="mcp.example.com",
            capabilities=["ipam"],
            backend=mock_backend,
        )

        with dns_bridge.patch_all():
            with pytest.raises(DNSSECError):
                await dns_aid.discover(
                    "example.com",
                    protocol="mcp",
                    name="unsigned",
                    require_dnssec=True,
                    enrich_endpoints=False,
                )

    async def test_require_dnssec_passes_when_signed(
        self,
        mock_backend: MockBackend,
        dns_bridge: MockDNSBridge,
    ):
        """Publish + enable_dnssec → discover(require_dnssec=True) → succeeds."""
        await dns_aid.publish(
            name="signed",
            domain="example.com",
            protocol="mcp",
            endpoint="mcp.example.com",
            capabilities=["ipam"],
            backend=mock_backend,
        )

        dns_bridge.enable_dnssec("example.com")

        with dns_bridge.patch_all():
            result = await dns_aid.discover(
                "example.com",
                protocol="mcp",
                name="signed",
                require_dnssec=True,
                enrich_endpoints=False,
            )
            assert result.count == 1
            assert result.dnssec_validated is True
            assert result.agents[0].name == "signed"


# ── Scenario I: DANE Certificate Matching ─────────────────────────────


class TestDANECertMatching:
    """Default DANE behavior unchanged (TLSA existence only)."""

    async def test_dane_advisory_default(
        self,
        mock_backend: MockBackend,
        dns_bridge: MockDNSBridge,
    ):
        """Default verify() → dane_valid=True when TLSA exists (no cert matching)."""
        await dns_aid.publish(
            name="dane-test",
            domain="example.com",
            protocol="mcp",
            endpoint="mcp.example.com",
            capabilities=["ipam"],
            backend=mock_backend,
        )

        dns_bridge.add_tlsa_record("mcp.example.com", 443)
        dns_bridge.set_endpoint_reachable("mcp.example.com")

        with dns_bridge.patch_all():
            verify = await dns_aid.verify("_dane-test._mcp._agents.example.com")
            assert verify.record_exists
            assert verify.svcb_valid
            assert verify.dane_valid is True
            # Confirm default note mentions advisory (no full cert matching)
            assert "advisory" in verify.dane_note.lower()
