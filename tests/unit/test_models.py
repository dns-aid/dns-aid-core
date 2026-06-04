# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for DNS-AID data models."""

import pytest
from pydantic import ValidationError

from dns_aid.core.models import AgentRecord, DiscoveryResult, Protocol, SvcbRecord, VerifyResult


class TestAgentRecord:
    """Tests for AgentRecord model."""

    def test_create_basic_agent(self):
        """Test creating a basic agent record."""
        agent = AgentRecord(
            name="chat",
            domain="example.com",
            protocol=Protocol.A2A,
            target_host="chat.example.com",
        )

        assert agent.name == "chat"
        assert agent.domain == "example.com"
        assert agent.protocol == Protocol.A2A
        assert agent.target_host == "chat.example.com"
        assert agent.port == 443  # default

    def test_endpoint_source_directory(self):
        """Test endpoint_source accepts 'directory' (Phase 5.7)."""
        agent = AgentRecord(
            name="search",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="mcp.example.com",
            endpoint_source="directory",
        )
        assert agent.endpoint_source == "directory"

    def test_endpoint_source_all_values(self):
        """Test all endpoint_source Literal values are accepted."""
        valid_sources = [
            "dns_svcb",
            "dns_svcb_enriched",
            "http_index",
            "http_index_fallback",
            "direct",
            "directory",
        ]
        for source in valid_sources:
            agent = AgentRecord(
                name="test",
                domain="example.com",
                protocol=Protocol.MCP,
                target_host="mcp.example.com",
                endpoint_source=source,
            )
            assert agent.endpoint_source == source

    def test_fqdn_generation(self):
        """Test FQDN is generated as the flat draft-02 form."""
        agent = AgentRecord(
            name="network-specialist",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="mcp.example.com",
        )

        # Flat draft-02 form: {name}.{domain}
        assert agent.fqdn == "network-specialist.example.com"

    def test_walkable_fqdn_generation(self):
        """The walkable AliasMode form uses the _agents leaf."""
        agent = AgentRecord(
            name="network-specialist",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="mcp.example.com",
        )
        assert agent.walkable_fqdn == "network-specialist._agents.example.com"

    def test_legacy_fqdn_generation(self):
        """The legacy -01 form is retained for the legacy-fallback discovery path."""
        agent = AgentRecord(
            name="network-specialist",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="mcp.example.com",
        )
        assert agent.legacy_fqdn == "_network-specialist._mcp._agents.example.com"

    def test_endpoint_url(self):
        """Test endpoint URL generation."""
        agent = AgentRecord(
            name="chat",
            domain="example.com",
            protocol=Protocol.A2A,
            target_host="chat.example.com",
            port=8443,
        )

        assert agent.endpoint_url == "https://chat.example.com:8443"

    def test_svcb_target(self):
        """Test SVCB target has trailing dot."""
        agent = AgentRecord(
            name="chat",
            domain="example.com",
            protocol=Protocol.A2A,
            target_host="chat.example.com",
        )

        assert agent.svcb_target == "chat.example.com."

    def test_svcb_params(self):
        """Test SVCB parameters generation."""
        agent = AgentRecord(
            name="chat",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="mcp.example.com",
            port=8443,
            ipv4_hint="192.0.2.1",
        )

        params = agent.to_svcb_params()

        assert params["alpn"] == "mcp"
        assert params["port"] == "8443"
        assert params["ipv4hint"] == "192.0.2.1"
        # DNS-AID compliance: mandatory param must be set
        assert params["mandatory"] == "alpn,port"

    def test_svcb_params_with_dnsaid_custom_params_keynnnnn(self):
        """Test SVCB params emit keyNNNNN format by default."""
        agent = AgentRecord(
            name="booking",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="mcp.example.com",
            cap_uri="https://mcp.example.com/.well-known/agent-cap.json",
            cap_sha256="abc123base64url",
            bap="mcp=2.1",
            policy_uri="https://example.com/agent-policy",
            realm="production",
        )

        params = agent.to_svcb_params()

        # Default: keyNNNNN format per RFC 9460
        assert params["key65400"] == "https://mcp.example.com/.well-known/agent-cap.json"
        assert params["key65401"] == "abc123base64url"
        assert params["key65402"] == "mcp=2.1"  # scalar bap per draft-02 §FutureWork
        assert params["key65403"] == "https://example.com/agent-policy"
        assert params["key65404"] == "production"
        # Standard params still present
        assert params["alpn"] == "mcp"
        assert params["port"] == "443"

    def test_svcb_params_with_dnsaid_custom_params_string_keys(self):
        """Test SVCB params emit string names when DNS_AID_SVCB_STRING_KEYS=1."""
        import os
        from unittest.mock import patch

        agent = AgentRecord(
            name="booking",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="mcp.example.com",
            cap_uri="https://mcp.example.com/.well-known/agent-cap.json",
            cap_sha256="abc123base64url",
            bap="mcp=2.1",
            policy_uri="https://example.com/agent-policy",
            realm="production",
        )

        with patch.dict(os.environ, {"DNS_AID_SVCB_STRING_KEYS": "1"}):
            params = agent.to_svcb_params()

        assert params["cap"] == "https://mcp.example.com/.well-known/agent-cap.json"
        assert params["cap-sha256"] == "abc123base64url"
        assert params["bap"] == "mcp=2.1"
        assert params["policy"] == "https://example.com/agent-policy"
        assert params["realm"] == "production"

    def test_svcb_params_without_dnsaid_params(self):
        """Test SVCB params exclude DNS-AID custom params when None/empty."""
        agent = AgentRecord(
            name="chat",
            domain="example.com",
            protocol=Protocol.A2A,
            target_host="chat.example.com",
        )

        params = agent.to_svcb_params()

        assert "cap" not in params
        assert "cap-sha256" not in params
        assert "bap" not in params
        assert "policy" not in params
        assert "realm" not in params
        # Standard params present
        assert params["alpn"] == "a2a"
        assert params["port"] == "443"

    def test_svcb_params_partial_dnsaid_params(self):
        """Test SVCB params with only some DNS-AID params set."""
        agent = AgentRecord(
            name="booking",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="mcp.example.com",
            cap_uri="https://mcp.example.com/.well-known/agent-cap.json",
            realm="demo",
            # cap_sha256, bap, and policy_uri not set
        )

        params = agent.to_svcb_params()

        # Default: keyNNNNN format
        assert params["key65400"] == "https://mcp.example.com/.well-known/agent-cap.json"
        assert params["key65404"] == "demo"
        assert "key65401" not in params
        assert "key65402" not in params
        assert "key65403" not in params

    def test_svcb_params_cap_sha256_without_cap_uri(self):
        """Test cap-sha256 can be set independently (unlikely but valid)."""
        agent = AgentRecord(
            name="booking",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="mcp.example.com",
            cap_sha256="dGVzdGhhc2g",
        )

        params = agent.to_svcb_params()

        assert params["key65401"] == "dGVzdGhhc2g"
        assert "key65400" not in params

    def test_svcb_params_bap_emits_as_scalar(self):
        """draft-02 §FutureWork: bap is a single versioned protocol per record."""
        agent = AgentRecord(
            name="booking",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="mcp.example.com",
            bap="mcp=2.1",
        )
        params = agent.to_svcb_params()
        # No comma, no list — emitted exactly as the scalar string.
        assert params["key65402"] == "mcp=2.1"
        assert "," not in params["key65402"]

    def test_svcb_params_bap_absent_when_none(self):
        """When bap is unset (None) the key65402 param is not emitted."""
        agent = AgentRecord(
            name="booking",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="mcp.example.com",
        )
        params = agent.to_svcb_params()
        assert "key65402" not in params
        assert "bap" not in params

    def test_svcb_params_with_well_known_path(self):
        """Test draft-02 ``well-known`` SvcParamKey is emitted at the
        project's interim private-use code point ``key65409``.

        Per draft section 7.1 the actual SvcParamKey numbers are
        deferred to IANA (Standards Action); 65409 is dns-aid-core's
        private-use placeholder, not draft-assigned."""
        agent = AgentRecord(
            name="booking",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="mcp.example.com",
            well_known_path="agent-card.json",
        )

        params = agent.to_svcb_params()

        assert params["key65409"] == "agent-card.json"

    def test_svcb_params_well_known_independent_of_cap(self):
        """`well-known` and `cap` are independent keys; both may be present."""
        agent = AgentRecord(
            name="booking",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="mcp.example.com",
            cap_uri="urn:example:agent-cap:abc",
            cap_sha256="dGVzdGhhc2g",
            well_known_path="agent-card.json",
        )

        params = agent.to_svcb_params()

        # All three SvcParamKeys present, none collapsing into another.
        assert params["key65400"] == "urn:example:agent-cap:abc"
        assert params["key65401"] == "dGVzdGhhc2g"
        assert params["key65409"] == "agent-card.json"

    def test_svcb_params_with_connect_fields(self):
        """Test provider-managed connection params are serialized as SVCB custom keys."""
        agent = AgentRecord(
            name="lattice-agent",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="service.internal",
            connect_class="lattice",
            connect_meta="arn:aws:vpc-lattice:us-east-1:123456789012:service/svc-123",
            enroll_uri="https://service.internal/.well-known/agent-connect",
        )

        params = agent.to_svcb_params()

        assert params["key65406"] == "lattice"
        assert params["key65407"] == "arn:aws:vpc-lattice:us-east-1:123456789012:service/svc-123"
        assert params["key65408"] == "https://service.internal/.well-known/agent-connect"

    def test_ttl_allows_30_seconds(self):
        """Dynamic publishers need a 30 second TTL floor."""
        agent = AgentRecord(
            name="fast-agent",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="fast.example.com",
            ttl=30,
        )
        assert agent.ttl == 30

    def test_connect_fields_have_length_bounds(self):
        """Connection metadata is bounded to avoid oversized records."""
        with pytest.raises(ValidationError):
            AgentRecord(
                name="bounded-agent",
                domain="example.com",
                protocol=Protocol.MCP,
                target_host="mcp.example.com",
                connect_meta="x" * 2049,
            )

    def test_txt_values(self):
        """Test TXT record values generation."""
        agent = AgentRecord(
            name="network",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="mcp.example.com",
            capabilities=["ipam", "dns", "vpn"],
            version="2.0.0",
            description="Network agent",
        )

        values = agent.to_txt_values()

        assert "capabilities=ipam,dns,vpn" in values
        assert "version=2.0.0" in values
        assert "description=Network agent" in values

    def test_name_validation_lowercase(self):
        """Test that name is normalized to lowercase."""
        agent = AgentRecord(
            name="MyAgent",
            domain="example.com",
            protocol=Protocol.A2A,
            target_host="agent.example.com",
        )

        assert agent.name == "myagent"

    def test_domain_validation_removes_trailing_dot(self):
        """Test that domain removes trailing dot."""
        agent = AgentRecord(
            name="chat",
            domain="example.com.",
            protocol=Protocol.A2A,
            target_host="chat.example.com",
        )

        assert agent.domain == "example.com"

    def test_invalid_name_rejected(self):
        """Test that invalid DNS label names are rejected."""
        with pytest.raises(ValidationError):
            AgentRecord(
                name="invalid_name",  # Underscores not allowed in DNS labels
                domain="example.com",
                protocol=Protocol.A2A,
                target_host="agent.example.com",
            )

    def test_invalid_port_rejected(self):
        """Test that invalid port numbers are rejected."""
        with pytest.raises(ValidationError):
            AgentRecord(
                name="chat",
                domain="example.com",
                protocol=Protocol.A2A,
                target_host="chat.example.com",
                port=70000,  # Invalid port
            )


class TestProtocol:
    """Tests for Protocol enum."""

    def test_protocol_values(self):
        """Test protocol enum values."""
        assert Protocol.A2A.value == "a2a"
        assert Protocol.MCP.value == "mcp"
        assert Protocol.HTTPS.value == "https"

    def test_protocol_from_string(self):
        """Test creating protocol from string."""
        assert Protocol("a2a") == Protocol.A2A
        assert Protocol("mcp") == Protocol.MCP


class TestSvcbRecord:
    """Tests for the shared SvcbRecord helper."""

    def test_to_params_with_connect_class_variants(self):
        direct = SvcbRecord(target="direct.example.com", alpn="mcp", connect_class="direct")
        lattice = SvcbRecord(target="lattice.example.com", alpn="mcp", connect_class="lattice")
        apphub = SvcbRecord(target="psc.example.com", alpn="mcp", connect_class="apphub-psc")

        assert direct.to_params()["key65406"] == "direct"
        assert lattice.to_params()["key65406"] == "lattice"
        assert apphub.to_params()["key65406"] == "apphub-psc"

    def test_to_params_with_string_keys(self):
        import os
        from unittest.mock import patch

        record = SvcbRecord(
            target="psc.example.com",
            alpn="mcp",
            connect_class="apphub-psc",
            connect_meta="projects/test/locations/us/discoveredServices/123",
            enroll_uri="https://psc.example.com/.well-known/agent-connect",
        )

        with patch.dict(os.environ, {"DNS_AID_SVCB_STRING_KEYS": "1"}):
            params = record.to_params()

        assert params["connect-class"] == "apphub-psc"
        assert params["connect-meta"] == "projects/test/locations/us/discoveredServices/123"
        assert params["enroll-uri"] == "https://psc.example.com/.well-known/agent-connect"

    def test_connect_class_uses_shared_normalization(self):
        record = SvcbRecord(target="svc.example.com", alpn="mcp", connect_class=" LATTICE ")
        assert record.connect_class == "lattice"

    def test_normalized_target_adds_trailing_dot(self):
        record = SvcbRecord(target="svc.example.com", alpn="mcp")
        assert record.normalized_target == "svc.example.com."


class TestDiscoveryResult:
    """Tests for DiscoveryResult model."""

    def test_count_property(self):
        """Test agents count property."""
        result = DiscoveryResult(
            query="_index._agents.example.com",
            domain="example.com",
            agents=[],
        )

        assert result.count == 0

    def test_with_agents(self, sample_agent):
        """Test discovery result with agents."""
        result = DiscoveryResult(
            query="_index._agents.example.com",
            domain="example.com",
            agents=[sample_agent],
            dnssec_validated=True,
            query_time_ms=45.5,
        )

        assert result.count == 1
        assert result.dnssec_validated is True
        assert result.query_time_ms == 45.5


class TestVerifyResult:
    """Tests for VerifyResult model."""

    def test_security_score_all_pass(self):
        """Test security score when all checks pass."""
        result = VerifyResult(
            fqdn="_chat._a2a._agents.example.com",
            record_exists=True,
            svcb_valid=True,
            dnssec_valid=True,
            dane_valid=True,
            endpoint_reachable=True,
        )

        assert result.security_score == 100
        assert result.security_rating == "Excellent"

    def test_security_score_no_dane(self):
        """Test security score without DANE."""
        result = VerifyResult(
            fqdn="_chat._a2a._agents.example.com",
            record_exists=True,
            svcb_valid=True,
            dnssec_valid=True,
            dane_valid=False,  # No DANE
            endpoint_reachable=True,
        )

        assert result.security_score == 85
        assert result.security_rating == "Excellent"

    def test_security_score_minimal(self):
        """Test security score with minimal checks."""
        result = VerifyResult(
            fqdn="_chat._a2a._agents.example.com",
            record_exists=True,
            svcb_valid=False,
        )

        assert result.security_score == 20
        assert result.security_rating == "Poor"

    def test_dane_without_dnssec_does_not_score(self):
        """DANE +15 must be gated on DNSSEC.

        A spoofer with no DNSSEC chain can still serve a TLSA record;
        TLSA without DNSSEC has no integrity guarantee (RFC 6698 §10.1).
        If a hand-built VerifyResult carries dane_valid=True but
        dnssec_valid=False, security_score MUST NOT credit the DANE
        bonus — otherwise a non-DNSSEC spoofer can reach ``Good``.
        """
        result = VerifyResult(
            fqdn="chat.example.com",
            record_exists=True,
            svcb_valid=True,
            dnssec_valid=False,  # NOT validated
            dane_valid=True,  # claims TLSA present
            endpoint_reachable=True,
        )

        # 20 (record) + 20 (svcb) + 0 (dnssec) + 0 (dane gated) + 15 (endpoint)
        assert result.security_score == 55
        assert result.security_rating == "Fair"


class TestBapValidator:
    """Regression tests for Igor's #158 review.

    The ``bap`` SvcParamKey value goes straight onto the wire as
    ``key65402="<value>"`` via the publisher and every backend formatter.
    Without a field-validator a crafted value can inject sibling
    SvcParamKeys (e.g. ``mcp" key65500="x``) — a multi-tenant publish
    path turns into server-side param injection. The validator now
    constrains bap to the canonical draft-02 form at the type boundary
    so every construction path (direct, ``to_svcb_record()``, MCP,
    CLI) inherits the rule.
    """

    def test_bare_protocol_accepted(self):
        agent = AgentRecord(
            name="chat",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="chat.example.com",
            bap="mcp",
        )
        assert agent.bap == "mcp"

    def test_versioned_form_accepted(self):
        for value in ("mcp=1.0", "a2a=1.1", "https=2"):
            agent = AgentRecord(
                name="chat",
                domain="example.com",
                protocol=Protocol.MCP,
                target_host="chat.example.com",
                bap=value,
            )
            assert agent.bap == value

    def test_svcparam_injection_rejected(self):
        """The original vulnerability: a crafted value with a quote
        escape can be parsed by dnspython as two SvcParamKeys, the
        second one attacker-controlled."""
        for evil in (
            'mcp" key65500="x',
            'mcp\\"',
            'mcp" key65500="x',
        ):
            with pytest.raises(ValidationError):
                AgentRecord(
                    name="chat",
                    domain="example.com",
                    protocol=Protocol.MCP,
                    target_host="chat.example.com",
                    bap=evil,
                )

    def test_legacy_comma_list_rejected(self):
        """Pre-draft-02 comma-list (``mcp,a2a``) is rejected at the
        type — callers passing legacy input should run
        ``normalize_bap`` first."""
        with pytest.raises(ValidationError):
            AgentRecord(
                name="chat",
                domain="example.com",
                protocol=Protocol.MCP,
                target_host="chat.example.com",
                bap="mcp,a2a",
            )

    def test_list_form_rejected_on_agent_record(self):
        """Pin the breaking change direction: ``bap=["mcp"]`` raises."""
        with pytest.raises(ValidationError):
            AgentRecord(
                name="chat",
                domain="example.com",
                protocol=Protocol.MCP,
                target_host="chat.example.com",
                bap=["mcp"],  # type: ignore[arg-type]
            )

    def test_list_form_rejected_on_svcb_record(self):
        from dns_aid.core.models import SvcbRecord

        with pytest.raises(ValidationError):
            SvcbRecord(
                target="chat.example.com.",
                alpn="mcp",
                port=443,
                bap=["mcp"],  # type: ignore[arg-type]
            )

    def test_uppercase_protocol_rejected(self):
        with pytest.raises(ValidationError):
            AgentRecord(
                name="chat",
                domain="example.com",
                protocol=Protocol.MCP,
                target_host="chat.example.com",
                bap="MCP",
            )

    def test_whitespace_in_value_rejected(self):
        with pytest.raises(ValidationError):
            AgentRecord(
                name="chat",
                domain="example.com",
                protocol=Protocol.MCP,
                target_host="chat.example.com",
                bap="mcp 1.0",
            )

    def test_empty_string_passed_as_bap_rejected(self):
        with pytest.raises(ValidationError):
            AgentRecord(
                name="chat",
                domain="example.com",
                protocol=Protocol.MCP,
                target_host="chat.example.com",
                bap="",
            )


class TestNormalizeBap:
    """Tests for the shared ``normalize_bap`` collapse helper.

    The discoverer, SDK adapter, and indexer all route through this
    one function so they agree on edge inputs (empty string vs None
    vs whitespace-only vs leading-comma legacy etc.).
    """

    def test_none_passthrough(self):
        from dns_aid.core.bap import normalize_bap

        assert normalize_bap(None) is None

    def test_empty_string_to_none(self):
        from dns_aid.core.bap import normalize_bap

        assert normalize_bap("") is None
        assert normalize_bap("   ") is None
        assert normalize_bap("\t\n") is None

    def test_scalar_passthrough(self):
        from dns_aid.core.bap import normalize_bap

        assert normalize_bap("mcp") == "mcp"
        assert normalize_bap("mcp=1.0") == "mcp=1.0"
        assert normalize_bap("  mcp=1.0  ") == "mcp=1.0"

    def test_comma_list_collapsed_to_first_non_empty(self):
        from dns_aid.core.bap import normalize_bap

        assert normalize_bap("mcp,a2a") == "mcp"
        assert normalize_bap("mcp=1.0,a2a=1.1") == "mcp=1.0"
        # Leading comma — Igor's #158 item 5 regression.
        assert normalize_bap(",mcp=1.0") == "mcp=1.0"
        # Trailing comma.
        assert normalize_bap("mcp=1.0,") == "mcp=1.0"
        # Comma-only / all empties.
        assert normalize_bap(",,,") is None
        assert normalize_bap(", ,") is None

    def test_list_form_collapsed_to_first(self):
        from dns_aid.core.bap import normalize_bap

        assert normalize_bap(["mcp"]) == "mcp"
        assert normalize_bap(["mcp", "a2a"]) == "mcp"
        # Empty list, list of empties.
        assert normalize_bap([]) is None
        assert normalize_bap(["", " ", None]) is None  # type: ignore[list-item]
        # Defensive: non-string elements survive via str().
        assert normalize_bap([" mcp "]) == "mcp"

    def test_non_string_non_list_input(self):
        from dns_aid.core.bap import normalize_bap

        # Forgiving public API: anything not a str/list/None returns None.
        assert normalize_bap(42) is None  # type: ignore[arg-type]
        assert normalize_bap({"mcp": True}) is None  # type: ignore[arg-type]


class TestSplitBapToken:
    """Tests for protocol/version token extraction."""

    def test_bare_form(self):
        from dns_aid.core.bap import split_bap_token

        assert split_bap_token("mcp") == ("mcp", None)
        assert split_bap_token("a2a") == ("a2a", None)

    def test_versioned_form(self):
        from dns_aid.core.bap import split_bap_token

        assert split_bap_token("mcp=1.0") == ("mcp", "1.0")
        assert split_bap_token("a2a=1.1") == ("a2a", "1.1")

    def test_none_and_empty(self):
        from dns_aid.core.bap import split_bap_token

        assert split_bap_token(None) == (None, None)
        assert split_bap_token("") == (None, None)
        assert split_bap_token("   ") == (None, None)

    def test_dangling_equals_returns_only_proto(self):
        from dns_aid.core.bap import split_bap_token

        # ``mcp=`` is unusual but defensive — keep the proto, no version.
        assert split_bap_token("mcp=") == ("mcp", None)
