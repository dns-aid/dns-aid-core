# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for DNS-AID discoverer module."""

from unittest.mock import AsyncMock, MagicMock, patch

import dns.resolver
import pytest

from dns_aid.core.cap_fetcher import CapabilityDocument
from dns_aid.core.discoverer import (
    _build_index_tasks,
    _collect_agent_results,
    _discover_via_http_index,
    _enrich_from_http_index,
    _http_agent_to_record,
    _normalize_protocol,
    _parse_fqdn,
    _parse_svcb_custom_params,
    _process_http_agent,
    _query_capabilities,
    discover,
    discover_at_fqdn,
)
from dns_aid.core.http_index import HttpIndexAgent
from dns_aid.core.models import Protocol


class TestParseFqdn:
    """Tests for _parse_fqdn helper across all three draft-02 shapes."""

    def test_legacy_01_form(self):
        name, proto = _parse_fqdn("_booking._mcp._agents.example.com")
        assert name == "booking"
        assert proto == "mcp"

    def test_legacy_01_form_a2a(self):
        name, proto = _parse_fqdn("_chat._a2a._agents.example.com")
        assert name == "chat"
        assert proto == "a2a"

    def test_walkable_draft02_form(self):
        """Walkable AliasMode form: protocol comes from SVCB SvcParams, not FQDN."""
        name, proto = _parse_fqdn("chat._agents.example.com")
        assert name == "chat"
        assert proto is None

    def test_flat_draft02_form(self):
        """Flat primary owner: protocol comes from SVCB SvcParams, not FQDN."""
        name, proto = _parse_fqdn("booking.example.com")
        assert name == "booking"
        assert proto is None

    def test_empty_string(self):
        assert _parse_fqdn("") == (None, None)

    def test_none_value(self):
        assert _parse_fqdn(None) == (None, None)

    def test_walkable_rejects_underscore_prefix(self):
        """The walkable parser rejects underscored prefixes (only legacy uses them)."""
        assert _parse_fqdn("_booking._agents.example.com") == (None, None)

    def test_too_short(self):
        """Inputs without enough labels to be an FQDN return (None, None)."""
        assert _parse_fqdn("_a._b") == (None, None)
        assert _parse_fqdn("a.b") == (None, None)  # only 2 labels — not a 3-label FQDN
        assert _parse_fqdn("single") == (None, None)

    def test_legacy_with_malformed_protocol(self):
        """An underscore-prefixed legacy-looking FQDN with malformed protocol is rejected."""
        assert _parse_fqdn("_booking.mcp._agents.example.com") == (None, None)

    def test_walkable_empty_suffix_rejected(self):
        """A walkable-shaped input with no domain part ('foo._agents.') is rejected."""
        assert _parse_fqdn("foo._agents.") == (None, None)


class TestDiscover:
    """Tests for the main discover() function."""

    @pytest.mark.asyncio
    async def test_discover_with_name_and_protocol(self):
        with patch(
            "dns_aid.core.discoverer._query_single_agent",
            new_callable=AsyncMock,
            return_value=None,
        ) as mock_query:
            result = await discover("example.com", protocol="mcp", name="chat")
            mock_query.assert_called_once_with(
                "example.com", "chat", Protocol.MCP, allow_legacy=None
            )
            assert result.domain == "example.com"
            assert result.query == "chat.example.com"

    @pytest.mark.asyncio
    async def test_discover_with_protocol_only(self):
        with patch(
            "dns_aid.core.discoverer._discover_agents_in_zone",
            new_callable=AsyncMock,
            return_value=[],
        ):
            result = await discover("example.com", protocol="mcp")
            assert result.query == "_index._mcp._agents.example.com"
            assert result.agents == []

    @pytest.mark.asyncio
    async def test_discover_no_filters(self):
        with patch(
            "dns_aid.core.discoverer._discover_agents_in_zone",
            new_callable=AsyncMock,
            return_value=[],
        ):
            result = await discover("example.com")
            assert result.query == "_index._agents.example.com"

    @pytest.mark.asyncio
    async def test_discover_with_http_index(self):
        with patch(
            "dns_aid.core.discoverer._discover_via_http_index",
            new_callable=AsyncMock,
            return_value=[],
        ) as mock_http:
            result = await discover("example.com", use_http_index=True)
            mock_http.assert_called_once_with("example.com", None, None)
            assert result.domain == "example.com"

    @pytest.mark.asyncio
    async def test_discover_handles_nxdomain(self):
        with patch(
            "dns_aid.core.discoverer._discover_agents_in_zone",
            new_callable=AsyncMock,
            side_effect=dns.resolver.NXDOMAIN(),
        ):
            result = await discover("example.com")
            assert result.agents == []
            assert result.count == 0

    @pytest.mark.asyncio
    async def test_discover_handles_noanswer(self):
        with patch(
            "dns_aid.core.discoverer._discover_agents_in_zone",
            new_callable=AsyncMock,
            side_effect=dns.resolver.NoAnswer(),
        ):
            result = await discover("example.com")
            assert result.agents == []

    @pytest.mark.asyncio
    async def test_discover_handles_no_nameservers(self):
        with patch(
            "dns_aid.core.discoverer._discover_agents_in_zone",
            new_callable=AsyncMock,
            side_effect=dns.resolver.NoNameservers(),
        ):
            result = await discover("example.com")
            assert result.agents == []

    @pytest.mark.asyncio
    async def test_discover_handles_generic_exception(self):
        with patch(
            "dns_aid.core.discoverer._discover_agents_in_zone",
            new_callable=AsyncMock,
            side_effect=Exception("unexpected"),
        ):
            result = await discover("example.com")
            assert result.agents == []

    @pytest.mark.asyncio
    async def test_discover_protocol_string_normalized(self):
        with patch(
            "dns_aid.core.discoverer._discover_agents_in_zone",
            new_callable=AsyncMock,
            return_value=[],
        ):
            result = await discover("example.com", protocol="MCP")
            assert result.query == "_index._mcp._agents.example.com"

    @pytest.mark.asyncio
    async def test_discover_records_query_time(self):
        with patch(
            "dns_aid.core.discoverer._discover_agents_in_zone",
            new_callable=AsyncMock,
            return_value=[],
        ):
            result = await discover("example.com")
            assert result.query_time_ms > 0


class TestQueryCapabilities:
    """Tests for _query_capabilities."""

    @pytest.mark.asyncio
    async def test_parses_capabilities_from_txt(self):
        mock_rdata = MagicMock()
        mock_rdata.strings = [b"capabilities=chat,code-review"]

        mock_answers = MagicMock()
        mock_answers.__iter__ = lambda self: iter([mock_rdata])

        mock_resolver = MagicMock()
        mock_resolver.resolve = AsyncMock(return_value=mock_answers)

        with patch(
            "dns_aid.core.discoverer.dns.asyncresolver.Resolver",
            return_value=mock_resolver,
        ):
            caps = await _query_capabilities("_chat._mcp._agents.example.com")
        assert caps == ["chat", "code-review"]

    @pytest.mark.asyncio
    async def test_returns_empty_on_error(self):
        mock_resolver = MagicMock()
        mock_resolver.resolve = AsyncMock(side_effect=Exception("no TXT"))

        with patch(
            "dns_aid.core.discoverer.dns.asyncresolver.Resolver",
            return_value=mock_resolver,
        ):
            caps = await _query_capabilities("_chat._mcp._agents.example.com")
        assert caps == []

    @pytest.mark.asyncio
    async def test_ignores_non_capability_txt(self):
        mock_rdata = MagicMock()
        mock_rdata.strings = [b"version=1.0.0", b"description=A chat agent"]

        mock_answers = MagicMock()
        mock_answers.__iter__ = lambda self: iter([mock_rdata])

        mock_resolver = MagicMock()
        mock_resolver.resolve = AsyncMock(return_value=mock_answers)

        with patch(
            "dns_aid.core.discoverer.dns.asyncresolver.Resolver",
            return_value=mock_resolver,
        ):
            caps = await _query_capabilities("_chat._mcp._agents.example.com")
        assert caps == []


class TestHttpAgentToRecord:
    """Tests for _http_agent_to_record."""

    def test_converts_with_protocol_from_caller(self):
        http_agent = HttpIndexAgent(
            name="booking-agent",
            fqdn="_booking._mcp._agents.example.com",
            description="Book flights",
        )
        record = _http_agent_to_record(
            http_agent, "example.com", dns_name="booking", dns_protocol=Protocol.MCP
        )
        assert record is not None
        assert record.name == "booking"
        assert record.protocol == Protocol.MCP
        assert record.endpoint_source == "http_index_fallback"
        assert record.description == "Book flights"

    def test_falls_back_to_primary_protocol(self):
        """When caller doesn't provide protocol, falls back to HTTP index."""
        http_agent = HttpIndexAgent(
            name="chat",
            fqdn="_chat._mcp._agents.example.com",
            protocols=["mcp"],
        )
        record = _http_agent_to_record(http_agent, "example.com")
        assert record is not None
        assert record.protocol == Protocol.MCP

    def test_returns_none_when_no_protocol_anywhere(self):
        http_agent = HttpIndexAgent(
            name="test",
            fqdn="test.example.com",
            protocols=[],
        )
        record = _http_agent_to_record(http_agent, "example.com")
        assert record is None

    def test_returns_none_for_invalid_fallback_protocol(self):
        http_agent = HttpIndexAgent(
            name="test",
            fqdn="test.example.com",
            protocols=["unknown_proto"],
        )
        record = _http_agent_to_record(http_agent, "example.com")
        assert record is None

    def test_with_direct_endpoint(self):
        http_agent = HttpIndexAgent(
            name="booking-agent",
            fqdn="_booking._mcp._agents.example.com",
            endpoint="https://booking.example.com/mcp",
        )
        record = _http_agent_to_record(
            http_agent, "example.com", dns_name="booking", dns_protocol=Protocol.MCP
        )
        assert record is not None
        assert record.endpoint_override == "https://booking.example.com/mcp"
        assert record.target_host == "booking.example.com"

    def test_with_non_agents_fqdn(self):
        http_agent = HttpIndexAgent(
            name="external",
            fqdn="agent.external.com.",
        )
        record = _http_agent_to_record(
            http_agent, "example.com", dns_name="external", dns_protocol=Protocol.MCP
        )
        assert record is not None
        assert record.target_host == "agent.external.com"

    def test_with_agents_fqdn_uses_domain(self):
        http_agent = HttpIndexAgent(
            name="chat-agent",
            fqdn="_chat._mcp._agents.example.com",
        )
        record = _http_agent_to_record(
            http_agent, "example.com", dns_name="chat", dns_protocol=Protocol.MCP
        )
        assert record is not None
        assert record.target_host == "example.com"


class TestDiscoverAtFqdn:
    """Tests for discover_at_fqdn."""

    @pytest.mark.asyncio
    async def test_valid_fqdn(self):
        with patch(
            "dns_aid.core.discoverer._query_single_agent",
            new_callable=AsyncMock,
            return_value=None,
        ) as mock_query:
            result = await discover_at_fqdn("_chat._a2a._agents.example.com")
            mock_query.assert_called_once_with("example.com", "chat", Protocol.A2A)
            assert result is None

    @pytest.mark.asyncio
    async def test_invalid_fqdn_too_short(self):
        result = await discover_at_fqdn("foo.bar")
        assert result is None

    @pytest.mark.asyncio
    async def test_invalid_fqdn_no_underscore(self):
        result = await discover_at_fqdn("chat.a2a._agents.example.com")
        assert result is None

    @pytest.mark.asyncio
    async def test_invalid_fqdn_no_agents_marker(self):
        result = await discover_at_fqdn("_chat._a2a._other.example.com")
        assert result is None

    @pytest.mark.asyncio
    async def test_invalid_protocol(self):
        result = await discover_at_fqdn("_chat._unknown._agents.example.com")
        assert result is None

    @pytest.mark.asyncio
    async def test_extracts_domain_correctly(self):
        with patch(
            "dns_aid.core.discoverer._query_single_agent",
            new_callable=AsyncMock,
            return_value=None,
        ) as mock_query:
            await discover_at_fqdn("_chat._mcp._agents.sub.example.com")
            mock_query.assert_called_once_with("sub.example.com", "chat", Protocol.MCP)

    @pytest.mark.asyncio
    async def test_flat_draft02_shape_resolves_once_with_default_protocol(self):
        """Under the flat shape the SVCB DNS query is identical for any
        Protocol — earlier the function tried MCP then A2A back-to-back,
        firing the same query twice. Verify the single-call refactor."""
        from dns_aid.core.models import AgentRecord

        fake_record = AgentRecord(
            name="chat",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="chat.example.com",
            bap="mcp",
        )
        with patch(
            "dns_aid.core.discoverer._query_single_agent",
            new_callable=AsyncMock,
            return_value=fake_record,
        ) as mock_query:
            result = await discover_at_fqdn("chat.example.com")

        # Single call — no MCP-then-A2A retry pair.
        mock_query.assert_called_once_with("example.com", "chat", Protocol.MCP)
        assert result is not None
        assert result.name == "chat"
        assert result.protocol == Protocol.MCP

    @pytest.mark.asyncio
    async def test_flat_shape_reads_protocol_from_bap(self):
        """When the record's bap announces A2A, the discoverer reflects
        that on the returned AgentRecord — not the default it queried
        with."""
        from dns_aid.core.models import AgentRecord

        fake_record = AgentRecord(
            name="chat",
            domain="example.com",
            protocol=Protocol.MCP,  # default applied during the lookup
            target_host="chat.example.com",
            bap="a2a",  # but the record itself announces A2A
        )
        with patch(
            "dns_aid.core.discoverer._query_single_agent",
            new_callable=AsyncMock,
            return_value=fake_record,
        ):
            result = await discover_at_fqdn("chat.example.com")

        assert result is not None
        assert result.protocol == Protocol.A2A

    @pytest.mark.asyncio
    async def test_walkable_shape_resolves(self):
        """The walkable draft-02 shape `{name}._agents.{domain}` parses
        cleanly and routes to a single _query_single_agent call."""
        from dns_aid.core.models import AgentRecord

        fake_record = AgentRecord(
            name="chat",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="chat.example.com",
            bap="mcp",
        )
        with patch(
            "dns_aid.core.discoverer._query_single_agent",
            new_callable=AsyncMock,
            return_value=fake_record,
        ) as mock_query:
            result = await discover_at_fqdn("chat._agents.example.com")

        mock_query.assert_called_once_with("example.com", "chat", Protocol.MCP)
        assert result is not None
        assert result.name == "chat"


class TestDiscoverViaHttpIndex:
    """Tests for _discover_via_http_index."""

    @pytest.mark.asyncio
    async def test_returns_empty_when_no_http_agents(self):
        with patch(
            "dns_aid.core.discoverer.fetch_http_index_or_empty",
            new_callable=AsyncMock,
            return_value=[],
        ):
            agents = await _discover_via_http_index("example.com")
            assert agents == []

    @pytest.mark.asyncio
    async def test_filters_by_name(self):
        http_agents = [
            HttpIndexAgent(
                name="booking",
                fqdn="_booking._mcp._agents.example.com",
            ),
            HttpIndexAgent(
                name="chat",
                fqdn="_chat._mcp._agents.example.com",
            ),
        ]

        with (
            patch(
                "dns_aid.core.discoverer.fetch_http_index_or_empty",
                new_callable=AsyncMock,
                return_value=http_agents,
            ),
            patch(
                "dns_aid.core.discoverer._query_single_agent",
                new_callable=AsyncMock,
                return_value=None,
            ),
        ):
            agents = await _discover_via_http_index("example.com", name="booking")
            assert len(agents) == 1
            assert agents[0].name == "booking"

    @pytest.mark.asyncio
    async def test_filters_by_protocol(self):
        http_agents = [
            HttpIndexAgent(
                name="booking",
                fqdn="_booking._mcp._agents.example.com",
            ),
            HttpIndexAgent(
                name="chat",
                fqdn="_chat._a2a._agents.example.com",
            ),
        ]

        with (
            patch(
                "dns_aid.core.discoverer.fetch_http_index_or_empty",
                new_callable=AsyncMock,
                return_value=http_agents,
            ),
            patch(
                "dns_aid.core.discoverer._query_single_agent",
                new_callable=AsyncMock,
                return_value=None,
            ),
        ):
            agents = await _discover_via_http_index("example.com", protocol=Protocol.MCP)
            assert len(agents) == 1
            assert agents[0].name == "booking"

    @pytest.mark.asyncio
    async def test_skips_unparseable_fqdn(self):
        """Single-label fqdn entries are still rejected by _parse_fqdn under draft-02."""
        http_agents = [
            HttpIndexAgent(
                name="bad",
                fqdn="bogus",
            ),
        ]

        with patch(
            "dns_aid.core.discoverer.fetch_http_index_or_empty",
            new_callable=AsyncMock,
            return_value=http_agents,
        ):
            agents = await _discover_via_http_index("example.com")
            assert agents == []

    @pytest.mark.asyncio
    async def test_skips_unknown_protocol_in_fqdn(self):
        http_agents = [
            HttpIndexAgent(
                name="weird",
                fqdn="_weird._unknown._agents.example.com",
            ),
        ]

        with patch(
            "dns_aid.core.discoverer.fetch_http_index_or_empty",
            new_callable=AsyncMock,
            return_value=http_agents,
        ):
            agents = await _discover_via_http_index("example.com")
            assert agents == []

    @pytest.mark.asyncio
    async def test_extracts_name_from_fqdn(self):
        """Agent name comes from FQDN, not HTTP index key."""
        http_agents = [
            HttpIndexAgent(
                name="booking-agent",  # HTTP key
                fqdn="_booking._mcp._agents.example.com",  # DNS name = 'booking'
            ),
        ]

        with (
            patch(
                "dns_aid.core.discoverer.fetch_http_index_or_empty",
                new_callable=AsyncMock,
                return_value=http_agents,
            ),
            patch(
                "dns_aid.core.discoverer._query_single_agent",
                new_callable=AsyncMock,
                return_value=None,
            ) as mock_query,
        ):
            await _discover_via_http_index("example.com")
            mock_query.assert_called_once_with("example.com", "booking", Protocol.MCP)

    @pytest.mark.asyncio
    async def test_protocol_extracted_from_fqdn_not_http_field(self):
        """Protocol comes from FQDN, not HTTP index protocols field."""
        http_agents = [
            HttpIndexAgent(
                name="chat",
                fqdn="_chat._a2a._agents.example.com",
                protocols=["mcp"],  # This should be ignored
            ),
        ]

        with (
            patch(
                "dns_aid.core.discoverer.fetch_http_index_or_empty",
                new_callable=AsyncMock,
                return_value=http_agents,
            ),
            patch(
                "dns_aid.core.discoverer._query_single_agent",
                new_callable=AsyncMock,
                return_value=None,
            ) as mock_query,
        ):
            await _discover_via_http_index("example.com")
            # Should use a2a from FQDN, not mcp from protocols field
            mock_query.assert_called_once_with("example.com", "chat", Protocol.A2A)


class TestParseSvcbCustomParams:
    """Tests for _parse_svcb_custom_params."""

    def test_parses_all_dnsaid_params(self):
        svcb_text = (
            '1 mcp.example.com. alpn="mcp" port="443" '
            'cap="https://mcp.example.com/.well-known/agent-cap.json" '
            'cap-sha256="dGVzdGhhc2g" '
            'bap="mcp/1,a2a/1" policy="https://example.com/policy" realm="production" '
            'connect-class="lattice" connect-meta="arn:aws:vpc-lattice:::service/svc-123" '
            'enroll-uri="https://service.example.com/.well-known/agent-connect"'
        )
        params = _parse_svcb_custom_params(svcb_text)
        assert params["cap"] == "https://mcp.example.com/.well-known/agent-cap.json"
        assert params["cap-sha256"] == "dGVzdGhhc2g"
        assert params["bap"] == "mcp/1,a2a/1"
        assert params["policy"] == "https://example.com/policy"
        assert params["realm"] == "production"
        assert params["connect-class"] == "lattice"
        assert params["connect-meta"] == "arn:aws:vpc-lattice:::service/svc-123"
        assert params["enroll-uri"] == "https://service.example.com/.well-known/agent-connect"

    def test_ignores_non_dnsaid_params(self):
        svcb_text = '1 mcp.example.com. alpn="mcp" port="443" ipv4hint="192.0.2.1"'
        params = _parse_svcb_custom_params(svcb_text)
        assert "alpn" not in params
        assert "port" not in params
        assert "ipv4hint" not in params

    def test_partial_dnsaid_params(self):
        svcb_text = '1 mcp.example.com. alpn="mcp" port="443" cap="https://cap.example.com/cap.json" realm="demo"'
        params = _parse_svcb_custom_params(svcb_text)
        assert params["cap"] == "https://cap.example.com/cap.json"
        assert params["realm"] == "demo"
        assert "cap-sha256" not in params
        assert "bap" not in params
        assert "policy" not in params

    def test_parses_cap_sha256(self):
        svcb_text = (
            '1 mcp.example.com. alpn="mcp" port="443" '
            'cap="https://example.com/cap.json" cap-sha256="abc123base64url"'
        )
        params = _parse_svcb_custom_params(svcb_text)
        assert params["cap-sha256"] == "abc123base64url"
        assert params["cap"] == "https://example.com/cap.json"

    def test_parses_well_known(self):
        """draft-02 `well-known` SvcParamKey is recognized in string form."""
        svcb_text = '1 mcp.example.com. alpn="mcp" port="443" well-known="agent-card.json"'
        params = _parse_svcb_custom_params(svcb_text)
        assert params["well-known"] == "agent-card.json"

    def test_parses_well_known_via_keynnnnn(self):
        """`key65409` resolves back to the `well-known` string name."""
        svcb_text = '1 mcp.example.com. alpn="mcp" port="443" key65409="agent-card.json"'
        params = _parse_svcb_custom_params(svcb_text)
        assert params["well-known"] == "agent-card.json"

    def test_well_known_and_cap_coexist(self):
        """`cap` and `well-known` are independent keys; both must be parsed when present."""
        svcb_text = (
            '1 mcp.example.com. alpn="mcp" port="443" '
            'cap="urn:example:agent-cap:abc" '
            'well-known="agent-card.json"'
        )
        params = _parse_svcb_custom_params(svcb_text)
        assert params["cap"] == "urn:example:agent-cap:abc"
        assert params["well-known"] == "agent-card.json"

    def test_empty_svcb_text(self):
        params = _parse_svcb_custom_params("")
        assert params == {}

    def test_no_custom_params(self):
        svcb_text = '1 mcp.example.com. alpn="mcp" port="443"'
        params = _parse_svcb_custom_params(svcb_text)
        assert params == {}

    def test_case_insensitive_keys(self):
        svcb_text = '1 mcp.example.com. CAP="https://example.com/cap.json" REALM="prod"'
        params = _parse_svcb_custom_params(svcb_text)
        assert params["cap"] == "https://example.com/cap.json"
        assert params["realm"] == "prod"

    def test_preserves_quoted_values_with_spaces(self):
        svcb_text = (
            '1 mcp.example.com. connect-meta="apphub.googleapis.com/projects/test/services/My Service" '
            'enroll-uri="https://example.com/.well-known/agent-connect?label=My Service"'
        )
        params = _parse_svcb_custom_params(svcb_text)
        assert params["connect-meta"] == "apphub.googleapis.com/projects/test/services/My Service"
        assert (
            params["enroll-uri"] == "https://example.com/.well-known/agent-connect?label=My Service"
        )


class TestDiscoveryWithCapUri:
    """Tests for discovery with cap URI in SVCB (DNS-AID draft alignment)."""

    @pytest.mark.asyncio
    async def test_discovery_uses_cap_uri_when_present(self):
        """Test that capabilities come from cap URI when SVCB has cap param."""
        # Mock SVCB record with cap param
        mock_rdata = MagicMock()
        mock_rdata.target = dns.name.from_text("mcp.example.com.")
        mock_rdata.priority = 1
        mock_rdata.port = 443
        mock_rdata.params = {}
        mock_rdata.__str__ = lambda self: (
            '1 mcp.example.com. alpn="mcp" port="443" '
            'cap="https://mcp.example.com/.well-known/agent-cap.json" '
            'cap-sha256="dGVzdGhhc2g" realm="demo"'
        )

        mock_answers = MagicMock()
        mock_answers.__iter__ = lambda self: iter([mock_rdata])

        mock_resolver = MagicMock()
        mock_resolver.resolve = AsyncMock(return_value=mock_answers)

        cap_doc = CapabilityDocument(
            capabilities=["travel", "booking", "calendar"],
            version="1.0.0",
            description="Booking agent",
        )

        with (
            patch(
                "dns_aid.core.discoverer.dns.asyncresolver.Resolver",
                return_value=mock_resolver,
            ),
            patch(
                "dns_aid.core.discoverer.fetch_cap_document",
                new_callable=AsyncMock,
                return_value=cap_doc,
            ) as mock_fetch,
        ):
            from dns_aid.core.discoverer import _query_single_agent

            agent = await _query_single_agent("example.com", "booking", Protocol.MCP)

        assert agent is not None
        assert agent.capabilities == ["travel", "booking", "calendar"]
        assert agent.capability_source == "cap_uri"
        assert agent.cap_uri == "https://mcp.example.com/.well-known/agent-cap.json"
        assert agent.cap_sha256 == "dGVzdGhhc2g"
        assert agent.realm == "demo"
        mock_fetch.assert_called_once_with(
            "https://mcp.example.com/.well-known/agent-cap.json",
            expected_sha256="dGVzdGhhc2g",
        )

    @pytest.mark.asyncio
    async def test_discovery_falls_back_to_txt_when_no_cap(self):
        """Test that TXT capabilities are used when SVCB has no cap param."""
        mock_rdata = MagicMock()
        mock_rdata.target = dns.name.from_text("mcp.example.com.")
        mock_rdata.priority = 1
        mock_rdata.port = 443
        mock_rdata.params = {}
        mock_rdata.__str__ = lambda self: '1 mcp.example.com. alpn="mcp" port="443"'

        mock_answers = MagicMock()
        mock_answers.__iter__ = lambda self: iter([mock_rdata])

        mock_resolver = MagicMock()
        mock_resolver.resolve = AsyncMock(return_value=mock_answers)

        with (
            patch(
                "dns_aid.core.discoverer.dns.asyncresolver.Resolver",
                return_value=mock_resolver,
            ),
            patch(
                "dns_aid.core.discoverer._query_capabilities",
                new_callable=AsyncMock,
                return_value=["ipam", "dns"],
            ),
            patch(
                "dns_aid.core.discoverer.fetch_cap_document",
                new_callable=AsyncMock,
            ) as mock_fetch,
        ):
            from dns_aid.core.discoverer import _query_single_agent

            agent = await _query_single_agent("example.com", "network", Protocol.MCP)

        assert agent is not None
        assert agent.capabilities == ["ipam", "dns"]
        assert agent.capability_source == "txt_fallback"
        assert agent.cap_uri is None
        mock_fetch.assert_not_called()

    @pytest.mark.asyncio
    async def test_discovery_falls_back_to_txt_when_cap_fetch_fails(self):
        """Test fallback to TXT when cap URI fetch fails."""
        mock_rdata = MagicMock()
        mock_rdata.target = dns.name.from_text("mcp.example.com.")
        mock_rdata.priority = 1
        mock_rdata.port = 443
        mock_rdata.params = {}
        mock_rdata.__str__ = lambda self: (
            '1 mcp.example.com. alpn="mcp" port="443" '
            'cap="https://mcp.example.com/.well-known/agent-cap.json"'
        )

        mock_answers = MagicMock()
        mock_answers.__iter__ = lambda self: iter([mock_rdata])

        mock_resolver = MagicMock()
        mock_resolver.resolve = AsyncMock(return_value=mock_answers)

        with (
            patch(
                "dns_aid.core.discoverer.dns.asyncresolver.Resolver",
                return_value=mock_resolver,
            ),
            patch(
                "dns_aid.core.discoverer.fetch_cap_document",
                new_callable=AsyncMock,
                return_value=None,  # fetch failed
            ),
            patch(
                "dns_aid.core.discoverer._query_capabilities",
                new_callable=AsyncMock,
                return_value=["network-mgmt"],
            ),
        ):
            from dns_aid.core.discoverer import _query_single_agent

            agent = await _query_single_agent("example.com", "network", Protocol.MCP)

        assert agent is not None
        assert agent.capabilities == ["network-mgmt"]
        assert agent.capability_source == "txt_fallback"
        assert agent.cap_uri == "https://mcp.example.com/.well-known/agent-cap.json"

    @pytest.mark.asyncio
    async def test_discovery_extracts_bap_and_policy(self):
        """Test that bap and policy_uri are extracted from SVCB.

        Per draft-02 §FutureWork (Bulk Agent Protocol), bap is scalar.
        The discoverer accepts a pre-draft-02 comma-separated value and
        collapses to the first entry, preserving a sensible scalar.
        """
        mock_rdata = MagicMock()
        mock_rdata.target = dns.name.from_text("mcp.example.com.")
        mock_rdata.priority = 1
        mock_rdata.port = 443
        mock_rdata.params = {}
        mock_rdata.__str__ = lambda self: (
            '1 mcp.example.com. alpn="mcp" port="443" '
            'bap="mcp2.1" policy="https://example.com/policy" realm="staging"'
        )

        mock_answers = MagicMock()
        mock_answers.__iter__ = lambda self: iter([mock_rdata])

        mock_resolver = MagicMock()
        mock_resolver.resolve = AsyncMock(return_value=mock_answers)

        with (
            patch(
                "dns_aid.core.discoverer.dns.asyncresolver.Resolver",
                return_value=mock_resolver,
            ),
            patch(
                "dns_aid.core.discoverer._query_capabilities",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            from dns_aid.core.discoverer import _query_single_agent

            agent = await _query_single_agent("example.com", "chat", Protocol.MCP)

        assert agent is not None
        assert agent.bap == "mcp2.1"
        assert agent.policy_uri == "https://example.com/policy"
        assert agent.realm == "staging"

    @pytest.mark.asyncio
    async def test_discovery_collapses_legacy_comma_bap_to_scalar(self):
        """Pre-draft-02 publishers may have written bap as a comma-separated
        list. The discoverer takes the first value to preserve a sensible
        scalar (per draft-02 §FutureWork — Bulk Agent Protocol is scalar)."""
        mock_rdata = MagicMock()
        mock_rdata.target = dns.name.from_text("mcp.example.com.")
        mock_rdata.priority = 1
        mock_rdata.port = 443
        mock_rdata.params = {}
        mock_rdata.__str__ = lambda self: (
            '1 mcp.example.com. alpn="mcp" port="443" bap="mcp/1,a2a/1"'
        )
        mock_answers = MagicMock()
        mock_answers.__iter__ = lambda self: iter([mock_rdata])
        mock_resolver = MagicMock()
        mock_resolver.resolve = AsyncMock(return_value=mock_answers)

        with (
            patch(
                "dns_aid.core.discoverer.dns.asyncresolver.Resolver",
                return_value=mock_resolver,
            ),
            patch(
                "dns_aid.core.discoverer._query_capabilities",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            from dns_aid.core.discoverer import _query_single_agent

            agent = await _query_single_agent("example.com", "chat", Protocol.MCP)

        assert agent is not None
        assert agent.bap == "mcp/1"

    @pytest.mark.asyncio
    async def test_discovery_extracts_connect_fields(self):
        """Test that provider-specific connection params round-trip through discovery."""
        mock_rdata = MagicMock()
        mock_rdata.target = dns.name.from_text("service.example.com.")
        mock_rdata.priority = 1
        mock_rdata.port = 443
        mock_rdata.params = {}
        mock_rdata.__str__ = lambda self: (
            '1 service.example.com. alpn="mcp" port="443" '
            'connect-class="apphub-psc" '
            'connect-meta="projects/test/locations/us/discoveredServices/123" '
            'enroll-uri="https://psc.example.com/.well-known/agent-connect"'
        )

        mock_answers = MagicMock()
        mock_answers.__iter__ = lambda self: iter([mock_rdata])

        mock_resolver = MagicMock()
        mock_resolver.resolve = AsyncMock(return_value=mock_answers)

        with (
            patch(
                "dns_aid.core.discoverer.dns.asyncresolver.Resolver",
                return_value=mock_resolver,
            ),
            patch(
                "dns_aid.core.discoverer._query_capabilities",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            from dns_aid.core.discoverer import _query_single_agent

            agent = await _query_single_agent("example.com", "chat", Protocol.MCP)

        assert agent is not None
        assert agent.connect_class == "apphub-psc"
        assert agent.connect_meta == "projects/test/locations/us/discoveredServices/123"
        assert agent.enroll_uri == "https://psc.example.com/.well-known/agent-connect"


# =============================================================================
# Tests for refactored helpers
# =============================================================================


class TestNormalizeProtocol:
    """Tests for _normalize_protocol helper."""

    def test_string_normalized(self):
        assert _normalize_protocol("MCP") == Protocol.MCP

    def test_enum_passthrough(self):
        assert _normalize_protocol(Protocol.A2A) == Protocol.A2A

    def test_none_passthrough(self):
        assert _normalize_protocol(None) is None


class TestBuildIndexTasks:
    """Tests for _build_index_tasks helper."""

    def test_builds_tasks_for_valid_entries(self):
        from dns_aid.core.indexer import IndexEntry

        entries = [
            IndexEntry(name="chat", protocol="mcp"),
            IndexEntry(name="billing", protocol="a2a"),
        ]
        calls = []

        async def fake_query(name, proto):
            calls.append((name, proto))

        tasks = _build_index_tasks(entries, None, fake_query)
        assert len(tasks) == 2

    def test_filters_by_protocol(self):
        from dns_aid.core.indexer import IndexEntry

        entries = [
            IndexEntry(name="chat", protocol="mcp"),
            IndexEntry(name="billing", protocol="a2a"),
        ]

        async def fake_query(name, proto):
            pass

        tasks = _build_index_tasks(entries, Protocol.MCP, fake_query)
        assert len(tasks) == 1

    def test_skips_invalid_protocol(self):
        from dns_aid.core.indexer import IndexEntry

        entries = [IndexEntry(name="chat", protocol="unknown_proto")]

        async def fake_query(name, proto):
            pass

        tasks = _build_index_tasks(entries, None, fake_query)
        assert len(tasks) == 0


class TestCollectAgentResults:
    """Tests for _collect_agent_results helper."""

    def test_filters_agent_records(self):
        from dns_aid.core.models import AgentRecord, Protocol

        agent = AgentRecord(
            name="test",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="test.example.com",
            port=443,
        )
        results = [agent, Exception("error"), None, agent]
        collected = _collect_agent_results(results)
        assert len(collected) == 2

    def test_empty_results(self):
        assert _collect_agent_results([]) == []

    def test_all_exceptions(self):
        results = [Exception("a"), Exception("b")]
        assert _collect_agent_results(results) == []


class TestEnrichFromHttpIndex:
    """Tests for _enrich_from_http_index helper."""

    def test_enriches_description(self):
        from dns_aid.core.models import AgentRecord, Protocol

        agent = AgentRecord(
            name="chat",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="chat.example.com",
            port=443,
        )
        http_agent = HttpIndexAgent(
            name="chat",
            fqdn="_chat._mcp._agents.example.com",
            description="A chat agent",
        )
        _enrich_from_http_index(agent, http_agent)
        assert agent.description == "A chat agent"

    def test_enriches_endpoint_override(self):
        from dns_aid.core.models import AgentRecord, Protocol

        agent = AgentRecord(
            name="chat",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="chat.example.com",
            port=443,
        )
        http_agent = HttpIndexAgent(
            name="chat",
            fqdn="_chat._mcp._agents.example.com",
            endpoint="https://chat.example.com/mcp",
        )
        _enrich_from_http_index(agent, http_agent)
        assert agent.endpoint_override == "https://chat.example.com/mcp"
        assert agent.endpoint_source == "http_index"

    def test_does_not_override_existing_endpoint(self):
        from dns_aid.core.models import AgentRecord, Protocol

        agent = AgentRecord(
            name="chat",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="chat.example.com",
            port=443,
            endpoint_override="https://original.com/mcp",
        )
        http_agent = HttpIndexAgent(
            name="chat",
            fqdn="_chat._mcp._agents.example.com",
            endpoint="https://chat.example.com/new-mcp",
        )
        _enrich_from_http_index(agent, http_agent)
        assert agent.endpoint_override == "https://original.com/mcp"


class TestProcessHttpAgent:
    """Tests for _process_http_agent helper."""

    @pytest.mark.asyncio
    async def test_skips_name_mismatch(self):
        http_agent = HttpIndexAgent(
            name="billing",
            fqdn="_billing._mcp._agents.example.com",
        )
        result = await _process_http_agent(http_agent, "example.com", None, "chat")
        assert result is None

    @pytest.mark.asyncio
    async def test_skips_unparseable_fqdn(self):
        """Single-label fqdn entries are still rejected by _parse_fqdn under draft-02."""
        http_agent = HttpIndexAgent(
            name="bad",
            fqdn="bogus",
        )
        result = await _process_http_agent(http_agent, "example.com", None, None)
        assert result is None

    @pytest.mark.asyncio
    async def test_skips_unknown_protocol(self):
        """Legacy form with a protocol not in the Protocol enum is rejected."""
        http_agent = HttpIndexAgent(
            name="weird",
            fqdn="_weird._unknown._agents.example.com",
        )
        result = await _process_http_agent(http_agent, "example.com", None, None)
        assert result is None

    @pytest.mark.asyncio
    async def test_skips_protocol_filter_mismatch(self):
        http_agent = HttpIndexAgent(
            name="chat",
            fqdn="_chat._a2a._agents.example.com",
        )
        result = await _process_http_agent(http_agent, "example.com", Protocol.MCP, None)
        assert result is None


class TestWellKnownReconstruction:
    """End-to-end coverage for the draft-02 ``well-known`` SvcParamKey
    path: the discoverer validates the suffix, reconstructs
    ``https://<target>/.well-known/<path>`` from the SVCB target, fetches
    the cap document there, and stamps ``capability_source="well_known"``
    on the resulting AgentRecord.

    Adversarial cases confirm path traversal, query-string injection,
    and embedded slashes are rejected before the URL is built rather
    than being normalised away by httpx (which would silently escape
    the /.well-known/ confinement).
    """

    @pytest.mark.asyncio
    async def test_well_known_reconstructed_url_drives_fetch(self):
        from dns_aid.core.discoverer import _query_single_agent

        fake_rdata = MagicMock()
        fake_rdata.priority = 1
        fake_rdata.target = MagicMock()
        fake_rdata.target.__str__ = MagicMock(return_value="chat.example.com.")
        fake_rdata.params = {}
        fake_rdata.__str__ = MagicMock(
            return_value=('1 chat.example.com. alpn="mcp" port=443 well-known="agent-card.json"')
        )
        fake_answers = MagicMock()
        fake_answers.__iter__ = lambda self: iter([fake_rdata])

        captured_urls: list[str] = []

        async def fake_fetch(url, expected_sha256=None):
            captured_urls.append(url)
            return CapabilityDocument(capabilities=["chat"], raw_data={"capabilities": ["chat"]})

        with patch("dns_aid.core.discoverer.dns.asyncresolver") as mock_mod:
            resolver = MagicMock()
            resolver.resolve = AsyncMock(return_value=fake_answers)
            mock_mod.Resolver.return_value = resolver
            with patch(
                "dns_aid.core.discoverer.fetch_cap_document",
                side_effect=fake_fetch,
            ):
                result = await _query_single_agent("example.com", "chat", Protocol.MCP)

        assert result is not None
        # URL reconstructed correctly from SVCB target + well-known suffix.
        assert captured_urls == ["https://chat.example.com/.well-known/agent-card.json"]
        assert result.well_known_path == "agent-card.json"
        assert result.capability_source == "well_known"
        assert "chat" in result.capabilities

    @pytest.mark.asyncio
    async def test_well_known_with_cap_sha256_forwarded_to_fetch(self):
        """`cap-sha256` flows through to fetch_cap_document as
        expected_sha256 so the integrity check fires on the well-known
        path too — not just on explicit cap URIs."""
        from dns_aid.core.discoverer import _query_single_agent

        fake_rdata = MagicMock()
        fake_rdata.priority = 1
        fake_rdata.target = MagicMock()
        fake_rdata.target.__str__ = MagicMock(return_value="chat.example.com.")
        fake_rdata.params = {}
        fake_rdata.__str__ = MagicMock(
            return_value=(
                '1 chat.example.com. alpn="mcp" port=443 '
                'well-known="agent-card.json" cap-sha256="EXPECTED_DIGEST"'
            )
        )
        fake_answers = MagicMock()
        fake_answers.__iter__ = lambda self: iter([fake_rdata])

        seen_sha: list[str | None] = []

        async def fake_fetch(url, expected_sha256=None):
            seen_sha.append(expected_sha256)
            return CapabilityDocument(capabilities=["chat"], raw_data={})

        with patch("dns_aid.core.discoverer.dns.asyncresolver") as mock_mod:
            resolver = MagicMock()
            resolver.resolve = AsyncMock(return_value=fake_answers)
            mock_mod.Resolver.return_value = resolver
            with patch(
                "dns_aid.core.discoverer.fetch_cap_document",
                side_effect=fake_fetch,
            ):
                result = await _query_single_agent("example.com", "chat", Protocol.MCP)

        assert result is not None
        assert seen_sha == ["EXPECTED_DIGEST"]
        assert result.capability_source == "well_known"

    @pytest.mark.asyncio
    async def test_malicious_well_known_value_rejected_before_fetch(self):
        """Path-traversal / query-string / embedded-slash values must
        be rejected by the validator before any URL is constructed.

        Without this validator a value like ``../../admin`` would
        survive ``.lstrip('/')`` and httpx would normalise the
        dot-segments — silently escaping ``/.well-known/`` confinement
        and turning a discovery-fetch into a path-traversal primitive.
        """
        from dns_aid.core.discoverer import _query_single_agent

        fake_rdata = MagicMock()
        fake_rdata.priority = 1
        fake_rdata.target = MagicMock()
        fake_rdata.target.__str__ = MagicMock(return_value="chat.example.com.")
        fake_rdata.params = {}
        fake_rdata.__str__ = MagicMock(
            return_value=('1 chat.example.com. alpn="mcp" port=443 well-known="../../admin"')
        )
        fake_answers = MagicMock()
        fake_answers.__iter__ = lambda self: iter([fake_rdata])

        captured_urls: list[str] = []

        async def fake_fetch(url, expected_sha256=None):
            captured_urls.append(url)
            return None

        with patch("dns_aid.core.discoverer.dns.asyncresolver") as mock_mod:
            resolver = MagicMock()
            resolver.resolve = AsyncMock(return_value=fake_answers)
            mock_mod.Resolver.return_value = resolver
            with patch(
                "dns_aid.core.discoverer.fetch_cap_document",
                side_effect=fake_fetch,
            ):
                result = await _query_single_agent("example.com", "chat", Protocol.MCP)

        # The malicious URL must NOT have been constructed or fetched.
        assert captured_urls == [], (
            "validator must reject the malicious value before URL construction"
        )
        # The record is not stamped as well_known (validator skipped the fetch).
        assert result is None or result.capability_source != "well_known"

    @pytest.mark.asyncio
    async def test_absolute_path_well_known_resolves_origin_relative(self):
        """Per draft Figure 3, `/.well-known/agent-card.json` and
        `/not-well-known/other-card.json` are valid values. Earlier the
        code would double-prefix the first into
        ``/.well-known/.well-known/agent-card.json`` and treat the
        second as a single segment. Now they're recognised as absolute
        origin paths and used as-is."""
        from dns_aid.core.discoverer import _query_single_agent

        cases = [
            (
                "/.well-known/agent-card.json",
                "https://chat.example.com/.well-known/agent-card.json",
            ),
            (
                "/not-well-known/other-card.json",
                "https://chat.example.com/not-well-known/other-card.json",
            ),
        ]

        async def _run_one_case(wk_value: str) -> list[str]:
            fake_rdata = MagicMock()
            fake_rdata.priority = 1
            fake_rdata.target = MagicMock()
            fake_rdata.target.__str__ = MagicMock(return_value="chat.example.com.")
            fake_rdata.params = {}
            fake_rdata.__str__ = MagicMock(
                return_value=(f'1 chat.example.com. alpn="mcp" port=443 well-known="{wk_value}"')
            )
            fake_answers = MagicMock()
            fake_answers.__iter__ = lambda self: iter([fake_rdata])

            captured: list[str] = []

            async def fake_fetch(url, expected_sha256=None):
                captured.append(url)
                return CapabilityDocument(
                    capabilities=["chat"], raw_data={"capabilities": ["chat"]}
                )

            with patch("dns_aid.core.discoverer.dns.asyncresolver") as mock_mod:
                resolver = MagicMock()
                resolver.resolve = AsyncMock(return_value=fake_answers)
                mock_mod.Resolver.return_value = resolver
                with patch(
                    "dns_aid.core.discoverer.fetch_cap_document",
                    side_effect=fake_fetch,
                ):
                    result = await _query_single_agent("example.com", "chat", Protocol.MCP)
            assert result is not None
            return captured

        for wk_value, expected_url in cases:
            captured = await _run_one_case(wk_value)
            assert captured == [expected_url], (
                f"expected {expected_url}, got {captured} for {wk_value}"
            )

    @pytest.mark.asyncio
    async def test_https_cap_wins_over_well_known_at_fetch_time(self):
        """When both `cap` (https-fetchable) and `well-known` are
        present, the cap URL is the one the discoverer actually fetches.

        Per Igor's #154 review: the precedence had only been proven at
        serialization (to_params/to_svcb_record) — this asserts it at
        fetch time, which is the load-bearing path."""
        from dns_aid.core.discoverer import _query_single_agent

        fake_rdata = MagicMock()
        fake_rdata.priority = 1
        fake_rdata.target = MagicMock()
        fake_rdata.target.__str__ = MagicMock(return_value="chat.example.com.")
        fake_rdata.params = {}
        fake_rdata.__str__ = MagicMock(
            return_value=(
                '1 chat.example.com. alpn="mcp" port=443 '
                'cap="https://cdn.example.com/cap.json" '
                'well-known="agent-card.json"'
            )
        )
        fake_answers = MagicMock()
        fake_answers.__iter__ = lambda self: iter([fake_rdata])

        captured: list[str] = []

        async def fake_fetch(url, expected_sha256=None):
            captured.append(url)
            return CapabilityDocument(capabilities=["chat"], raw_data={})

        with patch("dns_aid.core.discoverer.dns.asyncresolver") as mock_mod:
            resolver = MagicMock()
            resolver.resolve = AsyncMock(return_value=fake_answers)
            mock_mod.Resolver.return_value = resolver
            with patch(
                "dns_aid.core.discoverer.fetch_cap_document",
                side_effect=fake_fetch,
            ):
                result = await _query_single_agent("example.com", "chat", Protocol.MCP)

        assert result is not None
        # cap URL fetched, not the reconstructed well-known URL.
        assert captured == ["https://cdn.example.com/cap.json"]
        assert result.capability_source == "cap_uri"

    @pytest.mark.asyncio
    async def test_non_https_cap_falls_back_to_well_known(self):
        """When `cap` is a URN or JSON-Ref (non-https), treating it as
        terminal would silently disable a perfectly good `well-known`
        and downgrade discovery to unauthenticated TXT. Per Igor's #154
        review: fall through to well-known on non-https cap, keep the
        URN cap on the record as a metadata locator."""
        from dns_aid.core.discoverer import _query_single_agent

        fake_rdata = MagicMock()
        fake_rdata.priority = 1
        fake_rdata.target = MagicMock()
        fake_rdata.target.__str__ = MagicMock(return_value="chat.example.com.")
        fake_rdata.params = {}
        fake_rdata.__str__ = MagicMock(
            return_value=(
                '1 chat.example.com. alpn="mcp" port=443 '
                'cap="urn:dns-aid:cap:chat:v1" '
                'well-known="agent-card.json"'
            )
        )
        fake_answers = MagicMock()
        fake_answers.__iter__ = lambda self: iter([fake_rdata])

        captured: list[str] = []

        async def fake_fetch(url, expected_sha256=None):
            captured.append(url)
            return CapabilityDocument(capabilities=["chat"], raw_data={})

        with patch("dns_aid.core.discoverer.dns.asyncresolver") as mock_mod:
            resolver = MagicMock()
            resolver.resolve = AsyncMock(return_value=fake_answers)
            mock_mod.Resolver.return_value = resolver
            with patch(
                "dns_aid.core.discoverer.fetch_cap_document",
                side_effect=fake_fetch,
            ):
                result = await _query_single_agent("example.com", "chat", Protocol.MCP)

        assert result is not None
        # The well-known URL was used, not the URN cap.
        assert captured == ["https://chat.example.com/.well-known/agent-card.json"]
        assert result.capability_source == "well_known"
        # The cap URN stays on the record as a metadata locator.
        assert result.cap_uri == "urn:dns-aid:cap:chat:v1"

    @pytest.mark.asyncio
    async def test_cap_sha256_verified_true_only_when_fetch_succeeds(self):
        """The `cap_sha256_verified` flag is True only when the digest
        was actually checked against fetched bytes — distinguishes
        'integrity pin honoured' from 'pin declared but never applied'."""
        from dns_aid.core.discoverer import _query_single_agent

        fake_rdata = MagicMock()
        fake_rdata.priority = 1
        fake_rdata.target = MagicMock()
        fake_rdata.target.__str__ = MagicMock(return_value="chat.example.com.")
        fake_rdata.params = {}
        fake_rdata.__str__ = MagicMock(
            return_value=(
                '1 chat.example.com. alpn="mcp" port=443 '
                'well-known="agent-card.json" cap-sha256="DIGEST_HERE"'
            )
        )
        fake_answers = MagicMock()
        fake_answers.__iter__ = lambda self: iter([fake_rdata])

        async def fake_fetch(url, expected_sha256=None):
            return CapabilityDocument(capabilities=["chat"], raw_data={})

        with patch("dns_aid.core.discoverer.dns.asyncresolver") as mock_mod:
            resolver = MagicMock()
            resolver.resolve = AsyncMock(return_value=fake_answers)
            mock_mod.Resolver.return_value = resolver
            with patch(
                "dns_aid.core.discoverer.fetch_cap_document",
                side_effect=fake_fetch,
            ):
                result = await _query_single_agent("example.com", "chat", Protocol.MCP)

        assert result is not None
        assert result.cap_sha256 == "DIGEST_HERE"
        assert result.cap_sha256_verified is True

    @pytest.mark.asyncio
    async def test_cap_sha256_verified_false_when_dangling(self):
        """When `cap_sha256` is declared but no descriptor URL is
        constructible (no cap, no well-known), cap_sha256_verified
        stays False so consumers don't treat the declared pin as
        integrity-applied."""
        from dns_aid.core.discoverer import _query_single_agent

        fake_rdata = MagicMock()
        fake_rdata.priority = 1
        fake_rdata.target = MagicMock()
        fake_rdata.target.__str__ = MagicMock(return_value="chat.example.com.")
        fake_rdata.params = {}
        fake_rdata.__str__ = MagicMock(
            return_value=('1 chat.example.com. alpn="mcp" port=443 cap-sha256="ORPHANED"')
        )
        fake_answers = MagicMock()
        fake_answers.__iter__ = lambda self: iter([fake_rdata])

        with patch("dns_aid.core.discoverer.dns.asyncresolver") as mock_mod:
            resolver = MagicMock()
            resolver.resolve = AsyncMock(return_value=fake_answers)
            mock_mod.Resolver.return_value = resolver
            with patch(
                "dns_aid.core.discoverer.fetch_cap_document",
                AsyncMock(return_value=None),
            ):
                with patch(
                    "dns_aid.core.discoverer._query_capabilities",
                    AsyncMock(return_value=[]),
                ):
                    result = await _query_single_agent("example.com", "chat", Protocol.MCP)

        assert result is not None
        # Pin value present for transparency, but the verified flag is
        # False so consumers don't treat it as applied.
        assert result.cap_sha256 == "ORPHANED"
        assert result.cap_sha256_verified is False


class TestLegacyFallback:
    """Igor: legacy-fallback opt-in semantics are the migration proof.

    Behaviours under test:
      1. ``allow_legacy=True`` + flat miss → legacy query runs.
      2. ``allow_legacy=False`` → legacy never queried, even when env flag set.
      3. ``allow_legacy=None`` + env unset → legacy never queried (default).
      4. ``allow_legacy=None`` + env set → legacy queried (back-compat path).
      5. A record served via legacy → ``legacy_resolved=True`` stamped.
      6. Both flat and legacy miss → empty result.
    """

    @pytest.mark.asyncio
    async def test_explicit_allow_legacy_true_falls_back_on_miss(self, monkeypatch):
        from dns_aid.core.discoverer import _query_single_agent

        monkeypatch.delenv("DNS_AID_LEGACY_01_FALLBACK", raising=False)

        flat_calls: list[str] = []
        legacy_calls: list[str] = []

        async def fake_resolve(name, rtype):
            if "_chat._mcp._agents." in name:
                legacy_calls.append(name)
                fake_rdata = MagicMock()
                fake_rdata.priority = 1
                fake_rdata.target = MagicMock()
                fake_rdata.target.__str__ = MagicMock(return_value="chat.example.com.")
                fake_rdata.params = {}
                fake_rdata.__str__ = MagicMock(
                    return_value='1 chat.example.com. alpn="mcp" port=443'
                )
                fake = MagicMock()
                fake.__iter__ = lambda self: iter([fake_rdata])
                return fake
            flat_calls.append(name)
            raise dns.resolver.NXDOMAIN()

        resolver = MagicMock()
        resolver.resolve = fake_resolve
        with patch("dns_aid.core.discoverer.dns.asyncresolver") as mock_mod:
            mock_mod.Resolver.return_value = resolver
            result = await _query_single_agent(
                "example.com", "chat", Protocol.MCP, allow_legacy=True
            )

        assert flat_calls, "flat FQDN must be queried first"
        assert legacy_calls, "legacy form must be queried after flat miss"
        assert result is not None
        assert result.legacy_resolved is True

    @pytest.mark.asyncio
    async def test_explicit_allow_legacy_false_overrides_env(self, monkeypatch):
        from dns_aid.core.discoverer import _query_single_agent

        monkeypatch.setenv("DNS_AID_LEGACY_01_FALLBACK", "1")

        queried: list[str] = []

        async def fake_resolve(name, rtype):
            queried.append(name)
            raise dns.resolver.NXDOMAIN()

        resolver = MagicMock()
        resolver.resolve = fake_resolve
        with patch("dns_aid.core.discoverer.dns.asyncresolver") as mock_mod:
            mock_mod.Resolver.return_value = resolver
            result = await _query_single_agent(
                "example.com", "chat", Protocol.MCP, allow_legacy=False
            )

        assert result is None
        assert all("_chat._mcp._agents." not in n for n in queried), (
            "allow_legacy=False must override the env flag and skip the legacy query"
        )

    @pytest.mark.asyncio
    async def test_default_off_without_env_does_not_query_legacy(self, monkeypatch):
        from dns_aid.core.discoverer import _query_single_agent

        monkeypatch.delenv("DNS_AID_LEGACY_01_FALLBACK", raising=False)

        queried: list[str] = []

        async def fake_resolve(name, rtype):
            queried.append(name)
            raise dns.resolver.NXDOMAIN()

        resolver = MagicMock()
        resolver.resolve = fake_resolve
        with patch("dns_aid.core.discoverer.dns.asyncresolver") as mock_mod:
            mock_mod.Resolver.return_value = resolver
            result = await _query_single_agent("example.com", "chat", Protocol.MCP)

        assert result is None
        assert all("_chat._mcp._agents." not in n for n in queried)

    @pytest.mark.asyncio
    async def test_env_var_still_triggers_legacy_for_back_compat(self, monkeypatch):
        from dns_aid.core.discoverer import _query_single_agent

        monkeypatch.setenv("DNS_AID_LEGACY_01_FALLBACK", "1")

        queried: list[str] = []

        async def fake_resolve(name, rtype):
            queried.append(name)
            raise dns.resolver.NXDOMAIN()

        resolver = MagicMock()
        resolver.resolve = fake_resolve
        with patch("dns_aid.core.discoverer.dns.asyncresolver") as mock_mod:
            mock_mod.Resolver.return_value = resolver
            await _query_single_agent("example.com", "chat", Protocol.MCP)

        assert any(n == "chat.example.com" for n in queried)
        assert any("_chat._mcp._agents." in n for n in queried)


class TestPerAgentDnssec:
    """Under draft-02 each agent has its own flat fqdn, so DNSSEC must
    be validated per agent — not once for ``agents[0]`` with the result
    stamped on every record. Two behaviours under test:

      1. ``_apply_post_discovery`` checks each agent independently and
         stamps ``dnssec_validated`` per-agent.
      2. The result-level boolean it returns is True only if every
         agent's owner-name validated. A partial-fail result-level says
         False, AND raises (since require_dnssec is set in this path).
    """

    @pytest.mark.asyncio
    async def test_per_agent_stamps_each_record(self):
        """Each agent's fqdn is checked; per-agent dnssec_validated reflects own outcome."""
        from dns_aid.core.discoverer import _apply_post_discovery
        from dns_aid.core.models import AgentRecord, Protocol

        agent_a = AgentRecord(
            name="chat",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="chat.example.com",
        )
        agent_b = AgentRecord(
            name="search",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="search.example.com",
        )

        with patch(
            "dns_aid.core.validator._check_dnssec",
            new_callable=AsyncMock,
            return_value=True,
        ):
            result_level = await _apply_post_discovery(
                [agent_a, agent_b],
                require_dnssec=True,
                enrich_endpoints=False,
                verify_signatures=False,
                domain="example.com",
            )

        assert result_level is True
        assert agent_a.dnssec_validated is True
        assert agent_b.dnssec_validated is True

    @pytest.mark.asyncio
    async def test_partial_failure_raises_and_names_failed(self):
        """One agent validates, the other doesn't → require_dnssec must raise."""
        from dns_aid.core.discoverer import _apply_post_discovery
        from dns_aid.core.models import AgentRecord, DNSSECError, Protocol

        agent_a = AgentRecord(
            name="chat",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="chat.example.com",
        )
        agent_b = AgentRecord(
            name="search",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="search.example.com",
        )

        async def selective_check(fqdn):
            return fqdn == "chat.example.com"

        with patch(
            "dns_aid.core.validator._check_dnssec",
            new=selective_check,
        ):
            with pytest.raises(DNSSECError) as excinfo:
                await _apply_post_discovery(
                    [agent_a, agent_b],
                    require_dnssec=True,
                    enrich_endpoints=False,
                    verify_signatures=False,
                    domain="example.com",
                )

        import re

        msg = str(excinfo.value)
        assert re.search(r"\bsearch\.example\.com\b", msg)
        assert not re.search(r"\bchat\.example\.com\b", msg)


class TestCapSha256HardFail:
    """Draft §6.1: a cap-sha256 digest mismatch MUST cause the consumer
    to refuse the record. Earlier the discoverer silently downgraded to
    TXT fallback while still stamping cap_sha256 on the record, letting
    an attacker swap the descriptor while keeping the SVCB pin intact
    and have the record look integrity-pinned.

    The cap_sha256_verified field (added in #154's deferred work) is
    the explicit consumer signal; this test class covers the
    drop-on-mismatch contract."""

    @pytest.mark.asyncio
    async def test_digest_mismatch_drops_record(self):
        """Mismatched cap-sha256 → _query_single_agent returns None."""
        from dns_aid.core.cap_fetcher import CapDigestMismatchError
        from dns_aid.core.discoverer import _query_single_agent

        fake_rdata = MagicMock()
        fake_rdata.priority = 1
        fake_rdata.target = MagicMock()
        fake_rdata.target.__str__ = MagicMock(return_value="chat.example.com.")
        fake_rdata.params = {}
        fake_rdata.__str__ = MagicMock(
            return_value=(
                '1 chat.example.com. alpn="mcp" port=443 '
                'cap="https://chat.example.com/cap.json" '
                'cap-sha256="EXPECTED_BUT_WRONG"'
            )
        )

        fake_answers = MagicMock()
        fake_answers.__iter__ = lambda self: iter([fake_rdata])

        with patch("dns_aid.core.discoverer.dns.asyncresolver") as mock_resolver_mod:
            resolver = MagicMock()
            resolver.resolve = AsyncMock(return_value=fake_answers)
            mock_resolver_mod.Resolver.return_value = resolver

            with patch(
                "dns_aid.core.discoverer.fetch_cap_document",
                side_effect=CapDigestMismatchError(
                    "https://chat.example.com/cap.json",
                    "EXPECTED_BUT_WRONG",
                    "actual_digest_value",
                ),
            ):
                result = await _query_single_agent("example.com", "chat", Protocol.MCP)

        assert result is None, "digest mismatch must cause the record to be refused"


class TestCapabilitySourceProvenance:
    """Regression — PR #154 v2 review item 5.

    The trust hierarchy (most → least: cap_uri > well_known >
    agent_card > http_index > txt_fallback) is recorded on the
    record via ``capability_source``. Enrichment (_apply_agent_card)
    must not erase a higher-trust source by overwriting with
    ``agent_card``.
    """

    def test_apply_agent_card_preserves_well_known_source(self):
        """``_apply_agent_card`` must NOT overwrite a well_known
        provenance with ``agent_card``. Before the v2 fix, only
        ``cap_uri`` was preserved, so a record whose descriptor was
        fetched via the SVCB ``well-known`` SvcParamKey would be
        relabelled to ``agent_card`` after enrichment — losing the
        spec-mandated locator's provenance."""
        from dns_aid.core.a2a_card import A2AAgentCard, A2ASkill
        from dns_aid.core.discoverer import _apply_agent_card
        from dns_aid.core.models import AgentRecord, Protocol

        agent = AgentRecord(
            name="chat",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="chat.example.com",
            port=443,
            capabilities=["preexisting"],
            capability_source="well_known",
        )
        card = A2AAgentCard(
            name="chat",
            description="",
            url="https://chat.example.com",
            version="1.0.0",
            skills=[A2ASkill(id="payments", name="Payments", description="", tags=[])],
        )

        _apply_agent_card(agent, card)

        assert agent.capability_source == "well_known", (
            "well_known provenance must survive _apply_agent_card; see PR #154 v2 review item 5"
        )

    def test_apply_agent_card_preserves_cap_uri_source(self):
        """Existing pre-v2 invariant: cap_uri provenance survives."""
        from dns_aid.core.a2a_card import A2AAgentCard, A2ASkill
        from dns_aid.core.discoverer import _apply_agent_card
        from dns_aid.core.models import AgentRecord, Protocol

        agent = AgentRecord(
            name="chat",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="chat.example.com",
            port=443,
            capabilities=["preexisting"],
            capability_source="cap_uri",
        )
        card = A2AAgentCard(
            name="chat",
            description="",
            url="https://chat.example.com",
            version="1.0.0",
            skills=[A2ASkill(id="payments", name="Payments", description="", tags=[])],
        )

        _apply_agent_card(agent, card)

        assert agent.capability_source == "cap_uri"

    def test_apply_agent_card_upgrades_txt_fallback(self):
        """The override SHOULD still fire for lower-trust sources
        (txt_fallback, http_index) — those are weaker than the
        agent_card skill data."""
        from dns_aid.core.a2a_card import A2AAgentCard, A2ASkill
        from dns_aid.core.discoverer import _apply_agent_card
        from dns_aid.core.models import AgentRecord, Protocol

        agent = AgentRecord(
            name="chat",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="chat.example.com",
            port=443,
            capabilities=["txt-only"],
            capability_source="txt_fallback",
        )
        card = A2AAgentCard(
            name="chat",
            description="",
            url="https://chat.example.com",
            version="1.0.0",
            skills=[A2ASkill(id="payments", name="Payments", description="", tags=[])],
        )

        _apply_agent_card(agent, card)

        assert agent.capability_source == "agent_card"
