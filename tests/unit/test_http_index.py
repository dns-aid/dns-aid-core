# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for HTTP Index discovery (ANS-style compatibility)."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from dns_aid.core.http_index import (
    Capability,
    HttpIndexAgent,
    HttpIndexError,
    ModelCard,
    fetch_http_index,
    fetch_http_index_or_empty,
    parse_http_index,
)


def _stream_response(payload, status: int = 200):
    """A mock httpx streaming response (async CM) yielding `payload` as JSON bytes.

    fetch_http_index now streams the body with a size cap instead of calling
    ``response.json()``, so tests provide the body via ``aiter_bytes``.
    """
    body = payload if isinstance(payload, (bytes, bytearray)) else json.dumps(payload).encode()

    async def _aiter_bytes():
        yield bytes(body)

    resp = MagicMock()
    resp.status_code = status
    resp.is_redirect = 300 <= status < 400
    resp.aiter_bytes = _aiter_bytes
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=resp)
    cm.__aexit__ = AsyncMock(return_value=None)
    return cm


def _streaming_client(*responses):
    """Mock httpx.AsyncClient whose .stream() yields each response in order."""
    mock_client = MagicMock()
    if len(responses) == 1:
        mock_client.stream = MagicMock(return_value=responses[0])
    else:
        mock_client.stream = MagicMock(side_effect=list(responses))
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=None)
    return mock_client


class TestModelCard:
    """Tests for ModelCard dataclass."""

    def test_from_dict_empty(self):
        """Test parsing empty dict."""
        model_card = ModelCard.from_dict({})
        assert model_card.description is None
        assert model_card.provider is None

    def test_from_dict_none(self):
        """Test parsing None."""
        model_card = ModelCard.from_dict(None)
        assert model_card.description is None

    def test_from_dict_full(self):
        """Test parsing full model card."""
        data = {
            "description": "A travel booking agent",
            "provider": "Example Corp",
            "version": "2.0",
            "license": "MIT",
            "documentation_url": "https://docs.example.com",
        }
        model_card = ModelCard.from_dict(data)

        assert model_card.description == "A travel booking agent"
        assert model_card.provider == "Example Corp"
        assert model_card.version == "2.0"
        assert model_card.license == "MIT"
        assert model_card.documentation_url == "https://docs.example.com"

    def test_from_dict_camel_case(self):
        """Test parsing camelCase keys (ANS compatibility)."""
        data = {"documentationUrl": "https://docs.example.com"}
        model_card = ModelCard.from_dict(data)

        assert model_card.documentation_url == "https://docs.example.com"


class TestCapability:
    """Tests for Capability dataclass."""

    def test_from_dict_empty(self):
        """Test parsing empty dict."""
        capability = Capability.from_dict({})
        assert capability.modality is None
        assert capability.protocols == []

    def test_from_dict_none(self):
        """Test parsing None."""
        capability = Capability.from_dict(None)
        assert capability.protocols == []

    def test_from_dict_full(self):
        """Test parsing full capability."""
        data = {
            "modality": "text",
            "protocols": ["mcp", "a2a"],
            "cost": "free",
            "rate_limit": "100/min",
            "authentication": "api_key",
        }
        capability = Capability.from_dict(data)

        assert capability.modality == "text"
        assert capability.protocols == ["mcp", "a2a"]
        assert capability.cost == "free"
        assert capability.rate_limit == "100/min"
        assert capability.authentication == "api_key"

    def test_from_dict_protocols_string(self):
        """Test protocols as single string."""
        data = {"protocols": "mcp"}
        capability = Capability.from_dict(data)

        assert capability.protocols == ["mcp"]

    def test_from_dict_camel_case(self):
        """Test parsing camelCase keys."""
        data = {"rateLimit": "50/hour"}
        capability = Capability.from_dict(data)

        assert capability.rate_limit == "50/hour"


class TestHttpIndexAgent:
    """Tests for HttpIndexAgent dataclass."""

    def test_from_dict_stakeholder_format(self):
        """Test parsing stakeholder JSON format."""
        data = {
            "location": {"fqdn": "travel._mcp._agents.example.com"},
            "model-card": {"description": "A travel booking agent"},
            "capability": {
                "modality": "text",
                "protocols": ["mcp"],
                "cost": "free",
            },
        }
        agent = HttpIndexAgent.from_dict("travel-agent", data)

        assert agent.name == "travel-agent"
        assert agent.fqdn == "travel._mcp._agents.example.com"
        assert agent.description == "A travel booking agent"
        assert agent.protocols == ["mcp"]
        assert agent.modality == "text"
        assert agent.cost == "free"

    def test_from_dict_minimal(self):
        """Test parsing minimal data."""
        data = {"location": {"fqdn": "agent.example.com"}}
        agent = HttpIndexAgent.from_dict("minimal", data)

        assert agent.name == "minimal"
        assert agent.fqdn == "agent.example.com"
        assert agent.description is None
        assert agent.protocols == []

    def test_primary_protocol(self):
        """Test primary_protocol property."""
        agent = HttpIndexAgent(
            name="test",
            fqdn="test.example.com",
            protocols=["mcp", "a2a"],
        )
        assert agent.primary_protocol == "mcp"

    def test_primary_protocol_empty(self):
        """Test primary_protocol with no protocols."""
        agent = HttpIndexAgent(name="test", fqdn="test.example.com")
        assert agent.primary_protocol is None

    def test_to_index_entry_format(self):
        """Test conversion to index entry format."""
        agent = HttpIndexAgent(
            name="chat",
            fqdn="chat.example.com",
            protocols=["mcp"],
        )
        assert agent.to_index_entry_format() == "chat:mcp"

    def test_to_index_entry_format_default_protocol(self):
        """Test conversion with no protocol defaults to https."""
        agent = HttpIndexAgent(name="web", fqdn="web.example.com")
        assert agent.to_index_entry_format() == "web:https"


class TestParseHttpIndex:
    """Tests for parse_http_index function."""

    def test_parse_stakeholder_format(self):
        """Test parsing stakeholder example format."""
        data = {
            "travel-agent": {
                "location": {"fqdn": "travel.example.com"},
                "model-card": {"description": "Travel booking"},
                "capability": {"modality": "text", "cost": "free"},
            },
            "paint-agent": {
                "location": {"fqdn": "paint.example.com"},
                "model-card": {"description": "Paint ordering"},
                "capability": {"modality": "text", "cost": "paid"},
            },
        }
        agents = parse_http_index(data)

        assert len(agents) == 2
        names = {a.name for a in agents}
        assert "travel-agent" in names
        assert "paint-agent" in names

    def test_parse_nested_agents_key(self):
        """Test parsing with nested 'agents' key."""
        data = {
            "agents": {
                "booking": {
                    "location": {"fqdn": "booking.example.com"},
                }
            }
        }
        agents = parse_http_index(data)

        assert len(agents) == 1
        assert agents[0].name == "booking"

    def test_parse_skips_invalid_entries(self):
        """Test that invalid entries are skipped."""
        data = {
            "valid-agent": {"location": {"fqdn": "valid.example.com"}},
            "invalid-agent": {"location": {}},  # No FQDN
            "metadata": "not-an-agent",  # Non-dict value
        }
        agents = parse_http_index(data)

        assert len(agents) == 1
        assert agents[0].name == "valid-agent"

    def test_parse_empty(self):
        """Test parsing empty dict."""
        agents = parse_http_index({})
        assert agents == []


class TestFetchHttpIndex:
    """Tests for fetch_http_index function."""

    @pytest.mark.asyncio
    async def test_fetch_success(self):
        """Test successful fetch."""
        mock_client = _streaming_client(
            _stream_response({"booking": {"location": {"fqdn": "booking.example.com"}}})
        )

        with patch("dns_aid.core.http_index.httpx.AsyncClient", return_value=mock_client):
            agents = await fetch_http_index("example.com")

        assert len(agents) == 1
        assert agents[0].name == "booking"

    @pytest.mark.asyncio
    async def test_fetch_tries_multiple_endpoints(self):
        """Test that multiple URL patterns are tried."""
        # First pattern (ANS-style subdomain) 404s, second pattern succeeds.
        mock_client = _streaming_client(
            _stream_response(None, status=404),
            _stream_response({"agent": {"location": {"fqdn": "agent.example.com"}}}),
        )

        with patch("dns_aid.core.http_index.httpx.AsyncClient", return_value=mock_client):
            agents = await fetch_http_index("example.com")

        assert len(agents) == 1
        assert mock_client.stream.call_count == 2  # first pattern failed, second succeeded

    @pytest.mark.asyncio
    async def test_fetch_all_endpoints_fail(self):
        """Test error when all endpoints fail."""
        mock_response = MagicMock()
        mock_response.status_code = 404

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("dns_aid.core.http_index.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(HttpIndexError) as excinfo:
                await fetch_http_index("example.com")

        assert "No HTTP index found at example.com" in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_fetch_timeout(self):
        """Test timeout handling."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("Timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("dns_aid.core.http_index.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(HttpIndexError):
                await fetch_http_index("example.com")

    @pytest.mark.asyncio
    async def test_fetch_connection_error(self):
        """Test connection error handling."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("dns_aid.core.http_index.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(HttpIndexError):
                await fetch_http_index("example.com")


class TestFetchHttpIndexOrEmpty:
    """Tests for fetch_http_index_or_empty function."""

    @pytest.mark.asyncio
    async def test_returns_agents_on_success(self):
        """Test returns agents on success."""
        mock_client = _streaming_client(
            _stream_response({"test": {"location": {"fqdn": "test.example.com"}}})
        )

        with patch("dns_aid.core.http_index.httpx.AsyncClient", return_value=mock_client):
            agents = await fetch_http_index_or_empty("example.com")

        assert len(agents) == 1

    @pytest.mark.asyncio
    async def test_returns_empty_on_failure(self):
        """Test returns empty list on failure."""
        mock_response = MagicMock()
        mock_response.status_code = 404

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("dns_aid.core.http_index.httpx.AsyncClient", return_value=mock_client):
            agents = await fetch_http_index_or_empty("example.com")

        assert agents == []

    @pytest.mark.asyncio
    async def test_returns_empty_on_exception(self):
        """Test returns empty list on unexpected exception."""
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=Exception("Unexpected error"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("dns_aid.core.http_index.httpx.AsyncClient", return_value=mock_client):
            agents = await fetch_http_index_or_empty("example.com")

        assert agents == []


class TestIntegrationWithDiscoverer:
    """Integration tests with the discoverer module."""

    @pytest.mark.asyncio
    async def test_discover_with_http_index(self, mock_backend):
        """Test discover() with use_http_index=True."""
        from dns_aid.core.discoverer import discover

        # Mock HTTP response (streamed body)
        mock_client = _streaming_client(
            _stream_response(
                {
                    "booking": {
                        "location": {"fqdn": "_booking._mcp._agents.example.com"},
                        "model-card": {"description": "Booking agent"},
                        "capability": {"protocols": ["mcp"]},
                    }
                }
            )
        )

        with patch("dns_aid.core.http_index.httpx.AsyncClient", return_value=mock_client):
            result = await discover("example.com", use_http_index=True)

        # Query string shows ANS-style endpoint
        assert result.query == "https://_index._aiagents.example.com/index-wellknown"
        # Even if DNS fails, we get agents from HTTP index with fallback data
        assert result.count >= 1

    @pytest.mark.asyncio
    async def test_discover_http_index_query_format(self, mock_backend):
        """Test that HTTP index sets correct query string."""
        from dns_aid.core.discoverer import discover

        mock_response = MagicMock()
        mock_response.status_code = 404

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)

        with patch("dns_aid.core.http_index.httpx.AsyncClient", return_value=mock_client):
            result = await discover("example.com", use_http_index=True)

        # Query string shows ANS-style endpoint
        assert "_index._aiagents.example.com/index-wellknown" in result.query


# ---------------------------------------------------------------------------
# ARD ai-catalog support (spec 007 — https://agenticresourcediscovery.org/spec/)
# ---------------------------------------------------------------------------

from pathlib import Path  # noqa: E402

from dns_aid.core.http_index import (  # noqa: E402
    _MAX_ARD_DEPTH,
    _MAX_HTTP_INDEX_AGENTS,
    HTTP_INDEX_PATTERNS,
    _is_ard_catalog,
    _name_from_urn,
    _protocol_from_media_type,
)

_FIXTURES = Path(__file__).parent.parent / "fixtures"


def _canonical_catalog() -> dict:
    """The ARD spec §4.1 canonical example catalog."""
    return json.loads((_FIXTURES / "ard_catalog_canonical.json").read_text())


def _ard_agent_entry(name: str = "weather", **overrides) -> dict:
    """A minimal valid ARD MCP agent entry."""
    entry = {
        "identifier": f"urn:air:acme.com:server:{name}",
        "displayName": f"{name} agent",
        "type": "application/mcp-server-card+json",
        "url": f"https://api.acme.com/mcp/{name}.json",
    }
    entry.update(overrides)
    return entry


def _ard_catalog(entries: list[dict]) -> dict:
    return {"specVersion": "1.0", "entries": entries}


class TestArdDetection:
    """ARD document detection (contract C2)."""

    def test_detects_ard_shape(self):
        assert _is_ard_catalog(_ard_catalog([]))
        assert _is_ard_catalog(_canonical_catalog())

    def test_rejects_unknown_spec_version(self):
        assert not _is_ard_catalog({"specVersion": "2.0", "entries": []})
        assert not _is_ard_catalog({"specVersion": 1.0, "entries": []})

    def test_rejects_entries_not_a_list(self):
        assert not _is_ard_catalog({"specVersion": "1.0", "entries": {}})
        assert not _is_ard_catalog({"specVersion": "1.0"})

    def test_rejects_legacy_shapes(self):
        assert not _is_ard_catalog({"booking": {"location": {"fqdn": "x"}}})
        assert not _is_ard_catalog({"agents": {"booking": {}}})

    def test_parse_http_index_routes_ard(self):
        agents = parse_http_index(_ard_catalog([_ard_agent_entry()]))
        assert len(agents) == 1
        assert agents[0].source_format == "ard"

    def test_unknown_spec_version_falls_through_to_legacy(self):
        # Not ARD → legacy loop → no keyed-object agents → empty, no error.
        agents = parse_http_index({"specVersion": "2.0", "entries": [_ard_agent_entry()]})
        assert agents == []


class TestArdBackwardCompat:
    """Legacy formats must behave byte-identically (contract C6)."""

    def test_legacy_direct_format_unchanged(self):
        data = {
            "booking": {
                "location": {"fqdn": "_booking._mcp._agents.example.com"},
                "model-card": {"description": "Booking agent"},
                "capability": {"protocols": ["mcp"]},
            }
        }
        agents = parse_http_index(data)
        assert len(agents) == 1
        assert agents[0].name == "booking"
        assert agents[0].source_format == "legacy"
        assert agents[0].trust_manifest is None

    def test_pattern_order_preserved_ard_appended_last(self):
        assert len(HTTP_INDEX_PATTERNS) == 5
        assert HTTP_INDEX_PATTERNS[0]["host"] == "index.aiagents.{domain}"
        assert HTTP_INDEX_PATTERNS[3]["path"] == "/.well-known/agents.json"
        assert HTTP_INDEX_PATTERNS[4]["path"] == "/.well-known/ai-catalog.json"
        assert HTTP_INDEX_PATTERNS[4]["type"] == "ard_well_known"


class TestArdEntryMapping:
    """CatalogEntry → HttpIndexAgent mapping (contracts C3/C4)."""

    def test_canonical_example_yields_exactly_its_agents(self):
        agents = parse_http_index(_canonical_catalog())
        by_name = {a.name: a for a in agents}
        # SC-005: exactly the 3 agent entries; registry, dataset and
        # URL-only nested catalog skipped.
        assert set(by_name) == {"assistant", "weather", "a2a"}
        assert by_name["assistant"].primary_protocol == "a2a"
        assert by_name["weather"].primary_protocol == "mcp"
        assert by_name["weather"].fqdn == "api.acme.com"
        # ARD `url` is a card locator (§3.4), captured as card_url — NOT endpoint.
        assert by_name["weather"].card_url == "https://api.acme.com/mcp/weather.json"
        assert by_name["weather"].endpoint is None
        assert by_name["weather"].capability.capabilities == ["WeatherTool", "ForecastTool"]
        assert by_name["weather"].identifier == "urn:air:acme.com:server:weather"
        assert len(by_name["weather"].use_cases) == 2

    def test_protocol_mapping(self):
        assert _protocol_from_media_type("application/mcp-server-card+json") == "mcp"
        assert _protocol_from_media_type("application/a2a-agent-card+json") == "a2a"
        assert _protocol_from_media_type("application/parquet") is None

    def test_name_from_urn(self):
        assert _name_from_urn("urn:air:acme.com:server:weather") == ("weather", "acme.com")
        # Namespace segment optional; URN charset normalized to DNS label
        assert _name_from_urn("urn:air:hf.co:Alice_dev.Agent") == ("alice-dev-agent", "hf.co")
        assert _name_from_urn("not-a-urn") == (None, None)
        assert _name_from_urn("urn:air:acme.com") == (None, None)

    def test_description_falls_back_to_display_name(self):
        entry = _ard_agent_entry()
        del entry["url"]
        entry["data"] = {"some": "card"}
        agents = parse_http_index(_ard_catalog([entry]))
        assert agents[0].description == "weather agent"
        # Inline artifact → fqdn from URN publisher domain
        assert agents[0].fqdn == "acme.com"
        assert agents[0].endpoint is None
        # Inline card captured as card_data (no url locator).
        assert agents[0].card_data == {"some": "card"}
        assert agents[0].card_url is None

    def test_version_maps_to_model_card(self):
        agents = parse_http_index(_ard_catalog([_ard_agent_entry(version="2.1.0")]))
        assert agents[0].model_card.version == "2.1.0"


class TestArdTrustManifest:
    """trustManifest preservation through the pipeline (contract C5)."""

    SPIFFE_MANIFEST = {
        "identity": "spiffe://acme.com/agents/weather",
        "identityType": "spiffe",
        "attestations": [
            {"type": "SOC2-Type2", "uri": "https://trust.acme.com/soc2.pdf"},
            {
                "type": "ISO27001",
                "uri": "https://trust.acme.com/iso.pdf",
                "mediaType": "application/pdf",
                "digest": "abc123",
            },
        ],
        "provenance": [{"relation": "publishedFrom", "sourceId": "urn:air:acme.com:src:repo"}],
        "signature": "eyJhbGciOi..detached..",
    }

    def test_raw_manifest_preserved_on_transport_dto(self):
        entry = _ard_agent_entry(trustManifest=self.SPIFFE_MANIFEST)
        agents = parse_http_index(_ard_catalog([entry]))
        assert agents[0].trust_manifest == self.SPIFFE_MANIFEST

    def test_validated_manifest_on_agent_record(self):
        from dns_aid.core.discoverer import _http_agent_to_record
        from dns_aid.core.models import Protocol

        entry = _ard_agent_entry(trustManifest=self.SPIFFE_MANIFEST)
        http_agent = parse_http_index(_ard_catalog([entry]))[0]
        record = _http_agent_to_record(http_agent, "acme.com", http_agent.name, Protocol.MCP)
        assert record is not None
        tm = record.trust_manifest
        assert tm is not None
        assert tm.identity == "spiffe://acme.com/agents/weather"
        assert tm.identity_type == "spiffe"
        assert [a.type for a in tm.attestations] == ["SOC2-Type2", "ISO27001"]
        # mediaType optional on read (spec discrepancy)
        assert tm.attestations[0].media_type is None
        assert tm.attestations[1].media_type == "application/pdf"
        assert tm.provenance[0].relation == "publishedFrom"
        assert tm.signature == "eyJhbGciOi..detached.."
        # Provenance marker (FR-008) + serialization surface (CLI/MCP --json)
        assert record.capability_source == "ard_catalog"
        assert record.model_dump()["trust_manifest"]["identity"] == (
            "spiffe://acme.com/agents/weather"
        )

    def test_absent_manifest_is_none(self):
        from dns_aid.core.discoverer import _http_agent_to_record
        from dns_aid.core.models import Protocol

        http_agent = parse_http_index(_ard_catalog([_ard_agent_entry()]))[0]
        record = _http_agent_to_record(http_agent, "acme.com", http_agent.name, Protocol.MCP)
        assert record.trust_manifest is None
        assert record.capability_source == "ard_catalog"

    def test_malformed_manifest_keeps_agent(self):
        from dns_aid.core.discoverer import _http_agent_to_record
        from dns_aid.core.models import Protocol

        entry = _ard_agent_entry(trustManifest={"identityType": "spiffe"})  # no identity
        http_agent = parse_http_index(_ard_catalog([entry]))[0]
        record = _http_agent_to_record(http_agent, "acme.com", http_agent.name, Protocol.MCP)
        assert record is not None
        assert record.trust_manifest is None


class TestArdIdentityAlignment:
    """ARD alignment rule: trust domain MUST align with the URN publisher."""

    def test_identity_domain_extraction(self):
        from dns_aid.core.http_index import _ard_identity_domain

        assert _ard_identity_domain("spiffe://acme.com/agents/x") == "acme.com"
        assert _ard_identity_domain("spiffe://sub.acme.com:8443/x") == "sub.acme.com"
        assert _ard_identity_domain("https://acme.com/.well-known/id") == "acme.com"
        assert _ard_identity_domain("did:web:acme.com") == "acme.com"
        assert _ard_identity_domain("did:web:acme.com:users:alice") == "acme.com"
        assert _ard_identity_domain("did:web:acme.com%3A8443:x") == "acme.com"
        assert _ard_identity_domain("did:key:z6Mkf...") is None  # unparseable scheme
        assert _ard_identity_domain("urn:whatever") is None

    def test_domains_aligned(self):
        from dns_aid.core.http_index import _ard_domains_aligned

        assert _ard_domains_aligned("acme.com", "acme.com")
        assert _ard_domains_aligned("spiffe-td.acme.com", "acme.com")  # subdomain of publisher
        assert _ard_domains_aligned("acme.com", "agents.acme.com")  # publisher under trust domain
        assert not _ard_domains_aligned("evil.com", "acme.com")
        assert not _ard_domains_aligned("notacme.com", "acme.com")  # no suffix trickery

    def _record_for(self, trust_manifest: dict):
        from dns_aid.core.discoverer import _http_agent_to_record
        from dns_aid.core.models import Protocol

        entry = _ard_agent_entry(trustManifest=trust_manifest)
        http_agent = parse_http_index(_ard_catalog([entry]))[0]
        return _http_agent_to_record(http_agent, "acme.com", http_agent.name, Protocol.MCP)

    def test_aligned_identity_no_warning(self):
        from dns_aid.core import discoverer as disc

        with patch.object(disc.logger, "warning") as warn:
            record = self._record_for({"identity": "spiffe://acme.com/agents/weather"})
        assert record.trust_manifest is not None
        events = [c.args[0] for c in warn.call_args_list]
        assert "http_index.ard_trust_identity_mismatch" not in events

    def test_mismatched_identity_warns_but_passes_through(self):
        from dns_aid.core import discoverer as disc

        with patch.object(disc.logger, "warning") as warn:
            record = self._record_for({"identity": "spiffe://evil.com/agents/weather"})
        # Pass-through preserved — the manifest is NOT dropped (warning-only)
        assert record.trust_manifest is not None
        assert record.trust_manifest.identity == "spiffe://evil.com/agents/weather"
        events = [c.args[0] for c in warn.call_args_list]
        assert "http_index.ard_trust_identity_mismatch" in events
        kwargs = next(
            c.kwargs
            for c in warn.call_args_list
            if c.args[0] == "http_index.ard_trust_identity_mismatch"
        )
        assert kwargs["identity_domain"] == "evil.com"
        assert kwargs["publisher"] == "acme.com"

    def test_unparseable_identity_scheme_skips_check(self):
        from dns_aid.core import discoverer as disc

        with patch.object(disc.logger, "warning") as warn:
            record = self._record_for({"identity": "did:key:z6MkfDx", "identityType": "other"})
        assert record.trust_manifest is not None
        events = [c.args[0] for c in warn.call_args_list]
        assert "http_index.ard_trust_identity_mismatch" not in events

    def test_userinfo_spoofing_does_not_suppress_warning(self):
        """`spiffe://acme.com:1@evil.com` must resolve to evil.com, not acme.com."""
        from dns_aid.core import discoverer as disc

        with patch.object(disc.logger, "warning") as warn:
            self._record_for({"identity": "spiffe://acme.com:1@evil.com/ns/agent"})
        kwargs = next(
            c.kwargs
            for c in warn.call_args_list
            if c.args[0] == "http_index.ard_trust_identity_mismatch"
        )
        assert kwargs["identity_domain"] == "evil.com"

    def test_userinfo_extraction_direct(self):
        from dns_aid.core.http_index import _ard_identity_domain

        assert _ard_identity_domain("spiffe://acme.com:1@evil.com/x") == "evil.com"
        assert _ard_identity_domain("https://acme.com:443@evil.com/x") == "evil.com"
        assert _ard_identity_domain("spiffe://acme.com@evil.com/x") == "evil.com"

    def test_foreign_publisher_warns_against_serving_domain(self):
        """A catalog served by evil.com asserting an acme.com URN is flagged."""
        from dns_aid.core import discoverer as disc
        from dns_aid.core.models import Protocol

        # URN publisher = acme.com, identity = acme.com (internally consistent),
        # but the catalog was served from evil.com.
        entry = _ard_agent_entry(trustManifest={"identity": "spiffe://acme.com/agents/weather"})
        http_agent = parse_http_index(_ard_catalog([entry]))[0]
        with patch.object(disc.logger, "warning") as warn:
            record = disc._http_agent_to_record(
                http_agent, "evil.com", http_agent.name, Protocol.MCP
            )
        assert record.trust_manifest is not None  # still pass-through
        events = [c.args[0] for c in warn.call_args_list]
        assert "http_index.ard_trust_foreign_publisher" in events
        # Internally consistent, so the identity-vs-publisher check stays quiet
        assert "http_index.ard_trust_identity_mismatch" not in events

    def test_self_published_no_foreign_warning(self):
        from dns_aid.core import discoverer as disc
        from dns_aid.core.models import Protocol

        entry = _ard_agent_entry(trustManifest={"identity": "spiffe://acme.com/agents/weather"})
        http_agent = parse_http_index(_ard_catalog([entry]))[0]
        with patch.object(disc.logger, "warning") as warn:
            disc._http_agent_to_record(http_agent, "acme.com", http_agent.name, Protocol.MCP)
        events = [c.args[0] for c in warn.call_args_list]
        assert "http_index.ard_trust_foreign_publisher" not in events


class TestArdHardening:
    """Resource / log-flood hardening on untrusted catalogs (production)."""

    def test_entry_cap_bounds_total_work(self):
        from dns_aid.core.http_index import _MAX_ARD_ENTRIES

        # All-invalid entries never append an agent, but must not iterate
        # (or log) unboundedly — total entries seen is capped.
        entries = [
            {"type": "application/mcp-server-card+json"} for _ in range(_MAX_ARD_ENTRIES + 500)
        ]
        assert parse_http_index(_ard_catalog(entries)) == []

    def test_skip_warnings_aggregated_not_per_entry(self):
        import dns_aid.core.http_index as hi

        entries = [{"type": "application/mcp-server-card+json"} for _ in range(50)]
        with patch.object(hi.logger, "warning") as warn:
            parse_http_index(_ard_catalog(entries))
        # Exactly ONE aggregated summary, not 50 lines
        skip_events = [
            c for c in warn.call_args_list if c.args[0] == "http_index.ard_entries_skipped"
        ]
        assert len(skip_events) == 1
        assert skip_events[0].kwargs["by_reason"]["missing_required"] == 50
        assert skip_events[0].kwargs["skipped_total"] == 50

    def test_logged_identifier_truncated_and_denewlined(self):
        import dns_aid.core.http_index as hi
        from dns_aid.core.http_index import _MAX_LOGGED_IDENTIFIER

        # Newline placed early (before truncation) so escaping is exercised;
        # trailing padding forces truncation.
        evil_id = "urn:air:acme.com:x\ninjected-log-line" + "A" * 5000
        entry = {
            "identifier": evil_id,
            "displayName": "x",
            "type": "application/mcp-server-card+json",
            # neither url nor data → locator_violation, identifier sampled
        }
        with patch.object(hi.logger, "warning") as warn:
            parse_http_index(_ard_catalog([entry]))
        summary = next(
            c for c in warn.call_args_list if c.args[0] == "http_index.ard_entries_skipped"
        )
        sample = summary.kwargs["samples"][0]
        assert "\n" not in sample  # no raw newline → no forged log lines
        assert "\\n" in sample  # escaped instead
        # reason prefix + capped identifier (+ ellipsis), nowhere near 5000
        assert len(sample) <= len("locator_violation:") + _MAX_LOGGED_IDENTIFIER + 1

    def test_per_entry_arrays_bounded(self):
        from dns_aid.core.http_index import _MAX_ARD_LIST_ITEMS

        entry = _ard_agent_entry(
            capabilities=["c" + str(i) for i in range(_MAX_ARD_LIST_ITEMS * 10)],
            representativeQueries=["q" + str(i) for i in range(_MAX_ARD_LIST_ITEMS * 10)],
        )
        agent = parse_http_index(_ard_catalog([entry]))[0]
        assert len(agent.capability.capabilities) == _MAX_ARD_LIST_ITEMS
        assert len(agent.use_cases) == _MAX_ARD_LIST_ITEMS

    def test_string_lengths_bounded(self):
        from dns_aid.core.http_index import _MAX_ARD_STR_LEN

        entry = _ard_agent_entry(
            description="D" * (_MAX_ARD_STR_LEN * 4),
            capabilities=["C" * (_MAX_ARD_STR_LEN * 4)],
        )
        agent = parse_http_index(_ard_catalog([entry]))[0]
        assert len(agent.description) == _MAX_ARD_STR_LEN
        assert len(agent.capability.capabilities[0]) == _MAX_ARD_STR_LEN

    def test_malformed_port_is_clean_skip_not_silent_drop(self):
        entries = [
            {
                "identifier": "urn:air:acme.com:server:bad",
                "displayName": "bad",
                "type": "application/mcp-server-card+json",
                "url": "https://acme.com:notaport/card.json",
            },
            _ard_agent_entry("good"),
        ]
        import dns_aid.core.http_index as hi

        with patch.object(hi.logger, "warning") as warn:
            agents = parse_http_index(_ard_catalog(entries))
        assert {a.name for a in agents} == {"good"}
        summary = next(
            c for c in warn.call_args_list if c.args[0] == "http_index.ard_entries_skipped"
        )
        assert summary.kwargs["by_reason"]["locator_violation"] == 1


class TestArdNesting:
    """Inline nested catalogs (user story 3, contract C3)."""

    def test_nested_agent_found_in_canonical_example(self):
        agents = parse_http_index(_canonical_catalog())
        assert "a2a" in {a.name for a in agents}  # finance bundle's agent

    def test_depth_bomb_truncated(self):
        # Build a chain nested one level deeper than the limit, an agent
        # at each level. Levels 0.._MAX_ARD_DEPTH are parsed; deeper skipped.
        innermost = _ard_catalog([_ard_agent_entry(f"agent-{_MAX_ARD_DEPTH + 1}")])
        current = innermost
        for depth in range(_MAX_ARD_DEPTH, -1, -1):
            nested_entry = {
                "identifier": f"urn:air:acme.com:catalog:level{depth}",
                "displayName": f"level {depth}",
                "type": "application/ai-catalog+json",
                "data": current,
            }
            current = _ard_catalog([_ard_agent_entry(f"agent-{depth}"), nested_entry])
        agents = parse_http_index(current)
        names = {a.name for a in agents}
        assert names == {f"agent-{d}" for d in range(_MAX_ARD_DEPTH + 1)}
        assert f"agent-{_MAX_ARD_DEPTH + 1}" not in names

    def test_nested_entries_share_agent_budget(self):
        nested = _ard_catalog([_ard_agent_entry(f"nested-{i}") for i in range(20)])
        entries = [_ard_agent_entry(f"top-{i}") for i in range(_MAX_HTTP_INDEX_AGENTS - 10)]
        entries.append(
            {
                "identifier": "urn:air:acme.com:catalog:bundle",
                "displayName": "bundle",
                "type": "application/ai-catalog+json",
                "data": nested,
            }
        )
        agents = parse_http_index(_ard_catalog(entries))
        assert len(agents) == _MAX_HTTP_INDEX_AGENTS


class TestArdGuards:
    """Resource guards over hostile catalogs (user story 3)."""

    def test_entry_flood_capped(self):
        entries = [_ard_agent_entry(f"agent-{i}") for i in range(_MAX_HTTP_INDEX_AGENTS + 1)]
        agents = parse_http_index(_ard_catalog(entries))
        assert len(agents) == _MAX_HTTP_INDEX_AGENTS

    @pytest.mark.asyncio
    async def test_oversized_ard_document_aborted(self):
        # Existing fetch-layer size cap applies to the ARD pattern too.
        big = {"specVersion": "1.0", "entries": [], "pad": "x" * (2 * 1024 * 1024)}
        mock_client = _streaming_client(
            *[_stream_response(big) for _ in range(len(HTTP_INDEX_PATTERNS))]
        )
        with patch("dns_aid.core.http_index.httpx.AsyncClient", return_value=mock_client):
            with pytest.raises(HttpIndexError):
                await fetch_http_index("acme.com")


class TestArdTolerance:
    """Tolerant parsing per verified spec discrepancies."""

    def test_empty_entries_is_valid(self):
        assert parse_http_index(_ard_catalog([])) == []

    def test_unknown_entry_fields_tolerated(self):
        agents = parse_http_index(
            _ard_catalog([_ard_agent_entry(futureField={"x": 1}, updatedAt="2026-07-04")])
        )
        assert len(agents) == 1

    def test_malformed_entries_skipped_siblings_survive(self):
        entries = [
            _ard_agent_entry("good-one"),
            _ard_agent_entry("bad-urn", identifier="urn:wrong:acme.com:x"),
            {k: v for k, v in _ard_agent_entry("no-display").items() if k != "displayName"},
            _ard_agent_entry("both-locators", data={"inline": True}),  # url AND data
            {
                k: v
                for k, v in _ard_agent_entry("no-locator").items()
                if k != "url"  # neither url nor data
            },
            "not-a-dict",
            _ard_agent_entry("good-two"),
        ]
        agents = parse_http_index(_ard_catalog(entries))
        assert {a.name for a in agents} == {"good-one", "good-two"}

    def test_host_block_optional(self):
        catalog = _ard_catalog([_ard_agent_entry()])
        assert "host" not in catalog
        assert len(parse_http_index(catalog)) == 1


class TestArdFetchEndToEnd:
    """Fetch → detect → map → AgentRecord pipeline (mocked HTTP + DNS)."""

    @pytest.mark.asyncio
    async def test_fetch_ard_catalog_after_legacy_404s(self):
        responses = [_stream_response({}, status=404) for _ in range(4)]
        responses.append(_stream_response(_canonical_catalog()))
        mock_client = _streaming_client(*responses)
        with patch("dns_aid.core.http_index.httpx.AsyncClient", return_value=mock_client):
            agents = await fetch_http_index("acme.com")
        assert {a.name for a in agents} == {"assistant", "weather", "a2a"}
        # The ARD URL was the 5th (final) pattern probed
        assert mock_client.stream.call_count == 5
        last_url = mock_client.stream.call_args_list[-1][0][1]
        assert last_url == "https://acme.com/.well-known/ai-catalog.json"

    @pytest.mark.asyncio
    async def test_discoverer_falls_back_to_catalog_data(self):
        """DNS miss → ARD catalog data surfaces as AgentRecord (contract C4)."""
        from dns_aid.core import discoverer as disc

        entry = _ard_agent_entry(
            capabilities=["WeatherTool"],
            trustManifest=TestArdTrustManifest.SPIFFE_MANIFEST,
        )
        http_agents = parse_http_index(_ard_catalog([entry]))
        with (
            patch.object(disc, "fetch_http_index_or_empty", AsyncMock(return_value=http_agents)),
            patch.object(disc, "_query_single_agent", AsyncMock(return_value=None)),
            patch.object(disc, "resolve_catalog_pointer", AsyncMock(return_value=None)),
            patch.object(
                disc, "fetch_cap_document", AsyncMock(return_value=None)
            ),  # card unfetchable
        ):
            records = await disc._discover_via_http_index("acme.com")
        assert len(records) == 1
        record = records[0]
        assert record.name == "weather"
        assert record.protocol.value == "mcp"
        assert record.capability_source == "ard_catalog"
        assert record.capabilities == ["WeatherTool"]
        assert record.endpoint_source == "http_index_fallback"
        # Card unreachable → no fabricated endpoint (pre-0.26.2 stuffed the card URL here).
        assert record.endpoint_override is None
        assert record.trust_manifest is not None
        assert record.trust_manifest.identity == "spiffe://acme.com/agents/weather"

    @pytest.mark.asyncio
    async def test_dns_record_present_but_ard_uses_card(self):
        """Even when a DNS SVCB record exists for the ARD agent's name, ARD
        resolution ignores it (no identifier→hostname synthesis, §4.2.1) and
        resolves the endpoint from the card; catalog trust still attaches."""
        from dns_aid.core import discoverer as disc
        from dns_aid.core.cap_fetcher import CapabilityDocument
        from dns_aid.core.models import AgentRecord, Protocol

        dns_record = AgentRecord(
            name="weather", domain="acme.com", protocol=Protocol.MCP, target_host="mcp.acme.com"
        )
        entry = _ard_agent_entry(
            capabilities=["WeatherTool"],
            trustManifest=TestArdTrustManifest.SPIFFE_MANIFEST,
        )
        http_agents = parse_http_index(_ard_catalog([entry]))
        card_doc = CapabilityDocument(
            raw_data={"endpoint": "https://weather.acme.com/mcp", "tools": [{"name": "forecast"}]}
        )
        with (
            patch.object(disc, "fetch_http_index_or_empty", AsyncMock(return_value=http_agents)),
            patch.object(disc, "resolve_catalog_pointer", AsyncMock(return_value=None)),
            patch.object(disc, "fetch_cap_document", AsyncMock(return_value=card_doc)),
            patch.object(disc, "_query_single_agent", AsyncMock(return_value=dns_record)) as qsa,
        ):
            records = await disc._discover_via_http_index("acme.com")
        record = records[0]
        qsa.assert_not_called()  # DNS never consulted for an ARD entry
        assert record.target_host == "weather.acme.com"  # endpoint from the card
        assert record.endpoint_source == "ard_card"
        assert record.trust_manifest is not None
        assert record.trust_manifest.identity == "spiffe://acme.com/agents/weather"

    @pytest.mark.asyncio
    async def test_protocol_filter_applies_to_ard_agents(self):
        from dns_aid.core import discoverer as disc
        from dns_aid.core.models import Protocol

        http_agents = parse_http_index(_ard_catalog([_ard_agent_entry()]))  # mcp agent
        with (
            patch.object(disc, "fetch_http_index_or_empty", AsyncMock(return_value=http_agents)),
            patch.object(disc, "_query_single_agent", AsyncMock(return_value=None)),
            patch.object(disc, "resolve_catalog_pointer", AsyncMock(return_value=None)),
        ):
            records = await disc._discover_via_http_index("acme.com", protocol=Protocol.A2A)
        assert records == []


class TestArdCardDereference:
    """B: fetch the ARD entry's referenced card → real endpoint/skills/auth."""

    @pytest.mark.asyncio
    async def test_a2a_card_dereferenced(self):
        from dns_aid.core import discoverer as disc
        from dns_aid.core.cap_fetcher import CapabilityDocument

        entry = {
            "identifier": "urn:air:acme.com:agents:assistant",
            "displayName": "Assistant",
            "type": "application/a2a-agent-card+json",
            "url": "https://cards.acme.com/assistant.json",
        }
        http_agents = parse_http_index(_ard_catalog([entry]))
        card_doc = CapabilityDocument(
            raw_data={
                "name": "Assistant",
                "url": "https://assistant.acme.com/a2a",
                "skills": [{"id": "chat", "name": "Chat"}, {"id": "summarize", "name": "Sum"}],
                "authentication": {"schemes": ["bearer"]},
            }
        )
        with (
            patch.object(disc, "fetch_http_index_or_empty", AsyncMock(return_value=http_agents)),
            patch.object(disc, "_query_single_agent", AsyncMock(return_value=None)),
            patch.object(disc, "resolve_catalog_pointer", AsyncMock(return_value=None)),
            patch.object(disc, "fetch_cap_document", AsyncMock(return_value=card_doc)) as fc,
        ):
            records = await disc._discover_via_http_index("acme.com")
        r = records[0]
        assert (
            r.endpoint_override == "https://assistant.acme.com/a2a"
        )  # real endpoint, not card URL
        assert r.endpoint_source == "ard_card"
        assert r.target_host == "assistant.acme.com"
        assert r.capabilities == ["chat", "summarize"]
        assert r.capability_source == "agent_card"
        assert r.auth_type == "bearer"
        assert fc.call_args.kwargs.get("follow_redirects") is False  # SSRF: redirects refused

    @pytest.mark.asyncio
    async def test_mcp_card_dereferenced(self):
        from dns_aid.core import discoverer as disc
        from dns_aid.core.cap_fetcher import CapabilityDocument

        entry = {
            "identifier": "urn:air:acme.com:agents:billing",
            "displayName": "Billing",
            "type": "application/mcp-server-card+json",
            "url": "https://cards.acme.com/billing.json",
        }
        http_agents = parse_http_index(_ard_catalog([entry]))
        card_doc = CapabilityDocument(
            raw_data={
                "name": "Billing",
                "endpoint": "https://billing.acme.com/mcp",
                "tools": [{"name": "create_invoice"}, {"name": "list_payments"}],
            }
        )
        with (
            patch.object(disc, "fetch_http_index_or_empty", AsyncMock(return_value=http_agents)),
            patch.object(disc, "_query_single_agent", AsyncMock(return_value=None)),
            patch.object(disc, "resolve_catalog_pointer", AsyncMock(return_value=None)),
            patch.object(disc, "fetch_cap_document", AsyncMock(return_value=card_doc)),
        ):
            records = await disc._discover_via_http_index("acme.com")
        r = records[0]
        assert r.endpoint_override == "https://billing.acme.com/mcp"
        assert r.endpoint_source == "ard_card"
        assert r.capabilities == ["create_invoice", "list_payments"]

    @pytest.mark.asyncio
    async def test_card_fetch_failure_keeps_catalog_data(self):
        from dns_aid.core import discoverer as disc

        entry = _ard_agent_entry(capabilities=["invoicing"])
        http_agents = parse_http_index(_ard_catalog([entry]))
        with (
            patch.object(disc, "fetch_http_index_or_empty", AsyncMock(return_value=http_agents)),
            patch.object(disc, "_query_single_agent", AsyncMock(return_value=None)),
            patch.object(disc, "resolve_catalog_pointer", AsyncMock(return_value=None)),
            patch.object(disc, "fetch_cap_document", AsyncMock(return_value=None)),  # fetch fails
        ):
            records = await disc._discover_via_http_index("acme.com")
        r = records[0]
        # Card unreachable → NO fabricated endpoint. The record keeps its
        # catalog-level data (caps, trust) but must not masquerade the card
        # URL as the service endpoint (the pre-0.26.2 bug).
        assert r.endpoint_override is None
        assert r.endpoint_source == "http_index_fallback"
        assert r.capability_source == "ard_catalog"
        assert r.capabilities == ["invoicing"]

    @pytest.mark.asyncio
    async def test_inline_data_card_resolved_without_fetch(self):
        # §3.4: an entry may carry its card INLINE via `data` — resolve it
        # directly, no network fetch, endpoint_source="ard_inline".
        from dns_aid.core import discoverer as disc

        entry = {
            "identifier": "urn:air:acme.com:agents:inline-bot",
            "displayName": "Inline Bot",
            "type": "application/a2a-agent-card+json",
            "data": {
                "name": "Inline Bot",
                "url": "https://inline-bot.acme.com/a2a",
                "skills": [{"id": "greet", "name": "Greet"}],
            },
        }
        http_agents = parse_http_index(_ard_catalog([entry]))
        with (
            patch.object(disc, "fetch_http_index_or_empty", AsyncMock(return_value=http_agents)),
            patch.object(disc, "_query_single_agent", AsyncMock(return_value=None)),
            patch.object(disc, "resolve_catalog_pointer", AsyncMock(return_value=None)),
            patch.object(disc, "fetch_cap_document", AsyncMock()) as fc,
        ):
            records = await disc._discover_via_http_index("acme.com")
        r = records[0]
        assert r.endpoint_override == "https://inline-bot.acme.com/a2a"
        assert r.endpoint_source == "ard_inline"
        assert r.target_host == "inline-bot.acme.com"
        assert r.capabilities == ["greet"]
        assert r.capability_source == "agent_card"
        fc.assert_not_awaited()  # inline data → zero network fetches

    @pytest.mark.asyncio
    async def test_identifier_never_synthesizes_dns_lookup(self):
        # ARD §4.2.1: the identifier is an abstract name, NOT a locator. Even
        # when a DNS SVCB record EXISTS for {name}.{domain}, ARD resolution must
        # NOT query it or prefer it — the endpoint comes from the entry's card.
        from dns_aid.core import discoverer as disc
        from dns_aid.core.cap_fetcher import CapabilityDocument

        entry = {
            "identifier": "urn:air:acme.com:agents:billing",
            "displayName": "Billing",
            "type": "application/mcp-server-card+json",
            "url": "https://cards.acme.com/billing.json",
        }
        http_agents = parse_http_index(_ard_catalog([entry]))
        card_doc = CapabilityDocument(
            raw_data={"endpoint": "https://billing.acme.com/mcp", "tools": [{"name": "invoice"}]}
        )
        decoy = object()  # what a DNS lookup would return — must never be used
        with (
            patch.object(disc, "fetch_http_index_or_empty", AsyncMock(return_value=http_agents)),
            patch.object(disc, "resolve_catalog_pointer", AsyncMock(return_value=None)),
            patch.object(disc, "fetch_cap_document", AsyncMock(return_value=card_doc)),
            patch.object(disc, "_query_single_agent", AsyncMock(return_value=decoy)) as qsa,
        ):
            records = await disc._discover_via_http_index("acme.com")
        r = records[0]
        assert r is not decoy  # resolved from the card, not a DNS record
        assert r.endpoint_override == "https://billing.acme.com/mcp"
        assert r.endpoint_source == "ard_card"
        qsa.assert_not_called()  # the identifier was never turned into a DNS query
