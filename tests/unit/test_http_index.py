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
