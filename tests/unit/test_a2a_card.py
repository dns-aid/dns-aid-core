# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for A2A Agent Card parsing and fetching."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dns_aid.core.a2a_card import (
    A2AAgentCard,
    A2AAuthentication,
    A2ASkill,
    fetch_agent_card,
    fetch_agent_card_from_domain,
    publish_agent_card,
)
from dns_aid.core.models import AgentRecord, Protocol


class TestA2ASkill:
    """Tests for A2ASkill dataclass."""

    def test_from_dict_full(self) -> None:
        """Test parsing a full skill dict."""
        data = {
            "id": "process-payment",
            "name": "Process Payment",
            "description": "Handles credit card payments",
            "inputModes": ["text", "data"],
            "outputModes": ["text"],
            "tags": ["payment", "finance"],
        }
        skill = A2ASkill.from_dict(data)

        assert skill.id == "process-payment"
        assert skill.name == "Process Payment"
        assert skill.description == "Handles credit card payments"
        assert skill.input_modes == ["text", "data"]
        assert skill.output_modes == ["text"]
        assert skill.tags == ["payment", "finance"]

    def test_from_dict_minimal(self) -> None:
        """Test parsing a minimal skill dict."""
        data = {"id": "ping", "name": "Ping"}
        skill = A2ASkill.from_dict(data)

        assert skill.id == "ping"
        assert skill.name == "Ping"
        assert skill.description is None
        assert skill.input_modes == ["text"]
        assert skill.output_modes == ["text"]
        assert skill.tags == []


class TestA2AAuthentication:
    """Tests for A2AAuthentication dataclass."""

    def test_from_dict_full(self) -> None:
        """Test parsing full auth dict."""
        data = {
            "schemes": ["oauth2", "api_key"],
            "credentials": "https://example.com/.well-known/oauth",
        }
        auth = A2AAuthentication.from_dict(data)

        assert auth.schemes == ["oauth2", "api_key"]
        assert auth.credentials == "https://example.com/.well-known/oauth"

    def test_from_dict_empty(self) -> None:
        """Test parsing empty auth dict."""
        auth = A2AAuthentication.from_dict({})

        assert auth.schemes == []
        assert auth.credentials is None


class TestA2AAgentCard:
    """Tests for A2AAgentCard dataclass."""

    def test_from_dict_full(self) -> None:
        """Test parsing a full Agent Card."""
        data = {
            "name": "Payment Agent",
            "description": "Handles payment processing",
            "url": "https://payment.example.com",
            "version": "2.0.0",
            "provider": {
                "organization": "Example Corp",
                "url": "https://example.com",
            },
            "skills": [
                {"id": "pay", "name": "Pay"},
                {"id": "refund", "name": "Refund"},
            ],
            "authentication": {
                "schemes": ["oauth2"],
            },
            "defaultInputModes": ["text", "data"],
            "defaultOutputModes": ["text"],
            "customField": "custom value",
        }
        card = A2AAgentCard.from_dict(data)

        assert card.name == "Payment Agent"
        assert card.description == "Handles payment processing"
        assert card.url == "https://payment.example.com"
        assert card.version == "2.0.0"
        assert card.provider is not None
        assert card.provider.organization == "Example Corp"
        assert card.provider.url == "https://example.com"
        assert len(card.skills) == 2
        assert card.skills[0].id == "pay"
        assert card.skills[1].id == "refund"
        assert card.authentication is not None
        assert card.authentication.schemes == ["oauth2"]
        assert card.default_input_modes == ["text", "data"]
        assert card.default_output_modes == ["text"]
        assert card.metadata == {"customField": "custom value"}

    def test_from_dict_minimal(self) -> None:
        """Test parsing a minimal Agent Card."""
        data = {"name": "Simple Agent", "url": "https://agent.example.com"}
        card = A2AAgentCard.from_dict(data)

        assert card.name == "Simple Agent"
        assert card.url == "https://agent.example.com"
        assert card.version == "1.0.0"
        assert card.description is None
        assert card.provider is None
        assert card.skills == []
        assert card.authentication is None
        assert card.default_input_modes == ["text"]
        assert card.default_output_modes == ["text"]

    def test_skill_ids(self) -> None:
        """Test skill_ids property."""
        card = A2AAgentCard(
            name="Test",
            url="https://test.com",
            skills=[
                A2ASkill(id="skill-1", name="Skill 1"),
                A2ASkill(id="skill-2", name="Skill 2"),
            ],
        )
        assert card.skill_ids == ["skill-1", "skill-2"]

    def test_skill_names(self) -> None:
        """Test skill_names property."""
        card = A2AAgentCard(
            name="Test",
            url="https://test.com",
            skills=[
                A2ASkill(id="s1", name="First Skill"),
                A2ASkill(id="s2", name="Second Skill"),
            ],
        )
        assert card.skill_names == ["First Skill", "Second Skill"]

    def test_to_capabilities(self) -> None:
        """Test converting skills to DNS-AID capabilities."""
        card = A2AAgentCard(
            name="Test",
            url="https://test.com",
            skills=[
                A2ASkill(id="payment", name="Payment"),
                A2ASkill(id="refund", name="Refund"),
            ],
        )
        assert card.to_capabilities() == ["payment", "refund"]

    def test_from_agent_record(self) -> None:
        """Test converting an AgentRecord into an A2A agent card."""
        agent = AgentRecord(
            name="payments",
            domain="example.com",
            protocol=Protocol.A2A,
            target_host="a2a.example.com",
            capabilities=["pay", "refund"],
            version="2.0.0",
            description="Payment workflows",
        )

        card = A2AAgentCard.from_agent_record(agent)

        assert card.name == "payments"
        assert card.url == "https://a2a.example.com"
        assert card.version == "2.0.0"
        assert card.description == "Payment workflows"
        assert [skill.id for skill in card.skills] == ["pay", "refund"]

    def test_to_publish_params_derives_defaults(self) -> None:
        """Test publish helper derives endpoint, cap_uri, and DNS-safe name from card url."""
        card = A2AAgentCard(
            name="Payments Agent",
            url="https://a2a.example.com/tasks",
            version="2.0.0",
            description="Payment workflows",
            skills=[A2ASkill(id="pay", name="Pay"), A2ASkill(id="refund", name="Refund")],
        )

        params = card.to_publish_params("example.com")

        assert params == {
            "name": "payments-agent",
            "domain": "example.com",
            "protocol": "a2a",
            "endpoint": "a2a.example.com",
            "port": 443,
            "capabilities": ["pay", "refund"],
            "version": "2.0.0",
            "description": "Payment workflows",
            "ttl": 3600,
            "cap_uri": "https://a2a.example.com/.well-known/agent-card.json",
            "bap": "a2a=1.0",
        }

    def test_to_publish_params_respects_overrides(self) -> None:
        """Test publish helper respects explicit name, endpoint, and port overrides."""
        card = A2AAgentCard(name="Payments Agent", url="https://a2a.example.com")

        params = card.to_publish_params(
            "example.com",
            name="payments-v2",
            endpoint="overlay.internal",
            port=8443,
            ttl=30,
        )

        assert params["name"] == "payments-v2"
        assert params["endpoint"] == "overlay.internal"
        assert params["port"] == 8443
        assert params["ttl"] == 30
        assert params["cap_uri"] == "https://overlay.internal:8443/.well-known/agent-card.json"

    def test_to_publish_params_requires_endpoint_source(self) -> None:
        """Test publish helper rejects cards with no usable endpoint source."""
        card = A2AAgentCard(name="No Endpoint", url="")

        with pytest.raises(ValueError, match="endpoint must be provided or derivable"):
            card.to_publish_params("example.com")


class TestPublishAgentCard:
    """Tests for publish_agent_card helper."""

    @pytest.mark.asyncio
    async def test_publish_agent_card_calls_publish(self) -> None:
        card = A2AAgentCard(
            name="Payments Agent",
            url="https://a2a.example.com/api",
            skills=[A2ASkill(id="pay", name="Pay")],
        )

        publish_result = MagicMock()

        with patch(
            "dns_aid.core.publisher.publish", AsyncMock(return_value=publish_result)
        ) as mock_publish:
            result = await publish_agent_card(card, domain="example.com", ttl=30)

        assert result is publish_result
        mock_publish.assert_awaited_once_with(
            name="payments-agent",
            domain="example.com",
            protocol="a2a",
            endpoint="a2a.example.com",
            port=443,
            capabilities=["pay"],
            version="1.0.0",
            description=None,
            ttl=30,
            cap_uri="https://a2a.example.com/.well-known/agent-card.json",
            bap="a2a=1.0",
            backend=None,
        )


class TestFetchAgentCard:
    """Tests for fetch_agent_card function."""

    @pytest.mark.asyncio
    async def test_fetch_success(self) -> None:
        """Test successful Agent Card fetch."""
        import json

        mock_card_data = {
            "name": "Test Agent",
            "url": "https://agent.example.com",
            "skills": [{"id": "ping", "name": "Ping"}],
        }

        async def mock_fetch(url, **kwargs):
            return json.dumps(mock_card_data).encode()

        with (
            patch("dns_aid.utils.url_safety.validate_fetch_url", side_effect=lambda u: u),
            patch("dns_aid.utils.url_safety.safe_fetch_bytes", side_effect=mock_fetch),
        ):
            card = await fetch_agent_card("https://agent.example.com")

        assert card is not None
        assert card.name == "Test Agent"
        assert len(card.skills) == 1
        assert card.skills[0].id == "ping"

    @pytest.mark.asyncio
    async def test_fetch_adds_https(self) -> None:
        """Test that https:// is added if missing."""
        import json

        captured_url: list[str] = []

        async def mock_fetch(url, **kwargs):
            captured_url.append(url)
            return json.dumps({"name": "Test", "url": "https://x.com"}).encode()

        with (
            patch("dns_aid.utils.url_safety.validate_fetch_url", side_effect=lambda u: u),
            patch("dns_aid.utils.url_safety.safe_fetch_bytes", side_effect=mock_fetch),
        ):
            await fetch_agent_card("agent.example.com")

        assert captured_url[0] == "https://agent.example.com/.well-known/agent-card.json"

    @pytest.mark.asyncio
    async def test_fetch_404(self) -> None:
        """Test fetch returns None on 404."""

        async def mock_fetch(url, **kwargs):
            return None  # safe_fetch_bytes returns None for non-200

        with (
            patch("dns_aid.utils.url_safety.validate_fetch_url", side_effect=lambda u: u),
            patch("dns_aid.utils.url_safety.safe_fetch_bytes", side_effect=mock_fetch),
        ):
            card = await fetch_agent_card("https://agent.example.com")

        assert card is None

    @pytest.mark.asyncio
    async def test_fetch_timeout(self) -> None:
        """Test fetch returns None on timeout."""
        import httpx

        async def mock_fetch(url, **kwargs):
            raise httpx.TimeoutException("timeout")

        with (
            patch("dns_aid.utils.url_safety.validate_fetch_url", side_effect=lambda u: u),
            patch("dns_aid.utils.url_safety.safe_fetch_bytes", side_effect=mock_fetch),
        ):
            card = await fetch_agent_card("https://agent.example.com")

        assert card is None

    @pytest.mark.asyncio
    async def test_fetch_connect_error(self) -> None:
        """Test fetch returns None on connection error."""
        import httpx

        async def mock_fetch(url, **kwargs):
            raise httpx.ConnectError("failed")

        with (
            patch("dns_aid.utils.url_safety.validate_fetch_url", side_effect=lambda u: u),
            patch("dns_aid.utils.url_safety.safe_fetch_bytes", side_effect=mock_fetch),
        ):
            card = await fetch_agent_card("https://agent.example.com")

        assert card is None

    @pytest.mark.asyncio
    async def test_fetch_invalid_json(self) -> None:
        """Test fetch returns None on invalid JSON (not a dict)."""

        async def mock_fetch(url, **kwargs):
            return b'"not an object"'

        with (
            patch("dns_aid.utils.url_safety.validate_fetch_url", side_effect=lambda u: u),
            patch("dns_aid.utils.url_safety.safe_fetch_bytes", side_effect=mock_fetch),
        ):
            card = await fetch_agent_card("https://agent.example.com")

        assert card is None

    @pytest.mark.asyncio
    async def test_fetch_oversized_response(self) -> None:
        """Test fetch returns None when response exceeds size limit."""
        from dns_aid.utils.url_safety import ResponseTooLargeError

        async def mock_fetch(url, **kwargs):
            raise ResponseTooLargeError("too big")

        with (
            patch("dns_aid.utils.url_safety.validate_fetch_url", side_effect=lambda u: u),
            patch("dns_aid.utils.url_safety.safe_fetch_bytes", side_effect=mock_fetch),
        ):
            card = await fetch_agent_card("https://agent.example.com")

        assert card is None


class TestFetchAgentCardFromDomain:
    """Tests for fetch_agent_card_from_domain function."""

    @pytest.mark.asyncio
    async def test_constructs_url_correctly(self) -> None:
        """Test that domain is converted to full URL."""
        import json

        captured_url: list[str] = []

        async def mock_fetch(url, **kwargs):
            captured_url.append(url)
            return json.dumps({"name": "Test", "url": "https://x.com"}).encode()

        with (
            patch("dns_aid.utils.url_safety.validate_fetch_url", side_effect=lambda u: u),
            patch("dns_aid.utils.url_safety.safe_fetch_bytes", side_effect=mock_fetch),
        ):
            await fetch_agent_card_from_domain("example.com")

        assert captured_url[0] == "https://example.com/.well-known/agent-card.json"
