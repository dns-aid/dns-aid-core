# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for the experimental site agent convention (site_agent module)."""

from unittest.mock import AsyncMock, patch

import pytest

from dns_aid.core.bap import validate_bap
from dns_aid.core.models import AgentRecord, Protocol
from dns_aid.core.site_agent import (
    SITE_AGENT_NAME,
    WEBMCP_BAP_TOKEN,
    discover_site_agent,
    is_webmcp_surface,
    site_agent_fqdn,
)
from dns_aid.utils.validation import validate_agent_name


def _agent(**overrides) -> AgentRecord:
    """A minimal valid AgentRecord for the site agent, with overrides."""
    base = {
        "name": SITE_AGENT_NAME,
        "domain": "example.com",
        "protocol": Protocol.MCP,
        "target_host": "mcp.example.com",
    }
    base.update(overrides)
    return AgentRecord(**base)


class TestConstants:
    """The convention must stay inside the existing wire grammar."""

    def test_site_agent_name_is_a_valid_agent_name(self):
        assert validate_agent_name(SITE_AGENT_NAME) == SITE_AGENT_NAME

    def test_webmcp_is_a_valid_bap_token(self):
        assert validate_bap(WEBMCP_BAP_TOKEN) == WEBMCP_BAP_TOKEN

    def test_webmcp_versioned_is_a_valid_bap_value(self):
        assert validate_bap(f"{WEBMCP_BAP_TOKEN}=1.0") == "webmcp=1.0"

    def test_webmcp_token_survives_agent_record_validation(self):
        agent = _agent(protocol=Protocol.HTTPS, bap=WEBMCP_BAP_TOKEN)
        assert agent.bap == WEBMCP_BAP_TOKEN


class TestSiteAgentFqdn:
    """site_agent_fqdn builds the draft-02 flat primary owner."""

    def test_basic(self):
        assert site_agent_fqdn("example.com") == "site.example.com"

    def test_trailing_dot_is_stripped(self):
        assert site_agent_fqdn("example.com.") == "site.example.com"

    def test_surrounding_whitespace_is_stripped(self):
        assert site_agent_fqdn("  example.com ") == "site.example.com"

    def test_multi_label_domain(self):
        assert site_agent_fqdn("shop.example.co.jp") == "site.shop.example.co.jp"


class TestIsWebmcpSurface:
    """The webmcp marker lives in bap, with or without a version suffix."""

    def test_bare_webmcp_token(self):
        agent = _agent(protocol=Protocol.HTTPS, bap="webmcp")
        assert is_webmcp_surface(agent) is True

    def test_versioned_webmcp_token(self):
        agent = _agent(protocol=Protocol.HTTPS, bap="webmcp=1.0")
        assert is_webmcp_surface(agent) is True

    def test_no_bap_is_not_a_webmcp_surface(self):
        agent = _agent(bap=None)
        assert is_webmcp_surface(agent) is False

    def test_other_bap_token_is_not_a_webmcp_surface(self):
        agent = _agent(bap="mcp")
        assert is_webmcp_surface(agent) is False

    def test_other_versioned_bap_token_is_not_a_webmcp_surface(self):
        agent = _agent(bap="mcp=2.1")
        assert is_webmcp_surface(agent) is False

    def test_marker_is_independent_of_protocol(self):
        # The marker is the bap token alone; alpn/protocol keeps carrying
        # the plain connection protocol and must not affect the check.
        agent = _agent(protocol=Protocol.MCP, bap="webmcp")
        assert is_webmcp_surface(agent) is True


class TestDiscoverSiteAgent:
    """discover_site_agent delegates to discover_at_fqdn on the flat owner."""

    @pytest.mark.asyncio
    async def test_queries_the_flat_site_owner(self):
        with patch(
            "dns_aid.core.discoverer.discover_at_fqdn",
            new_callable=AsyncMock,
            return_value=None,
        ) as mock_discover:
            result = await discover_site_agent("example.com")
            mock_discover.assert_called_once_with("site.example.com")
            assert result is None

    @pytest.mark.asyncio
    async def test_returns_the_discovered_agent(self):
        agent = _agent()
        with patch(
            "dns_aid.core.discoverer.discover_at_fqdn",
            new_callable=AsyncMock,
            return_value=agent,
        ):
            result = await discover_site_agent("example.com")
            assert result is agent

    @pytest.mark.asyncio
    async def test_domain_is_normalized_before_the_query(self):
        with patch(
            "dns_aid.core.discoverer.discover_at_fqdn",
            new_callable=AsyncMock,
            return_value=None,
        ) as mock_discover:
            await discover_site_agent("example.com.")
            mock_discover.assert_called_once_with("site.example.com")
