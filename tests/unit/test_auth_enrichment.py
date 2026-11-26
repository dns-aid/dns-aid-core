# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for auth metadata enrichment during discovery."""

from __future__ import annotations

from dns_aid.core.a2a_card import A2AAgentCard, A2AAuthentication
from dns_aid.core.discoverer import _apply_agent_card, _apply_auth_from_metadata
from dns_aid.core.models import AgentRecord, Protocol


def _make_agent(**kwargs: object) -> AgentRecord:
    defaults = {
        "name": "test-agent",
        "domain": "example.com",
        "protocol": Protocol.MCP,
        "target_host": "mcp.example.com",
        "port": 443,
    }
    defaults.update(kwargs)
    return AgentRecord(**defaults)


def _make_card(
    auth: A2AAuthentication | None = None,
    metadata: dict | None = None,
) -> A2AAgentCard:
    return A2AAgentCard(
        name="test-agent",
        url="https://mcp.example.com",
        authentication=auth,
        metadata=metadata or {},
    )


class TestApplyAgentCardAuth:
    def test_extracts_auth_from_a2a_schemes(self) -> None:
        agent = _make_agent()
        card = _make_card(auth=A2AAuthentication(schemes=["oauth2", "api_key"]))

        _apply_agent_card(agent, card)

        assert agent.auth_type == "oauth2"
        assert agent.auth_config == {"schemes": ["oauth2", "api_key"]}

    def test_no_auth_when_no_schemes(self) -> None:
        agent = _make_agent()
        card = _make_card(auth=A2AAuthentication(schemes=[]))

        _apply_agent_card(agent, card)

        assert agent.auth_type is None
        assert agent.auth_config is None

    def test_no_auth_when_no_authentication(self) -> None:
        agent = _make_agent()
        card = _make_card(auth=None)

        _apply_agent_card(agent, card)

        assert agent.auth_type is None

    def test_does_not_overwrite_existing_auth(self) -> None:
        agent = _make_agent(auth_type="bearer", auth_config={"header_name": "Authorization"})
        card = _make_card(auth=A2AAuthentication(schemes=["oauth2"]))

        _apply_agent_card(agent, card)

        # Existing auth preserved — card auth does NOT override
        assert agent.auth_type == "bearer"
        assert agent.auth_config == {"header_name": "Authorization"}

    def test_extracts_dns_aid_native_auth_from_metadata(self) -> None:
        """Card metadata may contain DNS-AID native auth (aid_version present)."""
        agent = _make_agent()
        card = _make_card(
            metadata={
                "auth": {
                    "type": "oauth2",
                    "oauth_discovery": "https://auth.example.com/.well-known/openid-configuration",
                    "location": "header",
                }
            }
        )

        _apply_agent_card(agent, card)

        assert agent.auth_type == "oauth2"
        assert agent.auth_config == {
            "oauth_discovery": "https://auth.example.com/.well-known/openid-configuration",
            "location": "header",
        }


class TestApplyAuthFromMetadata:
    def test_extracts_full_auth_spec(self) -> None:
        agent = _make_agent()
        _apply_auth_from_metadata(
            agent,
            {
                "auth": {
                    "type": "bearer",
                    "header_name": "Authorization",
                    "location": "header",
                }
            },
        )

        assert agent.auth_type == "bearer"
        assert agent.auth_config == {
            "header_name": "Authorization",
            "location": "header",
        }

    def test_skips_none_type(self) -> None:
        agent = _make_agent()
        _apply_auth_from_metadata(agent, {"auth": {"type": "none"}})

        assert agent.auth_type is None

    def test_skips_missing_auth(self) -> None:
        agent = _make_agent()
        _apply_auth_from_metadata(agent, {})

        assert agent.auth_type is None

    def test_skips_non_dict_auth(self) -> None:
        agent = _make_agent()
        _apply_auth_from_metadata(agent, {"auth": "invalid"})

        assert agent.auth_type is None

    def test_excludes_none_values_from_config(self) -> None:
        agent = _make_agent()
        _apply_auth_from_metadata(
            agent,
            {
                "auth": {
                    "type": "api_key",
                    "header_name": "X-API-Key",
                    "oauth_discovery": None,
                    "location": None,
                }
            },
        )

        assert agent.auth_type == "api_key"
        assert agent.auth_config == {"header_name": "X-API-Key"}

    def test_oauth2_with_discovery_url(self) -> None:
        agent = _make_agent()
        _apply_auth_from_metadata(
            agent,
            {
                "auth": {
                    "type": "oauth2",
                    "oauth_discovery": "https://auth.example.com/.well-known/openid-configuration",
                }
            },
        )

        assert agent.auth_type == "oauth2"
        assert agent.auth_config == {
            "oauth_discovery": "https://auth.example.com/.well-known/openid-configuration",
        }

    def test_rejects_unknown_auth_type(self) -> None:
        """Unknown auth_type from malicious metadata should be skipped."""
        agent = _make_agent()
        _apply_auth_from_metadata(
            agent,
            {
                "auth": {
                    "type": "evil_handler",
                    "location": "header",
                }
            },
        )

        # auth_type should NOT be set — unknown type was rejected
        assert agent.auth_type is None
        assert agent.auth_config is None

    def test_accepts_ztaip_alias_auth_type(self) -> None:
        """ZTAIP aliases (e.g., bearer_token) should be accepted."""
        agent = _make_agent()
        _apply_auth_from_metadata(
            agent,
            {
                "auth": {
                    "type": "bearer_token",
                    "header_name": "Authorization",
                }
            },
        )

        assert agent.auth_type == "bearer_token"

    def test_http_msg_sig_with_algorithms(self) -> None:
        agent = _make_agent()
        _apply_auth_from_metadata(
            agent,
            {
                "auth": {
                    "type": "http_msg_sig",
                    "key_directory_url": "https://example.com/.well-known/jwks.json",
                    "supported_algorithms": ["ed25519", "ml-dsa-65"],
                }
            },
        )

        assert agent.auth_type == "http_msg_sig"
        assert agent.auth_config == {
            "key_directory_url": "https://example.com/.well-known/jwks.json",
            "supported_algorithms": ["ed25519", "ml-dsa-65"],
        }


class TestApiKeyCardEnrichment:
    def test_discovered_agent_gets_registry_type_and_placement(self):
        """Discovery and endpoint mode share A2AAuthentication.sdk_auth()."""
        agent = _make_agent()
        card = A2AAgentCard.from_dict(
            {
                "name": "Agent",
                "url": "https://agent.example/a2a",
                "securitySchemes": {"k": {"type": "apiKey", "in": "header", "name": "X-Agent-Key"}},
            }
        )
        _apply_agent_card(agent, card)

        assert agent.auth_type == "api_key"
        assert agent.auth_config == {
            "schemes": ["api_key"],
            "location": "header",
            "header_name": "X-Agent-Key",
        }
