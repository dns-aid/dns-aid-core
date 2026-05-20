# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for the Agent Metadata Contract (Phase 5.5)."""

from datetime import UTC, datetime

from dns_aid.core.agent_metadata import (
    AgentIdentity,
    AgentMetadata,
    AuthSpec,
    AuthType,
    ConnectionSpec,
    MetadataContact,
    TransportType,
)
from dns_aid.core.capability_model import Action, ActionIntent, CapabilitySpec


class TestTransportType:
    """Test TransportType enum."""

    def test_values(self):
        assert TransportType.streamable_http == "streamable-http"
        assert TransportType.https == "https"
        assert TransportType.ws == "ws"
        assert TransportType.stdio == "stdio"
        assert TransportType.sse == "sse"

    def test_all_members(self):
        assert len(TransportType) == 5


class TestAuthType:
    """Test AuthType enum."""

    def test_values(self):
        assert AuthType.none == "none"
        assert AuthType.api_key == "api_key"
        assert AuthType.bearer == "bearer"
        assert AuthType.oauth2 == "oauth2"
        assert AuthType.mtls == "mtls"
        assert AuthType.http_msg_sig == "http_msg_sig"

    def test_all_members(self):
        assert len(AuthType) == 6


class TestAgentIdentity:
    """Test AgentIdentity model."""

    def test_minimal(self):
        identity = AgentIdentity(name="chat-agent")
        assert identity.name == "chat-agent"
        assert identity.agent_id is None
        assert identity.fqdn is None
        assert identity.version is None
        assert identity.deprecated is False
        assert identity.sunset_date is None
        assert identity.successor is None

    def test_full(self):
        sunset = datetime(2025, 12, 31, tzinfo=UTC)
        identity = AgentIdentity(
            agent_id="abc-123",
            name="legacy-agent",
            fqdn="_legacy._mcp._agents.example.com",
            version="2.0.0",
            deprecated=True,
            sunset_date=sunset,
            successor="_new._mcp._agents.example.com",
        )
        assert identity.deprecated is True
        assert identity.sunset_date == sunset
        assert identity.successor == "_new._mcp._agents.example.com"


class TestConnectionSpec:
    """Test ConnectionSpec model."""

    def test_minimal(self):
        conn = ConnectionSpec(protocol="mcp", endpoint="https://mcp.example.com")
        assert conn.protocol == "mcp"
        assert conn.transport == TransportType.https
        assert conn.endpoint == "https://mcp.example.com"
        assert conn.base_url is None

    def test_with_transport(self):
        conn = ConnectionSpec(
            protocol="mcp",
            transport=TransportType.streamable_http,
            endpoint="https://mcp.example.com/mcp",
            base_url="https://mcp.example.com",
        )
        assert conn.transport == TransportType.streamable_http
        assert conn.base_url == "https://mcp.example.com"


class TestAuthSpec:
    """Test AuthSpec model."""

    def test_defaults(self):
        auth = AuthSpec()
        assert auth.type == AuthType.none
        assert auth.location is None
        assert auth.header_name is None
        assert auth.oauth_discovery is None

    def test_api_key(self):
        auth = AuthSpec(
            type=AuthType.api_key,
            location="header",
            header_name="X-API-Key",
        )
        assert auth.type == AuthType.api_key
        assert auth.header_name == "X-API-Key"

    def test_oauth2(self):
        auth = AuthSpec(
            type=AuthType.oauth2,
            oauth_discovery="https://auth.example.com/.well-known/openid-configuration",
        )
        assert auth.type == AuthType.oauth2
        assert "openid-configuration" in auth.oauth_discovery

    def test_http_msg_sig(self):
        auth = AuthSpec(
            type=AuthType.http_msg_sig,
            key_directory_url="https://example.com/.well-known/jwks.json",
            signature_agent_card_url="https://example.com/.well-known/agent-card.json",
            supported_algorithms=["ed25519"],
        )
        assert auth.type == AuthType.http_msg_sig
        assert auth.supported_algorithms == ["ed25519"]


class TestMetadataContact:
    """Test MetadataContact model."""

    def test_defaults(self):
        contact = MetadataContact()
        assert contact.owner is None
        assert contact.contact is None
        assert contact.documentation is None

    def test_full(self):
        contact = MetadataContact(
            owner="Acme Corp",
            contact="agents@acme.com",
            documentation="https://docs.acme.com/agents",
        )
        assert contact.owner == "Acme Corp"


class TestAgentMetadata:
    """Test top-level AgentMetadata model."""

    def test_minimal(self):
        metadata = AgentMetadata(
            identity=AgentIdentity(name="test-agent"),
            connection=ConnectionSpec(
                protocol="mcp",
                endpoint="https://mcp.example.com",
            ),
        )
        assert metadata.aid_version == "1.0"
        assert metadata.identity.name == "test-agent"
        assert metadata.auth.type == AuthType.none
        assert metadata.capabilities.actions == []
        assert metadata.contact.owner is None

    def test_full(self):
        metadata = AgentMetadata(
            aid_version="1.0",
            identity=AgentIdentity(
                name="network-specialist",
                fqdn="_network._mcp._agents.example.com",
                version="3.0.0",
            ),
            connection=ConnectionSpec(
                protocol="mcp",
                transport=TransportType.streamable_http,
                endpoint="https://mcp.example.com/mcp",
            ),
            auth=AuthSpec(type=AuthType.bearer, location="header"),
            capabilities=CapabilitySpec(
                supports_streaming=True,
                actions=[
                    Action(name="lookup-dns", intent=ActionIntent.query),
                ],
            ),
            contact=MetadataContact(owner="Network Team"),
        )
        assert metadata.identity.version == "3.0.0"
        assert metadata.connection.transport == TransportType.streamable_http
        assert metadata.auth.type == AuthType.bearer
        assert len(metadata.capabilities.actions) == 1
        assert metadata.contact.owner == "Network Team"

    def test_serialization_roundtrip(self):
        metadata = AgentMetadata(
            identity=AgentIdentity(name="roundtrip"),
            connection=ConnectionSpec(
                protocol="a2a",
                endpoint="https://a2a.example.com",
            ),
        )
        data = metadata.model_dump()
        restored = AgentMetadata.model_validate(data)
        assert restored.identity.name == "roundtrip"
        assert restored.connection.protocol == "a2a"
        assert restored.aid_version == "1.0"
