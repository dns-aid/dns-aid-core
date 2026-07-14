# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Agent Metadata Contract — the `.well-known/agent.json` schema for DNS-AID.

Status: Experimental — defined but not yet wired into discover()/publish().

Bridges DNS discovery (WHERE is this agent?) with actionable connection
metadata (HOW to connect, WHAT it can do, WHETHER it's still active).

Both DNS-AID and Google A2A serve `/.well-known/agent.json`.  DNS-AID native
documents include an ``aid_version`` key; the metadata fetcher uses this as
a discriminator to choose the right parser.

Phase 5.5 — Agent Metadata Contract.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from dns_aid.core.capability_model import CapabilitySpec

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TransportType(StrEnum):
    """Wire transport the agent listens on."""

    streamable_http = "streamable-http"
    https = "https"
    ws = "ws"
    stdio = "stdio"
    sse = "sse"


class AuthType(StrEnum):
    """Authentication method required to call the agent."""

    none = "none"
    api_key = "api_key"
    bearer = "bearer"
    oauth2 = "oauth2"
    mtls = "mtls"
    http_msg_sig = "http_msg_sig"  # RFC 9421 HTTP Message Signatures (Web Bot Auth)


# ---------------------------------------------------------------------------
# Nested sections
# ---------------------------------------------------------------------------


class AgentIdentity(BaseModel):
    """WHO — agent identification and lifecycle."""

    agent_id: str | None = Field(None, max_length=36, description="UUID identifier for the agent")
    name: str = Field(..., min_length=1, max_length=255, description="Human-readable agent name")
    fqdn: str | None = Field(
        None, max_length=512, description="DNS-AID FQDN (e.g., chat.example.com)"
    )
    version: str | None = Field(None, max_length=20, description="Agent version string")
    deprecated: bool = Field(False, description="Whether this agent is deprecated")
    sunset_date: datetime | None = Field(
        None, description="Date after which the agent will be decommissioned"
    )
    successor: str | None = Field(
        None, max_length=512, description="FQDN of the replacement agent (if deprecated)"
    )


class ConnectionSpec(BaseModel):
    """HOW — transport and connection details."""

    protocol: str = Field(..., min_length=1, max_length=20, description="Protocol: mcp, a2a, https")
    transport: TransportType = Field(
        TransportType.https, description="Wire transport for the connection"
    )
    endpoint: str = Field(..., min_length=1, max_length=512, description="Agent endpoint URL")
    base_url: str | None = Field(None, max_length=512, description="Base URL for relative paths")


class AuthSpec(BaseModel):
    """ACCESS — authentication requirements."""

    type: AuthType = Field(AuthType.none, description="Authentication method")
    location: str | None = Field(
        None, max_length=50, description="Where to send credentials: header, query, body"
    )
    header_name: str | None = Field(
        None, max_length=100, description="Header name for api_key/bearer (e.g., Authorization)"
    )
    oauth_discovery: str | None = Field(
        None,
        max_length=512,
        description="OAuth 2.0 discovery URL (.well-known/openid-configuration)",
    )
    # Web Bot Auth (RFC 9421 HTTP Message Signatures)
    key_directory_url: str | None = Field(
        None,
        max_length=512,
        description="This agent's own JWKS key directory for identity verification",
    )
    signature_agent_card_url: str | None = Field(
        None,
        max_length=512,
        description="This agent's own Signature Agent Card (structured identity)",
    )
    supported_algorithms: list[str] | None = Field(
        None,
        description="Signing algorithms this agent accepts from callers (e.g., ['ed25519'])",
    )


class MetadataContact(BaseModel):
    """OWNER — organizational contact info."""

    owner: str | None = Field(None, max_length=255, description="Organization or team name")
    contact: str | None = Field(None, max_length=255, description="Contact email or URL")
    documentation: str | None = Field(None, max_length=512, description="Documentation URL")


# ---------------------------------------------------------------------------
# Top-level schema
# ---------------------------------------------------------------------------


class AgentMetadata(BaseModel):
    """
    Full `.well-known/agent.json` schema for DNS-AID agents.

    The ``aid_version`` field distinguishes DNS-AID native documents from
    Google A2A Agent Cards (which share the same well-known path).
    """

    aid_version: str = Field(
        "1.0", description="DNS-AID metadata schema version (discriminator vs A2A)"
    )

    identity: AgentIdentity
    connection: ConnectionSpec
    auth: AuthSpec = AuthSpec()  # type: ignore[call-arg]
    capabilities: CapabilitySpec = CapabilitySpec()  # type: ignore[call-arg]
    contact: MetadataContact = MetadataContact()  # type: ignore[call-arg]
