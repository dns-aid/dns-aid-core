# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Shared fixtures for cross-interface parity tests (FR-024, FR-025, US4).

The whole point of US4 is the *equivalent surfaces* invariant: identical inputs
must produce identical outputs whether they enter the system through the SDK,
the CLI, or the MCP tool. The fixtures here build the canonical Path A agent
set and Path B search response *once*, so the parity matrix asserts equality
against a single source of truth instead of re-deriving expectations per surface.
"""

from __future__ import annotations

from typing import Any

import pytest

from dns_aid.core.models import AgentRecord, Protocol


@pytest.fixture
def parity_agents() -> list[AgentRecord]:
    """Three agents with mixed metadata to exercise every Path A filter at once."""
    return [
        AgentRecord(
            name="payments",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="payments.example.com",
            port=443,
            capabilities=["payment-processing", "fraud-detection"],
            description="Process card payments and run fraud heuristics.",
            auth_type="oauth2",
            realm="prod",
            sig="hdr.payload.sig",
            signature_verified=True,
            signature_algorithm="ES256",
            dnssec_validated=True,
        ),
        AgentRecord(
            name="search",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="search.example.com",
            port=443,
            capabilities=["search"],
            description="Catalog full-text search.",
            auth_type="api_key",
            realm="prod",
            dnssec_validated=True,
        ),
        AgentRecord(
            name="legacy",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="legacy.example.com",
            port=443,
            capabilities=["fraud-detection"],
            description="Older fraud rules engine, kept for staging.",
            auth_type="oauth2",
            realm="staging",
            sig="hdr.payload.sig",
            signature_verified=True,
            signature_algorithm="HS256",
            dnssec_validated=False,
        ),
    ]


@pytest.fixture
def parity_search_payload() -> dict[str, Any]:
    """
    Canonical /api/v1/search response in the directory's flat wire shape.

    Mirrors ``dns_aid_directory.api.schemas.SearchResponse`` exactly: ``query``
    is a string echo, results carry only ``agent`` + ``score``, and trust +
    provenance signals live flat on the agent. The SDK's
    ``_adapt_search_payload`` lifts these into the typed nested objects
    ``TrustAttestation`` / ``Provenance`` before validation — so this fixture
    exercises the production round-trip, not a pre-adapted SDK shape.
    """
    return {
        "query": "payments",
        "results": [
            {
                "agent": {
                    "fqdn": "_payments._mcp._agents.example.com",
                    "name": "payments",
                    "domain": "example.com",
                    "protocol": "mcp",
                    "endpoint_url": "https://payments.example.com",
                    "port": 443,
                    "capabilities": ["payment-processing", "fraud-detection"],
                    "description": "Process card payments.",
                    "auth_type": "oauth2",
                    "bap": "mcp=1.0",
                    # Trust signals flat on the agent.
                    "security_score": 88,
                    "trust_score": 91,
                    "popularity_score": 80,
                    "trust_tier": 1,
                    "safety_status": "active",
                    "dnssec_valid": True,
                    "dane_valid": False,
                    "svcb_valid": True,
                    "endpoint_reachable": True,
                    "protocol_verified": True,
                    "trust_badges": ["Verified", "DNSSEC"],
                    # Provenance signals flat on the agent.
                    "discovery_level": 2,
                    "first_seen": "2026-04-01T00:00:00Z",
                    "last_seen": "2026-05-01T00:00:00Z",
                    "last_verified": "2026-04-30T00:00:00Z",
                },
                "score": 39.2,
            },
            {
                "agent": {
                    "fqdn": "_search._mcp._agents.example.com",
                    "name": "search",
                    "domain": "example.com",
                    "protocol": "mcp",
                    "endpoint_url": "https://search.example.com",
                    "port": 443,
                    "capabilities": ["search"],
                    "description": "Catalog search.",
                    "auth_type": "api_key",
                    "security_score": 72,
                    "trust_score": 70,
                    "popularity_score": 60,
                    "trust_tier": 2,
                    "safety_status": "active",
                    "first_seen": "2026-04-15T00:00:00Z",
                    "last_seen": "2026-05-01T00:00:00Z",
                },
                "score": 28.4,
            },
        ],
        "total": 2,
        "limit": 20,
        "offset": 0,
    }
