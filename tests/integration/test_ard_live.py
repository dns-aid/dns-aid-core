# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Live integration tests for ARD ai-catalog discovery (spec 007, SC-006).

Targets the real deployment for highvelocitynetworking.com over public
DNS + HTTPS:

- ``ard.highvelocitynetworking.com`` serves ONLY the ARD catalog at the
  well-known location — proves native ARD discovery end-to-end.
- ``highvelocitynetworking.com`` (apex) serves BOTH a legacy HTTP index
  (index.aiagents subdomain, pre-existing demo infra) and the ARD catalog
  — proves the contract C1 precedence rule live: legacy wins.

Gated behind DNS_AID_LIVE_TESTS=1 so CI stays hermetic:

    DNS_AID_LIVE_TESTS=1 uv run pytest tests/integration/test_ard_live.py -x -q
"""

import os

import pytest

pytestmark = [
    pytest.mark.live,  # excluded by CI's `-m "not live"`; run explicitly with the env flag
    pytest.mark.asyncio,
    pytest.mark.skipif(
        os.environ.get("DNS_AID_LIVE_TESTS") != "1",
        reason="live network test — set DNS_AID_LIVE_TESTS=1 to run",
    ),
]

ARD_ONLY_DOMAIN = "ard.highvelocitynetworking.com"
APEX_DOMAIN = "highvelocitynetworking.com"

EXPECTED_ARD_AGENTS = {
    "chat-assistant",
    "billing",
    "medical-triage",
    "booking",  # from the nested travel bundle
    "booking-premium",  # from the nested travel bundle
}


async def test_live_ard_catalog_fetch():
    """The ARD catalog is served and parsed from the well-known location."""
    from dns_aid.core.http_index import fetch_http_index

    agents = await fetch_http_index(ARD_ONLY_DOMAIN)
    ard_agents = [a for a in agents if a.source_format == "ard"]
    assert {a.name for a in ard_agents} == EXPECTED_ARD_AGENTS
    assert all(a.identifier and a.identifier.startswith("urn:air:") for a in ard_agents)


async def test_live_discover_via_library():
    """SDK surface: discover() returns ARD agents, cards dereferenced (B)."""
    from dns_aid import discover

    result = await discover(ARD_ONLY_DOMAIN, use_http_index=True)
    by_name = {a.name: a for a in result.agents}
    assert set(by_name) == EXPECTED_ARD_AGENTS

    # B: each ARD entry's card was fetched and its REAL service endpoint applied,
    # not the shallow card URL.
    assert all(a.endpoint_source == "ard_card" for a in result.agents), (
        "every ARD agent's card should be dereferenced to its real endpoint"
    )
    billing = by_name["billing"]
    assert billing.endpoint_url.startswith("https://billing.highvelocitynetworking.com")
    assert "create_invoice" in billing.capabilities  # tools from the fetched card
    assert billing.capability_source == "agent_card"

    # The catalogue entry's trust manifest survives card enrichment.
    tm = by_name["chat-assistant"].trust_manifest
    assert tm is not None
    assert tm.identity == "spiffe://highvelocitynetworking.com/agents/chat-assistant"
    assert {a.type for a in tm.attestations} == {"SOC2-Type2", "ISO27001", "GDPR"}


async def test_live_apex_legacy_precedence():
    """Contract C1 live: a domain serving both formats keeps legacy precedence."""
    from dns_aid.core.http_index import fetch_http_index

    agents = await fetch_http_index(APEX_DOMAIN)
    assert agents, "apex serves a legacy index — expected agents"
    assert all(a.source_format == "legacy" for a in agents), (
        "legacy index endpoints are probed before the ARD well-known location"
    )
