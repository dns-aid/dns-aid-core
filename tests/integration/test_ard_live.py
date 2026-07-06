# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Live integration test for ARD ai-catalog discovery (spec 007, SC-006).

Hits the real ARD catalog deployed for highvelocitynetworking.com over
public HTTPS. Gated behind DNS_AID_LIVE_TESTS=1 so CI stays hermetic:

    DNS_AID_LIVE_TESTS=1 uv run pytest tests/integration/test_ard_live.py -x -q
"""

import os

import pytest

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        os.environ.get("DNS_AID_LIVE_TESTS") != "1",
        reason="live network test — set DNS_AID_LIVE_TESTS=1 to run",
    ),
]

LIVE_DOMAIN = "highvelocitynetworking.com"


async def test_live_ard_catalog_fetch():
    """The raw catalog is served at the ARD well-known location."""
    from dns_aid.core.http_index import fetch_http_index

    agents = await fetch_http_index(LIVE_DOMAIN)
    ard_agents = [a for a in agents if a.source_format == "ard"]
    assert ard_agents, f"no ARD-sourced agents discovered at {LIVE_DOMAIN}"
    assert all(a.identifier and a.identifier.startswith("urn:air:") for a in ard_agents)


async def test_live_discover_via_library():
    """SDK surface: discover() returns ARD agents with trust manifests."""
    from dns_aid import discover

    result = await discover(LIVE_DOMAIN, use_http_index=True)
    ard_records = [a for a in result.agents if a.capability_source == "ard_catalog"]
    assert ard_records, f"no ard_catalog records discovered at {LIVE_DOMAIN}"
    with_trust = [a for a in ard_records if a.trust_manifest is not None]
    assert with_trust, "expected at least one agent with a populated trust_manifest"
    tm = with_trust[0].trust_manifest
    assert tm.identity
    assert tm.attestations, "expected published attestations to survive the pipeline"
