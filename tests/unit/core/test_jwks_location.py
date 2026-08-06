# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""JWKS document location is derived, not declared.

Two properties are under test:

1. The location comes from a dedicated ``dns-aid.<zone>`` host rather than the
   zone apex. A zone that exists only to carry agent records has no web
   presence at its apex, so requiring HTTPS there made the JWS path
   undeployable for exactly the delegated-namespace shape it was meant to
   serve. The derived host is a fresh name and may CNAME anywhere.

2. The zone is taken from the record, not from the caller's ``discover()``
   argument. Otherwise the same record verifies against a different JWKS
   depending on how discovery was entered, and a publisher would have to serve
   the document at every name a consumer might use.

No pointer is involved by design: this path runs when the DNS answer is
unauthenticated, so a pointer in the record could be forged alongside it.
"""

from unittest.mock import AsyncMock, patch

import pytest

from dns_aid.core.jwks import JWKS_WELL_KNOWN_PATH, fetch_jwks, jwks_urls

JWKS_DOC = {"keys": [{"kty": "EC", "crv": "P-256", "kid": "k1", "x": "eA", "y": "eQ"}]}


@pytest.fixture(autouse=True)
def _clear_cache():
    from dns_aid.core.jwks import _jwks_cache

    _jwks_cache.clear()
    yield
    _jwks_cache.clear()


class TestDerivedLocation:
    def test_derived_host_is_preferred_apex_is_fallback(self):
        urls = jwks_urls("ai.example.com")

        assert urls[0] == f"https://dns-aid.ai.example.com{JWKS_WELL_KNOWN_PATH}"
        assert urls[1] == f"https://ai.example.com{JWKS_WELL_KNOWN_PATH}"

    def test_derived_host_has_no_underscore(self):
        """It is fetched over HTTPS, so it must be certifiable.

        CA/Browser Forum rules bar underscores from certificate dNSName SANs.
        """
        host = jwks_urls("ai.example.com")[0].split("/")[2]

        assert "_" not in host

    def test_trailing_dot_is_normalised(self):
        assert jwks_urls("ai.example.com.")[0] == jwks_urls("ai.example.com")[0]

    @pytest.mark.asyncio
    async def test_fetches_from_derived_host_first(self):
        seen = []

        async def fake_fetch(url, domain):
            seen.append(url)
            return JWKS_DOC

        with patch("dns_aid.core.jwks._fetch_jwks_from", new=AsyncMock(side_effect=fake_fetch)):
            result = await fetch_jwks("ai.example.com")

        assert result == JWKS_DOC
        assert seen == [f"https://dns-aid.ai.example.com{JWKS_WELL_KNOWN_PATH}"], (
            "the apex must not be contacted when the derived host answers"
        )

    @pytest.mark.asyncio
    async def test_falls_back_to_apex_when_derived_host_absent(self):
        """Deployments that published before the derived host keep working."""
        seen = []

        async def fake_fetch(url, domain):
            seen.append(url)
            return None if url.startswith("https://dns-aid.") else JWKS_DOC

        with patch("dns_aid.core.jwks._fetch_jwks_from", new=AsyncMock(side_effect=fake_fetch)):
            result = await fetch_jwks("ai.example.com")

        assert result == JWKS_DOC
        assert seen == jwks_urls("ai.example.com")

    @pytest.mark.asyncio
    async def test_returns_none_when_neither_location_serves(self):
        with patch("dns_aid.core.jwks._fetch_jwks_from", new=AsyncMock(return_value=None)):
            assert await fetch_jwks("ai.example.com") is None


class TestZoneAnchoring:
    """The JWKS zone comes from the record, not the caller's query string."""

    @pytest.mark.asyncio
    async def test_same_record_resolves_to_one_location_from_any_entry_point(self):
        """Entering by zone or by agent FQDN must hit the same JWKS."""
        from dns_aid.core.discoverer import _verify_agent_signatures
        from dns_aid.core.models import AgentRecord, Protocol

        def _agent():
            return AgentRecord(
                name="ddi-agent",
                domain="ai.example.com",
                protocol=Protocol.MCP,
                target_host="edge.ai.example.com",
                port=443,
                sig="eyJhbGciOiJFUzI1NiJ9.eyJ9.c2ln",
            )

        zones_asked = []

        async def fake_verify(zone, jws):
            zones_asked.append(zone)
            return False, None

        with patch(
            "dns_aid.core.jwks.verify_record_signature",
            new=AsyncMock(side_effect=fake_verify),
        ):
            # Entry point A: the caller queried the zone.
            await _verify_agent_signatures([_agent()], "ai.example.com", dnssec_validated=False)
            # Entry point B: the caller queried the agent FQDN directly.
            await _verify_agent_signatures(
                [_agent()], "ddi-agent.ai.example.com", dnssec_validated=False
            )

        assert zones_asked == ["ai.example.com", "ai.example.com"], (
            "JWKS zone must come from the record, not the discover() argument"
        )
