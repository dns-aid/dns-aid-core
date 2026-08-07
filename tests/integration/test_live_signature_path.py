# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Live verification of the record-signature path against published zones.

Gated behind DNS_AID_LIVE_TESTS=1 so CI stays hermetic:

    DNS_AID_LIVE_TESTS=1 uv run pytest tests/integration/test_live_signature_path.py -x -q

Why this file exists: the ``sig`` SvcParam was published correctly and dropped
during parsing for several releases, and no unit test caught it because the
suite constructed AgentRecord objects directly with ``sig=`` pre-set -- mocking
the exact seam where the defect lived. These tests drive real DNS answers
through the real parser.

Resolver pinning is deliberate. ``dnssec_validated`` follows the AD flag, which
only a validating resolver sets, so a non-validating resolver reports False for
the same signed zone that 8.8.8.8 reports True for. Whether the host running
these tests validates is not knowable in advance and changes with the network,
so an unpinned live test is not reproducible. Pin, and assert the difference
rather than leaving it to be rediscovered.
"""

import os

import dns.asyncresolver
import pytest

from dns_aid.core.discoverer import (
    _parse_svcb_custom_params,
    _verify_agent_signatures,
    discover,
    discover_at_fqdn,
)
from dns_aid.core.jwks import SignatureStatus, jwks_urls

pytestmark = [
    pytest.mark.live,  # excluded by CI's `-m "not live"`; run explicitly with the env flag
    pytest.mark.skipif(
        os.environ.get("DNS_AID_LIVE_TESTS") != "1",
        reason="live network test — set DNS_AID_LIVE_TESTS=1 to run",
    ),
]

# A DNSSEC-signed zone with a published agent. Signed, so agents here take the
# DNSSEC branch and JWS verification is correctly skipped.
SIGNED_ZONE = "ai.infoblox.com"
SIGNED_ZONE_AGENT = "ddi-agent"

# An UNSIGNED zone carrying a signed record. Required as a separate fixture:
# the JWS path only runs where DNSSEC does not, so it cannot be exercised on
# the signed zone above.
SIGNED_RECORD_FQDN = "ddi-agent.agents.ai.infoblox.com"

VALIDATING_RESOLVER = "8.8.8.8"


@pytest.fixture
def pinned_resolver(monkeypatch):
    """Pin discovery to a validating resolver so the AD flag is meaningful."""
    original = dns.asyncresolver.Resolver

    class _Pinned(original):  # type: ignore[valid-type,misc]
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.nameservers = [VALIDATING_RESOLVER]

    monkeypatch.setattr(dns.asyncresolver, "Resolver", _Pinned)
    return VALIDATING_RESOLVER


async def _find_agent(zone: str, name: str):
    result = await discover(zone, verify_signatures=True, verify_dane=True)
    matches = [a for a in result.agents if a.name == name]
    assert matches, f"{name} not found in {zone}; found {[a.name for a in result.agents]}"
    return matches[0]


class TestLiveSignedZone:
    """ai.infoblox.com — DNSSEC-signed, so JWS is skipped by design."""

    @pytest.mark.asyncio
    async def test_agent_resolves_with_its_svcparams(self, pinned_resolver):
        """Published SvcParams survive the trip into AgentRecord."""
        agent = await _find_agent(SIGNED_ZONE, SIGNED_ZONE_AGENT)

        assert agent.domain == SIGNED_ZONE
        assert agent.target_host
        assert agent.port == 443
        # Whatever this record publishes must land, not be silently dropped.
        assert agent.realm, "realm (key65404) did not reach the record"
        assert agent.policy_uri, "policy (key65403) did not reach the record"
        assert agent.well_known_path, "well-known (key65409) did not reach the record"

    @pytest.mark.asyncio
    async def test_dnssec_and_dane_validate_against_a_validating_resolver(self, pinned_resolver):
        """The signed zone validates, and DANE binds the endpoint certificate.

        DANE exercises the multi-association path; a single published TLSA
        association must still verify after the loop was changed to try all.
        """
        agent = await _find_agent(SIGNED_ZONE, SIGNED_ZONE_AGENT)

        assert agent.dnssec_validated is True
        assert agent.dane_verified is True

    @pytest.mark.asyncio
    async def test_unsigned_record_reports_sig_none_not_false(self, pinned_resolver):
        """A record with no key65405 is unsigned, not failed.

        signature_verified must stay None here: nothing was verified. False
        would assert that a signature was checked and rejected.
        """
        agent = await _find_agent(SIGNED_ZONE, SIGNED_ZONE_AGENT)

        if agent.sig is None:
            assert agent.signature_verified is None
        else:
            # If a signature has since been published, it must have been read
            # off the record -- the regression this suite exists for.
            assert agent.sig.count(".") == 2, "sig is not a compact JWS"

    @pytest.mark.asyncio
    async def test_dnssec_validated_flag_depends_on_the_resolver(self):
        """Documents the trap: the same signed zone reports differently.

        Without a validating resolver the AD flag is absent and the agent falls
        out of the DNSSEC branch into the JWS branch. Asserted so the behaviour
        is recorded rather than rediscovered during an incident.
        """
        agent_unpinned = await _find_agent(SIGNED_ZONE, SIGNED_ZONE_AGENT)
        system_resolver_validates = agent_unpinned.dnssec_validated

        original = dns.asyncresolver.Resolver

        class _Pinned(original):  # type: ignore[valid-type,misc]
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.nameservers = [VALIDATING_RESOLVER]

        dns.asyncresolver.Resolver = _Pinned  # type: ignore[misc]
        try:
            agent_pinned = await _find_agent(SIGNED_ZONE, SIGNED_ZONE_AGENT)
        finally:
            dns.asyncresolver.Resolver = original  # type: ignore[misc]

        assert agent_pinned.dnssec_validated is True, (
            f"{SIGNED_ZONE} is DNSSEC-signed; a validating resolver must set AD"
        )
        if system_resolver_validates is not True:
            pytest.skip(
                "system resolver is non-validating (expected on many hosts) — "
                "pinned resolver validated correctly, which is the assertion that matters"
            )


class TestLiveSignedRecordOnUnsignedZone:
    """agents.ai.infoblox.com — unsigned, so the JWS path actually executes.

    The signed zone above is the wrong place to exercise JWS: DNSSEC validates
    there, so verification is skipped by design. Only an unsigned zone reaches
    this code, which is also the only situation the JWS path exists to serve.
    """

    @pytest.mark.asyncio
    async def test_signature_is_read_off_the_record(self, pinned_resolver):
        """The blocker: a published key65405 must reach AgentRecord.sig."""
        agent = await discover_at_fqdn(SIGNED_RECORD_FQDN)

        assert agent is not None, f"{SIGNED_RECORD_FQDN} did not resolve"
        assert agent.sig, "key65405 is published but was not read off the record"
        assert agent.sig.count(".") == 2, "sig is not a compact JWS"

    @pytest.mark.asyncio
    async def test_verification_reports_an_actionable_reason(self, pinned_resolver):
        """Whatever the outcome, it must say why -- not just True/False.

        Deliberately not asserting a fixed status: the record's signature
        lapses and is re-published over time. What must hold is that the status
        is meaningful and consistent with signature_verified, and that an
        unreachable key document is never reported as a rejection.
        """
        agent = await discover_at_fqdn(SIGNED_RECORD_FQDN)
        await _verify_agent_signatures([agent], agent.domain, dnssec_validated=False)

        assert agent.signature_status in {
            SignatureStatus.VERIFIED,
            # The published record predates the svcb claim, so it verifies with
            # endpoint-only coverage. Both count as verified.
            SignatureStatus.VERIFIED_ENDPOINT_ONLY,
            SignatureStatus.EXPIRED,
            SignatureStatus.INVALID,
            SignatureStatus.UNBOUND,
            SignatureStatus.NO_KEY,
        }, f"unexpected status {agent.signature_status!r}"

        if agent.signature_status in (
            SignatureStatus.VERIFIED,
            SignatureStatus.VERIFIED_ENDPOINT_ONLY,
        ):
            assert agent.signature_verified is True
            assert agent.signature_algorithm == "ES256"
        elif agent.signature_status == SignatureStatus.NO_KEY:
            # Nothing was verified -- unknown, never a rejection.
            assert agent.signature_verified is None
        else:
            assert agent.signature_verified is False

    @pytest.mark.asyncio
    async def test_require_signed_is_fail_closed(self, pinned_resolver):
        """An unverified record never passes the trust gate."""
        from dns_aid.core.filters import _matches_signed

        agent = await discover_at_fqdn(SIGNED_RECORD_FQDN)
        await _verify_agent_signatures([agent], agent.domain, dnssec_validated=False)

        passes = _matches_signed(agent, require=True, allowed_algorithms=None)
        assert passes is (agent.signature_verified is True)

    @pytest.mark.asyncio
    async def test_jwks_is_located_from_the_record_zone(self, pinned_resolver):
        """Derived host first, apex fallback -- both anchored on the record."""
        agent = await discover_at_fqdn(SIGNED_RECORD_FQDN)
        candidates = jwks_urls(agent.domain)

        assert candidates[0].startswith(f"https://dns-aid.{agent.domain}/")
        assert candidates[1].startswith(f"https://{agent.domain}/")
        # The zone must come from the record, not the FQDN that was queried.
        assert agent.domain != SIGNED_RECORD_FQDN


class TestLiveRecordParsesSig:
    """The published record's own wire format, run through the real parser."""

    @pytest.mark.asyncio
    async def test_sig_parses_from_the_live_record_shape(self, pinned_resolver):
        """Take the real SVCB text and confirm key65405 would be read.

        The zone may not publish a signature today, so a signature is appended
        to the genuine record text rather than fabricating a record: this keeps
        the mandatory=, alpn=, port= and existing keyNNNNN params exactly as the
        authoritative server renders them, which is what the parser must handle.
        """
        answers = await dns.asyncresolver.Resolver().resolve(
            f"{SIGNED_ZONE_AGENT}.{SIGNED_ZONE}", "SVCB"
        )
        live_text = str(list(answers)[0])

        as_published = _parse_svcb_custom_params(live_text)
        assert "realm" in as_published, f"live record did not parse as expected: {live_text}"

        jws = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcWRuIjoieCJ9.c2ln"
        with_sig = _parse_svcb_custom_params(f'{live_text} key65405="{jws}"')

        assert with_sig["sig"] == jws, (
            "key65405 was not parsed from a real published record — this is the "
            "defect that made publish --sign write-only"
        )
