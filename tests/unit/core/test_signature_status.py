# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Signature verification reports *why*, and key rollovers can overlap.

Two related properties.

Tri-state: an unreachable JWKS is unknown, not forged. Reporting a network
fault as a failed signature both misdirects the operator and, worse, trains
them to ignore the signal that a real forgery would raise. ``require_signed``
stays fail-closed throughout -- it demands ``is True``, so ``None`` is still
rejected; the change is in what the record *reports*, not in what passes.

Rollover: a signature names the key that produced it (``kid``), so the outgoing
and incoming keys can sit in one JWKS while records are re-signed. Without it
every signature is tried against every key, nothing is attributable to a
signer, and a newly published key is invisible until the cache expires.
"""

from unittest.mock import AsyncMock, patch

import pytest

from dns_aid.core.jwks import (
    RecordPayload,
    SignatureStatus,
    export_jwks,
    export_jwks_multi,
    generate_keypair,
    sign_record,
    verify_record_signature_detailed,
    verify_signature_detailed,
)
from dns_aid.core.models import AgentRecord, Protocol

ZONE = "agents.example.com"
FQDN = "ddi-agent.agents.example.com"
TARGET = "edge.example.com"


@pytest.fixture(autouse=True)
def _clear_cache():
    from dns_aid.core.jwks import _jwks_cache

    _jwks_cache.clear()
    yield
    _jwks_cache.clear()


def _payload(ttl_seconds: int = 3600, fqdn: str = FQDN, target: str = TARGET) -> RecordPayload:
    return RecordPayload.from_agent_record(
        fqdn=fqdn, target=target, port=443, protocol="a2a", ttl_seconds=ttl_seconds
    )


def _agent(sig: str) -> AgentRecord:
    return AgentRecord(
        name="ddi-agent",
        domain=ZONE,
        protocol=Protocol.A2A,
        target_host=TARGET,
        port=443,
        sig=sig,
    )


class TestUnknownIsNotForged:
    """An unfetchable key document must not read as a bad signature."""

    @pytest.mark.asyncio
    async def test_unreachable_jwks_is_no_key_not_invalid(self):
        priv, _ = generate_keypair()
        sig = sign_record(_payload(), priv)

        with patch("dns_aid.core.jwks.fetch_jwks", new=AsyncMock(return_value=None)):
            ok, payload, status = await verify_record_signature_detailed(ZONE, sig)

        assert ok is False
        assert status is SignatureStatus.NO_KEY

    @pytest.mark.asyncio
    async def test_discoverer_records_none_when_no_key_reachable(self):
        """The record reports unknown, and require_signed still drops it."""
        from dns_aid.core.discoverer import _verify_agent_signatures
        from dns_aid.core.filters import _matches_signed

        priv, _ = generate_keypair()
        agent = _agent(sign_record(_payload(), priv))

        with patch("dns_aid.core.jwks.fetch_jwks", new=AsyncMock(return_value=None)):
            await _verify_agent_signatures([agent], ZONE, dnssec_validated=False)

        assert agent.signature_verified is None, "an outage must not be reported as forgery"
        assert agent.signature_status == SignatureStatus.NO_KEY
        # Fail-closed is preserved: unknown does not pass a trust gate.
        assert _matches_signed(agent, require=True, allowed_algorithms=None) is False

    @pytest.mark.asyncio
    async def test_rejected_signature_is_false_not_none(self):
        """A key WAS retrieved and said no -- that is a real negative."""
        from dns_aid.core.discoverer import _verify_agent_signatures

        signing_key, _ = generate_keypair()
        _, unrelated_pub = generate_keypair()
        agent = _agent(sign_record(_payload(), signing_key))

        with patch(
            "dns_aid.core.jwks.fetch_jwks",
            new=AsyncMock(return_value=export_jwks(unrelated_pub, kid="other")),
        ):
            await _verify_agent_signatures([agent], ZONE, dnssec_validated=False)

        assert agent.signature_verified is False
        assert agent.signature_status == SignatureStatus.INVALID


class TestStatusDistinguishesCauses:
    def test_expired_is_reported_separately_from_invalid(self):
        """Both are 'do not trust', but only one is fixed by re-publishing."""
        priv, pub = generate_keypair()
        sig = sign_record(_payload(ttl_seconds=-10), priv)

        ok, _, status = verify_signature_detailed(sig, pub)

        assert ok is False
        assert status is SignatureStatus.EXPIRED

    @pytest.mark.asyncio
    async def test_expired_survives_a_multi_key_jwks(self):
        """Expiry is a property of the signature, not of which key was tried."""
        priv, pub = generate_keypair()
        _, other = generate_keypair()
        sig = sign_record(_payload(ttl_seconds=-10), priv)

        jwks = export_jwks_multi([(other, "a"), (pub, "b")])
        with patch("dns_aid.core.jwks.fetch_jwks", new=AsyncMock(return_value=jwks)):
            ok, _, status = await verify_record_signature_detailed(ZONE, sig)

        assert ok is False
        assert status is SignatureStatus.EXPIRED, "must not be masked by another key's INVALID"

    @pytest.mark.asyncio
    async def test_valid_signature_for_a_different_record_is_unbound(self):
        """A lifted signature pasted onto a spoofed record."""
        from dns_aid.core.discoverer import _verify_agent_signatures

        priv, pub = generate_keypair()
        # Signed for a different target than the record now claims.
        sig = sign_record(_payload(target="attacker.example.net"), priv)
        agent = _agent(sig)

        with patch(
            "dns_aid.core.jwks.fetch_jwks",
            new=AsyncMock(return_value=export_jwks(pub, kid="k")),
        ):
            await _verify_agent_signatures([agent], ZONE, dnssec_validated=False)

        assert agent.signature_verified is False
        assert agent.signature_status == SignatureStatus.UNBOUND

    @pytest.mark.asyncio
    async def test_record_without_sig_is_not_signed(self):
        from dns_aid.core.discoverer import _verify_agent_signatures

        agent = AgentRecord(
            name="plain", domain=ZONE, protocol=Protocol.A2A, target_host=TARGET, port=443
        )

        await _verify_agent_signatures([agent], ZONE, dnssec_validated=False)

        assert agent.signature_verified is None
        assert agent.signature_status == SignatureStatus.NOT_SIGNED

    @pytest.mark.asyncio
    async def test_verified_record_reports_verified(self):
        from dns_aid.core.discoverer import _verify_agent_signatures

        priv, pub = generate_keypair()
        agent = _agent(sign_record(_payload(), priv))

        with patch(
            "dns_aid.core.jwks.fetch_jwks",
            new=AsyncMock(return_value=export_jwks(pub, kid="k")),
        ):
            await _verify_agent_signatures([agent], ZONE, dnssec_validated=False)

        assert agent.signature_verified is True
        assert agent.signature_status == SignatureStatus.VERIFIED
        assert agent.signature_algorithm == "ES256"


class TestKeyRollover:
    """Overlapping keys, selected by kid."""

    def test_kid_is_published_in_the_protected_header(self):
        import base64
        import json

        priv, _ = generate_keypair()
        sig = sign_record(_payload(), priv, kid="ddi-agent-2026-08")

        header_b64 = sig.split(".")[0]
        header_b64 += "=" * (-len(header_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64))

        assert header["kid"] == "ddi-agent-2026-08"
        assert header["alg"] == "ES256"

    def test_header_is_unchanged_when_no_kid_is_supplied(self):
        """Previously published signatures keep their exact byte shape."""
        import base64
        import json

        priv, _ = generate_keypair()
        header_b64 = sign_record(_payload(), priv).split(".")[0]
        header_b64 += "=" * (-len(header_b64) % 4)

        assert json.loads(base64.urlsafe_b64decode(header_b64)) == {"alg": "ES256", "typ": "JWT"}

    @pytest.mark.asyncio
    async def test_both_keys_verify_during_an_overlap(self):
        """The rollover window: old records and new records both validate."""
        old_priv, old_pub = generate_keypair()
        new_priv, new_pub = generate_keypair()
        jwks = export_jwks_multi([(old_pub, "old"), (new_pub, "new")])

        old_sig = sign_record(_payload(), old_priv, kid="old")
        new_sig = sign_record(_payload(), new_priv, kid="new")

        with patch("dns_aid.core.jwks.fetch_jwks", new=AsyncMock(return_value=jwks)):
            old_ok, _, old_status = await verify_record_signature_detailed(ZONE, old_sig)
            new_ok, _, new_status = await verify_record_signature_detailed(ZONE, new_sig)

        assert (old_ok, old_status) == (True, SignatureStatus.VERIFIED)
        assert (new_ok, new_status) == (True, SignatureStatus.VERIFIED)

    @pytest.mark.asyncio
    async def test_legacy_signature_without_kid_still_verifies(self):
        """No kid means no selection hint -- fall back to trying the set."""
        priv, pub = generate_keypair()
        _, other = generate_keypair()
        sig = sign_record(_payload(), priv)  # no kid

        jwks = export_jwks_multi([(other, "other"), (pub, "mine")])
        with patch("dns_aid.core.jwks.fetch_jwks", new=AsyncMock(return_value=jwks)):
            ok, _, status = await verify_record_signature_detailed(ZONE, sig)

        assert (ok, status) == (True, SignatureStatus.VERIFIED)

    @pytest.mark.asyncio
    async def test_unknown_kid_triggers_exactly_one_refresh(self):
        """A key published inside the cache window must not wait it out."""
        priv, pub = generate_keypair()
        sig = sign_record(_payload(), priv, kid="rotated-in")

        _, stale_pub = generate_keypair()
        stale = export_jwks(stale_pub, kid="stale")
        fresh = export_jwks(pub, kid="rotated-in")

        calls = []

        async def fetch(domain):
            calls.append(domain)
            return stale if len(calls) == 1 else fresh

        with patch("dns_aid.core.jwks.fetch_jwks", new=AsyncMock(side_effect=fetch)):
            ok, _, status = await verify_record_signature_detailed(ZONE, sig)

        assert (ok, status) == (True, SignatureStatus.VERIFIED)
        assert len(calls) == 2, "expected exactly one forced refresh after the kid miss"

    def test_export_jwks_multi_carries_every_key(self):
        _, a = generate_keypair()
        _, b = generate_keypair()

        doc = export_jwks_multi([(a, "old"), (b, "new")])

        assert [k["kid"] for k in doc["keys"]] == ["old", "new"]
        assert all(k["crv"] == "P-256" for k in doc["keys"])
