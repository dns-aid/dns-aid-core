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
    from dns_aid.core.jwks import _jwks_cache, _jwks_forced_refresh, _jwks_negative

    # _jwks_forced_refresh is process-global and keyed on the shared test zone.
    # Leaving it set made the kid-refresh tests pass or fail on collection order.
    _jwks_cache.clear()
    _jwks_forced_refresh.clear()
    _jwks_negative.clear()
    yield
    _jwks_cache.clear()
    _jwks_forced_refresh.clear()
    _jwks_negative.clear()


def _payload(validity_seconds: int = 3600, fqdn: str = FQDN, target: str = TARGET) -> RecordPayload:
    return RecordPayload.from_agent_record(
        fqdn=fqdn, target=target, port=443, protocol="a2a", validity_seconds=validity_seconds
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
        sig = sign_record(_payload(validity_seconds=-10), priv)

        ok, _, status = verify_signature_detailed(sig, pub)

        assert ok is False
        assert status is SignatureStatus.EXPIRED

    @pytest.mark.asyncio
    async def test_expired_survives_a_multi_key_jwks(self):
        """Expiry is a property of the signature, not of which key was tried."""
        priv, pub = generate_keypair()
        _, other = generate_keypair()
        sig = sign_record(_payload(validity_seconds=-10), priv)

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
        """Signed without params, so this is the endpoint-only flavour."""
        from dns_aid.core.discoverer import _verify_agent_signatures

        priv, pub = generate_keypair()
        agent = _agent(sign_record(_payload(), priv))

        with patch(
            "dns_aid.core.jwks.fetch_jwks",
            new=AsyncMock(return_value=export_jwks(pub, kid="k")),
        ):
            await _verify_agent_signatures([agent], ZONE, dnssec_validated=False)

        assert agent.signature_verified is True
        assert agent.signature_status == SignatureStatus.VERIFIED_ENDPOINT_ONLY
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

    def test_export_jwks_multi_carries_every_key(self):
        _, a = generate_keypair()
        _, b = generate_keypair()

        doc = export_jwks_multi([(a, "old"), (b, "new")])

        assert [k["kid"] for k in doc["keys"]] == ["old", "new"]
        assert all(k["crv"] == "P-256" for k in doc["keys"])


class TestKidRefreshIsBoundedAndHonest:
    """A named key that is absent is unknown, and one bogus kid must not
    deny a legitimate rollover.

    The forced refetch exists so a key rolled in since the document was cached
    is picked up without waiting out the TTL. Left unbounded it re-fetched on
    every verification; bounded by domain alone, a single attacker-chosen kid
    -- `sig` comes off an unauthenticated DNS record -- burned the whole
    domain's budget and blocked a real rollover for the rest of the window. The
    stamp is therefore keyed by domain alone, on a monotonic clock.
    """

    def _sig(self, priv, kid=None):
        payload = RecordPayload.from_agent_record(
            "a.example.com", "t.example.com", 443, "a2a", validity_seconds=90 * 86400
        )
        return sign_record(payload, priv, kid=kid) if kid else sign_record(payload, priv)

    @pytest.mark.asyncio
    async def test_no_usable_key_is_unknown_not_a_rejection(self):
        """NO_KEY means nothing could be checked, and only that.

        It used to also cover "keys were tried and all rejected this, but we
        could not confirm the key set was current". That made the verdict depend
        on a refetch budget the attacker could spend, so a forgery could be
        laundered into the one status consumers are told is not an attack signal.
        The discriminator is now whether a real key rejected the bytes.
        """
        priv, _ = generate_keypair()

        with patch("dns_aid.core.jwks._fetch_jwks_from", new=AsyncMock(return_value={"keys": []})):
            ok, _, status = await verify_record_signature_detailed(
                ZONE, self._sig(priv, kid="never-served")
            )

        assert ok is False
        assert status is SignatureStatus.NO_KEY, "nothing was checked, so nothing is refuted"

    @pytest.mark.asyncio
    async def test_once_the_key_set_is_confirmed_current_an_absent_kid_is_a_rejection(self):
        """After a successful refetch it is no longer unknown.

        kid comes off the unauthenticated record, so the attacker picks it. If an
        absent kid always meant NO_KEY, every forgery would report the one status
        the MCP contract tells consumers is "unknown, not forged, do not treat as
        an attack signal" -- detection suppressed by attacker choice.
        """
        priv, _ = generate_keypair()
        _, other = generate_keypair()
        served = export_jwks(other, kid="something-else")

        with (
            patch("dns_aid.core.jwks._fetch_jwks_from", new=AsyncMock(return_value=served)),
            patch("dns_aid.core.jwks._fetch_jwks_uncached", new=AsyncMock(return_value=served)),
        ):
            ok, _, status = await verify_record_signature_detailed(
                ZONE, self._sig(priv, kid="never-served")
            )

        assert ok is False
        assert status is SignatureStatus.INVALID, (
            "the publisher's current keys were fetched and none verifies this "
            "signature, so an attacker cannot launder a forgery into unknown"
        )

    @pytest.mark.asyncio
    async def test_repeated_misses_do_not_refetch_every_time(self):
        """Without the bound this was one refetch per verification, forever."""
        priv, _ = generate_keypair()
        _, other = generate_keypair()
        served = export_jwks(other, kid="something-else")
        sig = self._sig(priv, kid="never-served")

        fetches = []

        async def http(url, domain):  # noqa: ARG001
            fetches.append(url)
            return served

        with patch("dns_aid.core.jwks._fetch_jwks_from", new=AsyncMock(side_effect=http)):
            for _ in range(5):
                await verify_record_signature_detailed(ZONE, sig)

        assert len(fetches) <= 2, f"{len(fetches)} fetches for 5 verifications"

    @pytest.mark.asyncio
    async def test_a_rollover_is_picked_up_when_a_refetch_is_permitted(self):
        """The budget is per domain, which is the deliberate trade.

        Keying it by (domain, kid) gave every attacker-chosen value its own
        unspent budget, so a rotating kid forced a refetch per lookup. A
        per-domain budget bounds that. The cost is that a bogus kid may delay a
        genuine rollover by up to one window, which is bounded and self-healing.
        """
        new_priv, new_pub = generate_keypair()
        _, old_pub = generate_keypair()
        served = {"doc": export_jwks(old_pub, kid="old-key")}

        async def http(url, domain):  # noqa: ARG001
            return served["doc"]

        with patch("dns_aid.core.jwks._fetch_jwks_from", new=AsyncMock(side_effect=http)):
            # The publisher rolls in a new key. The cached document predates it,
            # so the refetch is what finds it.
            served["doc"] = export_jwks(new_pub, kid="rolled-in")
            ok, _, status = await verify_record_signature_detailed(
                ZONE, self._sig(new_priv, kid="rolled-in")
            )

        assert ok is True
        assert status is SignatureStatus.VERIFIED

    @pytest.mark.asyncio
    async def test_a_rotating_kid_cannot_force_a_fetch_per_lookup(self):
        """kid is attacker-chosen per lookup, so the budget cannot be per kid."""
        priv, _ = generate_keypair()
        _, other = generate_keypair()
        served = export_jwks(other, kid="real")

        fetches = []

        async def http(url, domain):  # noqa: ARG001
            fetches.append(url)
            return served

        with patch("dns_aid.core.jwks._fetch_jwks_from", new=AsyncMock(side_effect=http)):
            for i in range(20):
                await verify_record_signature_detailed(ZONE, self._sig(priv, kid=f"atk-{i}"))

        assert len(fetches) <= 2, f"{len(fetches)} fetches for 20 rotating kids"

    @pytest.mark.asyncio
    async def test_a_failed_fetch_is_remembered_briefly_then_retried(self):
        """A dead JWKS host costs one timeout per zone, not one per agent.

        Successes were cached and failures were not, so a zone publishing N
        signed agents against an unreachable host paid two candidate URLs at 10s
        each, N times, inside one discovery -- six agents already exceeded the
        MCP server's 120s per-call cap and the caller lost every result.

        The window is deliberately short and self-healing: an outage must not
        suppress verification for a whole cache window.
        """
        from dns_aid.core.jwks import JWKS_NEGATIVE_TTL, _jwks_negative, fetch_jwks

        priv, pub = generate_keypair()
        endpoint_down = True

        async def http(url, domain):  # noqa: ARG001
            return None if endpoint_down else export_jwks(pub)

        with patch("dns_aid.core.jwks._fetch_jwks_from", new=AsyncMock(side_effect=http)):
            assert await fetch_jwks(ZONE) is None

            # Still down as far as we are concerned: no second round trip.
            endpoint_down = False
            assert await fetch_jwks(ZONE) is None, "the failure should be remembered"

            # Once the short window lapses the endpoint is tried again.
            _jwks_negative[ZONE] = 0.0
            assert await fetch_jwks(ZONE) is not None, "the block must be self-healing"

        assert JWKS_NEGATIVE_TTL <= 60, "a negative cache this long would mask a recovery"
        _ = priv

    @pytest.mark.asyncio
    async def test_a_signature_without_kid_still_searches_every_key(self):
        """RFC 7515 Section 4.1.4 makes kid a hint, so legacy signatures verify."""
        priv, pub = generate_keypair()
        _, other = generate_keypair()
        jwks = export_jwks_multi([(other, "other"), (pub, "mine")])

        with patch("dns_aid.core.jwks._fetch_jwks_from", new=AsyncMock(return_value=jwks)):
            ok, _, status = await verify_record_signature_detailed(ZONE, self._sig(priv))

        assert (ok, status) == (True, SignatureStatus.VERIFIED)


class TestDnssecVerdictIsNotFlagDependent:
    """The DNSSEC verdict must not depend on which unrelated flag was passed.

    The JWS branch consumes the verdict to decide skip vs verify, so it has to
    be computed whenever verify_signatures is on. It was originally gated on
    require_dnssec / min_dnssec / verify_dane only, which made the same record
    on the same zone through the same resolver report dnssec_validated=False
    and VERIFIED alone, then True and SKIPPED_DNSSEC once verify_dane was added.
    Harmless while the field was internal. A false statement about a zone's
    posture once discovery began reporting it.
    """

    @staticmethod
    def _agent():
        from dns_aid.core.models import AgentRecord, Protocol

        return AgentRecord(
            name="a",
            domain="signed.example.com",
            protocol=Protocol.MCP,
            target_host="edge.signed.example.com",
            port=443,
        )

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "extra",
        [
            pytest.param({}, id="verify_signatures alone"),
            pytest.param({"verify_dane": True}, id="plus verify_dane"),
            pytest.param({"min_dnssec": True}, id="plus min_dnssec"),
        ],
    )
    async def test_a_signed_zone_reports_validated_under_every_flag_combination(self, extra):
        from dns_aid.core.discoverer import _apply_post_discovery

        agent = self._agent()
        with (
            patch(
                "dns_aid.core.validator._check_dnssec_with_evidence",
                new=AsyncMock(return_value=(True, True)),
            ),
            patch("dns_aid.core.discoverer._verify_agent_signatures", new=AsyncMock()),
            patch("dns_aid.core.discoverer._verify_agents_dane", new=AsyncMock()),
        ):
            await _apply_post_discovery(
                [agent],
                False,
                False,
                True,
                "signed.example.com",
                **extra,
            )

        assert agent.dnssec_validated is True
        assert agent.dnssec_signed is True

    @pytest.mark.asyncio
    async def test_the_verdict_is_stamped_but_never_suppresses_verification(self):
        """Computed and reported, and deliberately NOT used to skip the JWS.

        An unvalidated AD flag must not suppress cryptography the caller asked
        for: an on-path attacker sets that bit and the forged record would then
        report skipped_dnssec, which reads as "already authenticated".
        """
        from dns_aid.core.discoverer import _apply_post_discovery

        agent = self._agent()
        seen = {}

        async def capture(agents, domain, *, dnssec_validated):  # noqa: ARG001
            seen["skip_map"] = dnssec_validated

        with (
            patch(
                "dns_aid.core.validator._check_dnssec_with_evidence",
                new=AsyncMock(return_value=(True, True)),
            ),
            patch("dns_aid.core.discoverer._verify_agent_signatures", new=capture),
        ):
            await _apply_post_discovery([agent], False, False, True, "signed.example.com")

        assert agent.dnssec_validated is True, "the verdict must still be computed and reported"
        assert seen["skip_map"] == {}, "a spoofable AD flag must not suppress the signature check"
