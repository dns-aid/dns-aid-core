# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Real cryptography against the chain walk.

The rest of the chain tests mock `_query` or replace `validate_chain` wholesale,
so `_validated_dnskey`, `_child_ds` and `dns.dnssec.validate` were never reached.
That is why a textbook flaw shipped: the DNSKEY RRset was validated against
EVERY key the responder served rather than the key the parent's DS references,
so an attacker could republish the genuine anchor's PUBLIC key beside their own,
sign with their own, and reach SECURE without the anchor's private key.

These tests generate keys, sign RRsets and exercise the real dnspython
validation path. Mutation-check them by reverting the fix at
dnssec_chain.py `_validated_dnskey` to `{zone: dnskeys}`.
"""

from __future__ import annotations

import datetime

import dns.dnssec
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from dns_aid.core.dnssec_chain import _BogusError, _validated_dnskey

ZONE = dns.name.from_text("example.com.")
ALGO = dns.dnssec.Algorithm.ECDSAP256SHA256


def _keypair():
    priv = ec.generate_private_key(ec.SECP256R1())
    dnskey = dns.dnssec.make_dnskey(priv.public_key(), algorithm=ALGO, flags=257)
    return priv, dnskey


def _dnskey_rrset(*dnskeys):
    return dns.rrset.from_rdata_list(ZONE, 3600, list(dnskeys))


def _sign(rrset, priv, dnskey):
    now = int(datetime.datetime.now(tz=datetime.UTC).timestamp())
    return dns.dnssec.sign(
        rrset=rrset,
        private_key=priv,
        dnskey=dnskey,
        signer=ZONE,
        inception=now - 300,
        expiration=now + 3600,
    )


def _response(dnskey_rrset, rrsig):
    """A minimal object shaped like the answer section _find_rrset reads."""

    class _Resp:
        answer = [dnskey_rrset, dns.rrset.from_rdata_list(ZONE, 3600, [rrsig])]

    return _Resp()


async def _run(dnskey_rrset, rrsig, ds_rrset):
    async def fake_query(resolver, qname, rdtype):  # noqa: ARG001
        return _response(dnskey_rrset, rrsig)

    import dns_aid.core.dnssec_chain as chain

    original = chain._query
    chain._query = fake_query
    try:
        return await _validated_dnskey(None, ZONE, ds_rrset)
    finally:
        chain._query = original


def _ds_for(dnskey):
    return dns.rrset.from_rdata_list(ZONE, 3600, [dns.dnssec.make_ds(ZONE, dnskey, "SHA256")])


class TestTheDsMustReferenceTheSigningKey:
    """RFC 4035 Section 5.2. This is the flaw the mocked tests could not see."""

    @pytest.mark.asyncio
    async def test_a_genuinely_signed_rrset_validates(self):
        priv, dnskey = _keypair()
        rrset = _dnskey_rrset(dnskey)

        result = await _run(rrset, _sign(rrset, priv, dnskey), _ds_for(dnskey))

        assert result is not None

    @pytest.mark.asyncio
    async def test_the_anchor_key_copied_beside_an_attacker_key_is_bogus(self):
        """The exploit: publish the real public key, sign with your own.

        The DS check is satisfied by the copied anchor key, which the attacker
        obtained from public DNS. Validating the RRset against every served key
        then lets their own signature carry the chain.
        """
        _, anchor_dnskey = _keypair()  # anchor's PRIVATE key never used
        attacker_priv, attacker_dnskey = _keypair()
        rrset = _dnskey_rrset(anchor_dnskey, attacker_dnskey)
        rrsig = _sign(rrset, attacker_priv, attacker_dnskey)

        with pytest.raises((_BogusError, dns.dnssec.ValidationFailure)):
            await _run(rrset, rrsig, _ds_for(anchor_dnskey))

    @pytest.mark.asyncio
    async def test_a_key_absent_from_the_parents_ds_is_bogus(self):
        """Control: without the copied anchor key the DS check itself fails."""
        _, anchor_dnskey = _keypair()
        attacker_priv, attacker_dnskey = _keypair()
        rrset = _dnskey_rrset(attacker_dnskey)

        with pytest.raises(_BogusError, match="matches the DS"):
            await _run(rrset, _sign(rrset, attacker_priv, attacker_dnskey), _ds_for(anchor_dnskey))

    @pytest.mark.asyncio
    async def test_a_second_legitimate_key_does_not_break_a_real_rollover(self):
        """The fix must not reject a zone mid-KSK-rollover.

        Both keys are DS-referenced, and the RRset is signed by one of them.
        """
        priv_a, dnskey_a = _keypair()
        _, dnskey_b = _keypair()
        rrset = _dnskey_rrset(dnskey_a, dnskey_b)
        ds_both = dns.rrset.from_rdata_list(
            ZONE,
            3600,
            [
                dns.dnssec.make_ds(ZONE, dnskey_a, "SHA256"),
                dns.dnssec.make_ds(ZONE, dnskey_b, "SHA256"),
            ],
        )

        result = await _run(rrset, _sign(rrset, priv_a, dnskey_a), ds_both)

        assert result is not None

    @pytest.mark.asyncio
    async def test_a_tampered_signature_is_rejected(self):
        priv, dnskey = _keypair()
        rrset = _dnskey_rrset(dnskey)
        rrsig = _sign(rrset, priv, dnskey)
        broken = dns.rdata.from_text(
            dns.rdataclass.IN,
            dns.rdatatype.RRSIG,
            rrsig.to_text()[:-8] + "AAAAAAA=",
        )

        with pytest.raises((dns.dnssec.ValidationFailure, Exception)):
            await _run(rrset, broken, _ds_for(dnskey))


class TestTheRootAnchorsAreTheRealOnes:
    """Zeroing the digest survived every existing test."""

    def test_the_ksk_2017_digest_is_the_iana_value(self):
        from dns_aid.core.dnssec_chain import ROOT_ANCHORS

        by_tag = {tag: digest for tag, _alg, _dt, digest in ROOT_ANCHORS}

        assert by_tag[20326] == ("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D")

    def test_no_anchor_digest_is_a_placeholder(self):
        from dns_aid.core.dnssec_chain import ROOT_ANCHORS

        for tag, _alg, _dt, digest in ROOT_ANCHORS:
            assert set(digest) != {"0"}, f"anchor {tag} digest is zeroed"
            assert len(digest) == 64
