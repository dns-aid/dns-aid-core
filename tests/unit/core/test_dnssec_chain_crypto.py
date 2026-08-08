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

import dns.asyncresolver
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


class TestCnameAnswersAreFollowedAndValidated:
    """Looking only at the queried name reported no-answer for every CNAME.

    The walk folded that into INDETERMINATE, so a name whose CNAME is signed and
    provable read the same as a resolver that could not answer. Most real
    deployments CNAME their agent names at a CDN, so this was the common case.
    """

    @staticmethod
    def _chain(name, target, rdtype, priv, dnskey, signed_cname=True):
        import datetime

        now = int(datetime.datetime.now(tz=datetime.UTC).timestamp())
        cname = dns.rrset.from_text(name, 3600, "IN", "CNAME", target.to_text())
        answer = dns.rrset.from_text(target, 3600, "IN", "A", "93.184.216.34")

        def sign(rrset):
            return dns.dnssec.sign(
                rrset=rrset,
                private_key=priv,
                dnskey=dnskey,
                signer=ZONE,
                inception=now - 300,
                expiration=now + 3600,
            )

        answers = [cname, answer, dns.rrset.from_rdata_list(target, 3600, [sign(answer)])]
        if signed_cname:
            answers.append(dns.rrset.from_rdata_list(name, 3600, [sign(cname)]))

        class _Resp:
            pass

        r = _Resp()
        r.answer = answers
        return r

    def test_a_signed_cname_is_followed_to_the_answer(self):
        from dns_aid.core.dnssec_chain import _follow_cname

        priv, dnskey = _keypair()
        keys = _dnskey_rrset(dnskey)
        name = dns.name.from_text("agent.example.com.")
        target = dns.name.from_text("edge.example.com.")
        resp = self._chain(name, target, dns.rdatatype.A, priv, dnskey)

        rrset, final = _follow_cname(resp, name, dns.rdatatype.A, ZONE, keys)

        assert rrset is not None, "the answer under the canonical name was not found"
        assert final == target

    def test_an_unsigned_cname_is_not_followed(self):
        """Otherwise a responder redirects the lookup and the answer there
        validates on its own merits."""
        from dns_aid.core.dnssec_chain import _BogusError, _follow_cname

        priv, dnskey = _keypair()
        keys = _dnskey_rrset(dnskey)
        name = dns.name.from_text("agent.example.com.")
        target = dns.name.from_text("edge.example.com.")
        resp = self._chain(name, target, dns.rdatatype.A, priv, dnskey, signed_cname=False)

        with pytest.raises(_BogusError, match="carries no signature"):
            _follow_cname(resp, name, dns.rdatatype.A, ZONE, keys)

    def test_the_hop_count_is_bounded(self):
        """The chain length is attacker-influenced."""
        from dns_aid.core.dnssec_chain import MAX_CNAME_HOPS

        assert 1 < MAX_CNAME_HOPS <= 16


class TestTheResolverCanBePointedAtOneThatServesDnssec:
    """A stub resolver that strips DNSKEY made the walk unusable.

    On a split-horizon network the internal resolver is often authoritative for
    the zone and answers DNSKEY empty, so the walk reported INDETERMINATE on
    exactly the networks DNS-AID targets -- and indistinguishable from a resolver
    stripping records under attack.
    """

    def test_the_env_override_selects_the_nameservers(self, monkeypatch):
        from dns_aid.core.dnssec_chain import _default_resolver

        monkeypatch.setenv("DNS_AID_DNSSEC_RESOLVERS", "8.8.8.8, 1.1.1.1")

        assert _default_resolver().nameservers == ["8.8.8.8", "1.1.1.1"]

    def test_without_the_override_the_system_resolver_is_used(self, monkeypatch):
        from dns_aid.core.dnssec_chain import _default_resolver

        monkeypatch.delenv("DNS_AID_DNSSEC_RESOLVERS", raising=False)
        system = dns.asyncresolver.Resolver().nameservers

        assert _default_resolver().nameservers == system

    def test_a_blank_override_does_not_empty_the_nameserver_list(self, monkeypatch):
        from dns_aid.core.dnssec_chain import _default_resolver

        monkeypatch.setenv("DNS_AID_DNSSEC_RESOLVERS", "  ,  ")

        assert _default_resolver().nameservers, "an empty list would break every query"

    @pytest.mark.asyncio
    async def test_a_stripping_resolver_says_why(self):
        """The reason must be actionable, not just 'indeterminate'."""
        import dns_aid.core.dnssec_chain as chain

        priv, dnskey = _keypair()
        _ = priv, dnskey

        async def empty(resolver, qname, rdtype):  # noqa: ARG001
            class _Resp:
                answer = []

            return _Resp()

        original = chain._query
        chain._query = empty
        try:
            result = await chain.validate_chain("agent.example.com", "A")
        finally:
            chain._query = original

        assert result.status is chain.ChainStatus.INDETERMINATE
        assert "DNS_AID_DNSSEC_RESOLVERS" in result.reason
