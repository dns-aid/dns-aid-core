# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""The chain walk proves an answer instead of trusting a bit.

DNS-AID's premise is that DNSSEC provides cryptographic verification. The
library asserted that on the strength of the AD flag -- one bit, set by
whichever resolver answered, over a path this code does not control. Every
trust decision built on it inherited that: the JWS skip, the DANE gate,
require_dnssec, min_dnssec.

Validating against a trust anchor shipped with the code makes the resolver
untrusted transport rather than an authority.
"""

import dns.name
import dns.rdatatype
import pytest

from dns_aid.core.dnssec_chain import (
    MAX_CHAIN_LABELS,
    ROOT_ANCHORS,
    ChainResult,
    ChainStatus,
    _anchor_ds_rrset,
    validate_chain,
)


class TestTrustAnchors:
    def test_the_anchors_parse_as_a_ds_rrset(self):
        rrset = _anchor_ds_rrset()

        assert rrset.rdtype == dns.rdatatype.DS
        assert len(rrset) == len(ROOT_ANCHORS)
        assert rrset.name == dns.name.root

    def test_the_current_ksk_is_present(self):
        """KSK-2017, tag 20326, is the anchor in force."""
        assert any(tag == 20326 for tag, _, _, _ in ROOT_ANCHORS)

    def test_the_successor_ksk_is_carried(self):
        """KSK-2024 so a rollover does not need a code change."""
        assert any(tag == 38696 for tag, _, _, _ in ROOT_ANCHORS)

    def test_anchors_are_sha256(self):
        for _tag, _alg, digest_type, digest in ROOT_ANCHORS:
            assert digest_type == 2, "digest type 2 is SHA-256"
            assert len(digest) == 64


class TestStatusSemantics:
    """Four outcomes, and only one of them may support a trust decision."""

    def test_only_secure_is_secure(self):
        for status in ChainStatus:
            result = ChainResult(status, "x")
            assert result.secure is (status is ChainStatus.SECURE)

    def test_insecure_is_not_bogus(self):
        """An unsigned zone opted out. That is not an attack and must not read
        like one, or every unsigned deployment looks hostile."""
        assert ChainStatus.INSECURE != ChainStatus.BOGUS

    def test_indeterminate_is_not_a_rejection(self):
        """A timeout or an unsupported algorithm is unknown, never refuted --
        the same tri-state discipline the signature and DANE paths use."""
        assert ChainResult(ChainStatus.INDETERMINATE, "timeout").secure is False
        assert ChainStatus.INDETERMINATE != ChainStatus.BOGUS


class TestWalkIsBounded:
    @pytest.mark.asyncio
    async def test_an_absurdly_deep_name_is_refused_without_querying(self):
        """The walk is one DNSKEY plus one DS per label, and the name is
        attacker-chosen, so it cannot be unbounded."""
        deep = ".".join(f"l{i}" for i in range(MAX_CHAIN_LABELS + 5)) + ".example.com"

        result = await validate_chain(deep, "A")

        assert result.status is ChainStatus.INDETERMINATE
        assert "labels" in result.reason

    def test_the_bound_leaves_room_for_real_names(self):
        """ddi-agent.agents.ai.infoblox.com is 5 labels plus root."""
        assert MAX_CHAIN_LABELS >= 8


class TestFailuresAreSafeDirection:
    @pytest.mark.asyncio
    async def test_a_transport_failure_is_indeterminate_not_secure(self, monkeypatch):
        async def explode(*a, **k):
            raise OSError("network down")

        monkeypatch.setattr("dns_aid.core.dnssec_chain._query", explode)

        result = await validate_chain("example.com", "A")

        assert result.status is ChainStatus.INDETERMINATE
        assert result.secure is False

    @pytest.mark.asyncio
    async def test_a_validation_failure_is_bogus(self, monkeypatch):
        import dns.dnssec

        async def fail(*a, **k):
            raise dns.dnssec.ValidationFailure("signature does not verify")

        monkeypatch.setattr("dns_aid.core.dnssec_chain._query", fail)

        result = await validate_chain("example.com", "A")

        assert result.status is ChainStatus.BOGUS
        assert result.secure is False
