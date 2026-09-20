# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""DANE verification across a multi-association TLSA RRset.

A TLSA RRset may carry several associations, and the presented certificate is
valid if it matches ANY of them (RFC 6698; RFC 7671 Section 5.1). Publishing two
associations is exactly how a certificate rollover is staged -- the outgoing and
incoming pins overlap (RFC 7671 Section 8.1).

Two properties are under test and they pull against each other, which is why
both are pinned here:

* **Correctness.** Every association must be considered, so a rollover can
  overlap and the outcome never depends on RRset ordering.
* **Boundedness.** RRset size is attacker-influenceable and a TCP answer can
  carry hundreds of associations. Considering them all must not mean opening a
  connection per record. The certificate is identical across associations, so it
  is fetched at most once per retrieval mode and compared in memory.

Only the network boundary (``_fetch_peer_cert``) is stubbed. The comparison
logic runs for real against genuine digests, so these tests exercise selector
and matching-type handling rather than asserting against a mocked answer.
"""

import asyncio
import hashlib
import ssl
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dns_aid.core.validator import MAX_TLSA_ASSOCIATIONS, _check_dane


@pytest.fixture(autouse=True)
def _allow_test_hosts():
    """_fetch_peer_cert SSRF-guards the dial, which resolves the host for real.

    These tests use reserved example.com names and mock the socket, so the guard
    would reject before any mocked behaviour is reached. Neutralised here rather
    than per test: the guard has its own coverage, and what is under test is what
    happens after the dial is permitted.
    """
    with patch("dns_aid.utils.url_safety.validate_fetch_url_async", new=AsyncMock(return_value="")):
        yield


PEER_CERT = b"peer-certificate-der-bytes"
MATCHING = hashlib.sha256(PEER_CERT).digest()
STALE = hashlib.sha256(b"a-previous-certificate").digest()

# usage 3 (DANE-EE) and usage 1 (PKIX-EE) select the two different retrieval
# modes, which is the only thing that can require a second connection.
DANE_EE = 3
PKIX_EE = 1


def _tlsa(cert: bytes, usage: int = DANE_EE, selector: int = 0, mtype: int = 1):
    """One TLSA association. selector 0 compares the full DER, mtype 1 is SHA-256."""
    rdata = MagicMock()
    rdata.usage = usage
    rdata.selector = selector
    rdata.mtype = mtype
    rdata.cert = cert
    return rdata


def _resolver(*records):
    answers = MagicMock()
    answers.__iter__ = lambda self: iter(list(records))
    resolver = MagicMock()
    resolver.resolve = AsyncMock(return_value=answers)
    return resolver


def _run(*records, fetch=None):
    """Patch DNS and the certificate fetch, leaving comparison real."""
    if fetch is None:

        async def fetch(target, port, *, pkix):  # noqa: ARG001
            return PEER_CERT

    return (
        patch(
            "dns_aid.core.validator.dns.asyncresolver.Resolver", return_value=_resolver(*records)
        ),
        patch("dns_aid.core.validator._fetch_peer_cert", new=AsyncMock(side_effect=fetch)),
    )


class TestAnyAssociationMayMatch:
    """Ordering must not decide the outcome."""

    @pytest.mark.asyncio
    async def test_matches_when_only_the_second_association_matches(self):
        """The rollover case: stale pin first, live pin second."""
        dns_p, fetch_p = _run(_tlsa(STALE), _tlsa(MATCHING))
        with dns_p, fetch_p:
            assert await _check_dane("mcp.example.com", 443, verify_cert=True) is True

    @pytest.mark.asyncio
    async def test_matches_when_only_the_first_association_matches(self):
        """Reversing the same RRset must give the same answer."""
        dns_p, fetch_p = _run(_tlsa(MATCHING), _tlsa(STALE))
        with dns_p, fetch_p:
            assert await _check_dane("mcp.example.com", 443, verify_cert=True) is True

    @pytest.mark.asyncio
    async def test_mismatch_only_after_every_association_was_compared(self):
        dns_p, fetch_p = _run(_tlsa(STALE), _tlsa(hashlib.sha256(b"other").digest()))
        with dns_p, fetch_p:
            assert await _check_dane("mcp.example.com", 443, verify_cert=True) is False

    @pytest.mark.asyncio
    async def test_single_matching_association(self):
        dns_p, fetch_p = _run(_tlsa(MATCHING))
        with dns_p, fetch_p:
            assert await _check_dane("mcp.example.com", 443, verify_cert=True) is True

    @pytest.mark.asyncio
    async def test_single_non_matching_association(self):
        dns_p, fetch_p = _run(_tlsa(STALE))
        with dns_p, fetch_p:
            assert await _check_dane("mcp.example.com", 443, verify_cert=True) is False


class TestConnectionsAreBounded:
    """Considering every association must not cost a connection per association.

    Before the certificate fetch was hoisted out of the loop, an RRset of N
    associations produced N sequential TLS connections with no timeout, so a
    target that black-holed turned one hang into N hangs. RRset size is
    attacker-influenceable.
    """

    @pytest.mark.asyncio
    @pytest.mark.parametrize("count", [1, 5, 25])
    async def test_one_connection_regardless_of_rrset_size(self, count):
        calls = []

        async def counting_fetch(target, port, *, pkix):  # noqa: ARG001
            calls.append(pkix)
            return PEER_CERT

        records = [_tlsa(hashlib.sha256(bytes([i])).digest()) for i in range(count)]
        dns_p, fetch_p = _run(*records, fetch=counting_fetch)
        with dns_p, fetch_p:
            await _check_dane("mcp.example.com", 443, verify_cert=True)

        assert len(calls) == 1, f"{count} associations opened {len(calls)} connections"

    @pytest.mark.asyncio
    async def test_mixed_usages_still_need_only_one_retrieval(self):
        """Usage 1 and usage 3 both pin the end-entity certificate.

        It is the same certificate, so one retrieval serves every association.
        Usage 1 only adds a PKIX requirement, and that is probed lazily -- only
        when a pin has already matched and the answer would change the verdict.
        """
        calls = []

        async def counting_fetch(target, port, *, pkix):  # noqa: ARG001
            calls.append(pkix)
            return PEER_CERT

        records = [
            _tlsa(STALE, usage=DANE_EE),
            _tlsa(STALE, usage=PKIX_EE),
            _tlsa(STALE, usage=DANE_EE),
            _tlsa(STALE, usage=PKIX_EE),
        ]
        dns_p, fetch_p = _run(*records, fetch=counting_fetch)
        with dns_p, fetch_p:
            await _check_dane("mcp.example.com", 443, verify_cert=True)

        assert calls == [False], "nothing matched, so PKIX never needed probing"

    @pytest.mark.asyncio
    async def test_pkix_is_probed_only_when_a_pin_matches(self):
        calls = []

        async def counting_fetch(target, port, *, pkix):  # noqa: ARG001
            calls.append(pkix)
            return PEER_CERT

        dns_p, fetch_p = _run(_tlsa(MATCHING, usage=PKIX_EE), fetch=counting_fetch)
        with dns_p, fetch_p:
            await _check_dane("mcp.example.com", 443, verify_cert=True)

        assert calls == [False, True], "a matching PKIX pin must also confirm the chain"

    @pytest.mark.asyncio
    async def test_advisory_mode_opens_no_connection(self):
        """Without verify_cert the answer is existence, so nothing is dialled."""
        calls = []

        async def counting_fetch(target, port, *, pkix):  # noqa: ARG001
            calls.append(pkix)
            return PEER_CERT

        dns_p, fetch_p = _run(_tlsa(STALE), _tlsa(MATCHING), fetch=counting_fetch)
        with dns_p, fetch_p:
            assert await _check_dane("mcp.example.com", 443) is True

        assert calls == []

    @pytest.mark.asyncio
    async def test_oversized_rrset_is_capped(self):
        """Comparison is in-memory, but unbounded input is still unbounded work."""
        compared = []

        async def fetch(target, port, *, pkix):  # noqa: ARG001
            return PEER_CERT

        records = [
            _tlsa(hashlib.sha256(bytes([i % 251])).digest())
            for i in range(MAX_TLSA_ASSOCIATIONS + 20)
        ]
        from dns_aid.core import validator as _v

        real_match = _v._association_matches

        def counting_match(der, selector, mtype, data):
            compared.append(data)
            return real_match(der, selector, mtype, data)

        dns_p, fetch_p = _run(*records, fetch=fetch)
        with dns_p, fetch_p, patch.object(_v, "_association_matches", counting_match):
            await _check_dane("mcp.example.com", 443, verify_cert=True)

        assert len(compared) == MAX_TLSA_ASSOCIATIONS


class TestUnevaluatedIsNotAMismatch:
    """An association that could not be compared must not produce a verdict.

    This is the rollover shape: the stale pin errors while the live pin does not
    match this certificate. Reporting that as a definite mismatch is the same
    inversion this module avoids elsewhere, where an unverifiable result must
    not read as forgery.
    """

    @pytest.mark.asyncio
    async def test_a_second_connection_cannot_be_used_to_downgrade_a_mismatch(self):
        """Only the PKIX probe can fail separately, and only after a match.

        When the certificate was fetched per mode, a hostile endpoint could
        reset the second connection and turn a definite mismatch into
        "unknown", because a False verdict requires every usable association to
        have been compared. One retrieval removes that lever entirely.
        """

        async def reset_pkix(target, port, *, pkix):  # noqa: ARG001
            if pkix:
                raise ConnectionResetError("attacker resets the second connection")
            return PEER_CERT

        dns_p, fetch_p = _run(
            _tlsa(STALE, usage=PKIX_EE), _tlsa(STALE, usage=DANE_EE), fetch=reset_pkix
        )
        with dns_p, fetch_p:
            assert await _check_dane("mcp.example.com", 443, verify_cert=True) is False

    @pytest.mark.asyncio
    async def test_an_unconfirmable_chain_does_not_mask_a_dane_match(self):
        async def reset_pkix(target, port, *, pkix):  # noqa: ARG001
            if pkix:
                raise TimeoutError("black-holed")
            return PEER_CERT

        dns_p, fetch_p = _run(
            _tlsa(STALE, usage=PKIX_EE), _tlsa(MATCHING, usage=DANE_EE), fetch=reset_pkix
        )
        with dns_p, fetch_p:
            assert await _check_dane("mcp.example.com", 443, verify_cert=True) is True

    @pytest.mark.asyncio
    async def test_no_certificate_at_all_is_unknown(self):
        async def always_fails(target, port, *, pkix):  # noqa: ARG001
            raise TimeoutError("endpoint unreachable")

        dns_p, fetch_p = _run(_tlsa(STALE), _tlsa(MATCHING), fetch=always_fails)
        with dns_p, fetch_p:
            assert await _check_dane("mcp.example.com", 443, verify_cert=True) is None

    @pytest.mark.asyncio
    async def test_malformed_association_does_not_produce_a_mismatch(self):
        """selector 1 needs a parseable certificate. Garbage in is unknown, not False."""
        dns_p, fetch_p = _run(_tlsa(STALE, selector=1))
        with dns_p, fetch_p:
            assert await _check_dane("mcp.example.com", 443, verify_cert=True) is None


class TestUnusableAssociationsAreIgnored:
    """RFC 7671 Section 5.1: unrecognised selector or matching type is unusable.

    An unusable association can neither satisfy nor fail the check. Before this
    was enforced, ``_association_matches`` fell through to comparing raw DER for
    any unknown selector and to an exact comparison for any unknown matching
    type, so a single ``3 7 9`` record returned a DANE PASS for the whole RRset.
    """

    @pytest.mark.asyncio
    async def test_unusable_association_does_not_grant_a_pass(self):
        dns_p, fetch_p = _run(_tlsa(PEER_CERT, selector=7, mtype=9))
        with dns_p, fetch_p:
            assert await _check_dane("mcp.example.com", 443, verify_cert=True) is None

    @pytest.mark.asyncio
    async def test_unusable_association_does_not_mask_a_real_match(self):
        dns_p, fetch_p = _run(_tlsa(PEER_CERT, selector=7, mtype=9), _tlsa(MATCHING))
        with dns_p, fetch_p:
            assert await _check_dane("mcp.example.com", 443, verify_cert=True) is True

    @pytest.mark.asyncio
    async def test_unusable_association_does_not_rescue_a_mismatch(self):
        dns_p, fetch_p = _run(_tlsa(PEER_CERT, selector=7, mtype=9), _tlsa(STALE))
        with dns_p, fetch_p:
            assert await _check_dane("mcp.example.com", 443, verify_cert=True) is False

    @pytest.mark.asyncio
    async def test_unknown_usage_is_unusable(self):
        dns_p, fetch_p = _run(_tlsa(MATCHING, usage=9))
        with dns_p, fetch_p:
            assert await _check_dane("mcp.example.com", 443, verify_cert=True) is None


class TestPkixFailureIsNotEvidenceAboutThePeer:
    """``SSLCertVerificationError`` does not prove the peer's certificate is bad.

    It equally covers a missing or empty local trust store and clock skew. An
    earlier version treated it as a definite negative, so dns-aid running in a
    container without CA certificates reported every PKIX-usage record as a
    certificate mismatch. A matching pin whose chain cannot be confirmed is
    therefore unevaluated, not refuted.
    """

    @pytest.mark.asyncio
    async def test_a_matching_pin_with_an_unconfirmable_chain_is_unknown(self):
        async def no_ca_store(target, port, *, pkix):  # noqa: ARG001
            if pkix:
                raise ssl.SSLCertVerificationError("unable to get local issuer")
            return PEER_CERT

        dns_p, fetch_p = _run(_tlsa(MATCHING, usage=PKIX_EE), fetch=no_ca_store)
        with dns_p, fetch_p:
            assert await _check_dane("mcp.example.com", 443, verify_cert=True) is None

    @pytest.mark.asyncio
    async def test_a_non_matching_pin_is_still_refuted(self):
        """The pin did not match the certificate, so the chain is irrelevant."""

        async def no_ca_store(target, port, *, pkix):  # noqa: ARG001
            if pkix:
                raise ssl.SSLCertVerificationError("unable to get local issuer")
            return PEER_CERT

        dns_p, fetch_p = _run(_tlsa(STALE, usage=PKIX_EE), fetch=no_ca_store)
        with dns_p, fetch_p:
            assert await _check_dane("mcp.example.com", 443, verify_cert=True) is False

    @pytest.mark.asyncio
    async def test_an_unconfirmable_chain_does_not_mask_a_dane_ee_match(self):
        async def no_ca_store(target, port, *, pkix):  # noqa: ARG001
            if pkix:
                raise ssl.SSLCertVerificationError("unable to get local issuer")
            return PEER_CERT

        dns_p, fetch_p = _run(
            _tlsa(STALE, usage=PKIX_EE), _tlsa(MATCHING, usage=DANE_EE), fetch=no_ca_store
        )
        with dns_p, fetch_p:
            assert await _check_dane("mcp.example.com", 443, verify_cert=True) is True


class TestTrustAnchorUsagesAreNotEvaluable:
    """Usages 0 and 2 pin a trust anchor in the chain, not the leaf.

    This verifier only ever sees the end-entity certificate, so it cannot
    evaluate them. Declaring them usable made a conformant ``2 1 1`` deployment
    report a certificate mismatch.
    """

    @pytest.mark.asyncio
    async def test_dane_ta_alone_is_unknown_not_a_mismatch(self):
        dns_p, fetch_p = _run(_tlsa(MATCHING, usage=2))
        with dns_p, fetch_p:
            assert await _check_dane("mcp.example.com", 443, verify_cert=True) is None

    @pytest.mark.asyncio
    async def test_pkix_ta_alone_is_unknown_not_a_mismatch(self):
        dns_p, fetch_p = _run(_tlsa(MATCHING, usage=0))
        with dns_p, fetch_p:
            assert await _check_dane("mcp.example.com", 443, verify_cert=True) is None

    @pytest.mark.asyncio
    async def test_an_evaluable_association_alongside_one_still_decides(self):
        dns_p, fetch_p = _run(_tlsa(STALE, usage=2), _tlsa(MATCHING, usage=DANE_EE))
        with dns_p, fetch_p:
            assert await _check_dane("mcp.example.com", 443, verify_cert=True) is True


class TestTruncationIsNotAMismatch:
    """Records dropped by the cap were never compared, so they cannot fail."""

    @pytest.mark.asyncio
    async def test_match_beyond_the_cap_is_not_reported_as_mismatch(self):
        records = [_tlsa(hashlib.sha256(bytes([i])).digest()) for i in range(MAX_TLSA_ASSOCIATIONS)]
        records.append(_tlsa(MATCHING))  # the only matching pin sits past the cap

        dns_p, fetch_p = _run(*records)
        with dns_p, fetch_p:
            result = await _check_dane("mcp.example.com", 443, verify_cert=True)

        assert result is None, "truncated records must not support a mismatch verdict"


class TestCertificateRetrieval:
    """The fetch itself: bounded, cleaned up, and honest about a missing cert."""

    @pytest.mark.asyncio
    async def test_connect_is_bounded_by_a_timeout(self):
        from dns_aid.core import validator as _v

        async def never_connects(*args, **kwargs):
            await asyncio.sleep(3600)

        with (
            patch.object(_v, "DANE_CONNECT_TIMEOUT", 0.01),
            patch.object(_v.asyncio, "open_connection", new=never_connects),
        ):
            with pytest.raises((TimeoutError, asyncio.TimeoutError)):
                await _v._fetch_peer_cert("mcp.example.com", 443, pkix=False)

    @pytest.mark.asyncio
    async def test_a_black_holing_endpoint_yields_unknown_not_mismatch(self):
        from dns_aid.core import validator as _v

        async def never_connects(*args, **kwargs):
            await asyncio.sleep(3600)

        dns_p = patch(
            "dns_aid.core.validator.dns.asyncresolver.Resolver",
            return_value=_resolver(_tlsa(STALE)),
        )
        with (
            dns_p,
            patch.object(_v, "DANE_CONNECT_TIMEOUT", 0.01),
            patch.object(_v.asyncio, "open_connection", new=never_connects),
        ):
            assert await _check_dane("mcp.example.com", 443, verify_cert=True) is None

    @pytest.mark.asyncio
    async def test_absent_peer_certificate_is_reported_not_compared(self):
        """getpeercert is typed bytes | None and mypy cannot see it here.

        A None reaching the comparison either raises or silently participates
        as a compared association depending on the matching type, so it is
        rejected at the boundary instead.
        """
        from dns_aid.core import validator as _v

        writer = MagicMock()
        ssl_object = MagicMock()
        ssl_object.getpeercert = MagicMock(return_value=None)
        writer.get_extra_info = MagicMock(return_value=ssl_object)
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        async def fake_open(*args, **kwargs):
            return (MagicMock(), writer)

        with patch.object(_v.asyncio, "open_connection", new=fake_open):
            with pytest.raises(ConnectionError, match="no certificate"):
                await _v._fetch_peer_cert("mcp.example.com", 443, pkix=False)

        writer.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_socket_is_closed_even_when_retrieval_raises(self):
        from dns_aid.core import validator as _v

        writer = MagicMock()
        ssl_object = MagicMock()
        ssl_object.getpeercert = MagicMock(side_effect=OSError("boom"))
        writer.get_extra_info = MagicMock(return_value=ssl_object)
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        async def fake_open(*args, **kwargs):
            return (MagicMock(), writer)

        with patch.object(_v.asyncio, "open_connection", new=fake_open):
            with pytest.raises(OSError, match="boom"):
                await _v._fetch_peer_cert("mcp.example.com", 443, pkix=False)

        writer.close.assert_called_once()
        writer.wait_closed.assert_awaited_once()


class TestUsage1BindsOneCertificate:
    """RFC 6698 section 2.1.1 binds ONE end-entity certificate under PKIX-EE.

    The pin is matched on an unverified connection and the chain proved on a
    second, verified one. Without comparing both against the same DER, a
    multi-homed or mid-rollover endpoint satisfies each half with a different
    certificate and collects a pass for neither.
    """

    PINNED = b"cert-X-matches-the-pin-but-does-not-chain"
    LIVE = b"cert-Y-chains-but-does-not-match-the-pin"

    @staticmethod
    def _split_endpoint():
        """Serve a different certificate on each retrieval mode."""

        async def fetch(target, port, *, pkix):  # noqa: ARG001
            return (
                TestUsage1BindsOneCertificate.LIVE if pkix else TestUsage1BindsOneCertificate.PINNED
            )

        return fetch

    @pytest.mark.asyncio
    async def test_a_split_endpoint_does_not_earn_a_pass(self):
        pin = hashlib.sha256(self.PINNED).digest()
        dns_p, fetch_p = _run(_tlsa(pin, usage=PKIX_EE), fetch=self._split_endpoint())

        with dns_p, fetch_p:
            verdict = await _check_dane("api.example.com", 443, verify_cert=True)

        assert verdict is not True, (
            "the pin matched cert X and PKIX passed on cert Y; no single "
            "certificate satisfied PKIX-EE"
        )

    @pytest.mark.asyncio
    async def test_one_certificate_doing_both_jobs_still_passes(self):
        """The fix must not reject the ordinary single-certificate deployment."""
        dns_p, fetch_p = _run(_tlsa(MATCHING, usage=PKIX_EE))

        with dns_p, fetch_p:
            verdict = await _check_dane("api.example.com", 443, verify_cert=True)

        assert verdict is True

    @pytest.mark.asyncio
    async def test_usage_3_is_unaffected(self):
        """DANE-EE needs no chain, so it must not pay for a second connection."""
        seen = []

        async def fetch(target, port, *, pkix):  # noqa: ARG001
            seen.append(pkix)
            return PEER_CERT

        dns_p, fetch_p = _run(_tlsa(MATCHING, usage=DANE_EE), fetch=fetch)
        with dns_p, fetch_p:
            verdict = await _check_dane("api.example.com", 443, verify_cert=True)

        assert verdict is True
        assert seen == [False], "usage 3 must not open a PKIX connection"
