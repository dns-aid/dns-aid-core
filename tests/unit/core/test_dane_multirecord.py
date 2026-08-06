# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""DANE verification across a multi-association TLSA RRset.

A TLSA RRset may carry several associations, and the presented certificate is
valid if it matches ANY of them (RFC 6698; RFC 7671 Section 5.1). Publishing two
associations is exactly how a certificate rollover is staged -- the outgoing and
incoming pins overlap (RFC 7671 Section 8.1).

``_check_dane`` previously returned on the first association it examined, so a
non-matching first record failed the whole check and the outcome depended on
RRset ordering, which is not stable. A rollover therefore could not overlap.
These tests assert both orderings so ordering-independence is proven, not assumed.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dns_aid.core.validator import _check_dane

OLD_PIN = b"\x11" * 32
NEW_PIN = b"\x22" * 32


def _tlsa(cert: bytes, usage: int = 3, selector: int = 1, mtype: int = 1):
    rdata = MagicMock()
    rdata.usage = usage
    rdata.selector = selector
    rdata.mtype = mtype
    rdata.cert = cert
    return rdata


def _resolver_with(*records):
    answers = MagicMock()
    answers.__iter__ = lambda self: iter(list(records))
    resolver = MagicMock()
    resolver.resolve = AsyncMock(return_value=answers)
    return resolver


def _run(records, match_fn):
    """Run _check_dane over the given TLSA RRset with a stubbed matcher."""

    async def fake_match(target, port, usage, selector, mtype, cert):
        return match_fn(cert)

    return patch(
        "dns_aid.core.validator.dns.asyncresolver.Resolver",
        return_value=_resolver_with(*records),
    ), patch(
        "dns_aid.core.validator._match_dane_cert",
        new=AsyncMock(side_effect=fake_match),
    )


class TestDaneMultiRecord:
    """Any association may match; ordering must not decide the outcome."""

    @pytest.mark.asyncio
    async def test_matches_when_only_second_association_matches(self):
        """The rollover case: stale pin first, live pin second.

        This is the scenario that failed before -- the first association did not
        match, the function returned False, and the valid second pin was never
        examined.
        """
        res, matcher = _run([_tlsa(OLD_PIN), _tlsa(NEW_PIN)], lambda cert: cert == NEW_PIN)
        with res, matcher:
            assert await _check_dane("mcp.example.com", 443, verify_cert=True) is True

    @pytest.mark.asyncio
    async def test_matches_when_only_first_association_matches(self):
        """Reverse ordering of the same RRset must give the same answer."""
        res, matcher = _run([_tlsa(NEW_PIN), _tlsa(OLD_PIN)], lambda cert: cert == NEW_PIN)
        with res, matcher:
            assert await _check_dane("mcp.example.com", 443, verify_cert=True) is True

    @pytest.mark.asyncio
    async def test_false_only_after_every_association_tried(self):
        """A genuine mismatch is still False -- but only once all were compared."""
        calls = []

        async def fake_match(target, port, usage, selector, mtype, cert):
            calls.append(cert)
            return False

        with (
            patch(
                "dns_aid.core.validator.dns.asyncresolver.Resolver",
                return_value=_resolver_with(_tlsa(OLD_PIN), _tlsa(NEW_PIN)),
            ),
            patch("dns_aid.core.validator._match_dane_cert", new=AsyncMock(side_effect=fake_match)),
        ):
            result = await _check_dane("mcp.example.com", 443, verify_cert=True)

        assert result is False
        assert calls == [OLD_PIN, NEW_PIN], "every association must be compared before failing"

    @pytest.mark.asyncio
    async def test_transient_error_does_not_mask_a_later_match(self):
        """An association that raises is skipped, not treated as a mismatch."""

        async def fake_match(target, port, usage, selector, mtype, cert):
            if cert == OLD_PIN:
                raise ConnectionResetError("transient")
            return True

        with (
            patch(
                "dns_aid.core.validator.dns.asyncresolver.Resolver",
                return_value=_resolver_with(_tlsa(OLD_PIN), _tlsa(NEW_PIN)),
            ),
            patch("dns_aid.core.validator._match_dane_cert", new=AsyncMock(side_effect=fake_match)),
        ):
            assert await _check_dane("mcp.example.com", 443, verify_cert=True) is True

    @pytest.mark.asyncio
    async def test_all_associations_erroring_is_unknown_not_mismatch(self):
        """Nothing was compared, so the answer is None -- not False.

        Reporting False here would present a network fault as a failed
        certificate binding, the same defect the JWS path draws a distinction
        for between "no key available" and "bad signature".
        """

        async def always_raises(target, port, usage, selector, mtype, cert):
            raise TimeoutError("endpoint unreachable")

        with (
            patch(
                "dns_aid.core.validator.dns.asyncresolver.Resolver",
                return_value=_resolver_with(_tlsa(OLD_PIN), _tlsa(NEW_PIN)),
            ),
            patch(
                "dns_aid.core.validator._match_dane_cert",
                new=AsyncMock(side_effect=always_raises),
            ),
        ):
            assert await _check_dane("mcp.example.com", 443, verify_cert=True) is None

    @pytest.mark.asyncio
    async def test_advisory_mode_still_short_circuits_on_existence(self):
        """Unchanged behaviour: without verify_cert, existence is the answer."""
        with (
            patch(
                "dns_aid.core.validator.dns.asyncresolver.Resolver",
                return_value=_resolver_with(_tlsa(OLD_PIN), _tlsa(NEW_PIN)),
            ),
            patch("dns_aid.core.validator._match_dane_cert", new=AsyncMock()) as matcher,
        ):
            assert await _check_dane("mcp.example.com", 443) is True
            matcher.assert_not_called()

    @pytest.mark.asyncio
    async def test_single_matching_association_unchanged(self):
        """The common single-record case keeps working exactly as before."""
        res, matcher = _run([_tlsa(NEW_PIN)], lambda cert: True)
        with res, matcher:
            assert await _check_dane("mcp.example.com", 443, verify_cert=True) is True

    @pytest.mark.asyncio
    async def test_single_non_matching_association_is_false(self):
        """And a single genuine mismatch is still a mismatch."""
        res, matcher = _run([_tlsa(OLD_PIN)], lambda cert: False)
        with res, matcher:
            assert await _check_dane("mcp.example.com", 443, verify_cert=True) is False
