# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""verify() compares cap-sha256 with the descriptor actually served."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import dns.rdata
import pytest

from dns_aid.core import validator
from dns_aid.core.cap_fetcher import cap_digest, check_cap_digest, descriptor_url
from dns_aid.core.models import DNSSECDetail, TLSDetail, VerifyResult

BODY = b'{"name": "transport", "skills": []}'
DIGEST = cap_digest(BODY)
CAP = "https://transport.example.com/.well-known/agent-card.json"


class TestHelpers:
    def test_cap_digest_is_unpadded_base64url(self):
        assert "=" not in DIGEST and len(DIGEST) == 43

    def test_descriptor_url_precedence(self):
        assert descriptor_url(CAP, "other.json", "h.example.com") == CAP
        assert (
            descriptor_url(None, "agent-card.json", "h.example.com.")
            == "https://h.example.com/.well-known/agent-card.json"
        )
        assert descriptor_url("urn:x:y", "/card.json", "h.example.com") == (
            "https://h.example.com/card.json"
        )
        assert descriptor_url("urn:x:y", None, "h.example.com") is None
        assert descriptor_url(None, "../etc/passwd", "h.example.com") is None

    @pytest.mark.asyncio
    async def test_check_cap_digest(self):
        with (
            patch("dns_aid.utils.url_safety.validate_fetch_url_async", AsyncMock()),
            patch("dns_aid.utils.url_safety.safe_fetch_bytes", AsyncMock(return_value=BODY)),
        ):
            assert await check_cap_digest(CAP, DIGEST) == ("match", DIGEST)
            assert await check_cap_digest(CAP, "A" * 43) == ("mismatch", DIGEST)

    @pytest.mark.asyncio
    async def test_check_cap_digest_unfetchable_is_unverified(self):
        from dns_aid.utils.url_safety import UnsafeURLError

        with patch(
            "dns_aid.utils.url_safety.validate_fetch_url_async",
            AsyncMock(side_effect=UnsafeURLError("private")),
        ):
            assert await check_cap_digest(CAP, DIGEST) == ("unverified", None)
        with (
            patch("dns_aid.utils.url_safety.validate_fetch_url_async", AsyncMock()),
            patch("dns_aid.utils.url_safety.safe_fetch_bytes", AsyncMock(return_value=None)),
        ):
            assert await check_cap_digest(CAP, DIGEST) == ("unverified", None)


class TestScore:
    def _full(self, status):
        return VerifyResult(
            fqdn="a.example.com",
            record_exists=True,
            svcb_valid=True,
            dnssec_valid=True,
            dane_valid=True,
            endpoint_reachable=True,
            cap_sha256_status=status,
        )

    @pytest.mark.parametrize("status", [None, "absent", "match", "unverified"])
    def test_no_penalty(self, status):
        assert self._full(status).security_score == 100

    def test_mismatch_withholds_svcb_points(self):
        result = self._full("mismatch")
        assert result.security_score == 80
        assert result.security_rating == "Good"


def _answers(*texts: str) -> list:
    return [dns.rdata.from_text("IN", "SVCB", t) for t in texts]


async def _run_verify(svcb_texts: list[str], served: bytes | None) -> VerifyResult:
    resolver = MagicMock()
    resolver.resolve = AsyncMock(return_value=_answers(*svcb_texts))
    with (
        patch("dns_aid.core.validator.make_resolver", return_value=resolver),
        patch.object(
            validator,
            "_check_dnssec_detail",
            AsyncMock(return_value=DNSSECDetail(validated=True)),
        ),
        patch.object(validator, "_check_dane", AsyncMock(return_value=None)),
        patch.object(validator, "_check_endpoint", AsyncMock(return_value={"reachable": True})),
        patch.object(validator, "_check_tls", AsyncMock(return_value=TLSDetail())),
        patch("dns_aid.utils.url_safety.validate_fetch_url_async", AsyncMock()),
        patch("dns_aid.utils.url_safety.safe_fetch_bytes", AsyncMock(return_value=served)),
    ):
        return await validator.verify("transport.example.com")


class TestVerify:
    @pytest.mark.asyncio
    async def test_match(self):
        result = await _run_verify(
            [f'1 transport.example.com. alpn="a2a" key65400="{CAP}" key65401="{DIGEST}"'],
            BODY,
        )
        assert result.cap_sha256_status == "match"
        assert result.security_score == 85

    @pytest.mark.asyncio
    async def test_mismatch_reported_and_scored(self):
        result = await _run_verify(
            [f'1 transport.example.com. alpn="a2a" key65400="{CAP}" key65401="{DIGEST}"'],
            BODY + b" ",
        )
        assert result.cap_sha256_status == "mismatch"
        assert DIGEST in result.cap_sha256_note
        assert cap_digest(BODY + b" ") in result.cap_sha256_note
        assert result.security_score == 65

    @pytest.mark.asyncio
    async def test_absent_is_not_fatal(self):
        result = await _run_verify([f'1 transport.example.com. alpn="a2a" key65400="{CAP}"'], BODY)
        assert result.cap_sha256_status == "absent"
        assert result.security_score == 85

    @pytest.mark.asyncio
    async def test_unreachable_descriptor_is_unverified(self):
        result = await _run_verify(
            [f'1 transport.example.com. alpn="a2a" key65400="{CAP}" key65401="{DIGEST}"'],
            None,
        )
        assert result.cap_sha256_status == "unverified"
        assert result.security_score == 85

    @pytest.mark.asyncio
    async def test_any_mismatching_protocol_record_counts(self):
        mcp_cap = "https://transport.example.com/mcp-card.json"
        result = await _run_verify(
            [
                f'1 transport.example.com. alpn="a2a" key65400="{CAP}" key65401="{DIGEST}"',
                f'2 transport.example.com. alpn="mcp" key65400="{mcp_cap}" key65401="{"B" * 43}"',
            ],
            BODY,
        )
        assert result.cap_sha256_status == "mismatch"
        assert mcp_cap in result.cap_sha256_note

    @pytest.mark.asyncio
    async def test_record_reported_is_lowest_priority(self):
        result = await _run_verify(
            [
                '5 backup.example.com. alpn="a2a" port=8443',
                '1 primary.example.com. alpn="a2a" port=443',
            ],
            BODY,
        )
        assert result.record_exists and result.cap_sha256_status == "absent"
