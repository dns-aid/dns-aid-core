# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for dns_aid.core.dcv — stateless DCV challenge/verify."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dns_aid.core.dcv import (
    DCVChallenge,
    DCVPlaceResult,
    DCVRevokeResult,
    _build_txt_value,
    _generate_token,
    _parse_txt_value,
    issue,
    place,
    revoke,
    verify,
)

# ---------------------------------------------------------------------------
# _generate_token
# ---------------------------------------------------------------------------


def test_generate_token_format():
    token = _generate_token()
    assert re.fullmatch(r"[a-z2-7]+", token), f"Unexpected token chars: {token}"


def test_generate_token_length():
    token = _generate_token()
    assert len(token) == 32


def test_generate_token_unique():
    tokens = {_generate_token() for _ in range(10)}
    assert len(tokens) == 10


# ---------------------------------------------------------------------------
# _build_txt_value
# ---------------------------------------------------------------------------


def test_build_txt_value_basic():
    expiry = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    txt = _build_txt_value("abc123", expiry, None)
    assert txt == "token=abc123 expiry=2026-01-02T03:04:05Z"


def test_build_txt_value_with_domain():
    expiry = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    txt = _build_txt_value("abc123", expiry, None, domain="example.com")
    assert txt == "token=abc123 domain=example.com expiry=2026-01-02T03:04:05Z"


def test_build_txt_value_with_bnd_req():
    expiry = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    txt = _build_txt_value("abc123", expiry, "svc:assistant@orga.test")
    assert txt == "token=abc123 bnd-req=svc:assistant@orga.test expiry=2026-01-02T03:04:05Z"


def test_build_txt_value_domain_before_bnd_req():
    expiry = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    txt = _build_txt_value("abc123", expiry, "svc:bot@orga.test", domain="example.com")
    assert (
        txt
        == "token=abc123 domain=example.com bnd-req=svc:bot@orga.test expiry=2026-01-02T03:04:05Z"
    )


# ---------------------------------------------------------------------------
# _parse_txt_value
# ---------------------------------------------------------------------------


def test_parse_txt_value_full():
    txt = "token=abc123 bnd-req=svc:assistant@orga.test expiry=2026-01-02T03:04:05Z"
    parsed = _parse_txt_value(txt)
    assert parsed["token"] == "abc123"
    assert parsed["bnd-req"] == "svc:assistant@orga.test"
    assert parsed["expiry"] == "2026-01-02T03:04:05Z"


def test_parse_txt_value_minimal():
    parsed = _parse_txt_value("token=xyz expiry=2026-01-01T00:00:00Z")
    assert parsed["token"] == "xyz"
    assert "bnd-req" not in parsed


def test_parse_txt_value_bare_token_not_accepted():
    # Bare values without 'token=' prefix are NOT accepted — explicit key= required
    parsed = _parse_txt_value("baretoken expiry=2026-01-01T00:00:00Z")
    assert "token" not in parsed


def test_parse_txt_value_case_insensitive_keys():
    parsed = _parse_txt_value("TOKEN=abc EXPIRY=2026-01-01T00:00:00Z")
    assert parsed["token"] == "abc"
    assert parsed["expiry"] == "2026-01-01T00:00:00Z"


def test_parse_txt_value_strips_outer_quotes():
    # Cloudflare wraps the entire content field in literal '"..."'
    txt = '"token=abc123 bnd-req=svc:assistant@orga.test expiry=2026-01-02T03:04:05Z"'
    parsed = _parse_txt_value(txt)
    assert parsed["token"] == "abc123"
    assert parsed["expiry"] == "2026-01-02T03:04:05Z"


def test_parse_txt_value_first_wins_on_duplicate_keys():
    # First occurrence wins; injected second value is discarded
    parsed = _parse_txt_value("token=first token=injected expiry=2099-01-01T00:00:00Z")
    assert parsed["token"] == "first"


# ---------------------------------------------------------------------------
# issue()
# ---------------------------------------------------------------------------


def test_issue_returns_challenge():
    ch = issue("example.com")
    assert isinstance(ch, DCVChallenge)
    assert ch.domain == "example.com"
    assert ch.fqdn == "_agents-challenge.example.com"
    assert ch.bnd_req is None


def test_issue_token_in_txt_value():
    ch = issue("example.com")
    assert f"token={ch.token}" in ch.txt_value


def test_issue_expiry_in_txt_value():
    ch = issue("example.com")
    assert "expiry=" in ch.txt_value


def test_issue_embeds_domain_in_txt_value():
    ch = issue("example.com")
    assert "domain=example.com" in ch.txt_value


def test_issue_bnd_req_when_both_supplied():
    ch = issue("example.com", agent_name="assistant", issuer_domain="orga.test")
    assert ch.bnd_req == "svc:assistant@orga.test"
    assert "bnd-req=svc:assistant@orga.test" in ch.txt_value


def test_issue_no_bnd_req_when_partial():
    ch1 = issue("example.com", agent_name="assistant")
    assert ch1.bnd_req is None
    ch2 = issue("example.com", issuer_domain="orga.test")
    assert ch2.bnd_req is None


def test_issue_ttl_affects_expiry():
    ch_short = issue("example.com", ttl_seconds=60)
    ch_long = issue("example.com", ttl_seconds=7200)
    assert ch_long.expiry > ch_short.expiry


def test_issue_is_stateless():
    ch1 = issue("example.com")
    ch2 = issue("example.com")
    assert ch1.token != ch2.token


def test_issue_rejects_agent_name_with_spaces():
    from dns_aid.utils.validation import ValidationError

    with pytest.raises(ValidationError):
        issue("example.com", agent_name="agent name with spaces", issuer_domain="orga.test")


def test_issue_rejects_ttl_above_cap():
    with pytest.raises(ValueError):
        issue("example.com", ttl_seconds=86401)


def test_issue_rejects_ttl_below_minimum():
    with pytest.raises(ValueError):
        issue("example.com", ttl_seconds=10)


def test_issue_rejects_invalid_domain():
    from dns_aid.utils.validation import ValidationError

    with pytest.raises(ValidationError):
        issue("bad..domain")


# ---------------------------------------------------------------------------
# place()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_place_calls_backend():
    mock_backend = AsyncMock()
    mock_backend.create_txt_record = AsyncMock()

    result = await place("orga.test", _generate_token(), backend=mock_backend)

    assert isinstance(result, DCVPlaceResult)
    assert result.fqdn == "_agents-challenge.orga.test"
    assert result.domain == "orga.test"
    mock_backend.create_txt_record.assert_awaited_once()
    call_kwargs = mock_backend.create_txt_record.call_args.kwargs
    assert call_kwargs["zone"] == "orga.test"
    assert call_kwargs["name"] == "_agents-challenge"
    assert len(call_kwargs["values"]) == 1


@pytest.mark.asyncio
async def test_place_embeds_domain_in_txt():
    mock_backend = AsyncMock()
    mock_backend.create_txt_record = AsyncMock()

    await place("orga.test", _generate_token(), backend=mock_backend)

    call_kwargs = mock_backend.create_txt_record.call_args.kwargs
    assert "domain=orga.test" in call_kwargs["values"][0]


@pytest.mark.asyncio
async def test_place_includes_bnd_req():
    mock_backend = AsyncMock()
    mock_backend.create_txt_record = AsyncMock()
    token = _generate_token()

    await place("orga.test", token, bnd_req="svc:bot@orga.test", backend=mock_backend)

    call_kwargs = mock_backend.create_txt_record.call_args.kwargs
    assert "bnd-req=svc:bot@orga.test" in call_kwargs["values"][0]


@pytest.mark.asyncio
async def test_place_rejects_invalid_token():
    mock_backend = AsyncMock()
    with pytest.raises(ValueError, match="base32"):
        await place("orga.test", "not-a-valid-token!!!", backend=mock_backend)


@pytest.mark.asyncio
async def test_place_rejects_expiry_above_cap():
    mock_backend = AsyncMock()
    token = _generate_token()
    with pytest.raises(ValueError):
        await place("orga.test", token, expiry_seconds=86401, backend=mock_backend)


# ---------------------------------------------------------------------------
# verify() helpers
# ---------------------------------------------------------------------------


def _make_rdata(txt: str):
    """Minimal stub for dns.rdata with a strings attribute."""
    rdata = MagicMock()
    rdata.strings = [txt.encode()]
    return rdata


def _patch_resolver(return_value=None, side_effect=None):
    """Context manager: patch dns.asyncresolver.Resolver for verify() tests.

    Uses MagicMock for the instance so that synchronous methods (cache, use_edns,
    nameservers, port) behave synchronously.  resolve() is an explicit AsyncMock.
    """
    mock_resolver_cls = MagicMock()
    mock_instance = MagicMock()
    mock_resolver_cls.return_value = mock_instance
    if side_effect is not None:
        mock_instance.resolve = AsyncMock(side_effect=side_effect)
    else:
        mock_instance.resolve = AsyncMock(return_value=return_value)
    return patch("dns_aid.core.dcv.dns.asyncresolver.Resolver", mock_resolver_cls), mock_instance


# ---------------------------------------------------------------------------
# verify() — happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_success():
    token = _generate_token()
    expiry = datetime(2099, 1, 1, tzinfo=UTC)
    txt = _build_txt_value(token, expiry, None)

    ctx, _ = _patch_resolver(return_value=[_make_rdata(txt)])
    with ctx:
        result = await verify("example.com", token)

    assert result.verified is True
    assert result.domain == "example.com"
    assert result.token == token


@pytest.mark.asyncio
async def test_verify_wrong_token():
    expiry = datetime(2099, 1, 1, tzinfo=UTC)
    txt = _build_txt_value("a" * 32, expiry, None)

    ctx, _ = _patch_resolver(return_value=[_make_rdata(txt)])
    with ctx:
        result = await verify("example.com", "b" * 32)

    assert result.verified is False
    assert result.error == "Token not found in any challenge record"


@pytest.mark.asyncio
async def test_verify_expired():
    token = _generate_token()
    expiry = datetime(2000, 1, 1, tzinfo=UTC)
    txt = _build_txt_value(token, expiry, None)

    ctx, _ = _patch_resolver(return_value=[_make_rdata(txt)])
    with ctx:
        result = await verify("example.com", token)

    assert result.verified is False
    assert result.expired is True


@pytest.mark.asyncio
async def test_verify_nxdomain():
    import dns.resolver

    ctx, _ = _patch_resolver(side_effect=dns.resolver.NXDOMAIN())
    with ctx:
        result = await verify("example.com", _generate_token())

    assert result.verified is False
    assert "NXDOMAIN" in result.error


@pytest.mark.asyncio
async def test_verify_no_answer():
    import dns.resolver

    ctx, _ = _patch_resolver(side_effect=dns.resolver.NoAnswer())
    with ctx:
        result = await verify("example.com", _generate_token())

    assert result.verified is False
    assert result.error is not None


@pytest.mark.asyncio
async def test_verify_custom_nameserver():
    token = _generate_token()
    expiry = datetime(2099, 1, 1, tzinfo=UTC)
    txt = _build_txt_value(token, expiry, None)

    ctx, mock_instance = _patch_resolver(return_value=[_make_rdata(txt)])
    with ctx:
        await verify("example.com", token, nameserver="1.2.3.4", port=5353)

    assert mock_instance.nameservers == ["1.2.3.4"]
    assert mock_instance.port == 5353


# ---------------------------------------------------------------------------
# verify() — fail-closed regression tests (Igor's confirmed exploits)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_fails_when_expiry_missing():
    """Exploit 1: record with no expiry= field must not pass."""
    token = _generate_token()
    txt = f"token={token}"  # no expiry

    ctx, _ = _patch_resolver(return_value=[_make_rdata(txt)])
    with ctx:
        result = await verify("example.com", token)

    assert result.verified is False


@pytest.mark.asyncio
async def test_verify_fails_when_expiry_malformed():
    """Exploit 2: malformed expiry must not pass (was: bare except: pass)."""
    token = _generate_token()
    txt = f"token={token} expiry=NOT-A-DATE"

    ctx, _ = _patch_resolver(return_value=[_make_rdata(txt)])
    with ctx:
        result = await verify("example.com", token)

    assert result.verified is False


@pytest.mark.asyncio
async def test_verify_fails_when_expiry_is_never():
    """Exploit 3: 'expiry=never' magic string must not pass."""
    token = _generate_token()
    txt = f"token={token} expiry=never"

    ctx, _ = _patch_resolver(return_value=[_make_rdata(txt)])
    with ctx:
        result = await verify("example.com", token)

    assert result.verified is False


@pytest.mark.asyncio
async def test_verify_rejects_bare_token():
    """Exploit 4: bare string (no token= prefix) must not match."""
    token = _generate_token()
    expiry = datetime(2099, 1, 1, tzinfo=UTC)
    # Record with bare value, no key= prefix
    txt = f"{token} expiry={expiry.strftime('%Y-%m-%dT%H:%M:%SZ')}"

    ctx, _ = _patch_resolver(return_value=[_make_rdata(txt)])
    with ctx:
        result = await verify("example.com", token)

    assert result.verified is False


@pytest.mark.asyncio
async def test_verify_invalid_nameserver_returns_error_not_exception():
    """Exploit 5: invalid nameserver must return DCVVerifyResult, not raise."""
    result = await verify("example.com", _generate_token(), nameserver="not-an-ip")

    assert result.verified is False
    assert result.error is not None
    assert "nameserver" in result.error.lower()


@pytest.mark.asyncio
async def test_verify_cloudflare_quoted_record():
    """Cloudflare stores TXT content with literal surrounding quotes."""
    token = _generate_token()
    expiry = datetime(2099, 1, 1, tzinfo=UTC)
    raw = _build_txt_value(token, expiry, None)
    quoted = f'"{raw}"'  # Cloudflare wrapping

    ctx, _ = _patch_resolver(return_value=[_make_rdata(quoted)])
    with ctx:
        result = await verify("example.com", token)

    assert result.verified is True


@pytest.mark.asyncio
async def test_verify_bnd_req_enforced_when_expected():
    """bnd-req mismatch must fail when expected_bnd_req is supplied."""
    token = _generate_token()
    expiry = datetime(2099, 1, 1, tzinfo=UTC)
    txt = _build_txt_value(token, expiry, "svc:assistant@orga.test")

    ctx, _ = _patch_resolver(return_value=[_make_rdata(txt)])
    with ctx:
        result = await verify("example.com", token, expected_bnd_req="svc:other-agent@other.test")

    assert result.verified is False


@pytest.mark.asyncio
async def test_verify_bnd_req_passes_when_matches():
    """bnd-req check passes when expected value matches the record."""
    token = _generate_token()
    expiry = datetime(2099, 1, 1, tzinfo=UTC)
    bnd_req = "svc:assistant@orga.test"
    txt = _build_txt_value(token, expiry, bnd_req)

    ctx, _ = _patch_resolver(return_value=[_make_rdata(txt)])
    with ctx:
        result = await verify("example.com", token, expected_bnd_req=bnd_req)

    assert result.verified is True


@pytest.mark.asyncio
async def test_verify_too_many_records():
    """DoS guard: more than MAX_CHALLENGE_RECORDS returns failure."""
    from dns_aid.core.dcv import MAX_CHALLENGE_RECORDS

    token = _generate_token()
    expiry = datetime(2099, 1, 1, tzinfo=UTC)
    txt = _build_txt_value(token, expiry, None)
    many_records = [_make_rdata(txt)] * (MAX_CHALLENGE_RECORDS + 1)

    ctx, _ = _patch_resolver(return_value=many_records)
    with ctx:
        result = await verify("example.com", token)

    assert result.verified is False
    assert "Too many" in result.error


@pytest.mark.asyncio
async def test_verify_skips_expired_finds_valid():
    """Multi-record: expired record first, valid second — should pass."""
    token = _generate_token()
    expired_txt = _build_txt_value(token, datetime(2000, 1, 1, tzinfo=UTC), None)
    valid_txt = _build_txt_value(token, datetime(2099, 1, 1, tzinfo=UTC), None)

    ctx, _ = _patch_resolver(return_value=[_make_rdata(expired_txt), _make_rdata(valid_txt)])
    with ctx:
        result = await verify("example.com", token)

    assert result.verified is True


@pytest.mark.asyncio
async def test_verify_multi_string_txt_record():
    """Multi-string TXT records (multiple rdata.strings) are concatenated."""
    token = _generate_token()
    expiry = datetime(2099, 1, 1, tzinfo=UTC)
    full_txt = _build_txt_value(token, expiry, None)
    # Simulate multi-string: split the value across two strings
    mid = len(full_txt) // 2
    rdata = MagicMock()
    rdata.strings = [full_txt[:mid].encode(), full_txt[mid:].encode()]

    ctx, _ = _patch_resolver(return_value=[rdata])
    with ctx:
        result = await verify("example.com", token)

    assert result.verified is True


# ---------------------------------------------------------------------------
# verify() — domain binding
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_domain_binding_matching():
    """domain= field in record matches the queried domain — must pass."""
    token = _generate_token()
    expiry = datetime(2099, 1, 1, tzinfo=UTC)
    txt = _build_txt_value(token, expiry, None, domain="example.com")

    ctx, _ = _patch_resolver(return_value=[_make_rdata(txt)])
    with ctx:
        result = await verify("example.com", token)

    assert result.verified is True


@pytest.mark.asyncio
async def test_verify_domain_binding_blocks_wrong_domain():
    """domain= field from a different zone must cause the record to be skipped."""
    token = _generate_token()
    expiry = datetime(2099, 1, 1, tzinfo=UTC)
    # Record was written for evil.com but placed (or replayed) at example.com
    txt = _build_txt_value(token, expiry, None, domain="evil.com")

    ctx, _ = _patch_resolver(return_value=[_make_rdata(txt)])
    with ctx:
        result = await verify("example.com", token)

    assert result.verified is False
    assert result.error == "Token not found in any challenge record"


@pytest.mark.asyncio
async def test_verify_domain_binding_absent_field_allowed():
    """Records without domain= (older format) are still accepted — backward compat."""
    token = _generate_token()
    expiry = datetime(2099, 1, 1, tzinfo=UTC)
    txt = _build_txt_value(token, expiry, None)  # no domain= field

    ctx, _ = _patch_resolver(return_value=[_make_rdata(txt)])
    with ctx:
        result = await verify("example.com", token)

    assert result.verified is True


# ---------------------------------------------------------------------------
# verify() — DNSSEC
# ---------------------------------------------------------------------------


def _make_answer_with_flags(rdatas, *, ad: bool = False):
    """Create a mock DNS Answer that supports both iteration and .response.flags."""
    import dns.flags as _dns_flags

    mock_answer = MagicMock()
    mock_answer.__iter__ = MagicMock(return_value=iter(rdatas))
    mock_answer.__len__ = MagicMock(return_value=len(rdatas))
    mock_answer.response = MagicMock()
    mock_answer.response.flags = _dns_flags.AD if ad else 0
    return mock_answer


@pytest.mark.asyncio
async def test_verify_dnssec_not_required_by_default():
    """require_dnssec defaults to False; missing AD flag must not block verification."""
    token = _generate_token()
    expiry = datetime(2099, 1, 1, tzinfo=UTC)
    txt = _build_txt_value(token, expiry, None)
    answer = _make_answer_with_flags([_make_rdata(txt)], ad=False)

    ctx, _ = _patch_resolver(return_value=answer)
    with ctx:
        result = await verify("example.com", token)

    assert result.verified is True
    assert result.dnssec_validated is False


@pytest.mark.asyncio
async def test_verify_dnssec_required_fails_without_ad_flag():
    """require_dnssec=True must fail when the resolver does not set AD=1."""
    token = _generate_token()
    expiry = datetime(2099, 1, 1, tzinfo=UTC)
    txt = _build_txt_value(token, expiry, None)
    answer = _make_answer_with_flags([_make_rdata(txt)], ad=False)

    ctx, _ = _patch_resolver(return_value=answer)
    with ctx:
        result = await verify("example.com", token, require_dnssec=True)

    assert result.verified is False
    assert "AD flag" in result.error


@pytest.mark.asyncio
async def test_verify_dnssec_required_passes_with_ad_flag():
    """require_dnssec=True must succeed when AD=1 and token matches."""
    token = _generate_token()
    expiry = datetime(2099, 1, 1, tzinfo=UTC)
    txt = _build_txt_value(token, expiry, None)
    answer = _make_answer_with_flags([_make_rdata(txt)], ad=True)

    ctx, _ = _patch_resolver(return_value=answer)
    with ctx:
        result = await verify("example.com", token, require_dnssec=True)

    assert result.verified is True
    assert result.dnssec_validated is True


@pytest.mark.asyncio
async def test_verify_dnssec_silently_skipped_with_nameserver():
    """require_dnssec=True + nameserver= is silently downgraded (authoritative can't validate)."""
    token = _generate_token()
    expiry = datetime(2099, 1, 1, tzinfo=UTC)
    txt = _build_txt_value(token, expiry, None)
    # Answer has AD=0 but that should not matter — dnssec check is skipped
    answer = _make_answer_with_flags([_make_rdata(txt)], ad=False)

    ctx, _ = _patch_resolver(return_value=answer)
    with ctx:
        result = await verify("example.com", token, nameserver="1.2.3.4", require_dnssec=True)

    assert result.verified is True
    assert result.dnssec_validated is False


# ---------------------------------------------------------------------------
# revoke()
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_revoke_calls_backend():
    mock_backend = AsyncMock()
    mock_backend.delete_record = AsyncMock(return_value=True)
    token = _generate_token()

    expiry = datetime(2099, 1, 1, tzinfo=UTC)
    txt = _build_txt_value(token, expiry, None)

    ctx, _ = _patch_resolver(return_value=[_make_rdata(txt)])
    with ctx:
        result = await revoke("orga.test", token=token, backend=mock_backend)

    assert isinstance(result, DCVRevokeResult)
    assert result.removed is True
    assert result.domain == "orga.test"
    mock_backend.delete_record.assert_awaited_once_with(
        zone="orga.test",
        name="_agents-challenge",
        record_type="TXT",
    )


@pytest.mark.asyncio
async def test_revoke_returns_false_when_token_not_found():
    """revoke() skips deletion if the token is not found in DNS."""
    import dns.resolver

    token = _generate_token()
    mock_backend = AsyncMock()

    ctx, _ = _patch_resolver(side_effect=dns.resolver.NXDOMAIN())
    with ctx:
        result = await revoke("orga.test", token=token, backend=mock_backend)

    assert isinstance(result, DCVRevokeResult)
    assert result.removed is False
    mock_backend.delete_record.assert_not_awaited()


@pytest.mark.asyncio
async def test_revoke_rejects_invalid_token():
    mock_backend = AsyncMock()
    with pytest.raises(ValueError, match="base32"):
        await revoke("orga.test", token="bad!", backend=mock_backend)
