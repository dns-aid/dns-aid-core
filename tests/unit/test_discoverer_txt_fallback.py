# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Discoverer integration tests for the TXT-record fallback path.

Mirrors the structure of ``tests/unit/test_discoverer.py``: mocks
``dns.asyncresolver.Resolver`` and dispatches per rdtype so each test can
declare independently whether SVCB / HTTPS / TXT yield records.

Covers the SVCB → HTTPS → TXT ladder added to ``_query_single_agent``:

- SVCB present  → SVCB used, fallback skipped
- SVCB+HTTPS NoAnswer, TXT v=1 present → fallback used (full record returned)
- SVCB+HTTPS NoAnswer, TXT metadata only → None
- SVCB+HTTPS NoAnswer, TXT malformed → None
- SVCB+HTTPS NoAnswer, no TXT → None
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import dns.resolver
import pytest

from dns_aid.core.discoverer import _query_single_agent
from dns_aid.core.models import Protocol

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_txt_answer(strings_list: list[list[bytes]]) -> MagicMock:
    """Build a mock TXT answer with one rdata per inner-list of strings.

    Each element of ``strings_list`` is the list of ``<character-string>``
    bytes that one TXT RR exposes via ``rdata.strings``.
    """
    rdatas = []
    for strings in strings_list:
        rdata = MagicMock()
        rdata.strings = strings
        rdatas.append(rdata)
    answer = MagicMock()
    answer.__iter__ = lambda self: iter(rdatas)
    return answer


def _make_svcb_answer(target: str, port: int = 443) -> MagicMock:
    """Minimal SVCB answer used when SVCB is present and the test wants it used."""
    rdata = MagicMock()
    rdata.priority = 1
    rdata.target = MagicMock()
    rdata.target.__str__ = lambda self: target  # type: ignore[misc]
    rdata.params = {}
    rdata.__str__ = lambda self: f"1 {target}. alpn=mcp port={port}"  # type: ignore[misc]
    answer = MagicMock()
    answer.__iter__ = lambda self: iter([rdata])
    return answer


def _dispatching_resolver(
    *,
    svcb: MagicMock | Exception | None = None,
    https: MagicMock | Exception | None = None,
    txt: MagicMock | Exception | None = None,
) -> MagicMock:
    """Build a resolver mock that returns / raises per rdtype.

    ``None`` for any of the three means "raise NoAnswer for that type."
    Pass an Exception instance to raise it; pass a MagicMock answer to
    return it.
    """

    async def fake_resolve(qname: str, rdtype: str) -> MagicMock:
        cfg = {"SVCB": svcb, "HTTPS": https, "TXT": txt}.get(rdtype)
        if cfg is None:
            raise dns.resolver.NoAnswer()
        if isinstance(cfg, Exception):
            raise cfg
        return cfg

    resolver = MagicMock()
    resolver.resolve = AsyncMock(side_effect=fake_resolve)
    return resolver


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_svcb_present_skips_txt_fallback() -> None:
    """SVCB returns a usable record → endpoint_source remains dns_svcb.

    (TXT may still be queried by the post-SVCB capability-enrichment tier,
    but that's a separate concern from the new endpoint-TXT fallback. The
    important property is that endpoint_source did not flip to
    ``dns_txt_fallback``.)
    """
    svcb = _make_svcb_answer(target="mcp.example.com")
    resolver = _dispatching_resolver(svcb=svcb)

    with patch("dns_aid.core.discoverer.dns.asyncresolver.Resolver", return_value=resolver):
        result = await _query_single_agent("example.com", "chat", Protocol.MCP)

    assert result is not None
    assert result.target_host == "mcp.example.com"
    assert result.endpoint_source == "dns_svcb"


@pytest.mark.asyncio
async def test_svcb_and_https_noanswer_txt_fallback_used() -> None:
    """SVCB+HTTPS NoAnswer, TXT carries a v=1 record → fallback path returns it."""
    txt = _make_txt_answer(
        [
            [b"v=1 target=mcp.example.com port=8443 alpn=mcp cap=https://example.com/cap"],
        ]
    )
    resolver = _dispatching_resolver(txt=txt)

    with patch("dns_aid.core.discoverer.dns.asyncresolver.Resolver", return_value=resolver):
        result = await _query_single_agent("example.com", "chat", Protocol.MCP)

    assert result is not None
    assert result.target_host == "mcp.example.com"
    assert result.port == 8443
    assert result.endpoint_source == "dns_txt_fallback"
    assert result.cap_uri == "https://example.com/cap"


@pytest.mark.asyncio
async def test_svcb_and_https_noanswer_txt_only_metadata_returns_none() -> None:
    """TXT exists but only carries capability/version metadata — no v=1 → None."""
    txt = _make_txt_answer(
        [
            [b"capabilities=chat,code-review", b"version=1.0.0"],
        ]
    )
    resolver = _dispatching_resolver(txt=txt)

    with patch("dns_aid.core.discoverer.dns.asyncresolver.Resolver", return_value=resolver):
        result = await _query_single_agent("example.com", "chat", Protocol.MCP)
    assert result is None


@pytest.mark.asyncio
async def test_svcb_and_https_noanswer_txt_malformed_returns_none() -> None:
    """TXT has a v= marker but missing target=. parse_txt_fallback returns None."""
    txt = _make_txt_answer(
        [
            [b"v=1 port=443"],  # missing target
        ]
    )
    resolver = _dispatching_resolver(txt=txt)

    with patch("dns_aid.core.discoverer.dns.asyncresolver.Resolver", return_value=resolver):
        result = await _query_single_agent("example.com", "chat", Protocol.MCP)
    assert result is None


@pytest.mark.asyncio
async def test_no_records_anywhere_returns_none() -> None:
    """SVCB+HTTPS+TXT all NoAnswer → None (today's behaviour preserved when no fallback)."""
    resolver = _dispatching_resolver()  # all three default to NoAnswer

    with patch("dns_aid.core.discoverer.dns.asyncresolver.Resolver", return_value=resolver):
        result = await _query_single_agent("example.com", "chat", Protocol.MCP)
    assert result is None


@pytest.mark.asyncio
async def test_txt_multiple_v1_records_uses_first_logs_warning() -> None:
    """Two v=1 records at the same FQDN — out of spec; use the first, warn."""
    txt = _make_txt_answer(
        [
            [b"v=1 target=first.example.com"],
            [b"v=1 target=second.example.com"],
        ]
    )
    resolver = _dispatching_resolver(txt=txt)

    with (
        patch("dns_aid.core.discoverer.dns.asyncresolver.Resolver", return_value=resolver),
        patch("dns_aid.core.discoverer.logger") as mock_logger,
    ):
        result = await _query_single_agent("example.com", "chat", Protocol.MCP)

    assert result is not None
    assert result.target_host == "first.example.com"
    # Confirm the warning fired
    warning_calls = [c for c in mock_logger.warning.call_args_list if c.args]
    assert any("txt_fallback.multiple_records" in c.args[0] for c in warning_calls)


@pytest.mark.asyncio
async def test_txt_fallback_with_metadata_alongside() -> None:
    """Real-world shape: v=1 endpoint TXT + capabilities= metadata TXT at same FQDN.

    Both come back in one TXT answer. The v=1 record drives the endpoint;
    capabilities= TXT is consumed by the existing _query_capabilities tier.
    """
    txt = _make_txt_answer(
        [
            [b"v=1 target=mcp.example.com port=443 alpn=mcp"],
            [b"capabilities=chat,code-review", b"version=1.0.0"],
        ]
    )
    resolver = _dispatching_resolver(txt=txt)

    with patch("dns_aid.core.discoverer.dns.asyncresolver.Resolver", return_value=resolver):
        result = await _query_single_agent("example.com", "chat", Protocol.MCP)

    assert result is not None
    assert result.target_host == "mcp.example.com"
    assert result.endpoint_source == "dns_txt_fallback"
    # Capabilities should have been picked up by _query_capabilities from the
    # adjacent metadata TXT RR.
    assert "chat" in result.capabilities
    assert "code-review" in result.capabilities
    assert result.capability_source == "txt_fallback"


@pytest.mark.asyncio
async def test_txt_fallback_alpn_mismatch_warns_and_reconciles() -> None:
    """Parsed alpn= disagrees with the query probe → warn AND reconcile.

    draft-02: the flat owner name carries no protocol, so the probe is only
    a placeholder — the record's own signal (bap, then alpn) is stamped onto
    the result via _reconcile_protocol, exactly like the SVCB path. The
    disagreement is still surfaced as a warning for observability.
    """
    txt = _make_txt_answer(
        [
            [b"v=1 target=mcp.example.com alpn=a2a"],  # alpn says a2a, probe says mcp
        ]
    )
    resolver = _dispatching_resolver(txt=txt)

    with (
        patch("dns_aid.core.discoverer.dns.asyncresolver.Resolver", return_value=resolver),
        patch("dns_aid.core.discoverer.logger") as mock_logger,
    ):
        result = await _query_single_agent("example.com", "chat", Protocol.MCP)

    assert result is not None
    assert result.target_host == "mcp.example.com"
    # Record signal wins (mirrors the SVCB path's _reconcile_protocol so the
    # JWS binding check payload.alpn == agent.protocol.value holds).
    assert result.protocol == Protocol.A2A
    # Warning fired with the mismatch event
    warning_events = [c.args[0] for c in mock_logger.warning.call_args_list if c.args]
    assert "txt_fallback.alpn_mismatch" in warning_events


@pytest.mark.asyncio
async def test_txt_fallback_alpn_matches_no_warning() -> None:
    """Round-trip happy path: parsed alpn= matches FQDN-derived protocol, no warning."""
    txt = _make_txt_answer(
        [
            [b"v=1 target=mcp.example.com alpn=mcp"],
        ]
    )
    resolver = _dispatching_resolver(txt=txt)

    with (
        patch("dns_aid.core.discoverer.dns.asyncresolver.Resolver", return_value=resolver),
        patch("dns_aid.core.discoverer.logger") as mock_logger,
    ):
        result = await _query_single_agent("example.com", "chat", Protocol.MCP)

    assert result is not None
    warning_events = [c.args[0] for c in mock_logger.warning.call_args_list if c.args]
    assert "txt_fallback.alpn_mismatch" not in warning_events


@pytest.mark.asyncio
async def test_txt_fallback_nxdomain_returns_none() -> None:
    """TXT NXDOMAIN (no records at all) returns None gracefully — no crash."""
    resolver = _dispatching_resolver(txt=dns.resolver.NXDOMAIN())

    with patch("dns_aid.core.discoverer.dns.asyncresolver.Resolver", return_value=resolver):
        result = await _query_single_agent("example.com", "chat", Protocol.MCP)
    assert result is None


@pytest.mark.asyncio
async def test_txt_fallback_at_legacy_fqdn_sets_legacy_resolved() -> None:
    """Flat ladder dry, legacy ladder reaches TXT → legacy_resolved=True.

    The full SVCB → HTTPS → TXT ladder runs at the flat owner name first;
    only when it comes up completely dry AND legacy fallback is active does
    the same ladder run at the legacy -01 shape. A TXT hit there must stamp
    ``legacy_resolved=True`` exactly like a legacy SVCB hit would.
    """
    legacy_fqdn = "_chat._mcp._agents.example.com"
    txt = _make_txt_answer([[b"v=1 target=mcp.example.com port=8443 alpn=mcp"]])

    async def fake_resolve(qname: str, rdtype: str) -> MagicMock:
        # TXT only exists at the legacy owner name; everything else is dry.
        if rdtype == "TXT" and str(qname).rstrip(".") == legacy_fqdn:
            return txt
        raise dns.resolver.NoAnswer()

    resolver = MagicMock()
    resolver.resolve = AsyncMock(side_effect=fake_resolve)

    with patch("dns_aid.core.discoverer.dns.asyncresolver.Resolver", return_value=resolver):
        result = await _query_single_agent("example.com", "chat", Protocol.MCP, allow_legacy=True)

    assert result is not None
    assert result.target_host == "mcp.example.com"
    assert result.port == 8443
    assert result.legacy_resolved is True
    assert result.endpoint_source == "dns_txt_fallback"


@pytest.mark.asyncio
async def test_txt_fallback_flat_txt_beats_legacy_svcb() -> None:
    """A flat TXT v=1 record wins over a leftover legacy SVCB record.

    The flat owner name is draft-02's canonical location: a publisher who
    deliberately placed a flat TXT record has migrated, and a stale legacy
    SVCB record must not shadow it.
    """
    flat_fqdn = "chat.example.com"
    legacy_fqdn = "_chat._mcp._agents.example.com"
    txt = _make_txt_answer([[b"v=1 target=new.example.com alpn=mcp"]])
    legacy_svcb = _make_svcb_answer(target="stale.example.com")

    async def fake_resolve(qname: str, rdtype: str) -> MagicMock:
        q = str(qname).rstrip(".")
        if q == flat_fqdn and rdtype == "TXT":
            return txt
        if q == legacy_fqdn and rdtype == "SVCB":
            return legacy_svcb
        raise dns.resolver.NoAnswer()

    resolver = MagicMock()
    resolver.resolve = AsyncMock(side_effect=fake_resolve)

    with patch("dns_aid.core.discoverer.dns.asyncresolver.Resolver", return_value=resolver):
        result = await _query_single_agent("example.com", "chat", Protocol.MCP, allow_legacy=True)

    assert result is not None
    assert result.target_host == "new.example.com"
    assert result.endpoint_source == "dns_txt_fallback"
    assert result.legacy_resolved is False


@pytest.mark.asyncio
async def test_txt_fallback_model_invalid_logs_and_returns_none() -> None:
    """Wire-valid but model-invalid TXT → specific warning, graceful None.

    TXT bodies are attacker-shapable: a record can pass the wire-format
    parser yet trip an AgentRecord field validator (here: underscored
    target_host). That boundary must not crash discovery, and must emit
    ``txt_fallback.model_rejected`` so operators can tell it apart from a
    plain DNS miss.
    """
    txt = _make_txt_answer([[b"v=1 target=_evil.example.com alpn=mcp"]])
    resolver = _dispatching_resolver(txt=txt)

    with (
        patch("dns_aid.core.discoverer.dns.asyncresolver.Resolver", return_value=resolver),
        patch("dns_aid.core.discoverer.logger") as mock_logger,
    ):
        result = await _query_single_agent("example.com", "chat", Protocol.MCP)

    assert result is None
    warning_events = [c.args[0] for c in mock_logger.warning.call_args_list if c.args]
    assert "txt_fallback.model_rejected" in warning_events
