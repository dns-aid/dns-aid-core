# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""well-known SvcParam decoding: plain string and wk-01 length-prefixed list (#317)."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import dns.rdata
import dns.resolver
import pytest
import structlog

from dns_aid.core.well_known import WellKnownDecodeError, decode_well_known, read_well_known


def _entry(b: bytes) -> bytes:
    return len(b).to_bytes(2, "big") + b


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (b"agent-card.json", ["agent-card.json"]),
        (_entry(b"modelmarket.json"), ["modelmarket.json"]),
        (_entry(b"agent-card.json") + _entry(b"api-catalog"), ["agent-card.json", "api-catalog"]),
        (b"/.well-known/agent-card.json", ["/.well-known/agent-card.json"]),
    ],
)
def test_decode(value: bytes, expected: list[str]) -> None:
    assert decode_well_known(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        _entry(b"agent-card.json") + b"x",  # trailing octet: prefixes don't walk exactly
        b"\x00\x00agent-card.json",  # zero-length entry
        b"\x00\x40short",  # length runs past the end
    ],
)
def test_values_that_do_not_walk_are_plain_strings(value: bytes) -> None:
    assert decode_well_known(value) == [value.decode()]


def test_a_plain_suffix_is_never_read_as_wk01() -> None:
    """Two ASCII octets read as a length >= 0x2020, far past any valid suffix."""
    for suffix in (b"ai-catalog.json", b"aa", b"a" * 128):
        assert decode_well_known(suffix) == [suffix.decode()]


@pytest.mark.parametrize("value", [b"", b"\xff\xfe", _entry(b"\xff\xfe")])
def test_undecodable_values_raise(value: bytes) -> None:
    with pytest.raises(WellKnownDecodeError):
        decode_well_known(value)


def test_read_well_known_absent_param() -> None:
    rdata = MagicMock()
    rdata.params = {}
    assert read_well_known(rdata) is None


# --- agent-record path (discoverer) ----------------------------------------


def _resolver(text: str) -> MagicMock:
    async def resolve(qname: str, rdtype: str):
        if rdtype != "SVCB":
            raise dns.resolver.NoAnswer()
        return [dns.rdata.from_text("IN", "SVCB", text)]

    resolver = MagicMock()
    resolver.resolve = AsyncMock(side_effect=resolve)
    return resolver


async def _query(text: str):
    from dns_aid.core.discoverer import _query_single_agent
    from dns_aid.core.models import Protocol

    fetch = AsyncMock(return_value=None)
    with (
        patch("dns_aid.core.discoverer.dns.asyncresolver.Resolver", return_value=_resolver(text)),
        patch("dns_aid.core.discoverer.fetch_cap_document", fetch),
    ):
        agent = await _query_single_agent("example.com", "chat", Protocol.MCP)
    return agent, fetch


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "param",
    ['key65409="agent-card.json"', 'key65409="\\000\\015agent-card.json"'],
    ids=["plain", "wk01"],
)
async def test_agent_record_reads_both_formats(param: str) -> None:
    agent, fetch = await _query(f'1 a.example.com. alpn="mcp" {param}')
    assert agent is not None
    assert agent.well_known_path == "agent-card.json"
    assert fetch.await_args.args[0] == "https://a.example.com/.well-known/agent-card.json"


@pytest.mark.asyncio
async def test_agent_record_with_undecodable_well_known_is_kept_and_logged() -> None:
    with structlog.testing.capture_logs() as logs:
        agent, fetch = await _query('1 a.example.com. alpn="mcp" key65409="\\255\\254"')
    assert agent is not None
    assert agent.well_known_path is None
    fetch.assert_not_called()
    assert any("undecodable" in e["event"] for e in logs)


@pytest.mark.asyncio
async def test_agent_record_with_invalid_well_known_is_kept() -> None:
    """Before: the invalid value reached AgentRecord validation and dropped the agent."""
    with structlog.testing.capture_logs() as logs:
        agent, fetch = await _query('1 a.example.com. alpn="mcp" key65409="../etc/passwd"')
    assert agent is not None
    assert agent.well_known_path is None
    fetch.assert_not_called()
    assert any("rejected" in e["event"] for e in logs)
