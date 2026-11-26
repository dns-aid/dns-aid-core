# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""RFC 9460 §8 ``mandatory`` enforcement (adapted from nicknacnic's tests in #132).

A record whose ``mandatory`` list names a key this client does not implement
MUST be ignored; other records in the RRset are still usable.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import dns.rdata
import dns.resolver
import pytest

from dns_aid.core.discoverer import _query_single_agent, _unsupported_mandatory_keys
from dns_aid.core.models import Protocol


@pytest.mark.parametrize(
    "text",
    [
        '1 svc.example.com. alpn="mcp" port=443',
        '1 svc.example.com. alpn="mcp" port=443 mandatory=alpn,port',
        '1 svc.example.com. alpn="mcp" mandatory=alpn,key65400,key65401',
        "1 svc.example.com. mandatory=alpn,cap-sha256,bap,well-known",
        "1 svc.example.com. mandatory=key1,key3,key4,key6",
    ],
)
def test_supported_mandatory_keys(text: str) -> None:
    assert _unsupported_mandatory_keys(text) == []


@pytest.mark.parametrize(
    ("text", "unsupported"),
    [
        ("1 svc.example.com. mandatory=alpn,ech", ["ech"]),
        ("1 svc.example.com. mandatory=key5", ["ech"]),
        ("1 svc.example.com. mandatory=dohpath", ["dohpath"]),
        ("1 svc.example.com. mandatory=alpn,key65499", ["key65499"]),
    ],
)
def test_unsupported_mandatory_keys(text: str, unsupported: list[str]) -> None:
    assert _unsupported_mandatory_keys(text) == unsupported


def _resolver(texts: list[str]) -> MagicMock:
    async def resolve(qname: str, rdtype: str):
        if rdtype != "SVCB":
            raise dns.resolver.NoAnswer()
        return [dns.rdata.from_text("IN", "SVCB", t) for t in texts]

    resolver = MagicMock()
    resolver.resolve = AsyncMock(side_effect=resolve)
    return resolver


async def _query(texts: list[str]):
    with (
        patch("dns_aid.core.discoverer.dns.asyncresolver.Resolver", return_value=_resolver(texts)),
        patch("dns_aid.core.discoverer.fetch_cap_document", AsyncMock(return_value=None)),
    ):
        return await _query_single_agent("example.com", "chat", Protocol.MCP)


@pytest.mark.asyncio
async def test_record_with_unsupported_mandatory_key_is_skipped() -> None:
    assert (
        await _query(['1 a.example.com. alpn="mcp" mandatory=alpn,key65499 key65499="x"']) is None
    )


@pytest.mark.asyncio
async def test_other_records_in_the_rrset_are_still_used() -> None:
    agent = await _query(
        [
            '1 a.example.com. alpn="mcp" mandatory=alpn,key65499 key65499="x"',
            '2 b.example.com. alpn="mcp" port=443 mandatory=alpn,port',
        ]
    )
    assert agent is not None
    assert agent.target_host == "b.example.com"


@pytest.mark.asyncio
async def test_discover_at_fqdn_stamps_discovered_at() -> None:
    from dns_aid.core.discoverer import discover_at_fqdn

    with (
        patch(
            "dns_aid.core.discoverer.dns.asyncresolver.Resolver",
            return_value=_resolver(['1 a.example.com. alpn="mcp"']),
        ),
        patch("dns_aid.core.discoverer.fetch_cap_document", AsyncMock(return_value=None)),
    ):
        agent = await discover_at_fqdn("chat.example.com")
    assert agent is not None
    assert agent.discovered_at is not None
