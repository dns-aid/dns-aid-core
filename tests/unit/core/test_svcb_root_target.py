# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""RFC 9460 §2.5.2: a ServiceMode TargetName of "." means the owner name."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import dns.rdata
import dns.resolver
import pytest

from dns_aid.core.discoverer import _query_single_agent
from dns_aid.core.models import Protocol


def _resolver(records: dict[tuple[str, str], list[str]]) -> MagicMock:
    async def resolve(qname: str, rdtype: str):
        texts = records.get((qname.rstrip(".").lower(), rdtype))
        if not texts:
            raise dns.resolver.NoAnswer()
        return [dns.rdata.from_text("IN", rdtype, t) for t in texts]

    resolver = MagicMock()
    resolver.resolve = AsyncMock(side_effect=resolve)
    return resolver


async def _query(resolver: MagicMock):
    with (
        patch("dns_aid.core.discoverer.dns.asyncresolver.Resolver", return_value=resolver),
        patch("dns_aid.core.discoverer.fetch_cap_document", AsyncMock(return_value=None)),
    ):
        return await _query_single_agent("example.com", "site", Protocol.MCP)


@pytest.mark.asyncio
async def test_root_target_resolves_to_the_owner() -> None:
    resolver = _resolver({("site.example.com", "SVCB"): ['1 . alpn="mcp" port=443']})

    agent = await _query(resolver)

    assert agent is not None
    assert agent.target_host == "site.example.com"
    assert agent.endpoint_url == "https://site.example.com:443"


@pytest.mark.asyncio
async def test_root_target_after_alias_resolves_to_the_alias_target() -> None:
    """The owner of the ServiceMode record is the alias target, not the queried name."""
    resolver = _resolver(
        {
            ("site.example.com", "SVCB"): ["0 web.example.net."],
            ("web.example.net", "SVCB"): ['1 . alpn="mcp" port=8443'],
        }
    )

    agent = await _query(resolver)

    assert agent is not None
    assert agent.target_host == "web.example.net"
    assert agent.port == 8443


@pytest.mark.asyncio
async def test_explicit_target_is_unchanged() -> None:
    resolver = _resolver({("site.example.com", "SVCB"): ['1 mcp.example.com. alpn="mcp"']})

    agent = await _query(resolver)

    assert agent is not None
    assert agent.target_host == "mcp.example.com"
