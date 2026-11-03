# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Discovery at an owner that publishes more than one agent protocol.

draft-02 §3.1.1 puts one SVCB record per protocol in the RRset at the flat
owner. The reported protocol must follow the request and SvcPriority, not
the order the resolver rotates the RRset into (finding F17).
"""

from __future__ import annotations

import itertools
from unittest.mock import AsyncMock, MagicMock, patch

import dns.rdata
import dns.resolver
import pytest

from dns_aid.core.discoverer import (
    _discover_agents_in_zone,
    _query_owner_agents,
    _query_single_agent,
    _select_service_rdatas,
    discover,
)
from dns_aid.core.indexer import IndexEntry
from dns_aid.core.models import Protocol

A2A = dns.rdata.from_text("IN", "SVCB", '1 a2a.example.com. alpn="a2a" port=443')
MCP = dns.rdata.from_text("IN", "SVCB", '2 mcp.example.com. alpn="mcp" port=443')
WEBMCP = dns.rdata.from_text(
    "IN", "SVCB", '3 site.example.com. alpn="https" port=443 key65402="webmcp"'
)
FOREIGN = dns.rdata.from_text("IN", "SVCB", '1 site.example.com. alpn="h2" port=443 key65420="a2a"')


def _resolver(svcb_by_name: dict[str, list]) -> MagicMock:
    async def resolve(qname, rdtype, *args, **kwargs):
        name = str(qname).rstrip(".")
        if rdtype == "SVCB" and name in svcb_by_name:
            return list(svcb_by_name[name])
        raise dns.resolver.NoAnswer()

    resolver = MagicMock()
    resolver.resolve = AsyncMock(side_effect=resolve)
    return resolver


def _patched(svcb_by_name: dict[str, list]):
    mod = patch("dns_aid.core.discoverer.dns.asyncresolver")
    return mod, _resolver(svcb_by_name)


class TestSelectServiceRdatas:
    @pytest.mark.parametrize("order", list(itertools.permutations([A2A, MCP])))
    def test_matching_protocol_wins_in_any_order(self, order):
        assert _select_service_rdatas(list(order), Protocol.MCP, all_protocols=False) == [MCP]
        assert _select_service_rdatas(list(order), Protocol.A2A, all_protocols=False) == [A2A]

    @pytest.mark.parametrize("order", list(itertools.permutations([A2A, MCP])))
    def test_no_match_falls_back_to_lowest_priority(self, order):
        assert _select_service_rdatas(list(order), Protocol.HTTPS, all_protocols=False) == [A2A]

    @pytest.mark.parametrize("order", list(itertools.permutations([A2A, MCP, FOREIGN])))
    def test_record_naming_no_protocol_does_not_shadow_probe(self, order):
        # FOREIGN (alpn h2, priority 1) names no protocol; it must not stand
        # in for mcp when a real mcp record (priority 2) exists.
        picked = _select_service_rdatas(list(order), Protocol.MCP, all_protocols=True)
        assert picked == [A2A, MCP]
        single = _select_service_rdatas(list(order), Protocol.MCP, all_protocols=False)
        assert single == [MCP]

    @pytest.mark.parametrize("order", [[FOREIGN, A2A], [A2A, FOREIGN]])
    def test_record_naming_no_protocol_used_when_nothing_else(self, order):
        assert _select_service_rdatas(order, Protocol.MCP, all_protocols=True) == [A2A, FOREIGN]
        assert _select_service_rdatas(order, Protocol.MCP, all_protocols=False) == [FOREIGN]

    def test_all_protocols_keeps_one_per_protocol(self):
        a2a_backup = dns.rdata.from_text("IN", "SVCB", '5 backup.example.com. alpn="a2a"')
        picked = _select_service_rdatas([a2a_backup, MCP, A2A], Protocol.MCP, all_protocols=True)
        assert picked == [A2A, MCP]


class TestQuerySingleAgentMultiProtocol:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("order", [[A2A, MCP], [MCP, A2A]])
    async def test_protocol_follows_request_not_rrset_order(self, order):
        mod, resolver = _patched({"concessions.example.com": order})
        with mod as mock_mod, patch("dns_aid.core.discoverer._query_capabilities", return_value=[]):
            mock_mod.Resolver.return_value = resolver
            mcp = await _query_single_agent("example.com", "concessions", Protocol.MCP)
            a2a = await _query_single_agent("example.com", "concessions", Protocol.A2A)
        assert mcp is not None and mcp.protocol == Protocol.MCP
        assert mcp.target_host == "mcp.example.com"
        assert a2a is not None and a2a.protocol == Protocol.A2A
        assert a2a.target_host == "a2a.example.com"

    @pytest.mark.asyncio
    async def test_unpublished_protocol_returns_lowest_priority(self):
        # Backward compatible: the probe is a placeholder when the owner
        # has nothing for it, and the record's own protocol is reported.
        mod, resolver = _patched({"concessions.example.com": [MCP, A2A]})
        with mod as mock_mod, patch("dns_aid.core.discoverer._query_capabilities", return_value=[]):
            mock_mod.Resolver.return_value = resolver
            agent = await _query_single_agent("example.com", "concessions", Protocol.HTTPS)
        assert agent is not None and agent.protocol == Protocol.A2A

    @pytest.mark.asyncio
    async def test_owner_agents_returns_every_protocol(self):
        mod, resolver = _patched({"concessions.example.com": [MCP, WEBMCP, A2A]})
        with mod as mock_mod, patch("dns_aid.core.discoverer._query_capabilities", return_value=[]):
            mock_mod.Resolver.return_value = resolver
            agents = await _query_owner_agents("example.com", "concessions", Protocol.MCP)
        # webmcp is not a Protocol we model, so it reconciles to its alpn (https).
        assert [a.protocol for a in agents] == [Protocol.A2A, Protocol.MCP, Protocol.HTTPS]
        assert agents[2].bap == "webmcp"

    @pytest.mark.asyncio
    async def test_alias_mode_followed_for_every_protocol(self):
        alias = dns.rdata.from_text("IN", "SVCB", "0 concessions.example.com.")
        mod, resolver = _patched({"c.example.com": [alias], "concessions.example.com": [MCP, A2A]})
        with mod as mock_mod, patch("dns_aid.core.discoverer._query_capabilities", return_value=[]):
            mock_mod.Resolver.return_value = resolver
            agents = await _query_owner_agents("example.com", "c", Protocol.MCP)
        assert sorted(a.protocol.value for a in agents) == ["a2a", "mcp"]


class TestZoneWalkMultiProtocol:
    @pytest.mark.asyncio
    async def test_one_record_per_protocol_even_if_index_names_one(self):
        mod, resolver = _patched({"concessions.example.com": [MCP, A2A]})
        with (
            mod as mock_mod,
            patch("dns_aid.core.discoverer._query_capabilities", return_value=[]),
            patch(
                "dns_aid.core.indexer.read_index_via_dns",
                AsyncMock(return_value=[IndexEntry(name="concessions", protocol="a2a")]),
            ),
        ):
            mock_mod.Resolver.return_value = resolver
            agents = await _discover_agents_in_zone("example.com")
            only_mcp = await _discover_agents_in_zone("example.com", Protocol.MCP)
            only_https = await _discover_agents_in_zone("example.com", Protocol.HTTPS)
        assert [a.protocol for a in agents] == [Protocol.A2A, Protocol.MCP]
        assert [a.protocol for a in only_mcp] == [Protocol.MCP]
        assert only_https == []

    @pytest.mark.asyncio
    async def test_index_listing_both_protocols_not_duplicated(self):
        mod, resolver = _patched({"concessions.example.com": [MCP, A2A]})
        with (
            mod as mock_mod,
            patch("dns_aid.core.discoverer._query_capabilities", return_value=[]),
            patch(
                "dns_aid.core.indexer.read_index_via_dns",
                AsyncMock(
                    return_value=[
                        IndexEntry(name="concessions", protocol="a2a"),
                        IndexEntry(name="concessions", protocol="mcp"),
                    ]
                ),
            ),
        ):
            mock_mod.Resolver.return_value = resolver
            agents = await _discover_agents_in_zone("example.com")
        assert sorted(a.protocol.value for a in agents) == ["a2a", "mcp"]

    @pytest.mark.asyncio
    async def test_discover_name_and_protocol(self):
        mod, resolver = _patched({"concessions.example.com": [A2A, MCP]})
        with mod as mock_mod, patch("dns_aid.core.discoverer._query_capabilities", return_value=[]):
            mock_mod.Resolver.return_value = resolver
            result = await discover(
                "example.com", protocol="mcp", name="concessions", enrich_endpoints=False
            )
        assert [a.protocol for a in result.agents] == [Protocol.MCP]
