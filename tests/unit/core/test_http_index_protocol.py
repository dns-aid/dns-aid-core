# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""HTTP index protocol selection with real DNS parsing and no network (#277)."""

import dns.asyncresolver
import dns.message
import dns.rdatatype
import dns.resolver
import dns.rrset
import httpx
import pytest

from dns_aid import discover
from dns_aid.core.discoverer import DNSSECError

ENDPOINT = "https://example.com/openapi.json"
CAPABILITIES = ["clinic-info", "services", "promotions", "prices", "callback-request"]


@pytest.fixture
def index_network(monkeypatch):
    """Mock only DNS/HTTP I/O; keep index, SVCB and discovery logic real."""
    entry = {
        "location": {"fqdn": "public-api.example.com", "endpoint": ENDPOINT},
        "capability": {"protocols": ["https"], "capabilities": CAPABILITIES},
    }
    state = {
        "entries": {"public-api": entry},
        "entry": entry,
        "rrtype": "HTTPS",
        "params": "",
        "dns_present": True,
        "dns_queries": [],
        "http_requests": [],
    }
    monkeypatch.delenv("DNS_AID_LEGACY_01_FALLBACK", raising=False)

    async def resolve(_self, qname, rdtype="A", *args, **kwargs):
        name = str(qname).rstrip(".").lower()
        kind = rdtype.upper() if isinstance(rdtype, str) else dns.rdatatype.to_text(rdtype)
        state["dns_queries"].append((name, kind))
        if name == "_index._agents.example.com" and kind == "TXT":
            text = '"agents=public-api:https"'
        elif state["dns_present"] and name == "public-api.example.com" and kind == state["rrtype"]:
            text = "1 example.com. " + state["params"]
        else:
            raise dns.resolver.NoAnswer()
        query = dns.message.make_query(name + ".", kind)
        response = dns.message.make_response(query)
        response.answer.append(dns.rrset.from_text(name + ".", 300, "IN", kind, text))
        response = dns.message.from_wire(response.to_wire())
        return dns.resolver.Answer(
            query.question[0].name, dns.rdatatype.from_text(kind), 1, response
        )

    def respond(request):
        state["http_requests"].append(str(request.url))
        if str(request.url) == "https://example.com/.well-known/agents-index.json":
            return httpx.Response(200, json=state["entries"])
        return httpx.Response(404)

    real_client = httpx.AsyncClient

    def client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(respond)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", resolve)
    monkeypatch.setattr(httpx, "AsyncClient", client)
    return state


@pytest.mark.parametrize("rrtype", ["SVCB", "HTTPS"])
@pytest.mark.parametrize(
    ("protocols", "expected"),
    [
        (["https"], "https"),
        (["mcp"], "mcp"),
        (["a2a"], "a2a"),
        (["https", "mcp"], "https"),
        (["mcp", "https"], "mcp"),
        (["HTTPS"], "https"),
        (["openapi", "https"], "https"),
        (["unknown", "https"], "https"),
        ([None, 42, "", "mcp"], "mcp"),
        ([None, "a2a"], "a2a"),
        (["", "HTTPS"], "https"),
        (["unknown", "mcp", "https"], "mcp"),
        (["unknown", "https", "mcp"], "https"),
    ],
)
async def test_first_supported_declared_protocol(index_network, rrtype, protocols, expected):
    index_network["rrtype"] = rrtype
    index_network["entry"]["capability"]["protocols"] = protocols
    result = await discover("example.com", use_http_index=True, enrich_endpoints=False)
    assert len(result.agents) == 1
    agent = result.agents[0]
    assert agent.protocol.value == expected
    assert agent.fqdn == "public-api.example.com"
    assert agent.endpoint_url == ENDPOINT
    assert agent.capabilities == CAPABILITIES
    assert agent.endpoint_source == "dns_svcb_enriched"
    assert agent.capability_source == "http_index"
    assert ("public-api.example.com", rrtype) in index_network["dns_queries"]


@pytest.mark.parametrize("rrtype", ["SVCB", "HTTPS"])
@pytest.mark.parametrize("caller", [None, "mcp"])
async def test_unknown_primary_uses_next_supported_protocol(index_network, rrtype, caller):
    index_network["rrtype"] = rrtype
    index_network["entry"]["capability"]["protocols"] = ["openapi", "mcp"]
    result = await discover(
        "example.com", protocol=caller, use_http_index=True, enrich_endpoints=False
    )
    assert ("public-api.example.com", rrtype) in index_network["dns_queries"], (
        result.agents,
        index_network["dns_queries"],
    )
    assert [agent.protocol.value for agent in result.agents] == ["mcp"]
    assert result.agents[0].endpoint_source == "dns_svcb_enriched"


@pytest.mark.parametrize("caller", ["https", "mcp", "a2a"])
async def test_caller_filter_against_https_only(index_network, caller):
    result = await discover(
        "example.com", protocol=caller, use_http_index=True, enrich_endpoints=False
    )
    assert [a.protocol.value for a in result.agents] == (["https"] if caller == "https" else [])
    if result.agents:
        assert result.agents[0].endpoint_url == ENDPOINT
        assert result.agents[0].capabilities == CAPABILITIES
    else:
        assert not any(
            qname == "public-api.example.com" for qname, _ in index_network["dns_queries"]
        )


@pytest.mark.parametrize(
    "protocols",
    [["https", "mcp"], ["mcp", "https"], ["openapi", "mcp"], ["unknown", "https"]],
)
@pytest.mark.parametrize("caller", ["https", "mcp", "a2a"])
@pytest.mark.parametrize("dns_present", [True, False])
async def test_filter_selects_declared_member(index_network, protocols, caller, dns_present):
    index_network["entry"]["capability"]["protocols"] = protocols
    index_network["dns_present"] = dns_present
    result = await discover(
        "example.com", protocol=caller, use_http_index=True, enrich_endpoints=False
    )
    assert [a.protocol.value for a in result.agents] == ([caller] if caller in protocols else [])
    if caller not in protocols:
        assert not any(
            qname == "public-api.example.com" for qname, _ in index_network["dns_queries"]
        )


@pytest.mark.parametrize("missing", [True, False])
@pytest.mark.parametrize("caller", [None, "https"])
async def test_undeclared_protocol_keeps_existing_fallback(index_network, missing, caller):
    capability = index_network["entry"]["capability"]
    if missing:
        capability.pop("protocols")
    else:
        capability["protocols"] = []
    result = await discover(
        "example.com", protocol=caller, use_http_index=True, enrich_endpoints=False
    )
    assert [a.protocol.value for a in result.agents] == [caller or "mcp"]


@pytest.mark.parametrize("protocols", [["unknown"], [42], [None], [""], [None, 42, "", "unknown"]])
@pytest.mark.parametrize("dns_present", [True, False])
async def test_unsupported_protocols_are_not_invented(index_network, protocols, dns_present):
    index_network["entry"]["capability"]["protocols"] = protocols
    index_network["dns_present"] = dns_present
    result = await discover("example.com", use_http_index=True, enrich_endpoints=False)
    assert result.agents == []
    assert not any(qname == "public-api.example.com" for qname, _ in index_network["dns_queries"])


@pytest.mark.parametrize("protocols", [["https"], ["openapi", "https"]])
@pytest.mark.parametrize("params", ['alpn="mcp"', 'key65402="mcp=1.0" alpn="https"'])
@pytest.mark.parametrize("caller", [None, "https"])
async def test_dns_protocol_remains_authoritative(index_network, protocols, params, caller):
    index_network["entry"]["capability"]["protocols"] = protocols
    index_network["params"] = params
    result = await discover(
        "example.com", protocol=caller, use_http_index=True, enrich_endpoints=False
    )
    assert [a.protocol.value for a in result.agents] == (["mcp"] if caller is None else [])


async def test_txt_enumeration_and_https65_unchanged(index_network):
    result = await discover("example.com", enrich_endpoints=False)
    assert len(result.agents) == 1
    agent = result.agents[0]
    assert agent.protocol.value == "https"
    assert agent.endpoint_url == "https://example.com:443"
    assert agent.capabilities == []
    assert agent.endpoint_source == "dns_svcb"
    assert agent.capability_source == "none"
    assert index_network["http_requests"] == []


@pytest.mark.parametrize(
    ("protocols", "expected"),
    [
        (["https"], "https"),
        (["openapi", "https"], "https"),
        ([None, 42, "", "mcp", "https"], "mcp"),
        (["unknown", "a2a"], "a2a"),
    ],
)
async def test_http_only_fallback_retains_provenance(index_network, protocols, expected):
    index_network["entry"]["capability"]["protocols"] = protocols
    index_network["dns_present"] = False
    result = await discover("example.com", use_http_index=True, enrich_endpoints=False)
    assert len(result.agents) == 1
    assert result.agents[0].protocol.value == expected
    assert result.agents[0].endpoint_source == "http_index_fallback"
    assert result.agents[0].capability_source == "http_index"
    assert result.agents[0].endpoint_url == ENDPOINT
    assert result.agents[0].capabilities == CAPABILITIES
    assert index_network["dns_queries"].count(("public-api.example.com", "SVCB")) == 1
    assert index_network["dns_queries"].count(("public-api.example.com", "HTTPS")) == 1


@pytest.mark.parametrize("protocols", [["https"], ["openapi", "https", "https"]])
async def test_duplicate_candidate_deduplicated(index_network, protocols):
    index_network["entry"]["capability"]["protocols"] = protocols
    index_network["entries"]["duplicate"] = index_network["entry"]
    result = await discover("example.com", use_http_index=True, enrich_endpoints=False)
    assert len(result.agents) == 1
    assert result.agents[0].protocol.value == "https"


@pytest.mark.parametrize("fqdn", ["public-api._agents.example.com", "public-api.example.com."])
@pytest.mark.parametrize("protocols", [["https"], ["openapi", "https"]])
async def test_walkable_and_absolute_fqdn(index_network, fqdn, protocols):
    index_network["entry"]["capability"]["protocols"] = protocols
    index_network["entry"]["location"]["fqdn"] = fqdn
    result = await discover("example.com", use_http_index=True, enrich_endpoints=False)
    assert [a.protocol.value for a in result.agents] == ["https"]
    assert result.agents[0].endpoint_source == "dns_svcb_enriched"


@pytest.mark.parametrize("caller", [None, "a2a", "mcp"])
async def test_legacy_fqdn_protocol_precedes_declarations(index_network, caller):
    index_network["entry"]["location"]["fqdn"] = "_public-api._a2a._agents.example.com"
    index_network["entry"]["capability"]["protocols"] = ["openapi", "mcp"]
    result = await discover(
        "example.com", protocol=caller, use_http_index=True, enrich_endpoints=False
    )
    assert [agent.protocol.value for agent in result.agents] == ([] if caller == "mcp" else ["a2a"])
    if caller == "mcp":
        assert not any(
            qname == "public-api.example.com" for qname, _ in index_network["dns_queries"]
        )


async def test_scalar_protocol_accepted_by_existing_parser(index_network):
    index_network["entry"]["capability"]["protocols"] = "https"
    result = await discover("example.com", use_http_index=True, enrich_endpoints=False)
    assert [a.protocol.value for a in result.agents] == ["https"]


async def test_enrichment_does_not_bypass_dnssec(index_network):
    with pytest.raises(DNSSECError):
        await discover(
            "example.com", use_http_index=True, enrich_endpoints=False, require_dnssec=True
        )


async def test_enrichment_does_not_bypass_signature_filter(index_network):
    result = await discover(
        "example.com", use_http_index=True, enrich_endpoints=False, require_signed=True
    )
    assert result.agents == []
