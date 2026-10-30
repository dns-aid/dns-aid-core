"""A2A 1.0 cards must contribute their endpoint.

1.0 removed the top-level ``url`` from ``AgentCard`` and made
``supportedInterfaces`` the required carrier of every endpoint
(``a2a.proto``, ``AgentCard`` field 3). The card object has parsed that list
since 0.3 support landed, but nothing read it back, so a conformant 1.0 card
resolved to whatever the *caller* already had -- the catalog domain on the ARD
path, the bare SVCB origin on the DNS path. These tests pin the read.
"""

from __future__ import annotations

from dns_aid.core.a2a_card import A2AAgentCard, A2AInterface, A2ASkill
from dns_aid.core.discoverer import _apply_agent_card
from dns_aid.core.models import AgentRecord, Protocol

CARD_1_0 = {
    "name": "Example Agent",
    "description": "Minimal conformant A2A 1.0 card.",
    "version": "1.0.0",
    "supportedInterfaces": [
        {
            "url": "https://agent.example.com/a2a",
            "protocolBinding": "JSONRPC",
            "protocolVersion": "1.0",
        }
    ],
    "capabilities": {"streaming": False},
    "defaultInputModes": ["application/json"],
    "defaultOutputModes": ["application/json"],
    "skills": [{"id": "example", "name": "Example", "description": "x", "tags": ["example"]}],
}


def _record(target_host: str = "agent.example.com") -> AgentRecord:
    return AgentRecord(
        name="agent",
        domain="example.com",
        protocol=Protocol.A2A,
        target_host=target_host,
        port=443,
    )


class TestEndpointFor:
    def test_conformant_1_0_card_resolves_through_the_interface_list(self):
        """The shape the current spec mandates: no url, one interface."""
        card = A2AAgentCard.from_dict(CARD_1_0)

        assert card.url == "", "1.0 cards carry no top-level url"
        assert card.endpoint_for() == "https://agent.example.com/a2a"

    def test_top_level_url_wins_when_present(self):
        """0.2/0.3 cards keep resolving exactly as before."""
        card = A2AAgentCard(
            name="a",
            url="https://agent.example.com/legacy",
            interfaces=[A2AInterface(url="https://agent.example.com/a2a")],
        )

        assert card.endpoint_for() == "https://agent.example.com/legacy"

    def test_preferred_binding_selects_its_interface(self):
        card = A2AAgentCard(
            name="a",
            url="",
            interfaces=[
                A2AInterface(url="https://agent.example.com/grpc", protocol_binding="GRPC"),
                A2AInterface(url="https://agent.example.com/a2a", protocol_binding="JSONRPC"),
            ],
        )

        assert card.endpoint_for("JSONRPC") == "https://agent.example.com/a2a"
        assert card.endpoint_for("jsonrpc") == "https://agent.example.com/a2a"

    def test_unmatched_binding_falls_back_to_the_first_entry(self):
        """`a2a.proto`: the list is ordered and the first entry is preferred."""
        card = A2AAgentCard(
            name="a",
            url="",
            interfaces=[
                A2AInterface(url="https://agent.example.com/grpc", protocol_binding="GRPC"),
                A2AInterface(url="https://agent.example.com/rest", protocol_binding="HTTP+JSON"),
            ],
        )

        assert card.endpoint_for("JSONRPC") == "https://agent.example.com/grpc"

    def test_no_https_anywhere_resolves_to_none(self):
        card = A2AAgentCard(
            name="a",
            url="http://agent.example.com",
            interfaces=[A2AInterface(url="http://agent.example.com/a2a")],
        )

        assert card.endpoint_for() is None


class TestApplyAgentCardUsesInterfaces:
    def test_interface_on_the_dns_host_becomes_the_endpoint(self):
        agent = _record()
        card = A2AAgentCard.from_dict(CARD_1_0)

        _apply_agent_card(agent, card)

        assert agent.endpoint_override == "https://agent.example.com/a2a"
        assert agent.endpoint_source == "dns_svcb_enriched"

    def test_off_host_interface_is_not_followed(self):
        """DNS says *where*; the card only says *which path*.

        An interface on another host is an internal runtime URL or a
        redirection the DNS owner never signed for.
        """
        agent = _record()
        card = A2AAgentCard.from_dict(
            {**CARD_1_0, "supportedInterfaces": [{"url": "https://internal.aws.example/a2a"}]}
        )

        _apply_agent_card(agent, card)

        assert agent.endpoint_override is None
        assert agent.endpoint_url == "https://agent.example.com:443"

    def test_dns_aid_endpoints_block_still_wins(self):
        """No regression: the `endpoints` convention keeps precedence."""
        agent = _record()
        card = A2AAgentCard.from_dict(CARD_1_0)
        card.metadata["endpoints"] = {"a2a": "/from-metadata"}

        _apply_agent_card(agent, card)

        assert agent.endpoint_override == "https://agent.example.com:443/from-metadata"

    def test_skills_still_become_capabilities(self):
        """The endpoint read must not disturb the rest of enrichment."""
        agent = _record()
        card = A2AAgentCard(
            name="a",
            url="",
            interfaces=[A2AInterface(url="https://agent.example.com/a2a")],
            skills=[A2ASkill(id="payments", name="Payments", description="", tags=[])],
        )

        _apply_agent_card(agent, card)

        assert agent.capabilities == ["payments"]
        assert agent.capability_source == "agent_card"
