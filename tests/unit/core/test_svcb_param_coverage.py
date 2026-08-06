# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""SVCB SvcParam extraction coverage on the DNS discovery path.

Regression net for a defect class rather than a single bug: the SVCB parser
derives its recognised key set from ``DNS_AID_KEY_MAP`` (single source of
truth), but the *extraction* below it was a hand-maintained list of
``custom_params.get(...)`` calls. A key added to the map therefore parsed
correctly into the intermediate dict and then silently failed to reach
``AgentRecord`` -- which is exactly how ``sig`` (key65405) was published by
``publish --sign`` for several releases while no consumer could read it back
over DNS.

``test_every_svcb_param_reaches_the_record`` fails if any future key repeats
that. The remaining tests cover the ``sig`` round trip specifically.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import dns.name
import pytest

from dns_aid.core.models import DNS_AID_KEY_MAP, Protocol

# Every DNS-AID SvcParam name -> the AgentRecord field it must populate.
# Kept explicit (not derived) so that adding a key to DNS_AID_KEY_MAP forces a
# deliberate decision here rather than silently widening the contract.
SVCB_PARAM_TO_FIELD = {
    "cap": "cap_uri",
    "cap-sha256": "cap_sha256",
    "bap": "bap",
    "policy": "policy_uri",
    "realm": "realm",
    "sig": "sig",
    "connect-class": "connect_class",
    "connect-meta": "connect_meta",
    "enroll-uri": "enroll_uri",
    "well-known": "well_known_path",
}

SAMPLE_VALUES = {
    "cap": "https://mcp.example.com/.well-known/agent-cap.json",
    "cap-sha256": "dGVzdGhhc2g",
    "bap": "mcp",
    "policy": "https://example.com/.well-known/agent-policy.json",
    "realm": "production",
    "sig": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcWRuIjoiYSJ9.c2lnbmF0dXJl",
    "connect-class": "direct",
    "connect-meta": "region=eu",
    "enroll-uri": "https://example.com/.well-known/agent-connect",
    "well-known": "agent-card.json",
}


def _svcb_rdata(param_text: str):
    """A mock SVCB rdata whose str() is what the parser actually reads."""
    rdata = MagicMock()
    rdata.target = dns.name.from_text("mcp.example.com.")
    rdata.priority = 1
    rdata.port = 443
    rdata.params = {}
    rdata.__str__ = lambda self: f'1 mcp.example.com. alpn="mcp" port="443" {param_text}'
    return rdata


async def _discover_with(param_text: str):
    """Run the real SVCB parse path over the given SvcParams."""
    answers = MagicMock()
    answers.__iter__ = lambda self: iter([_svcb_rdata(param_text)])

    resolver = MagicMock()
    resolver.resolve = AsyncMock(return_value=answers)

    with (
        patch(
            "dns_aid.core.discoverer.dns.asyncresolver.Resolver",
            return_value=resolver,
        ),
        # Descriptor fetching is out of scope here; the parse path is under test.
        patch(
            "dns_aid.core.discoverer.fetch_cap_document",
            new_callable=AsyncMock,
            return_value=None,
        ),
    ):
        from dns_aid.core.discoverer import _query_single_agent

        return await _query_single_agent("example.com", "booking", Protocol.MCP)


class TestSvcParamCoverage:
    """Every recognised SvcParam must survive the trip into AgentRecord."""

    def test_field_map_covers_every_known_key(self):
        """The map below must track DNS_AID_KEY_MAP exactly.

        Fails when a SvcParamKey is added to the protocol without a decision
        being recorded here -- the tripwire that makes the next test meaningful.
        """
        assert set(SVCB_PARAM_TO_FIELD) == set(DNS_AID_KEY_MAP), (
            "DNS_AID_KEY_MAP and SVCB_PARAM_TO_FIELD have diverged; a new "
            "SvcParam must be mapped to the AgentRecord field it populates."
        )
        assert set(SAMPLE_VALUES) == set(DNS_AID_KEY_MAP)

    @pytest.mark.asyncio
    async def test_every_svcb_param_reaches_the_record(self):
        """Parse a record carrying every param; none may be dropped.

        This is the guard that would have caught the ``sig`` gap: the parser
        decoded key65405 correctly, but no extraction assigned it to the record.
        """
        param_text = " ".join(f'{name}="{SAMPLE_VALUES[name]}"' for name in SVCB_PARAM_TO_FIELD)

        agent = await _discover_with(param_text)

        assert agent is not None
        dropped = [
            name
            for name, field in SVCB_PARAM_TO_FIELD.items()
            if getattr(agent, field, None) in (None, "", [])
        ]
        assert not dropped, f"SvcParams parsed but never assigned to AgentRecord: {dropped}"

    @pytest.mark.asyncio
    async def test_every_svcb_param_reaches_the_record_numeric_form(self):
        """Same guarantee via RFC 9460 keyNNNNN form, which is what is on the wire."""
        param_text = " ".join(
            f'{DNS_AID_KEY_MAP[name]}="{SAMPLE_VALUES[name]}"' for name in SVCB_PARAM_TO_FIELD
        )

        agent = await _discover_with(param_text)

        assert agent is not None
        dropped = [
            name
            for name, field in SVCB_PARAM_TO_FIELD.items()
            if getattr(agent, field, None) in (None, "", [])
        ]
        assert not dropped, f"SvcParams parsed but never assigned to AgentRecord: {dropped}"


class TestSigRoundTrip:
    """``sig`` (key65405) specifically -- the parameter that was being dropped."""

    @pytest.mark.asyncio
    async def test_sig_parsed_from_numeric_key(self):
        """key65405 on the wire lands on AgentRecord.sig."""
        agent = await _discover_with(f'key65405="{SAMPLE_VALUES["sig"]}"')

        assert agent is not None
        assert agent.sig == SAMPLE_VALUES["sig"]

    @pytest.mark.asyncio
    async def test_sig_parsed_from_string_name(self):
        """The human-readable ``sig=`` form is equally accepted."""
        agent = await _discover_with(f'sig="{SAMPLE_VALUES["sig"]}"')

        assert agent is not None
        assert agent.sig == SAMPLE_VALUES["sig"]

    @pytest.mark.asyncio
    async def test_record_without_sig_leaves_field_none(self):
        """Absence stays absent -- no accidental default."""
        agent = await _discover_with('realm="production"')

        assert agent is not None
        assert agent.sig is None
        assert agent.realm == "production"

    @pytest.mark.asyncio
    async def test_publish_serialise_reparse_preserves_sig(self):
        """Full write->read round trip through the publisher's own serialisation.

        ``to_svcb_params()`` is what the backends write; parsing its output back
        is the loop that was never closed and that let the gap ship.
        """
        from dns_aid.core.models import AgentRecord

        published = AgentRecord(
            name="booking",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="mcp.example.com",
            port=443,
            sig=SAMPLE_VALUES["sig"],
        )
        params = published.to_svcb_params()
        assert params["key65405"] == SAMPLE_VALUES["sig"], "publisher must emit key65405"

        param_text = " ".join(f'{k}="{v}"' for k, v in params.items() if k.startswith("key"))
        parsed = await _discover_with(param_text)

        assert parsed is not None
        assert parsed.sig == published.sig
