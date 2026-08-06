# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""The signature outcome must be reachable from all three interfaces.

Verifying a record is only half the job. If the result cannot be *seen*, an
operator running ``--require-signed`` gets an empty list with no way to learn
whether the signatures had merely lapsed or had genuinely failed -- and those
two call for different responses.

The CLI is the interface that needed work: its ``--json`` payload is a
hand-built dict rather than ``model_dump()``, so every new ``AgentRecord``
field is invisible until someone adds a line. That is the same defect shape as
the ``sig`` extraction this branch fixes, in a second location, which is why it
is pinned by tests here rather than left to review.
"""

import json
from unittest.mock import AsyncMock, patch

import pytest
from typer.testing import CliRunner

from dns_aid.cli.main import _format_dane, _format_dnssec, _format_signature, app
from dns_aid.core.jwks import SignatureStatus
from dns_aid.core.models import AgentRecord, DiscoveryResult, Protocol

runner = CliRunner()


def _agent(status: str | None, verified: bool | None, sig: str | None = "a.b.c") -> AgentRecord:
    return AgentRecord(
        name="ddi-agent",
        domain="agents.example.com",
        protocol=Protocol.A2A,
        target_host="edge.example.com",
        port=443,
        sig=sig,
        signature_verified=verified,
        signature_status=status,
        signature_algorithm="ES256" if status == "verified" else None,
    )


def _result(agent: AgentRecord) -> DiscoveryResult:
    return DiscoveryResult(
        domain="agents.example.com",
        query="_index._agents.agents.example.com",
        agents=[agent],
        count=1,
        query_time_ms=1.0,
    )


def _run_discover(agent: AgentRecord, *args: str):
    with patch(
        "dns_aid.core.discoverer.discover",
        new=AsyncMock(return_value=_result(agent)),
    ):
        return runner.invoke(app, ["discover", "agents.example.com", *args])


class TestSdkSurface:
    """The SDK hands back AgentRecord, so the fields are attributes."""

    def test_record_exposes_the_signature_outcome(self):
        agent = _agent("expired", False)

        assert agent.sig == "a.b.c"
        assert agent.signature_verified is False
        assert agent.signature_status == "expired"


class TestMcpSurface:
    """MCP builds its agent payload by hand, so assert on the real output.

    An earlier version of this test asserted on ``AgentRecord.model_dump()``
    and passed while the MCP tool was in fact emitting nothing. The tool
    constructs its own dict, so ``model_dump`` proves only that the model has
    the field, not that a caller ever receives it. That is the same
    mock-the-seam mistake that let the ``sig`` defect ship, so the payload is
    now driven end to end.
    """

    def _payload(self, agent: AgentRecord) -> dict:
        from dns_aid.mcp.server import discover_agents_via_dns

        fn = getattr(discover_agents_via_dns, "fn", discover_agents_via_dns)
        with patch(
            "dns_aid.core.discoverer.discover",
            new=AsyncMock(return_value=_result(agent)),
        ):
            return fn(domain="agents.example.com", verify_signatures=True)

    def test_payload_carries_every_signature_field(self):
        entry = self._payload(_agent("verified", True))["agents"][0]

        for field in ("sig", "signature_verified", "signature_status", "signature_algorithm"):
            assert field in entry, f"{field} never reaches the MCP caller"
        assert entry["signature_status"] == "verified"
        assert entry["signature_verified"] is True

    def test_payload_distinguishes_unknown_from_rejected(self):
        entry = self._payload(_agent("no_key", None))["agents"][0]

        assert entry["signature_status"] == "no_key"
        assert entry["signature_verified"] is None

    def test_payload_for_unsigned_records_is_unchanged(self):
        entry = self._payload(_agent(None, None, sig=None))["agents"][0]

        for field in ("sig", "signature_verified", "signature_status", "signature_algorithm"):
            assert field not in entry, f"{field} leaked into the payload for an unsigned record"

    def test_discover_tool_accepts_verify_signatures(self):
        """Verification must be requestable without also filtering.

        With only ``require_signed`` an agent could ask "drop anything
        unverified" but never "tell me the status and let me decide".
        """
        import inspect

        from dns_aid.mcp.server import discover_agents_via_dns

        fn = getattr(discover_agents_via_dns, "fn", discover_agents_via_dns)
        params = inspect.signature(fn).parameters
        assert "verify_signatures" in params
        assert params["verify_signatures"].default is False


class TestCliJsonSurface:
    """--json is hand-built, so each field is asserted explicitly."""

    def test_json_reports_status_when_verification_ran(self):
        result = _run_discover(_agent("expired", False), "--verify-signatures", "--json")

        assert result.exit_code == 0, result.output
        payload = json.loads(result.output[result.output.index("{") :])
        entry = payload["agents"][0]

        assert entry["signature_status"] == "expired"
        assert entry["signature_verified"] is False
        assert entry["sig"] == "a.b.c"

    def test_json_distinguishes_unknown_from_rejected(self):
        """``no_key`` must not be reported as a rejected signature."""
        result = _run_discover(_agent("no_key", None), "--verify-signatures", "--json")

        entry = json.loads(result.output[result.output.index("{") :])["agents"][0]

        assert entry["signature_status"] == "no_key"
        assert entry["signature_verified"] is None

    def test_json_for_unsigned_records_is_unchanged(self):
        """Legacy output stays byte-identical when nothing was verified."""
        result = _run_discover(_agent(None, None, sig=None), "--json")

        entry = json.loads(result.output[result.output.index("{") :])["agents"][0]

        for field in ("sig", "signature_verified", "signature_status", "signature_algorithm"):
            assert field not in entry, f"{field} leaked into output for an unsigned record"


class TestCliTableSurface:
    def test_signature_column_appears_when_verifying(self):
        result = _run_discover(_agent("verified", True), "--verify-signatures")

        assert "Signature" in result.output
        assert "verified" in result.output

    def test_no_signature_column_without_verification(self):
        """Default output is untouched for callers who never asked."""
        result = _run_discover(_agent(None, None, sig=None))

        assert "Signature" not in result.output

    def test_empty_result_under_require_signed_explains_itself(self):
        """The most confusing case: records found, then dropped by the gate."""
        empty = DiscoveryResult(
            domain="agents.example.com", query="q", agents=[], count=0, query_time_ms=1.0
        )
        with patch("dns_aid.core.discoverer.discover", new=AsyncMock(return_value=empty)):
            result = runner.invoke(app, ["discover", "agents.example.com", "--require-signed"])

        assert "require-signed" in result.output
        assert "dropped" in result.output


class TestSignatureFormatting:
    """Every status renders, and the actionable ones read differently."""

    @pytest.mark.parametrize(
        "status,expected",
        [
            (SignatureStatus.VERIFIED, "verified"),
            (SignatureStatus.EXPIRED, "re-publish"),
            (SignatureStatus.INVALID, "invalid"),
            (SignatureStatus.UNBOUND, "does not match"),
            (SignatureStatus.NO_KEY, "no JWKS"),
            (SignatureStatus.NOT_SIGNED, "unsigned"),
        ],
    )
    def test_each_status_has_its_own_wording(self, status, expected):
        rendered = _format_signature(_agent(str(status), None))

        assert expected in rendered

    def test_expired_and_invalid_do_not_read_the_same(self):
        """Both are False. Only one is fixed by re-publishing."""
        expired = _format_signature(_agent("expired", False))
        invalid = _format_signature(_agent("invalid", False))

        assert expired != invalid

    def test_unverified_record_renders_without_error(self):
        assert _format_signature(_agent(None, None, sig=None)) == "[dim]-[/dim]"


class TestTrustReporting:
    """DNSSEC and DANE must be reportable, and must not overclaim.

    Both were previously invisible on the CLI: ``dnssec_validated`` was never
    emitted at all and ``dane_verified`` only when non-None. A caller could see
    a verified signature and nothing about the two anchors underneath it.
    """

    def _agent_with(self, dnssec, dane):
        a = _agent(None, None, sig=None)
        a.dnssec_validated = dnssec
        a.dane_verified = dane
        return a

    def test_fields_absent_when_the_check_did_not_run(self):
        """Absence means not checked, so it can never read as a failure."""
        result = _run_discover(self._agent_with(False, None), "--json")
        entry = json.loads(result.output[result.output.index("{") :])["agents"][0]

        assert "dnssec_validated" not in entry
        assert "dane_verified" not in entry

    def test_fields_present_once_the_check_ran(self):
        result = _run_discover(self._agent_with(True, True), "--verify-dane", "--json")
        entry = json.loads(result.output[result.output.index("{") :])["agents"][0]

        assert entry["dnssec_validated"] is True
        assert entry["dane_verified"] is True

    def test_demoted_dane_is_reported_as_null_not_omitted(self):
        """None is the meaningful answer, not a reason to stay silent.

        Without a DNSSEC-validated chain a TLSA match is demoted to unknown
        (RFC 6698 section 10.1). Omitting the field made that indistinguishable
        from no TLSA record existing.
        """
        result = _run_discover(self._agent_with(False, None), "--verify-dane", "--json")
        entry = json.loads(result.output[result.output.index("{") :])["agents"][0]

        assert "dane_verified" in entry
        assert entry["dane_verified"] is None

    def test_unvalidated_dnssec_does_not_claim_the_zone_is_unsigned(self):
        """False follows the AD bit, which a non-validating resolver never sets.

        Rendering it as "no" asserted the zone was unsigned when the far more
        common cause is the caller's own resolver.
        """
        rendered = _format_dnssec(False)

        assert "unvalidated" in rendered
        assert "no" not in rendered.replace("unvalidated", "")

    def test_dnssec_states_are_distinct(self):
        assert "validated" in _format_dnssec(True)
        assert _format_dnssec(True) != _format_dnssec(False)
        assert "not checked" in _format_dnssec(None)

    def test_dane_false_is_a_real_negative(self):
        """Unlike DNSSEC, a False DANE means a TLSA existed and did not match."""
        assert "no match" in _format_dane(False)
        assert "unknown" in _format_dane(None)
        assert "verified" in _format_dane(True)

    def test_table_explains_why_records_are_unvalidated(self):
        result = _run_discover(self._agent_with(False, None), "--verify-dane")

        assert "unvalidated" in result.output
        assert "resolver" in result.output
