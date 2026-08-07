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

    def test_payload_carries_the_signature_outcome(self):
        entry = self._payload(_agent("verified", True))["agents"][0]

        for field in ("signature_verified", "signature_status", "signature_algorithm"):
            assert field in entry, f"{field} never reaches the MCP caller"
        assert entry["signature_status"] == "verified"
        assert entry["signature_verified"] is True

    def test_payload_omits_the_raw_jws(self):
        """The blob costs context and carries nothing a model can act on.

        ``signature_status`` already reports the outcome, and re-verifying the
        JWS would mean re-fetching the JWKS the server just checked. The CLI
        ``--json`` payload still carries it, where a script may want the
        artefact itself.
        """
        entry = self._payload(_agent("verified", True))["agents"][0]

        assert "sig" not in entry

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


class TestDnssecEvidence:
    """RRSIG evidence separates an unsigned zone from a non-validating resolver.

    ``dnssec_validated=False`` alone cannot say whether the zone owner never
    signed, or the caller's own resolver refuses to validate a zone that is
    signed. Those have opposite owners and opposite fixes.

    The safety property matters more than the feature: seeing an RRSIG proves
    the zone signs records, never that *this* answer is authentic, since an
    attacker able to spoof an answer can spoof an RRSIG beside it. So it must
    stay strictly diagnostic.
    """

    def _agent_with(self, validated, signed):
        a = _agent(None, None, sig=None)
        a.dnssec_validated = validated
        a.dnssec_signed = signed
        return a

    def test_signed_zone_behind_a_lazy_resolver_says_so(self):
        rendered = _format_dnssec(False, signed=True)

        assert "unvalidated" in rendered
        assert "resolver" in rendered

    def test_genuinely_unsigned_zone_says_so(self):
        rendered = _format_dnssec(False, signed=False)

        assert "unvalidated" in rendered
        assert "unsigned" in rendered

    def test_the_two_causes_do_not_render_alike(self):
        assert _format_dnssec(False, signed=True) != _format_dnssec(False, signed=False)

    def test_no_evidence_falls_back_to_the_plain_label(self):
        assert _format_dnssec(False, signed=None) == "[yellow]unvalidated[/yellow]"

    def test_validated_is_unaffected_by_the_evidence(self):
        assert "validated" in _format_dnssec(True, signed=False)
        assert "unvalidated" not in _format_dnssec(True, signed=False)

    def test_evidence_never_relaxes_the_trust_gate(self):
        """A signed-but-unvalidated zone must still fail require_dnssec.

        This is the property that keeps the signal safe: if dnssec_signed ever
        fed the trust decision, an attacker could spoof an RRSIG and be treated
        as validated.
        """
        from dns_aid.core.filters import apply_filters

        agent = self._agent_with(validated=False, signed=True)

        assert apply_filters([agent], min_dnssec=True) == []

    def test_json_and_mcp_agree_on_the_evidence(self):
        agent = self._agent_with(validated=False, signed=True)

        cli = json.loads(
            _run_discover(agent, "--verify-dane", "--json").output[
                _run_discover(agent, "--verify-dane", "--json").output.index("{") :
            ]
        )["agents"][0]

        from dns_aid.mcp.server import discover_agents_via_dns

        fn = getattr(discover_agents_via_dns, "fn", discover_agents_via_dns)
        with patch(
            "dns_aid.core.discoverer.discover",
            new=AsyncMock(return_value=_result(agent)),
        ):
            mcp = fn(domain="agents.example.com", verify_dane=True)["agents"][0]

        assert cli["dnssec_signed"] is True
        assert mcp["dnssec_signed"] is True
        assert cli["dnssec_validated"] == mcp["dnssec_validated"] is False


class TestDnssecSkipIsNotAFailure:
    """Asking for both strong guarantees at once must not return nothing.

    JWS verification is skipped for a DNSSEC-validated record: the DNS chain
    already authenticates it and JWS exists as the fallback for zones that
    cannot sign. Skipping is right, and --require-signed together with DNSSEC
    returning zero agents was not.

    The first fix let the skip satisfy the gate. That was wrong in both
    directions. DNSSEC here is the AD flag with no chain validation, so an
    attacker forging answers for an unsigned zone could set AD=1, attach a
    garbage sig, and pass with no cryptography performed. And a skip carries no
    algorithm, so require_signature_algorithm dropped every agent.

    The skip is an optimisation, never a substitute. When the caller demands a
    signature, discovery verifies it, and the record passes on its own merits.
    """

    def _signed(self, dnssec: bool, with_sig: bool = True):
        from dns_aid.core.jwks import RecordPayload, generate_keypair, sign_record

        priv, pub = generate_keypair()
        self._pub = pub
        sig = sign_record(
            RecordPayload.from_agent_record(
                "a.example.com", "t.example.com", 443, "mcp", validity_seconds=90 * 86400
            ),
            priv,
        )
        a = AgentRecord(
            name="a",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="t.example.com",
            port=443,
            sig=sig if with_sig else None,
        )
        a.dnssec_validated = dnssec
        return a

    async def _verified(self, agent):
        from dns_aid.core.discoverer import _verify_agent_signatures

        await _verify_agent_signatures(
            [agent], "example.com", dnssec_validated=agent.dnssec_validated
        )
        return agent

    async def _verify(self, agent, *, skip: bool):
        """skip=False is what discovery does when the caller demanded a signature."""
        from unittest.mock import AsyncMock, patch

        from dns_aid.core.discoverer import _verify_agent_signatures
        from dns_aid.core.jwks import export_jwks

        with patch(
            "dns_aid.core.jwks.fetch_jwks",
            new=AsyncMock(return_value=export_jwks(self._pub)),
        ):
            await _verify_agent_signatures(
                [agent],
                "example.com",
                dnssec_validated=(agent.dnssec_validated if skip else {}),
            )
        return agent

    @pytest.mark.asyncio
    async def test_skip_is_labelled_not_left_blank(self):
        agent = await self._verified(self._signed(dnssec=True))

        assert agent.signature_status == SignatureStatus.SKIPPED_DNSSEC

    @pytest.mark.asyncio
    async def test_require_signed_verifies_rather_than_trusting_the_skip(self):
        """The record passes because its signature verified, not because it skipped."""
        from dns_aid.core.filters import _matches_signed

        agent = self._signed(dnssec=True)
        # require_signature=True is what discovery passes when the caller asked
        # for a signature: the skip map is empty, so JWS runs.
        await self._verify(agent, skip=False)

        # Signed without params, so the endpoint tuple is all that is attested.
        assert agent.signature_status == SignatureStatus.VERIFIED_ENDPOINT_ONLY
        assert agent.signature_verified is True
        assert agent.signature_algorithm == "ES256"
        assert _matches_signed(agent, require=True, allowed_algorithms=None) is True

    @pytest.mark.asyncio
    async def test_require_signature_algorithm_survives_a_dnssec_zone(self):
        """A skip populates no algorithm, so this returned nothing on a signed zone."""
        from dns_aid.core.filters import _matches_signed

        agent = self._signed(dnssec=True)
        await self._verify(agent, skip=False)

        assert _matches_signed(agent, require=True, allowed_algorithms=["ES256"]) is True

    @pytest.mark.asyncio
    async def test_a_skip_alone_never_satisfies_the_gate(self):
        """The security half: a spoofable AD bit is not a signature.

        DNSSEC validation here is the AD flag with no chain validation. If a skip
        could satisfy require_signed, an attacker who can forge DNS for an
        unsigned zone -- exactly the adversary JWS defends against -- would set
        AD=1, attach anything at all, and pass.
        """
        from dns_aid.core.filters import _matches_signed

        agent = self._signed(dnssec=True)
        await self._verify(agent, skip=True)

        assert agent.signature_status == SignatureStatus.SKIPPED_DNSSEC
        assert agent.signature_verified is None
        assert _matches_signed(agent, require=True, allowed_algorithms=None) is False

    @pytest.mark.asyncio
    async def test_an_unsigned_record_on_a_signed_zone_is_still_not_signed(self):
        from dns_aid.core.filters import _matches_signed

        agent = self._signed(dnssec=True, with_sig=False)
        await self._verify(agent, skip=True)

        assert _matches_signed(agent, require=True, allowed_algorithms=None) is False


class TestExpiryIsSurfacedBeforeItBites:
    """A signature is valid until the moment it is not, with no prior signal."""

    def _agent_expiring_in(self, days: int):
        import time

        a = _agent("verified", True)
        a.signature_expires_at = int(time.time()) + days * 86400
        return a

    def test_remaining_window_is_shown(self):
        # Fractional time.time() means a 60-day window floors to 59.
        rendered = _format_signature(self._agent_expiring_in(60))

        assert "d left" in rendered
        assert "59d left" in rendered or "60d left" in rendered

    def test_approaching_expiry_asks_for_a_re_publish(self):
        rendered = _format_signature(self._agent_expiring_in(5))

        assert "re-publish" in rendered
        assert "yellow" in rendered

    def test_a_comfortable_window_is_not_alarming(self):
        rendered = _format_signature(self._agent_expiring_in(60))

        assert "re-publish" not in rendered
        assert "green" in rendered

    def test_expiry_reaches_the_json_payload(self):
        agent = self._agent_expiring_in(60)
        out = _run_discover(agent, "--verify-signatures", "--json").output
        entry = json.loads(out[out.index("{") :])["agents"][0]

        assert entry["signature_expires_at"] == agent.signature_expires_at


class TestEveryEmittedFieldIsDocumented:
    """For an MCP tool the docstring is the schema a model sees.

    A field the tool emits but never documents is invisible to the consumer,
    which is the same failure mode as a field that is documented but never
    emitted. Both halves are hand-maintained here, so they are diffed rather
    than trusted -- the same tripwire DNS_AID_KEY_MAP has in
    test_svcb_param_coverage.
    """

    def _documented_agent_fields(self) -> set[str]:
        import inspect
        import re

        from dns_aid.mcp.server import discover_agents_via_dns

        fn = getattr(discover_agents_via_dns, "fn", discover_agents_via_dns)
        doc = inspect.getdoc(fn) or ""
        returns = doc.split("Returns:", 1)[-1]
        # Agent fields are the deeper-indented bullets under "agents:".
        agents_block = returns.split("- agents:", 1)[-1].split("- count:", 1)[0]
        return set(re.findall(r"^\s+- (\w+):", agents_block, re.M))

    def _emitted_agent_fields(self) -> set[str]:
        from dns_aid.mcp.server import discover_agents_via_dns

        fn = getattr(discover_agents_via_dns, "fn", discover_agents_via_dns)
        agent = _agent("verified", True)
        agent.dnssec_validated = True
        agent.dnssec_signed = True
        agent.dane_verified = True
        agent.signature_expires_at = 1_900_000_000
        agent.cap_uri = "https://example.com/cap.json"
        agent.cap_sha256 = "abc"
        agent.well_known_path = "agent-card.json"
        agent.bap = "mcp"
        agent.policy_uri = "https://example.com/policy.json"
        agent.realm = "production"
        agent.description = "an agent"

        with patch(
            "dns_aid.core.discoverer.discover",
            new=AsyncMock(return_value=_result(agent)),
        ):
            payload = fn(
                domain="agents.example.com",
                verify_signatures=True,
                verify_dane=True,
                min_dnssec=True,
            )
        return set(payload["agents"][0].keys())

    def test_no_emitted_field_is_undocumented(self):
        undocumented = self._emitted_agent_fields() - self._documented_agent_fields()

        assert not undocumented, f"emitted but invisible to the model: {sorted(undocumented)}"

    def test_the_raw_jws_stays_out_of_the_payload(self):
        assert "sig" not in self._emitted_agent_fields()


class TestCliSigValidityIsRejectedAtTheBoundary:
    """Reject in the CLI rather than letting the library raise a bare ValueError."""

    def _publish(self, *args):
        return runner.invoke(
            app,
            [
                "publish",
                "--name",
                "x",
                "--domain",
                "example.com",
                "--protocol",
                "mcp",
                "--endpoint",
                "e.example.com",
                *args,
            ],
            env={"DNS_AID_BACKEND": "mock"},
        )

    def test_sig_validity_without_sign_is_rejected(self):
        result = self._publish("--sig-validity", "7776000")

        assert result.exit_code == 1
        assert "--sig-validity requires --sign" in result.output

    def test_below_the_minimum_is_rejected_with_the_range(self):
        result = self._publish("--sign", "--private-key", "/tmp/k.pem", "--sig-validity", "60")

        assert result.exit_code == 1
        assert "3600" in result.output and "34128000" in result.output

    def test_above_the_maximum_is_rejected(self):
        result = self._publish(
            "--sign", "--private-key", "/tmp/k.pem", "--sig-validity", "99999999"
        )

        assert result.exit_code == 1
        assert "must be between" in result.output


class TestExpiryRenderingEdges:
    """Verification is binary until it is not, so the window must read honestly."""

    def _at(self, days: float):
        import time as _t

        a = _agent("verified", True)
        a.signature_expires_at = int(_t.time() + days * 86400)
        return a

    def test_a_comfortable_window_is_green(self):
        assert "green" in _format_signature(self._at(60))

    def test_inside_the_warning_threshold_is_amber(self):
        assert "re-publish" in _format_signature(self._at(10))

    def test_a_lapsed_window_never_reads_as_valid(self):
        """A negative countdown previously rendered as verified in amber."""
        rendered = _format_signature(self._at(-1))

        assert "expired" in rendered
        assert "left" not in rendered

    def test_epoch_zero_is_not_silently_dropped(self):
        a = _agent("verified", True)
        a.signature_expires_at = 0

        assert "expired" in _format_signature(a)
