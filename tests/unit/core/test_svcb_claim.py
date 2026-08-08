# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""The signature must cover every parameter the record carries.

The payload originally bound only fqdn, target, port and alpn. cap, cap-sha256,
policy, realm and well-known sat outside it, so an attacker spoofing an unsigned
zone could replay a genuine signature verbatim, keep the endpoint tuple
byte-identical, and swap the capability pointer and its digest for a document of
their own. The record still reported verified, and the capability fetch then
digest-checked the attacker's document against the attacker's digest.

Coverage is reported rather than assumed: a record signed before the claim
existed still verifies, with signature_covers_params False.
"""

from unittest.mock import AsyncMock, patch

import pytest

from dns_aid.core.discoverer import _verify_agent_signatures
from dns_aid.core.jwks import (
    SIGNED_PARAM_FIELDS,
    RecordPayload,
    SignatureStatus,
    export_jwks,
    generate_keypair,
    params_from_record,
    sign_record,
    svcb_digest,
)
from dns_aid.core.models import DNS_AID_KEY_MAP, AgentRecord, Protocol

PARAMS = {
    "cap": "https://real.example.com/agent-card.json",
    "cap-sha256": "a" * 64,
    "bap": None,
    "policy": None,
    "realm": "prod",
    "connect-class": None,
    "connect-meta": None,
    "enroll-uri": None,
    "well-known": "agent-card.json",
}


def _record(sig, *, cap=PARAMS["cap"], sha=PARAMS["cap-sha256"], realm="prod"):
    return AgentRecord(
        name="a",
        domain="example.com",
        protocol=Protocol.MCP,
        target_host="t.example.com",
        port=443,
        sig=sig,
        cap_uri=cap,
        cap_sha256=sha,
        realm=realm,
        well_known_path="agent-card.json",
    )


@pytest.fixture
def keys():
    return generate_keypair()


async def _verify(agent, pub):
    with patch("dns_aid.core.jwks.fetch_jwks", new=AsyncMock(return_value=export_jwks(pub))):
        await _verify_agent_signatures([agent], "example.com")
    return agent


def _sign(priv, params=PARAMS):
    return sign_record(
        RecordPayload.from_agent_record(
            "a.example.com", "t.example.com", 443, "mcp", params=params
        ),
        priv,
    )


class TestEveryParamIsCovered:
    def test_no_svcparam_is_left_outside_the_signature(self):
        """A new key must not reach records without a coverage decision."""
        expected = set(DNS_AID_KEY_MAP) - {"sig"}

        assert set(SIGNED_PARAM_FIELDS) == expected, (
            "DNS_AID_KEY_MAP and SIGNED_PARAM_FIELDS have drifted; a parameter "
            "is either signed or it is forgeable, and this is where that is decided"
        )

    def test_every_mapped_field_exists_on_the_record(self):
        agent = _record(None)

        for name, field in SIGNED_PARAM_FIELDS.items():
            assert hasattr(agent, field), f"{name} maps to missing field {field}"


class TestDigest:
    def test_ordering_does_not_change_the_digest(self):
        a = {"cap": "x", "realm": "y"}
        b = {"realm": "y", "cap": "x"}

        assert svcb_digest(a) == svcb_digest(b)

    def test_absent_is_the_same_as_not_carried(self):
        assert svcb_digest({"cap": "x", "realm": None}) == svcb_digest({"cap": "x"})

    def test_empty_is_distinct_from_absent(self):
        """Collapsing them let an attacker inject realm="" into a record whose
        publisher never set it, without breaking the claim."""
        assert svcb_digest({"cap": "x", "realm": ""}) != svcb_digest({"cap": "x"})

    def test_a_changed_value_changes_the_digest(self):
        assert svcb_digest({"cap": "x"}) != svcb_digest({"cap": "y"})

    def test_the_record_round_trips(self):
        agent = _record(None)

        assert svcb_digest(params_from_record(agent)) == svcb_digest(PARAMS)


class TestReplayIsRefused:
    @pytest.mark.asyncio
    async def test_an_untouched_record_verifies_with_coverage(self, keys):
        priv, pub = keys
        agent = await _verify(_record(_sign(priv)), pub)

        assert agent.signature_status == SignatureStatus.VERIFIED
        assert agent.signature_verified is True
        assert agent.signature_covers_params is True

    @pytest.mark.asyncio
    async def test_swapping_the_capability_pointer_breaks_the_binding(self, keys):
        """The attack: genuine signature, endpoint tuple identical, cap swapped."""
        priv, pub = keys
        genuine = _sign(priv)

        agent = await _verify(
            _record(genuine, cap="https://attacker.example/evil.json", sha="b" * 64), pub
        )

        assert agent.signature_verified is False
        assert agent.signature_status == SignatureStatus.UNBOUND
        assert agent.signature_covers_params is False

    @pytest.mark.asyncio
    async def test_swapping_the_realm_breaks_the_binding(self, keys):
        priv, pub = keys

        agent = await _verify(_record(_sign(priv), realm="not-prod"), pub)

        assert agent.signature_verified is False
        assert agent.signature_status == SignatureStatus.UNBOUND


class TestLegacyRecordsStillVerify:
    @pytest.mark.asyncio
    async def test_a_record_signed_before_the_claim_still_verifies(self, keys):
        """Records already published must not stop verifying on upgrade."""
        priv, pub = keys
        legacy = sign_record(
            RecordPayload.from_agent_record("a.example.com", "t.example.com", 443, "mcp"), priv
        )

        agent = await _verify(_record(legacy), pub)

        assert agent.signature_verified is True, "an existing record must not stop verifying"
        assert agent.signature_status == SignatureStatus.VERIFIED_ENDPOINT_ONLY, (
            "it verified, but no surface should call an unattested capability "
            "pointer plainly 'verified' -- the attacker picks which signature to "
            "replay, so they pick one without the claim"
        )

    @pytest.mark.asyncio
    async def test_but_its_reduced_coverage_is_reported(self, keys):
        """A consumer has to be able to tell the capability pointer is unattested."""
        priv, pub = keys
        legacy = sign_record(
            RecordPayload.from_agent_record("a.example.com", "t.example.com", 443, "mcp"), priv
        )

        agent = await _verify(_record(legacy, cap="https://anything.example/x.json"), pub)

        assert agent.signature_verified is True
        assert agent.signature_covers_params is False

    def test_a_payload_without_the_claim_serialises_unchanged(self):
        """Byte-identical, or every already-published signature stops verifying."""
        import json

        p = RecordPayload(
            fqdn="a.example.com", target="t.example.com", port=443, alpn="mcp", iat=1, exp=2
        )

        assert "svcb" not in json.loads(p.to_json())


class TestRequireSignedParamsGate:
    """Opt-in, because every record published before the claim is endpoint-only.

    Requiring coverage by default would stop matching everything currently in
    DNS. Requiring nothing leaves the capability-pointer replay open on those
    same records. The gate lets a deployment close it once its publishers have
    re-signed, and is planned to become the default in 0.30.0.
    """

    @staticmethod
    def _verified(covers):
        agent = _record("x")
        agent.signature_verified = True
        agent.signature_algorithm = "ES256"
        agent.signature_covers_params = covers
        return agent

    def test_endpoint_only_is_refused_unless_explicitly_allowed(self):
        from dns_aid.core.filters import _matches_signed

        assert _matches_signed(self._verified(False), True, None, True) is False
        assert _matches_signed(self._verified(False), True, None, False) is True

    def test_on_it_refuses_endpoint_only_coverage(self):
        from dns_aid.core.filters import _matches_signed

        assert _matches_signed(self._verified(False), True, None, True) is False

    def test_on_it_admits_a_fully_covered_record(self):
        from dns_aid.core.filters import _matches_signed

        assert _matches_signed(self._verified(True), True, None, True) is True

    def test_it_is_inert_without_require_signed(self):
        """A sub-condition, not a peer. On by default, so it must not fire alone."""
        from dns_aid.core.filters import apply_filters

        rec = self._verified(False)

        assert apply_filters([rec], require_signed_params=True) == [rec]

    def test_endpoint_only_passes_until_the_gate_is_asked_for(self):
        """Default off, and deliberately so: the order is re-sign, then flip.

        Flipping before publishers re-sign returns zero agents for every record
        published today. The insecure state is never silent -- those records
        report VERIFIED_ENDPOINT_ONLY, render amber, and are named in a warning.
        """
        from dns_aid.core.filters import apply_filters

        assert apply_filters([self._verified(False)], require_signed=True) != []
        assert (
            apply_filters([self._verified(False)], require_signed=True, require_signed_params=True)
            == []
        )


class TestTheMigrationPathActuallyWorks:
    """Re-signing must produce a record that satisfies the gate.

    The gate defaults off because every record published before the claim reports
    endpoint-only coverage. That trade is only defensible if re-signing genuinely
    fixes it, so the publish-to-verify round trip is pinned here rather than
    assumed.
    """

    @pytest.mark.asyncio
    async def test_publish_sign_then_verify_yields_full_coverage(self, tmp_path, monkeypatch):
        import base64
        import json

        from cryptography.hazmat.primitives import serialization

        from dns_aid.core.filters import apply_filters
        from dns_aid.core.publisher import publish

        priv, pub = generate_keypair()
        key_path = tmp_path / "signing.pem"
        key_path.write_bytes(
            priv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        monkeypatch.setenv("DNS_AID_BACKEND", "mock")

        result = await publish(
            name="ddi-agent",
            domain="example.com",
            protocol="mcp",
            endpoint="edge.example.com",
            port=443,
            cap_uri="https://edge.example.com/.well-known/agent-card.json",
            realm="production",
            well_known_path="agent-card.json",
            sign=True,
            private_key_path=str(key_path),
        )

        assert result.success
        record = result.agent
        assert record.sig is not None

        payload = json.loads(base64.urlsafe_b64decode(record.sig.split(".")[1] + "=="))
        assert "svcb" in payload, "a freshly signed record must carry the claim"

        record.signature_status = None
        record.signature_verified = None
        with patch("dns_aid.core.jwks.fetch_jwks", new=AsyncMock(return_value=export_jwks(pub))):
            await _verify_agent_signatures([record], "example.com")

        assert record.signature_status == SignatureStatus.VERIFIED
        assert record.signature_covers_params is True
        assert apply_filters([record], require_signed=True, require_signed_params=True) == [
            record
        ], "re-signing must be a real remedy, not a nominal one"
