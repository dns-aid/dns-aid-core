# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for dns_aid.experimental.edns_hint — wire format encode/decode."""

from __future__ import annotations

import pytest

from dns_aid.experimental.edns_hint import (
    AGENT_HINT_OPTION_CODE,
    AXIS1_RANGE,
    AXIS2_RANGE,
    AgentHint,
    AgentHintEcho,
    EdnsSignalingAdvertisement,
    HintSelector,
    decode_agent_hint,
    decode_agent_hint_echo,
)

# ---------------------------------------------------------------------------
# Constants & taxonomy
# ---------------------------------------------------------------------------


def test_option_code_in_private_use_range():
    """Sanity check: chosen option code is in RFC 6891 private-use range."""
    assert 65001 <= AGENT_HINT_OPTION_CODE <= 65534


def test_axis1_selectors_in_axis1_range():
    """Substrate-filter selectors live in 0x01–0x0F."""
    axis1 = {
        HintSelector.REALM,
        HintSelector.TRANSPORT,
        HintSelector.POLICY_REQUIRED,
        HintSelector.MIN_TRUST,
        HintSelector.JURISDICTION,
    }
    for sel in axis1:
        assert sel.value in AXIS1_RANGE, f"{sel.name} ({sel.value:#x}) not in Axis 1 range"


def test_axis2_selectors_in_axis2_range():
    """Metering/lifecycle selectors live in 0x10–0x1F."""
    axis2 = {
        HintSelector.CLIENT_INTENT_CLASS,
        HintSelector.MAX_AGE,
        HintSelector.PARALLELISM,
        HintSelector.DEADLINE_MS,
    }
    for sel in axis2:
        assert sel.value in AXIS2_RANGE, f"{sel.name} ({sel.value:#x}) not in Axis 2 range"


# ---------------------------------------------------------------------------
# AgentHint encode / decode — Axis 1 (substrate filters)
# ---------------------------------------------------------------------------


def test_agent_hint_round_trip_all_axis1():
    hint = AgentHint(
        realm="prod-tenant-42",
        transport="mcp",
        policy_required=True,
        min_trust="signed+dnssec",
        jurisdiction="eu",
    )
    decoded = decode_agent_hint(hint.encode())
    assert decoded.realm == "prod-tenant-42"
    assert decoded.transport == "mcp"
    assert decoded.policy_required is True
    assert decoded.min_trust == "signed+dnssec"
    assert decoded.jurisdiction == "eu"


def test_agent_hint_policy_required_false_not_on_wire():
    """policy_required=False is the default — absence must mean 'don't care', not 'forbid'."""
    payload = AgentHint(realm="prod", policy_required=False).encode()
    decoded = decode_agent_hint(payload)
    assert decoded.policy_required is False
    # Wire payload should NOT carry the policy_required selector at all.
    # version(1) + count(1) + realm-header(2) + "prod"(4) = 8 bytes
    assert len(payload) == 8


def test_agent_hint_policy_required_true_emits_value_1():
    payload = AgentHint(policy_required=True).encode()
    decoded = decode_agent_hint(payload)
    assert decoded.policy_required is True


def test_agent_hint_partial_axis1():
    hint = AgentHint(transport="a2a")
    decoded = decode_agent_hint(hint.encode())
    assert decoded.transport == "a2a"
    assert decoded.realm is None
    assert decoded.min_trust is None


def test_agent_hint_utf8_value_round_trip():
    """Selector values are UTF-8 — non-ASCII survives the round trip."""
    hint = AgentHint(realm="résumé-prod-📝")
    decoded = decode_agent_hint(hint.encode())
    assert decoded.realm == "résumé-prod-📝"


# ---------------------------------------------------------------------------
# AgentHint encode / decode — Axis 2 (metering / lifecycle)
# ---------------------------------------------------------------------------


def test_agent_hint_round_trip_all_axis2():
    hint = AgentHint(
        client_intent_class="invocation",
        max_age=300,
        parallelism=4,
        deadline_ms=30000,
    )
    decoded = decode_agent_hint(hint.encode())
    assert decoded.client_intent_class == "invocation"
    assert decoded.max_age == 300
    assert decoded.parallelism == 4
    assert decoded.deadline_ms == 30000


def test_agent_hint_axis2_numeric_zero_round_trip():
    """Zero is a valid value (means 'don't tolerate any stale cache')."""
    hint = AgentHint(max_age=0, parallelism=0, deadline_ms=0)
    decoded = decode_agent_hint(hint.encode())
    assert decoded.max_age == 0
    assert decoded.parallelism == 0
    assert decoded.deadline_ms == 0


def test_agent_hint_axis2_rejects_negative_at_model_layer():
    """Pydantic field constraint (ge=0) rejects negatives before encode is even reached."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        AgentHint(max_age=-1)
    with pytest.raises(ValidationError):
        AgentHint(deadline_ms=-100)


# ---------------------------------------------------------------------------
# AgentHint — combined Axis 1 + Axis 2
# ---------------------------------------------------------------------------


def test_agent_hint_combined_axes_round_trip():
    hint = AgentHint(
        realm="prod",
        transport="mcp",
        min_trust="signed",
        client_intent_class="invocation",
        deadline_ms=5000,
    )
    decoded = decode_agent_hint(hint.encode())
    assert decoded.realm == "prod"
    assert decoded.transport == "mcp"
    assert decoded.min_trust == "signed"
    assert decoded.client_intent_class == "invocation"
    assert decoded.deadline_ms == 5000


def test_agent_hint_empty_hint_encodes_to_header_only():
    """An AgentHint with nothing set encodes to just (version, count=0)."""
    payload = AgentHint().encode()
    assert payload == bytes([0x00, 0x00])
    decoded = decode_agent_hint(payload)
    # All fields default to None / False
    assert decoded.realm is None
    assert decoded.transport is None
    assert decoded.policy_required is False
    assert decoded.max_age is None


# ---------------------------------------------------------------------------
# AgentHint encode / decode — error paths
# ---------------------------------------------------------------------------


def test_agent_hint_selector_value_too_long_rejected():
    """Selector value over 255 bytes UTF-8 must be rejected at encode."""
    hint = AgentHint(realm="x" * 256)
    with pytest.raises(ValueError, match="max is 255"):
        hint.encode()


def test_agent_hint_decode_rejects_truncated_header():
    with pytest.raises(ValueError, match="too short"):
        decode_agent_hint(b"\x00")


def test_agent_hint_decode_rejects_echo_bit_set():
    """A payload with echo bit must be routed to decode_agent_hint_echo, not decode_agent_hint."""
    echo_payload = bytes([0x80, 0x00])
    with pytest.raises(ValueError, match="echo bit set"):
        decode_agent_hint(echo_payload)


def test_agent_hint_decode_rejects_unknown_version():
    """Version bits 0–6 are the version number; non-zero rejected in v0."""
    payload = bytes([0x01, 0x00])  # version 1, no selectors
    with pytest.raises(ValueError, match="unsupported"):
        decode_agent_hint(payload)


def test_agent_hint_decode_rejects_truncated_selector_header():
    payload = bytes([0x00, 0x01, 0x01])  # claims 1 selector, has only 1B of its 2B header
    with pytest.raises(ValueError, match="truncated mid-selector header"):
        decode_agent_hint(payload)


def test_agent_hint_decode_rejects_truncated_selector_value():
    """Selector header says length=10 but only 3 bytes follow."""
    payload = bytes(
        [0x00, 0x01, HintSelector.REALM.value, 0x0A, 0x61, 0x62, 0x63]
    )  # claims 10-byte realm, has 3
    with pytest.raises(ValueError, match="truncated mid-selector value"):
        decode_agent_hint(payload)


def test_agent_hint_decode_silently_drops_unknown_selectors():
    """Forward-compat: future selector codes must be skipped, not rejected."""
    # version=0, count=2, selector(0xFE, "x"), selector(REALM, "prod")
    payload = bytes(
        [0x00, 0x02] + [0xFE, 0x01, ord("x")] + [HintSelector.REALM.value, 4] + list(b"prod")
    )
    decoded = decode_agent_hint(payload)
    assert decoded.realm == "prod"


def test_agent_hint_decode_rejects_invalid_utf8():
    payload = bytes(
        [0x00, 0x01, HintSelector.REALM.value, 0x02, 0xFF, 0xFE]
    )  # 0xFF 0xFE is not valid UTF-8
    with pytest.raises(ValueError, match="UTF-8"):
        decode_agent_hint(payload)


def test_agent_hint_decode_rejects_garbage_numeric_field():
    """Axis 2 numeric fields must fail closed on non-decimal input."""
    payload = bytes([0x00, 0x01, HintSelector.MAX_AGE.value, 0x03] + list(b"abc"))
    with pytest.raises(ValueError, match="decimal integer"):
        decode_agent_hint(payload)


# ---------------------------------------------------------------------------
# Adversarial regression: first-wins on duplicate selector codes
# (Mirrors the DCV _parse_txt_value pattern — last-wins is exploitable
#  via a hostile forwarder appending overriding selectors.)
# ---------------------------------------------------------------------------


def test_decode_first_wins_on_duplicate_axis1_string():
    """Duplicate realm selector: the FIRST occurrence wins."""
    payload = (
        bytes([0x00, 0x02])
        + bytes([HintSelector.REALM.value, 4])
        + b"prod"
        + bytes([HintSelector.REALM.value, 4])
        + b"evil"
    )
    decoded = decode_agent_hint(payload)
    assert decoded.realm == "prod"


def test_decode_first_wins_on_duplicate_axis2_numeric():
    """Duplicate max_age: first wins (5 seconds, not 999999)."""
    payload = (
        bytes([0x00, 0x02])
        + bytes([HintSelector.MAX_AGE.value, 1])
        + b"5"
        + bytes([HintSelector.MAX_AGE.value, 6])
        + b"999999"
    )
    decoded = decode_agent_hint(payload)
    assert decoded.max_age == 5


def test_decode_first_wins_on_duplicate_policy_required():
    """Hostile forwarder cannot flip policy_required by appending an override."""
    # First emits the True flavor, second tries to override with anything-not-"1".
    payload = (
        bytes([0x00, 0x02])
        + bytes([HintSelector.POLICY_REQUIRED.value, 1])
        + b"1"
        + bytes([HintSelector.POLICY_REQUIRED.value, 1])
        + b"0"
    )
    decoded = decode_agent_hint(payload)
    assert decoded.policy_required is True


# ---------------------------------------------------------------------------
# Adversarial regression: empty Axis-1 string values treated as field-not-set
# (Defense-in-depth: encode side already skips empty strings; decode must
#  agree so a forged empty-value payload cannot fragment the cache key.)
# ---------------------------------------------------------------------------


def test_decode_empty_realm_treated_as_none():
    """Forged payload with realm="" must decode to realm=None, not realm=""."""
    payload = bytes([0x00, 0x01, HintSelector.REALM.value, 0x00])  # zero-length value
    decoded = decode_agent_hint(payload)
    assert decoded.realm is None


def test_decode_empty_string_selectors_all_treated_as_none():
    """All str-typed Axis-1 and the Axis-2 string field treat empty as not-set."""
    payload = (
        bytes([0x00, 0x05])
        + bytes([HintSelector.REALM.value, 0x00])
        + bytes([HintSelector.TRANSPORT.value, 0x00])
        + bytes([HintSelector.MIN_TRUST.value, 0x00])
        + bytes([HintSelector.JURISDICTION.value, 0x00])
        + bytes([HintSelector.CLIENT_INTENT_CLASS.value, 0x00])
    )
    decoded = decode_agent_hint(payload)
    assert decoded.realm is None
    assert decoded.transport is None
    assert decoded.min_trust is None
    assert decoded.jurisdiction is None
    assert decoded.client_intent_class is None


def test_decode_empty_value_does_not_fragment_signature():
    """Forged empty-value payload and the no-realm-at-all payload share a signature.

    Encode side skips empty strings (`if self.realm:`); decode side must agree
    so an attacker cannot construct a cache key under a value the legitimate
    client would never produce.
    """
    empty_payload = bytes([0x00, 0x01, HintSelector.REALM.value, 0x00])
    no_realm_payload = bytes([0x00, 0x00])
    assert (
        decode_agent_hint(empty_payload).signature()
        == decode_agent_hint(no_realm_payload).signature()
        == ""
    )


# ---------------------------------------------------------------------------
# AgentHint.signature() — cache-key semantics
# ---------------------------------------------------------------------------


def test_signature_includes_axis1_only():
    """Two queries differing only in Axis 2 fields must share a cache key.

    This is the load-bearing design invariant: metering (parallelism, deadline,
    intent_class, max_age) does NOT change what answer set you get — it only
    changes policy applied to the request — so it MUST NOT fragment the cache.
    """
    h1 = AgentHint(realm="prod", transport="mcp", parallelism=4, deadline_ms=5000)
    h2 = AgentHint(realm="prod", transport="mcp", parallelism=64, deadline_ms=1)
    assert h1.signature() == h2.signature()


def test_signature_changes_with_axis1():
    """Different Axis 1 values → different signatures → different cache entries."""
    assert AgentHint(realm="prod").signature() != AgentHint(realm="staging").signature()
    assert AgentHint(transport="mcp").signature() != AgentHint(transport="a2a").signature()
    assert (
        AgentHint(policy_required=False).signature() != AgentHint(policy_required=True).signature()
    )


def test_signature_is_deterministic():
    h1 = AgentHint(realm="prod", min_trust="signed")
    h2 = AgentHint(realm="prod", min_trust="signed")
    assert h1.signature() == h2.signature()


def test_signature_empty_hint_is_stable():
    assert AgentHint().signature() == ""


def test_signature_axis2_only_hint_has_empty_signature():
    """A hint with only Axis 2 fields contributes nothing to the cache key —
    structurally equivalent to no hint at all for caching purposes."""
    hint = AgentHint(parallelism=8, deadline_ms=2000, client_intent_class="discovery")
    assert hint.signature() == ""


# ---------------------------------------------------------------------------
# AgentHintEcho — response side
# ---------------------------------------------------------------------------


def test_agent_hint_echo_round_trip():
    echo = AgentHintEcho(applied_selectors=[HintSelector.REALM.value, HintSelector.TRANSPORT.value])
    decoded = decode_agent_hint_echo(echo.encode())
    assert decoded.applied_selectors == [
        HintSelector.REALM.value,
        HintSelector.TRANSPORT.value,
    ]


def test_agent_hint_echo_empty_round_trip():
    """An echo with no applied selectors is valid — means 'I saw the hint but applied nothing'."""
    decoded = decode_agent_hint_echo(AgentHintEcho().encode())
    assert decoded.applied_selectors == []


def test_agent_hint_echo_decode_rejects_request_payload():
    """A payload with the echo bit clear must NOT be decoded as an echo."""
    request_payload = AgentHint(realm="prod").encode()
    with pytest.raises(ValueError, match="missing echo bit"):
        decode_agent_hint_echo(request_payload)


def test_agent_hint_echo_decode_rejects_truncated():
    with pytest.raises(ValueError, match="truncated"):
        decode_agent_hint_echo(bytes([0x80, 0x05, 0x01]))  # claims 5, has 1


def test_agent_hint_echo_rejects_out_of_range_selector_code():
    """Encoded selector codes must fit in one byte."""
    with pytest.raises(ValueError, match="out of range"):
        AgentHintEcho(applied_selectors=[300]).encode()


# ---------------------------------------------------------------------------
# EdnsSignalingAdvertisement — JSON publisher channel
# ---------------------------------------------------------------------------


def test_advertisement_round_trip_via_json():
    adv = EdnsSignalingAdvertisement(
        version=0,
        honored_selectors=["realm", "transport", "capabilities"],
        note="DNS-layer narrowing for realm/transport; client-side filter for capabilities",
    )
    restored = EdnsSignalingAdvertisement.model_validate_json(adv.model_dump_json())
    assert restored.version == 0
    assert "capabilities" in restored.honored_selectors
    assert "DNS-layer" in restored.note


def test_advertisement_optional_note():
    adv = EdnsSignalingAdvertisement(version=0, honored_selectors=["realm"])
    assert adv.note is None
