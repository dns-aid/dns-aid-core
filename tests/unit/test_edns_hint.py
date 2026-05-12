# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for dns_aid.experimental.edns_hint — wire format encode/decode."""

from __future__ import annotations

import pytest

from dns_aid.experimental.edns_hint import (
    AGENT_HINT_OPTION_CODE,
    AgentHint,
    AgentHintEcho,
    EdnsSignalingAdvertisement,
    HintSelector,
    decode_agent_hint,
    decode_agent_hint_echo,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


def test_option_code_in_private_use_range():
    """Sanity check: chosen option code is in RFC 6891 private-use range."""
    assert 65001 <= AGENT_HINT_OPTION_CODE <= 65534


# ---------------------------------------------------------------------------
# AgentHint encode / decode — request
# ---------------------------------------------------------------------------


def test_agent_hint_round_trip_all_selectors():
    hint = AgentHint(
        capabilities=["chat", "code-review"],
        intent="summarize",
        transport="mcp",
        auth_type="bearer",
    )
    decoded = decode_agent_hint(hint.encode())
    assert decoded.capabilities == ["chat", "code-review"]
    assert decoded.intent == "summarize"
    assert decoded.transport == "mcp"
    assert decoded.auth_type == "bearer"


def test_agent_hint_round_trip_partial_selectors():
    hint = AgentHint(capabilities=["chat"])
    decoded = decode_agent_hint(hint.encode())
    assert decoded.capabilities == ["chat"]
    assert decoded.intent is None
    assert decoded.transport is None
    assert decoded.auth_type is None


def test_agent_hint_empty_hint_encodes_to_header_only():
    """An AgentHint with no selectors encodes to just (version, count=0)."""
    payload = AgentHint().encode()
    assert payload == bytes([0x00, 0x00])
    decoded = decode_agent_hint(payload)
    assert decoded.capabilities is None and decoded.intent is None


def test_agent_hint_capabilities_strip_empties():
    """Empty/whitespace-only capability strings are stripped."""
    hint = AgentHint(capabilities=["chat", "", "  ", "code"])
    assert hint.capabilities == ["chat", "code"]


def test_agent_hint_capabilities_all_empty_becomes_none():
    """If every capability is empty after stripping, the field is None."""
    hint = AgentHint(capabilities=["", "   "])
    assert hint.capabilities is None


def test_agent_hint_utf8_value_round_trip():
    """Selector values are UTF-8 — non-ASCII survives the round trip."""
    hint = AgentHint(intent="résumé-📝")
    decoded = decode_agent_hint(hint.encode())
    assert decoded.intent == "résumé-📝"


# ---------------------------------------------------------------------------
# AgentHint encode / decode — error paths
# ---------------------------------------------------------------------------


def test_agent_hint_selector_value_too_long_rejected():
    """Selector value over 255 bytes UTF-8 must be rejected at encode."""
    hint = AgentHint(intent="x" * 256)
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
    """Payload claims a selector but lacks its 2-byte header."""
    payload = bytes([0x00, 0x01, 0x01])  # version=0, count=1, then only 1B before EOF
    with pytest.raises(ValueError, match="truncated mid-selector header"):
        decode_agent_hint(payload)


def test_agent_hint_decode_rejects_truncated_selector_value():
    """Selector header says length=10 but only 3 bytes follow."""
    payload = bytes([0x00, 0x01, 0x01, 0x0A, 0x61, 0x62, 0x63])
    with pytest.raises(ValueError, match="truncated mid-selector value"):
        decode_agent_hint(payload)


def test_agent_hint_decode_silently_drops_unknown_selectors():
    """Forward-compat: future selector codes must be skipped, not rejected."""
    # version=0, count=2, selector(0xFE, "x"), selector(0x02, "intent-tag")
    payload = bytes(
        [0x00, 0x02]
        + [0xFE, 0x01, ord("x")]
        + [HintSelector.INTENT.value, 10]
        + list(b"intent-tag")
    )
    decoded = decode_agent_hint(payload)
    assert decoded.intent == "intent-tag"
    # The unknown selector is silently dropped — no error.


def test_agent_hint_decode_rejects_invalid_utf8():
    payload = bytes(
        [0x00, 0x01, HintSelector.INTENT.value, 0x02, 0xFF, 0xFE]
    )  # 0xFF 0xFE is not valid UTF-8
    with pytest.raises(ValueError, match="UTF-8"):
        decode_agent_hint(payload)


# ---------------------------------------------------------------------------
# AgentHint signature() — cache-key stability
# ---------------------------------------------------------------------------


def test_signature_is_deterministic():
    h1 = AgentHint(capabilities=["chat"], intent="summarize")
    h2 = AgentHint(capabilities=["chat"], intent="summarize")
    assert h1.signature() == h2.signature()


def test_signature_is_order_independent_for_capabilities():
    """Capabilities are sorted in the signature — ordering doesn't change the key."""
    h1 = AgentHint(capabilities=["chat", "code", "search"])
    h2 = AgentHint(capabilities=["search", "chat", "code"])
    assert h1.signature() == h2.signature()


def test_signature_differs_when_selectors_differ():
    h1 = AgentHint(capabilities=["chat"])
    h2 = AgentHint(capabilities=["search"])
    assert h1.signature() != h2.signature()


def test_signature_empty_hint_is_stable():
    assert AgentHint().signature() == ""


# ---------------------------------------------------------------------------
# AgentHintEcho — response side
# ---------------------------------------------------------------------------


def test_agent_hint_echo_round_trip():
    echo = AgentHintEcho(
        applied_selectors=[HintSelector.CAPABILITIES.value, HintSelector.INTENT.value]
    )
    decoded = decode_agent_hint_echo(echo.encode())
    assert decoded.applied_selectors == [
        HintSelector.CAPABILITIES.value,
        HintSelector.INTENT.value,
    ]


def test_agent_hint_echo_empty_round_trip():
    """An echo with no applied selectors is valid — means 'I saw the hint but applied nothing'."""
    decoded = decode_agent_hint_echo(AgentHintEcho().encode())
    assert decoded.applied_selectors == []


def test_agent_hint_echo_decode_rejects_request_payload():
    """A payload with the echo bit clear must NOT be decoded as an echo."""
    request_payload = AgentHint(capabilities=["chat"]).encode()
    with pytest.raises(ValueError, match="missing echo bit"):
        decode_agent_hint_echo(request_payload)


def test_agent_hint_echo_decode_rejects_truncated():
    with pytest.raises(ValueError, match="truncated"):
        decode_agent_hint_echo(bytes([0x80, 0x05, 0x01]))  # claims 5 selectors, has 1


def test_agent_hint_echo_rejects_out_of_range_selector_code():
    """Encoded selector codes must fit in one byte."""
    with pytest.raises(ValueError, match="out of range"):
        AgentHintEcho(applied_selectors=[300]).encode()


# ---------------------------------------------------------------------------
# EdnsSignalingAdvertisement — JSON publisher channel
# ---------------------------------------------------------------------------


def test_advertisement_round_trip_via_json():
    """Pydantic model round trips through JSON without losing fields."""
    adv = EdnsSignalingAdvertisement(
        version=0,
        honored_selectors=["capabilities", "intent"],
        note="prefer pre-filtering",
    )
    restored = EdnsSignalingAdvertisement.model_validate_json(adv.model_dump_json())
    assert restored.version == 0
    assert restored.honored_selectors == ["capabilities", "intent"]
    assert restored.note == "prefer pre-filtering"


def test_advertisement_optional_note():
    adv = EdnsSignalingAdvertisement(version=0, honored_selectors=["capabilities"])
    assert adv.note is None
