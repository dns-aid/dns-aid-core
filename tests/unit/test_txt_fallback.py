# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for ``dns_aid.core._txt_fallback`` — TXT-fallback parser + builder.

Wire-format reference: ``docs/rfc/wire-format.abnf`` (dns-aid-txt-fallback).
"""

from __future__ import annotations

from dns_aid.core._txt_fallback import (
    KEY_TARGET,
    KEY_VERSION,
    TXT_FALLBACK_VERSION,
    TxtFallbackRecord,
    build_txt_fallback,
    parse_txt_fallback,
)
from dns_aid.core.models import AgentRecord, Protocol

# ---------------------------------------------------------------------------
# Constants smoke check
# ---------------------------------------------------------------------------


def test_version_constant() -> None:
    assert TXT_FALLBACK_VERSION == "1"
    assert KEY_VERSION == "v"
    assert KEY_TARGET == "target"


# ---------------------------------------------------------------------------
# parse_txt_fallback — happy path
# ---------------------------------------------------------------------------


def test_parse_minimal_record() -> None:
    """v=1 + target= is the smallest legal record."""
    result = parse_txt_fallback([b"v=1 target=mcp.example.com"])
    assert isinstance(result, TxtFallbackRecord)
    assert result.target == "mcp.example.com"
    assert result.port == 443  # default
    assert result.alpn is None
    assert result.bap is None


def test_parse_full_record() -> None:
    body = (
        b"v=1 target=mcp.example.com port=8443 alpn=mcp "
        b"ipv4hint=192.0.2.5 ipv6hint=2001:db8::5 "
        b"cap=https://example.com/cap/chat-v1.json "
        b"cap-sha256=DEADBEEF bap=mcp/1,a2a/1 "
        b"policy=https://example.com/policy/strict realm=prod "
        b"sig=eyJhbGc connect-class=direct connect-meta=arn:example "
        b"enroll-uri=https://example.com/enroll"
    )
    result = parse_txt_fallback([body])
    assert result is not None
    assert result.target == "mcp.example.com"
    assert result.port == 8443
    assert result.alpn == "mcp"
    assert result.ipv4hint == "192.0.2.5"
    assert result.ipv6hint == "2001:db8::5"
    assert result.cap == "https://example.com/cap/chat-v1.json"
    assert result.cap_sha256 == "DEADBEEF"
    # Raw pass-through — the consumer boundary (normalize_bap) collapses
    # legacy comma lists; the parser itself does not interpret the value.
    assert result.bap == "mcp/1,a2a/1"
    assert result.policy == "https://example.com/policy/strict"
    assert result.realm == "prod"
    assert result.sig == "eyJhbGc"
    assert result.connect_class == "direct"
    assert result.connect_meta == "arn:example"
    assert result.enroll_uri == "https://example.com/enroll"


def test_parse_multi_string_concatenation() -> None:
    """Multi-string TXT concatenates with no separator (SPF convention, RFC 7208 §3.3).

    A publisher splitting by hand keeps the spaces between tokens inside the
    strings; a backend splitting a long body may cut mid-token.
    """
    result = parse_txt_fallback(
        [
            b"v=1 target=mcp.example.com ",
            b"port=8443 alpn=mcp ",
            b"cap=https://example.com/cap/v1",
        ]
    )
    assert result is not None
    assert result.target == "mcp.example.com"
    assert result.port == 8443
    assert result.alpn == "mcp"
    assert result.cap == "https://example.com/cap/v1"


def test_parse_split_mid_token_round_trips() -> None:
    """A split inside a value (255-byte chunking) must not insert a space."""
    result = parse_txt_fallback(
        [b"v=1 target=mcp.exam", b"ple.com cap=https://example.com/c", b"ap/v1"]
    )
    assert result is not None
    assert result.target == "mcp.example.com"
    assert result.cap == "https://example.com/cap/v1"


def test_parse_quoted_value_with_space() -> None:
    """shlex respects double-quoted values so a description-style field with a space works."""
    result = parse_txt_fallback([b'v=1 target=mcp.example.com realm="prod east"'])
    assert result is not None
    assert result.realm == "prod east"


# ---------------------------------------------------------------------------
# parse_txt_fallback — rejection paths
# ---------------------------------------------------------------------------


def test_parse_missing_version_returns_none() -> None:
    """No v= field → not a fallback record. Returns None silently."""
    result = parse_txt_fallback([b"target=mcp.example.com port=443"])
    assert result is None


def test_parse_wrong_version_returns_none() -> None:
    result = parse_txt_fallback([b"v=99 target=mcp.example.com"])
    assert result is None


def test_parse_missing_target_returns_none() -> None:
    result = parse_txt_fallback([b"v=1 port=443"])
    assert result is None


def test_parse_empty_target_returns_none() -> None:
    result = parse_txt_fallback([b"v=1 target="])
    assert result is None


def test_parse_invalid_utf8_returns_none() -> None:
    result = parse_txt_fallback([b"v=1 target=\xff\xfe"])
    assert result is None


def test_parse_unclosed_quote_returns_none() -> None:
    result = parse_txt_fallback([b'v=1 target=mcp.example.com realm="oops'])
    assert result is None


# ---------------------------------------------------------------------------
# parse_txt_fallback — recoverable malformations
# ---------------------------------------------------------------------------


def test_parse_invalid_port_falls_back_to_default() -> None:
    """Malformed port= is not a fatal parse error — record is still usable."""
    result = parse_txt_fallback([b"v=1 target=mcp.example.com port=not-a-number"])
    assert result is not None
    assert result.port == 443


def test_parse_unknown_field_is_ignored() -> None:
    """Forward-compat: a future field the SDK doesn't know about is skipped silently."""
    result = parse_txt_fallback([b"v=1 target=mcp.example.com future-thing=hello"])
    assert result is not None
    assert result.target == "mcp.example.com"


def test_parse_tokens_without_equals_are_ignored() -> None:
    """A stray bareword in the body doesn't break the parse."""
    result = parse_txt_fallback([b"v=1 stray-word target=mcp.example.com"])
    assert result is not None
    assert result.target == "mcp.example.com"


def test_parse_key_case_insensitive() -> None:
    """Keys are normalized to lowercase so backend casing differences don't bite."""
    result = parse_txt_fallback([b"V=1 TARGET=mcp.example.com PORT=8443"])
    assert result is not None
    assert result.target == "mcp.example.com"
    assert result.port == 8443


# ---------------------------------------------------------------------------
# build_txt_fallback
# ---------------------------------------------------------------------------


def _agent(**overrides: object) -> AgentRecord:
    """Build a minimal AgentRecord with optional field overrides."""
    base: dict[str, object] = {
        "name": "chat",
        "domain": "example.com",
        "protocol": Protocol.MCP,
        "target_host": "mcp.example.com",
        "port": 443,
        "capabilities": ["chat"],
        "version": "1.0.0",
    }
    base.update(overrides)
    return AgentRecord(**base)  # type: ignore[arg-type]


def test_build_minimal() -> None:
    """Default port + no optional params → just v=1 target= alpn=."""
    body = build_txt_fallback(_agent())
    assert body == "v=1 target=mcp.example.com alpn=mcp"


def test_build_omits_default_port() -> None:
    """port=443 is the default; don't emit it."""
    body = build_txt_fallback(_agent(port=443))
    assert "port=" not in body


def test_build_includes_non_default_port() -> None:
    body = build_txt_fallback(_agent(port=8443))
    assert "port=8443" in body


def test_build_includes_optional_fields() -> None:
    agent = _agent(
        cap_uri="https://example.com/cap",
        cap_sha256="DEADBEEF",
        policy_uri="https://example.com/policy/strict",
        realm="prod",
        bap="mcp=1.0",
        ipv4_hint="192.0.2.5",
        sig="eyJhbGc",
    )
    body = build_txt_fallback(agent)
    assert "cap=https://example.com/cap" in body
    assert "cap-sha256=DEADBEEF" in body
    assert "policy=https://example.com/policy/strict" in body
    assert "realm=prod" in body
    assert "bap=mcp=1.0" in body
    assert "ipv4hint=192.0.2.5" in body
    assert "sig=eyJhbGc" in body


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------


def test_round_trip_minimal() -> None:
    original = _agent()
    body = build_txt_fallback(original)
    parsed = parse_txt_fallback([body.encode("utf-8")])
    assert parsed is not None
    assert parsed.target == original.target_host
    assert parsed.port == original.port
    assert parsed.alpn == original.protocol.value


def test_round_trip_full() -> None:
    original = _agent(
        port=8443,
        cap_uri="https://example.com/cap",
        cap_sha256="DEADBEEF",
        policy_uri="https://example.com/policy/strict",
        realm="prod",
        bap="mcp=1.0",
        ipv4_hint="192.0.2.5",
        ipv6_hint="2001:db8::5",
        sig="eyJhbGc",
        connect_class="direct",
        connect_meta="arn:example",
        enroll_uri="https://example.com/enroll",
    )
    body = build_txt_fallback(original)
    parsed = parse_txt_fallback([body.encode("utf-8")])
    assert parsed is not None
    assert parsed.target == original.target_host
    assert parsed.port == original.port
    assert parsed.alpn == original.protocol.value
    assert parsed.cap == original.cap_uri
    assert parsed.cap_sha256 == original.cap_sha256
    assert parsed.policy == original.policy_uri
    assert parsed.realm == original.realm
    assert parsed.bap == original.bap
    assert parsed.ipv4hint == original.ipv4_hint
    assert parsed.ipv6hint == original.ipv6_hint
    assert parsed.sig == original.sig
    assert parsed.connect_class == original.connect_class
    assert parsed.connect_meta == original.connect_meta
    assert parsed.enroll_uri == original.enroll_uri


# ---------------------------------------------------------------------------
# Review fixes: quoting, well-known, chunked bodies
# ---------------------------------------------------------------------------


def _chunk(body: str, size: int = 255) -> list[bytes]:
    """Split like a backend: fixed byte offsets, no regard for token boundaries."""
    raw = body.encode()
    return [raw[i : i + size] for i in range(0, len(raw), size)]


def test_values_with_spaces_and_quotes_round_trip() -> None:
    # The model refuses double quotes and backslashes in SvcParams; spaces and
    # single quotes are allowed and used to split or end tokens.
    agent = _agent(connect_meta="a b  c", realm="it's")
    parsed = parse_txt_fallback([build_txt_fallback(agent).encode()])
    assert parsed is not None
    assert parsed.connect_meta == "a b  c"
    assert parsed.realm == "it's"


def test_plain_values_stay_unquoted() -> None:
    assert build_txt_fallback(_agent()).startswith("v=1 target=mcp.example.com ")


def test_well_known_is_written_and_read() -> None:
    agent = _agent(well_known_path="agent-card.json")
    assert "well-known=agent-card.json" in build_txt_fallback(agent)
    parsed = parse_txt_fallback([build_txt_fallback(agent).encode()])
    assert parsed is not None
    assert parsed.well_known == "agent-card.json"


def test_long_signed_body_survives_255_byte_chunking() -> None:
    """A sig alone is ~360 chars, so every signed record is split by the backend."""
    sig = "eyJhbGciOiJFUzI1NiJ9." + "A" * 300 + "." + "B" * 86
    agent = _agent(
        sig=sig,
        cap_uri="https://example.com/cap/chat-v1.json",
        cap_sha256="q" * 43,
        connect_meta="arn:aws:vpc-lattice:::service/svc-123 extra",
        well_known_path="agent-card.json",
    )
    body = build_txt_fallback(agent)
    assert len(body) > 400
    parsed = parse_txt_fallback(_chunk(body))
    assert parsed is not None
    assert parsed.sig == sig
    assert parsed.cap_sha256 == "q" * 43
    assert parsed.connect_meta == "arn:aws:vpc-lattice:::service/svc-123 extra"
    assert parsed.well_known == "agent-card.json"


def test_quoted_values_use_the_abnf_double_quote_form() -> None:
    body = build_txt_fallback(_agent(connect_meta="a b", realm="it's"))
    assert 'connect-meta="a b"' in body
    assert 'realm="it\'s"' in body
    assert "'a b'" not in body


def test_parser_reads_abnf_escapes() -> None:
    parsed = parse_txt_fallback([b'v=1 target=t.example.com realm="a \\"b\\" \\\\ c"'])
    assert parsed is not None
    assert parsed.realm == 'a "b" \\ c'
