# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Experimental EDNS(0) ``agent-hint`` option — request + response wire format.

⚠ Experimental. See ``docs/experimental/edns-signaling.md`` for the full design.

The ``agent-hint`` option carries a compact set of selector filters from the
client to whichever hop on the resolution path is hint-aware:

- Locus 1: the client's own resolver wrapper (in-process cache, see
  :mod:`dns_aid.experimental.edns_cache`)
- Locus 2: a hint-aware recursive resolver / forwarder
- Locus 3: a hint-aware authoritative DNS server

Stock authoritative servers treat the option as inert per RFC 6891. A hint-aware
hop MAY include an :class:`AgentHintEcho` option in its response listing the
selectors it actually applied — this lets the client know what upstream
filtering happened.

Wire format (request)::

    +------------------+------------------+
    |  VERSION (0x00)  |  SELECTOR-COUNT  |
    +------------------+------------------+
    |  selector-code (1B) | selector-len (1B) | selector-value (N B UTF-8) |
    +------------------+------------------+
                       ...

Wire format (response echo)::

    +------------------+------------------+
    |  VERSION (0x80)  |  APPLIED-COUNT   |
    +------------------+------------------+
    |  selector-code (1B) | selector-code (1B) | ...                       |
    +------------------+------------------+
"""

from __future__ import annotations

from enum import IntEnum

from pydantic import BaseModel, Field, field_validator

# Private-use EDNS(0) option-code range is 65001–65534 (RFC 6891 §6.1.1).
# 65430 chosen arbitrarily within the range; subject to change before any IANA
# coordination.
AGENT_HINT_OPTION_CODE: int = 65430

VERSION_REQUEST: int = 0x00
VERSION_ECHO: int = 0x80
ECHO_FLAG_MASK: int = 0x80
VERSION_NUMBER_MASK: int = 0x7F

MAX_SELECTOR_VALUE_LEN: int = 255  # 1-byte length prefix
MAX_OPTION_PAYLOAD: int = 512  # soft cap to stay inside reasonable EDNS budget


class HintSelector(IntEnum):
    """Selector codes for ``agent-hint`` v0.

    Codes 0x05–0xFF are reserved for future versions. Consumers MUST ignore
    selector codes they do not recognise rather than rejecting the whole option.
    """

    CAPABILITIES = 0x01  # comma-separated list, e.g. "chat,code-review"
    INTENT = 0x02  # single tag, e.g. "summarize"
    TRANSPORT = 0x03  # "mcp" | "a2a" | "https"
    AUTH_TYPE = 0x04  # "none" | "bearer" | "oauth2" | "mtls"


# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------


class AgentHint(BaseModel):
    """Request-side EDNS(0) ``agent-hint`` payload.

    Encodes a small set of selector filters that the client wants applied (by
    whichever hop on the resolution path is hint-aware). Unrecognised selectors
    on decode are silently dropped — forward compatibility.
    """

    capabilities: list[str] | None = Field(
        default=None,
        description="List of capability tags the client is looking for.",
    )
    intent: str | None = Field(
        default=None,
        description="Single intent tag, e.g. 'summarize'.",
    )
    transport: str | None = Field(
        default=None,
        description="Transport: 'mcp' | 'a2a' | 'https'.",
    )
    auth_type: str | None = Field(
        default=None,
        description="Auth type: 'none' | 'bearer' | 'oauth2' | 'mtls'.",
    )

    @field_validator("capabilities")
    @classmethod
    def _strip_empty_caps(cls, v: list[str] | None) -> list[str] | None:
        if v is None:
            return None
        cleaned = [c.strip() for c in v if c and c.strip()]
        return cleaned or None

    def encode(self) -> bytes:
        """Encode this hint into the EDNS(0) option payload bytes.

        Raises:
            ValueError: if any selector value exceeds 255 bytes UTF-8, or the
                total payload would exceed ``MAX_OPTION_PAYLOAD``.
        """
        selectors: list[tuple[int, bytes]] = []

        if self.capabilities:
            value = ",".join(self.capabilities).encode("utf-8")
            selectors.append((HintSelector.CAPABILITIES.value, value))
        if self.intent:
            selectors.append((HintSelector.INTENT.value, self.intent.encode("utf-8")))
        if self.transport:
            selectors.append((HintSelector.TRANSPORT.value, self.transport.encode("utf-8")))
        if self.auth_type:
            selectors.append((HintSelector.AUTH_TYPE.value, self.auth_type.encode("utf-8")))

        if len(selectors) > 255:
            raise ValueError("agent-hint cannot carry more than 255 selectors")

        parts: list[bytes] = [bytes([VERSION_REQUEST, len(selectors)])]
        for code, value in selectors:
            if len(value) > MAX_SELECTOR_VALUE_LEN:
                raise ValueError(
                    f"selector value for code 0x{code:02x} is {len(value)} bytes; "
                    f"max is {MAX_SELECTOR_VALUE_LEN}"
                )
            parts.append(bytes([code, len(value)]))
            parts.append(value)

        payload = b"".join(parts)
        if len(payload) > MAX_OPTION_PAYLOAD:
            raise ValueError(
                f"agent-hint payload is {len(payload)} bytes; max is {MAX_OPTION_PAYLOAD}"
            )
        return payload

    def signature(self) -> str:
        """Stable cache-key string for this hint.

        Order-independent: two hints with the same selectors produce the same
        signature regardless of construction order. ``capabilities`` values are
        sorted to normalise.
        """
        parts: list[str] = []
        if self.capabilities:
            parts.append("cap:" + ",".join(sorted(self.capabilities)))
        if self.intent:
            parts.append(f"int:{self.intent}")
        if self.transport:
            parts.append(f"trn:{self.transport}")
        if self.auth_type:
            parts.append(f"aut:{self.auth_type}")
        return "|".join(parts)


class AgentHintEcho(BaseModel):
    """Response-side echo from a hint-aware DNS hop.

    Lists the selector codes the responder actually applied. Absence of an echo
    on a response means no upstream filtering happened — the client should fall
    back to local filtering against the returned record set.
    """

    applied_selectors: list[int] = Field(
        default_factory=list,
        description="Selector codes (HintSelector enum values) that the responder honoured.",
    )

    def encode(self) -> bytes:
        """Encode this echo into the EDNS(0) option payload bytes."""
        if len(self.applied_selectors) > 255:
            raise ValueError("agent-hint echo cannot carry more than 255 selector codes")
        for code in self.applied_selectors:
            if not 0 <= code <= 255:
                raise ValueError(f"selector code {code} out of range 0–255")
        return bytes([VERSION_ECHO, len(self.applied_selectors)]) + bytes(self.applied_selectors)


class EdnsSignalingAdvertisement(BaseModel):
    """Publisher advertisement carried in well-known JSON blobs (cap-doc, agent-card).

    Tells the client which selectors are *meaningful* for this publisher's
    agents — i.e. the publisher has populated the matching metadata fields so
    filtering on them will actually narrow results.

    Channel-1 advertisement (out-of-band, JSON). Independent of whether any hop
    on the DNS resolution path is hint-aware (which is the Channel-2 signal —
    the OPT response echo).
    """

    version: int = Field(description="Hint protocol version this publisher supports.")
    honored_selectors: list[str] = Field(
        default_factory=list,
        description="Selector names this publisher recommends populating, e.g. "
        "['capabilities', 'intent', 'transport'].",
    )
    note: str | None = Field(
        default=None,
        description="Free-form human-readable note from the publisher.",
    )


# -----------------------------------------------------------------------------
# Decoders
# -----------------------------------------------------------------------------


def decode_agent_hint(payload: bytes) -> AgentHint:
    """Decode an EDNS(0) ``agent-hint`` request payload into :class:`AgentHint`.

    Unrecognised selector codes are silently skipped (forward compat). Raises
    :class:`ValueError` for structural malformations (truncated payload, echo
    bit set, length overflow).
    """
    if len(payload) < 2:
        raise ValueError("agent-hint payload too short (need at least version + count)")

    version_byte = payload[0]
    if version_byte & ECHO_FLAG_MASK:
        raise ValueError("agent-hint payload has echo bit set (0x80); use decode_agent_hint_echo()")
    version_number = version_byte & VERSION_NUMBER_MASK
    if version_number != 0:
        raise ValueError(f"unsupported agent-hint version {version_number}; only v0 is defined")

    selector_count = payload[1]
    cursor = 2

    capabilities: list[str] | None = None
    intent: str | None = None
    transport: str | None = None
    auth_type: str | None = None

    for _ in range(selector_count):
        if cursor + 2 > len(payload):
            raise ValueError("agent-hint payload truncated mid-selector header")
        code = payload[cursor]
        length = payload[cursor + 1]
        value_start = cursor + 2
        value_end = value_start + length
        if value_end > len(payload):
            raise ValueError("agent-hint payload truncated mid-selector value")
        try:
            value = payload[value_start:value_end].decode("utf-8")
        except UnicodeDecodeError as e:
            raise ValueError(f"selector code 0x{code:02x} value is not valid UTF-8") from e
        cursor = value_end

        if code == HintSelector.CAPABILITIES.value:
            capabilities = [c.strip() for c in value.split(",") if c.strip()] or None
        elif code == HintSelector.INTENT.value:
            intent = value
        elif code == HintSelector.TRANSPORT.value:
            transport = value
        elif code == HintSelector.AUTH_TYPE.value:
            auth_type = value
        # else: silently drop unknown selectors (forward compat)

    return AgentHint(
        capabilities=capabilities,
        intent=intent,
        transport=transport,
        auth_type=auth_type,
    )


def decode_agent_hint_echo(payload: bytes) -> AgentHintEcho:
    """Decode an EDNS(0) ``agent-hint`` response echo payload.

    Raises :class:`ValueError` if the echo bit is not set, or if the payload is
    truncated.
    """
    if len(payload) < 2:
        raise ValueError("agent-hint echo payload too short (need at least version + count)")

    version_byte = payload[0]
    if not (version_byte & ECHO_FLAG_MASK):
        raise ValueError("agent-hint echo payload missing echo bit (0x80)")
    version_number = version_byte & VERSION_NUMBER_MASK
    if version_number != 0:
        raise ValueError(
            f"unsupported agent-hint echo version {version_number}; only v0 is defined"
        )

    applied_count = payload[1]
    if 2 + applied_count > len(payload):
        raise ValueError("agent-hint echo payload truncated")
    applied_selectors = list(payload[2 : 2 + applied_count])
    return AgentHintEcho(applied_selectors=applied_selectors)
