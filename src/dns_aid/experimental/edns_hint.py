# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Experimental EDNS(0) ``agent-hint`` option — request + response wire format.

⚠ Experimental. See ``docs/experimental/edns-signaling.md`` for the full design.

The ``agent-hint`` option carries selector filters from the client toward
whichever hop on the resolution path is hint-aware:

- Locus 1: an in-client programmable hop — today the
  :class:`~dns_aid.experimental.edns_cache.EdnsAwareResolver`, long-term the
  SDK growing into a real agentic cache or a co-located DNS-like cache process
- Locus 2: a hint-aware recursive resolver / forwarder
- Locus 3: a hint-aware authoritative DNS server

Stock authoritative servers treat the option as inert per RFC 6891 §6.1.1.
Hint-aware hops MAY include an :class:`AgentHintEcho` in their response
listing the selectors they actually applied — absence is meaningful (no
upstream filtering happened, client should fall back to local filtering).

Two-axis selector taxonomy
==========================

Selector codes are split into two axes by code range. The split is structural,
not advisory — Axis 1 and Axis 2 selectors have different cache semantics
(see :meth:`AgentHint.signature`).

**Axis 1 — substrate filters (codes 0x01–0x0F).**
Things the auth/cache can decide on without dereferencing anything out-of-band.
Different Axis-1 values mean different *answer* sets, so they participate in
the cache key.

**Axis 2 — metering / lifecycle (codes 0x10–0x1F).**
Things about the request itself — rate-limit class, freshness budget, sibling
count, deadline. Drive accept/reject/prefetch policy but should NOT fragment
the cache: two queries differing only in ``parallelism`` should hit the same
cache entry. Excluded from :meth:`AgentHint.signature`.

Codes 0x20+ are reserved for future axes (e.g. cookies, correlation IDs).

Wire format (request)::

    +----------------+----------------------+
    | VERSION (0x00) | SELECTOR-COUNT (1B)  |
    +----------------+----------------------+
    | selector-code (1B) | selector-len (1B) | selector-value (N B UTF-8) |
    +--------------------+-------------------+----------------------------+
                       ...

Wire format (response echo)::

    +----------------+----------------------+
    | VERSION (0x80) | APPLIED-COUNT (1B)   |
    +----------------+----------------------+
    | selector-code (1B) | selector-code (1B) | ...                       |
    +--------------------+--------------------+----------------------+
"""

from __future__ import annotations

from enum import IntEnum
from typing import Any

from pydantic import BaseModel, Field

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

# Axis boundaries — encoded into the selector-code numbering so the wire
# inspector can tell at a glance which axis a code belongs to.
AXIS1_RANGE = range(0x01, 0x10)  # substrate filters: 0x01–0x0F
AXIS2_RANGE = range(0x10, 0x20)  # metering / lifecycle: 0x10–0x1F


class HintSelector(IntEnum):
    """Selector codes for ``agent-hint`` v0.

    Codes 0x05–0x0F (Axis 1 tail) and 0x14–0x1F (Axis 2 tail) are reserved
    for future selectors within the same axis. Codes 0x20+ are reserved for
    future axes. Consumers MUST ignore selector codes they do not recognise
    rather than rejecting the whole option.
    """

    # Axis 1 — substrate filters
    REALM = 0x01  # multi-tenant scope (SVCB realm= param)
    TRANSPORT = 0x02  # "mcp" | "a2a" | "https"
    POLICY_REQUIRED = 0x03  # "1" means only records carrying a policy= URI
    MIN_TRUST = 0x04  # "signed" | "dnssec" | "signed+dnssec"
    JURISDICTION = 0x05  # ISO region tag, e.g. "eu", "us-east"

    # Axis 2 — metering / lifecycle
    CLIENT_INTENT_CLASS = 0x10  # "discovery" | "invocation"
    MAX_AGE = 0x11  # cache freshness in seconds (UTF-8 decimal)
    PARALLELISM = 0x12  # expected sibling-query count (UTF-8 decimal uint)
    DEADLINE_MS = 0x13  # client's wait budget in ms (UTF-8 decimal uint)


# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------


class AgentHint(BaseModel):
    """Request-side EDNS(0) ``agent-hint`` payload.

    Two-axis structure (see module docstring):

    - **Axis 1 (substrate filters)** — ``realm``, ``transport``,
      ``policy_required``, ``min_trust``, ``jurisdiction``. Different values
      → different answer sets → participate in the cache key.
    - **Axis 2 (metering / lifecycle)** — ``client_intent_class``,
      ``max_age``, ``parallelism``, ``deadline_ms``. Drive accept/reject/
      prefetch policy but do NOT fragment the cache.

    All fields are optional. Unrecognised selectors on decode are silently
    dropped (forward compatibility).

    Capabilities and intent are intentionally NOT DNS-layer selectors here —
    they belong in the publisher's well-known JSON (the
    :class:`EdnsSignalingAdvertisement` ``honored_selectors`` list) where
    clients use them for post-fetch local filtering.
    """

    # -- Axis 1: substrate filters --------------------------------------------

    realm: str | None = Field(
        default=None,
        description="Multi-tenant scope identifier (matches SVCB realm= param).",
    )
    transport: str | None = Field(
        default=None,
        description="Transport: 'mcp' | 'a2a' | 'https'.",
    )
    policy_required: bool = Field(
        default=False,
        description="When True, only return records carrying a policy= URI.",
    )
    min_trust: str | None = Field(
        default=None,
        description="Trust posture: 'signed' | 'dnssec' | 'signed+dnssec'.",
    )
    jurisdiction: str | None = Field(
        default=None,
        description="ISO region tag (e.g. 'eu', 'us-east'). Real compliance lever.",
    )

    # -- Axis 2: metering / lifecycle -----------------------------------------

    client_intent_class: str | None = Field(
        default=None,
        description="'discovery' (browsing) vs 'invocation' (about to call).",
    )
    max_age: int | None = Field(
        default=None,
        ge=0,
        description="Don't return cache entries older than this many seconds.",
    )
    parallelism: int | None = Field(
        default=None,
        ge=0,
        description="Expected sibling-query count (signals fan-out to caches).",
    )
    deadline_ms: int | None = Field(
        default=None,
        ge=0,
        description=(
            "Client's wait budget in milliseconds. Hint-only — DNS has no "
            "refuse-for-SLA semantic in v0; auths may log it, choose a faster "
            "code path, or serve a stale cache entry to meet it, but cannot "
            "return a 'won't meet deadline' error."
        ),
    )

    # -- Encode / decode ------------------------------------------------------

    def encode(self) -> bytes:
        """Encode this hint into the EDNS(0) option payload bytes.

        Raises:
            ValueError: if any selector value exceeds 255 bytes UTF-8, or the
                total payload would exceed ``MAX_OPTION_PAYLOAD``.
        """
        selectors: list[tuple[int, bytes]] = []

        # Axis 1
        if self.realm:
            selectors.append((HintSelector.REALM.value, self.realm.encode("utf-8")))
        if self.transport:
            selectors.append((HintSelector.TRANSPORT.value, self.transport.encode("utf-8")))
        if self.policy_required:
            # Only emit when explicitly required — absence == "don't care".
            selectors.append((HintSelector.POLICY_REQUIRED.value, b"1"))
        if self.min_trust:
            selectors.append((HintSelector.MIN_TRUST.value, self.min_trust.encode("utf-8")))
        if self.jurisdiction:
            selectors.append((HintSelector.JURISDICTION.value, self.jurisdiction.encode("utf-8")))

        # Axis 2 — int fields encode as UTF-8 decimal
        if self.client_intent_class:
            selectors.append(
                (HintSelector.CLIENT_INTENT_CLASS.value, self.client_intent_class.encode("utf-8"))
            )
        if self.max_age is not None:
            selectors.append((HintSelector.MAX_AGE.value, str(self.max_age).encode("ascii")))
        if self.parallelism is not None:
            selectors.append(
                (HintSelector.PARALLELISM.value, str(self.parallelism).encode("ascii"))
            )
        if self.deadline_ms is not None:
            selectors.append(
                (HintSelector.DEADLINE_MS.value, str(self.deadline_ms).encode("ascii"))
            )

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

        Includes ONLY Axis 1 selectors (substrate filters). Axis 2 selectors
        (metering, deadlines, parallelism) are intentionally excluded so two
        queries that differ only in lifecycle parameters share the same cache
        entry — the answer set is the same, the policy applied to the
        request is different.
        """
        parts: list[str] = []
        if self.realm:
            parts.append(f"rlm:{self.realm}")
        if self.transport:
            parts.append(f"trn:{self.transport}")
        if self.policy_required:
            parts.append("plc:1")
        if self.min_trust:
            parts.append(f"trs:{self.min_trust}")
        if self.jurisdiction:
            parts.append(f"jur:{self.jurisdiction}")
        return "|".join(parts)


class AgentHintEcho(BaseModel):
    """Response-side echo from a hint-aware DNS hop.

    Lists the selector codes the responder actually applied. Absence of an
    echo on a response means no upstream filtering happened — the client
    should fall back to local filtering against the returned record set.
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

    Channel-1 advertisement (out-of-band, JSON). Independent of whether any
    hop on the DNS resolution path is hint-aware (which is the Channel-2
    signal — the OPT response echo). Capabilities and intent live here, not
    in the DNS-layer option, because they require dereferencing per-record
    JSON which is not work the substrate can do.
    """

    version: int = Field(description="Hint protocol version this publisher supports.")
    honored_selectors: list[str] = Field(
        default_factory=list,
        description=(
            "Selector names this publisher recommends populating. "
            "May include DNS-layer selector names (e.g. 'realm', 'transport') "
            "OR JSON-only selectors the client should filter on locally after "
            "fetch (e.g. 'capabilities', 'intent')."
        ),
    )
    note: str | None = Field(
        default=None,
        description="Free-form human-readable note from the publisher.",
    )


# -----------------------------------------------------------------------------
# Decoders
# -----------------------------------------------------------------------------


def _decode_int_selector(code: int, value: str) -> int:
    """Parse a UTF-8 decimal selector value into an int; fail-closed on garbage."""
    try:
        n = int(value, 10)
    except ValueError as e:
        raise ValueError(
            f"selector code 0x{code:02x} expects a decimal integer, got {value!r}"
        ) from e
    if n < 0:
        raise ValueError(f"selector code 0x{code:02x} must be non-negative, got {n}")
    return n


def decode_agent_hint(payload: bytes) -> AgentHint:
    """Decode an EDNS(0) ``agent-hint`` request payload into :class:`AgentHint`.

    Unrecognised selector codes are silently skipped (forward compat). Raises
    :class:`ValueError` for structural malformations (truncated payload, echo
    bit set, unsupported version, length overflow, malformed numeric fields).
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

    fields: dict[str, Any] = {}
    # First-wins on duplicate selector codes — defends against a hostile forwarder
    # appending an overriding selector after a legitimate one. Mirrors the
    # _parse_txt_value pattern in dcv.py (Igor's DCV review, S3 / ADV-006 class).
    seen_codes: set[int] = set()

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

        # First-wins: drop any duplicate occurrence of a code we've already seen.
        # Applies to both known and unknown codes.
        if code in seen_codes:
            continue
        seen_codes.add(code)

        # For string-typed selectors, an empty value on the wire is treated as
        # "field not set" — matches the encode-side semantics (encode skips empty
        # strings) and avoids cache-key fragmentation under forged empty values.

        # Axis 1
        if code == HintSelector.REALM.value:
            if value:
                fields["realm"] = value
        elif code == HintSelector.TRANSPORT.value:
            if value:
                fields["transport"] = value
        elif code == HintSelector.POLICY_REQUIRED.value:
            fields["policy_required"] = value == "1"
        elif code == HintSelector.MIN_TRUST.value:
            if value:
                fields["min_trust"] = value
        elif code == HintSelector.JURISDICTION.value:
            if value:
                fields["jurisdiction"] = value
        # Axis 2
        elif code == HintSelector.CLIENT_INTENT_CLASS.value:
            if value:
                fields["client_intent_class"] = value
        elif code == HintSelector.MAX_AGE.value:
            fields["max_age"] = _decode_int_selector(code, value)
        elif code == HintSelector.PARALLELISM.value:
            fields["parallelism"] = _decode_int_selector(code, value)
        elif code == HintSelector.DEADLINE_MS.value:
            fields["deadline_ms"] = _decode_int_selector(code, value)
        # else: silently drop unknown selectors (forward compat)

    return AgentHint(**fields)


def decode_agent_hint_echo(payload: bytes) -> AgentHintEcho:
    """Decode an EDNS(0) ``agent-hint`` response echo payload.

    Raises :class:`ValueError` if the echo bit is not set, or if the payload
    is truncated.
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
