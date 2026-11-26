# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
TXT-record fallback parser and builder.

For DNS deployments that don't expose SVCB records (older managed-DNS
appliances, smaller hosted providers, self-hosted DNS that hasn't adopted
SVCB yet), the SDK falls back to a TXT-encoded representation of the same
agent endpoint information. The wire format mirrors the SVCB SvcParam
names as key=value pairs so the consumer parser is symmetric with the
SVCB parser already used by ``core.discoverer``.

Wire format (single TXT RR; ``v=1`` discriminator distinguishes endpoint
TXT from the metadata TXT that ``AgentRecord.to_txt_values()`` writes
alongside):

    _chat._mcp._agents.example.com. 3600 IN TXT (
        "v=1 target=mcp.example.com port=443 alpn=mcp "
        "cap=https://example.com/cap/chat-v1.json "
        "cap-sha256=DEADBEEF... policy=https://example.com/policy/strict"
    )

Required fields: ``v`` (must equal ``"1"``), ``target``.
Defaults: ``port=443``.
Optional: ``alpn``, ``ipv4hint``, ``ipv6hint``, ``cap``, ``cap-sha256``,
``bap``, ``policy``, ``realm``, ``sig``, ``connect-class``,
``connect-meta``, ``enroll-uri``, ``well-known``.

Unknown fields are silently ignored on parse (forward compatibility).

A value containing whitespace, a quote or a backslash is written in
double quotes with ``\"`` and ``\\`` escaped (``quotable-value`` in
docs/rfc/wire-format.abnf), so it round-trips through the ``shlex``
parser. Anything else is written bare.

Multiple TXT strings inside a single RR are concatenated with nothing in
between before key=value parsing, the convention SPF uses (RFC 7208
§3.3). A body longer than 255 bytes (any signed record: a ``sig`` alone is
~360 characters) is split by the backend at arbitrary byte offsets, so a
separator would corrupt whichever token straddles the split. Multiple TXT
*RRs* at the same FQDN are not supported as fallback containers in v1 —
callers that see more than one ``v=1`` RR should log a warning and use
the first.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from dns_aid.core.models import AgentRecord

logger = structlog.get_logger(__name__)

# Current wire-format version. Bump only on a wire-incompatible change.
TXT_FALLBACK_VERSION: str = "1"

# Field-name constants — kept in module scope so tests and downstream code can
# reference them without string duplication.
KEY_VERSION = "v"
KEY_TARGET = "target"
KEY_PORT = "port"
KEY_ALPN = "alpn"
KEY_IPV4HINT = "ipv4hint"
KEY_IPV6HINT = "ipv6hint"
KEY_CAP = "cap"
KEY_CAP_SHA256 = "cap-sha256"
KEY_BAP = "bap"
KEY_POLICY = "policy"
KEY_REALM = "realm"
KEY_SIG = "sig"
KEY_CONNECT_CLASS = "connect-class"
KEY_CONNECT_META = "connect-meta"
KEY_ENROLL_URI = "enroll-uri"
KEY_WELL_KNOWN = "well-known"

# Characters that split or open a token for the shlex parser; a value with
# any of them is double-quoted on write (ABNF quotable-value).
_NEEDS_QUOTES = re.compile(r"[\s'\"\\]")


@dataclass
class TxtFallbackRecord:
    """Parsed agent record from a TXT-fallback wire format.

    All optional fields are ``None`` when the publisher omitted them. The
    discoverer maps a populated record onto an ``AgentRecord`` using the
    same field correspondences SVCB uses.

    ``bap`` is kept as the raw wire value (draft-02 §5.1 scalar form,
    ``mcp`` / ``mcp=1.0``) exactly like the SVCB path's
    ``custom_params.get("bap")`` — the consumer boundary normalizes it via
    :func:`dns_aid.core.bap.normalize_bap`, which also collapses legacy
    comma-separated lists with a warning.
    """

    target: str
    port: int = 443
    alpn: str | None = None
    ipv4hint: str | None = None
    ipv6hint: str | None = None
    cap: str | None = None
    cap_sha256: str | None = None
    bap: str | None = None
    policy: str | None = None
    realm: str | None = None
    sig: str | None = None
    connect_class: str | None = None
    connect_meta: str | None = None
    enroll_uri: str | None = None
    well_known: str | None = None


def parse_txt_fallback(strings: Iterable[bytes]) -> TxtFallbackRecord | None:
    """Parse a TXT RR's per-string segments into a :class:`TxtFallbackRecord`.

    ``strings`` is the ``rdata.strings`` sequence dnspython exposes — each
    element is a ``<character-string>`` of at most 255 bytes. They are
    concatenated with no separator before parsing (see the module docstring:
    a backend splits a long body at arbitrary byte offsets).

    Returns ``None`` when the body cannot be interpreted as a v1 fallback
    record:

    - Any string is not valid UTF-8
    - ``shlex`` fails to tokenise the body (e.g., unclosed quotes)
    - No ``v=`` field is present
    - ``v`` is anything other than ``"1"``
    - The required ``target=`` field is missing or empty

    A malformed ``port=`` value falls back to the default (443) rather than
    failing the whole parse — this matches the publisher behaviour of
    omitting the port when it's the default.

    Unknown fields are silently dropped; the dataclass only exposes the
    fields this SDK understands.
    """
    try:
        body = b"".join(strings).decode("utf-8")
    except UnicodeDecodeError:
        logger.debug("txt_fallback.invalid_utf8")
        return None

    try:
        tokens = shlex.split(body)
    except ValueError as exc:
        logger.debug("txt_fallback.shlex_failed", error=str(exc))
        return None

    kv: dict[str, str] = {}
    for tok in tokens:
        if "=" not in tok:
            continue
        key, _, value = tok.partition("=")
        kv[key.strip().lower()] = value

    version = kv.get(KEY_VERSION)
    if version is None:
        # No version marker → this is not a fallback record. Not an error
        # condition; the caller may be looking at a metadata TXT.
        return None
    if version != TXT_FALLBACK_VERSION:
        logger.debug("txt_fallback.unsupported_version", version=version)
        return None

    target = kv.get(KEY_TARGET)
    if not target:
        logger.debug("txt_fallback.missing_target")
        return None

    port_raw = kv.get(KEY_PORT)
    port = 443
    if port_raw is not None:
        try:
            port = int(port_raw)
        except ValueError:
            logger.debug("txt_fallback.invalid_port", value=port_raw)
            # Continue with default; malformed port is recoverable.

    # Raw pass-through, like the SVCB path's ``custom_params.get("bap")``.
    # The consumer boundary runs ``normalize_bap`` (scalar draft-02 form;
    # legacy comma lists collapse there with a warning).
    bap = kv.get(KEY_BAP) or None

    return TxtFallbackRecord(
        target=target,
        port=port,
        alpn=kv.get(KEY_ALPN),
        ipv4hint=kv.get(KEY_IPV4HINT),
        ipv6hint=kv.get(KEY_IPV6HINT),
        cap=kv.get(KEY_CAP),
        cap_sha256=kv.get(KEY_CAP_SHA256),
        bap=bap,
        policy=kv.get(KEY_POLICY),
        realm=kv.get(KEY_REALM),
        sig=kv.get(KEY_SIG),
        connect_class=kv.get(KEY_CONNECT_CLASS),
        connect_meta=kv.get(KEY_CONNECT_META),
        enroll_uri=kv.get(KEY_ENROLL_URI),
        well_known=kv.get(KEY_WELL_KNOWN) or None,
    )


def build_txt_fallback(agent: AgentRecord) -> str:
    """Serialize an :class:`AgentRecord` into a single TXT body string.

    Returned string is the concatenated body that the publisher should pass
    to its backend as a TXT value. Backends typically chunk into 255-byte
    ``<character-string>`` segments transparently; this builder does not
    perform the chunking itself, so callers retain control of how the
    backend's TXT-write API expects the input.

    Fields that are unset on the AgentRecord are omitted from the output.
    The protocol enum is encoded as ``alpn=`` so the wire shape mirrors a
    SVCB ServiceMode record with ``alpn=`` set.
    """

    def field(key: str, value: object) -> str:
        text = str(value)
        if _NEEDS_QUOTES.search(text):
            text = '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'
        return f"{key}={text}"

    parts: list[str] = [
        field(KEY_VERSION, TXT_FALLBACK_VERSION),
        field(KEY_TARGET, agent.target_host),
    ]
    if agent.port != 443:
        parts.append(field(KEY_PORT, agent.port))

    proto = getattr(agent.protocol, "value", None) or str(agent.protocol)
    if proto:
        parts.append(field(KEY_ALPN, proto))

    optional: list[tuple[str, object]] = [
        (KEY_IPV4HINT, agent.ipv4_hint),
        (KEY_IPV6HINT, agent.ipv6_hint),
        (KEY_CAP, agent.cap_uri),
        (KEY_CAP_SHA256, agent.cap_sha256),
        # draft-02 scalar form (``mcp`` / ``mcp=1.0``).
        (KEY_BAP, agent.bap),
        (KEY_POLICY, agent.policy_uri),
        (KEY_REALM, agent.realm),
        (KEY_SIG, agent.sig),
        (KEY_CONNECT_CLASS, agent.connect_class),
        (KEY_CONNECT_META, agent.connect_meta),
        (KEY_ENROLL_URI, agent.enroll_uri),
        # Covered by the record signature (publisher signs it), so it must
        # be published or a signed record verifies as unbound.
        (KEY_WELL_KNOWN, agent.well_known_path),
    ]
    parts.extend(field(key, value) for key, value in optional if value)

    return " ".join(parts)
