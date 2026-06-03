# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Shared DNS-AID FQDN parsing.

The discoverer and the telemetry/otel layers both need to recognise the
three FQDN shapes that have ever been published under DNS-AID and pull
out the agent identity from each. Keeping a single parser here prevents
the two implementations from drifting — earlier each module had its
own, which had already diverged on strictness (one accepted the walkable
shape with an empty domain suffix, the other didn't).

Shapes recognised:

1. **Legacy draft-01** ``_{name}._{protocol}._agents.{domain}`` — the
   pre-flat shape; ``name`` and ``protocol`` both carry leading
   underscores. Strictly validated: rejects single-underscore-prefixed
   strings like ``_booking.mcp._agents.foo.com`` where only the first
   label is underscored, since that's neither legitimate -01 nor a
   correct walkable record.
2. **Walkable AliasMode draft-02** ``{name}._agents.{domain}`` — the
   optional walkable enumeration handle. Protocol is unknown from the
   FQDN alone (it now lives in the SVCB ``bap`` / ``alpn`` SvcParams),
   so ``protocol`` is returned as ``None``.
3. **Flat primary owner draft-02** ``{name}.{domain}`` — the canonical
   -02 shape, valid as an x.509 SAN dNSName. Protocol again ``None``.

Callers needing only a subset of the returned tuple should project from
the result rather than re-implementing the parser.
"""

from __future__ import annotations

from typing import NamedTuple


class DnsAidFqdn(NamedTuple):
    """Parsed DNS-AID FQDN components.

    Fields:
        name: Agent name (the publisher-chosen label).
        protocol: Agent protocol from the FQDN, or ``None`` under
            draft-02 where the protocol lives in the SVCB SvcParams
            (``bap`` / ``alpn``) rather than the name.
        domain: Trailing domain portion after the agent-identifying
            labels.
    """

    name: str
    protocol: str | None
    domain: str


def parse_dnsaid_fqdn(fqdn: str) -> DnsAidFqdn | None:
    """Parse a DNS-AID FQDN into ``(name, protocol|None, domain)``.

    Returns ``None`` when ``fqdn`` doesn't look like any of the
    recognised shapes (empty, single-label, or malformed). Callers
    should treat ``None`` as "this string didn't carry a DNS-AID
    agent identity I can interpret" — not as a bug.
    """
    if not fqdn:
        return None

    # Legacy -01: _{name}._{protocol}._agents.{domain}
    # Requires (a) leading underscore on label 0, (b) leading underscore
    # on label 1 (the protocol), AND (c) label 2 == "_agents" so we
    # reject strings like "_booking.mcp._agents.foo.com" where only the
    # first label is underscored — that's neither legitimate -01 nor a
    # correct walkable record.
    if fqdn.startswith("_") and "._agents." in fqdn:
        parts = fqdn.split(".")
        if len(parts) < 4:
            return None
        name_part = parts[0]
        protocol_part = parts[1]
        agents_part = parts[2]
        if (
            not name_part.startswith("_")
            or not protocol_part.startswith("_")
            or agents_part != "_agents"
        ):
            return None
        domain = ".".join(parts[3:])
        if not domain:
            return None
        return DnsAidFqdn(name=name_part[1:], protocol=protocol_part[1:], domain=domain)

    # Walkable AliasMode draft-02: {name}._agents.{domain}
    if "._agents." in fqdn:
        prefix, _, suffix = fqdn.partition("._agents.")
        if prefix and suffix and "." not in prefix and not prefix.startswith("_"):
            return DnsAidFqdn(name=prefix, protocol=None, domain=suffix)
        return None

    # Flat draft-02: {name}.{domain}. Require at least three labels
    # total ({name} + at least a two-label domain such as example.com)
    # and reject names that start with an underscore.
    if "." in fqdn:
        first_label, _, rest = fqdn.partition(".")
        if first_label and rest and "." in rest and not first_label.startswith("_"):
            return DnsAidFqdn(name=first_label, protocol=None, domain=rest)

    return None
