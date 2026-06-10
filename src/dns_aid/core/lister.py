# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Enumerate the DNS-AID records published in a zone, via a DNS backend.

Under draft-mozleywilliams-dnsop-dnsaid-02 an agent's primary owner is the
**flat** FQDN ``{name}.{domain}`` (SVCB + companion TXT). The pre-flat
listing logic filtered records by the substring ``_agents`` in the owner
label, which only ever matched the organization index (``_index._agents``)
and walkable aliases (``{name}._agents``) — it silently missed every flat
agent owner. This module identifies DNS-AID records by *structure* instead of
by a name substring, so flat owners are surfaced.

A record is a DNS-AID record when it is:

* an **SVCB** record — every published agent (flat owner) and every walkable
  alias has exactly one;
* a **TXT** record sharing an owner with an SVCB record — the companion
  capability/metadata TXT of a flat agent owner;
* a record in the ``_agents`` bookkeeping namespace — the organization index
  (``_index._agents``) and walkable-alias owners.

System records (SOA/NS/A/AAAA/CNAME/...) are excluded. Used by ``dns-aid
list`` (CLI) and the ``list_published_agents`` MCP tool so both interfaces
report the same, correct set.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from dns_aid.backends.base import DNSBackend

# The label that marks the DNS-AID bookkeeping namespace (index + walkable
# aliases). Agent *primary* owners are flat and do NOT contain it — that is
# exactly why a substring filter on it is insufficient on its own.
_AGENTS_LABEL = "_agents"


def _owner(record: dict[str, Any]) -> str:
    """Stable owner key for a record: name-in-zone, falling back to the FQDN."""
    return record.get("name") or record.get("fqdn", "")


async def list_dns_aid_records(backend: DNSBackend, domain: str) -> list[dict[str, Any]]:
    """Return the DNS-AID records published under ``domain``.

    Issues two type-filtered backend queries (SVCB, TXT) so unrelated system
    records are never fetched. The result preserves the backend's record-dict
    shape (``name``, ``fqdn``, ``type``, ``ttl``, ``values``, ``id``) and
    de-duplicates by ``(fqdn, type)``.

    Args:
        backend: DNS backend to query.
        domain: Zone to enumerate.

    Returns:
        DNS-AID records (SVCB owners + walkable aliases + companion TXT +
        the ``_agents`` bookkeeping records), in backend order.
    """
    svcb_records = [r async for r in backend.list_records(domain, record_type="SVCB")]
    txt_records = [r async for r in backend.list_records(domain, record_type="TXT")]

    svcb_owners = {_owner(r) for r in svcb_records}

    out: list[dict[str, Any]] = list(svcb_records)
    for record in txt_records:
        owner = _owner(record)
        # Companion TXT of a flat agent owner, or an `_agents` bookkeeping TXT.
        if owner in svcb_owners or _AGENTS_LABEL in owner:
            out.append(record)

    # De-duplicate defensively (a backend could surface a record under both
    # queries); keep first occurrence and preserve order.
    seen: set[tuple[str, str]] = set()
    deduped: list[dict[str, Any]] = []
    for record in out:
        key = (record.get("fqdn", ""), record.get("type", ""))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(record)
    return deduped
