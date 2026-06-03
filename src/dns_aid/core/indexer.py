# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
DNS-AID Indexer: Manage _index._agents.* TXT records.

This module handles reading and writing the index record that lists
all agents published at a domain. The index enables efficient single-query
discovery of all agents.

Index Format:
    _index._agents.{domain}. TXT "agents=chat:mcp,billing:a2a,support:https"

Each entry is: {name}:{protocol}
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import dns.asyncresolver
import dns.resolver
import structlog

from dns_aid.backends.base import DNSBackend
from dns_aid.core.models import SVCB_SERVICE_MODE
from dns_aid.utils.validation import validate_no_underscore_in_target

logger = structlog.get_logger(__name__)

# Index record name pattern
INDEX_RECORD_NAME = "_index._agents"

# Sentinel for an index entry whose protocol couldn't be derived from
# the primary SVCB record (record absent, malformed, or the publisher
# didn't set alpn/bap). Kept as a named constant so consumers can
# filter on it without string-matching.
UNKNOWN_PROTOCOL = "unknown"


@dataclass
class IndexEntry:
    """An entry in the agent index."""

    name: str
    protocol: str

    def __str__(self) -> str:
        """Format as name:protocol."""
        return f"{self.name}:{self.protocol}"

    def __eq__(self, other: object) -> bool:
        """Compare by name and protocol."""
        if not isinstance(other, IndexEntry):
            return NotImplemented
        return self.name == other.name and self.protocol == other.protocol

    def __hash__(self) -> int:
        """Hash by name and protocol."""
        return hash((self.name, self.protocol))


@dataclass
class IndexResult:
    """Result of an index operation."""

    domain: str
    entries: list[IndexEntry]
    success: bool
    message: str
    created: bool = False  # True if index was newly created


def parse_index_txt(txt: str) -> list[IndexEntry]:
    """
    Parse an index TXT record value into entries.

    Args:
        txt: TXT record value like "agents=chat:mcp,billing:a2a"

    Returns:
        List of IndexEntry objects
    """
    entries = []

    # Handle format: "agents=name:proto,name:proto,..."
    if txt.startswith("agents="):
        agents_str = txt[len("agents=") :]

        for entry in agents_str.split(","):
            entry = entry.strip()
            if ":" in entry:
                parts = entry.split(":", 1)
                name = parts[0].strip()
                protocol = parts[1].strip().lower()
                if name and protocol:
                    entries.append(IndexEntry(name=name, protocol=protocol))

    return entries


def format_index_txt(entries: list[IndexEntry]) -> str:
    """
    Format index entries as a TXT record value.

    Args:
        entries: List of IndexEntry objects

    Returns:
        Formatted string like "agents=chat:mcp,billing:a2a"
    """
    if not entries:
        return "agents="

    # Sort for consistent output
    sorted_entries = sorted(entries, key=lambda e: (e.name, e.protocol))
    entries_str = ",".join(str(e) for e in sorted_entries)
    return f"agents={entries_str}"


async def read_index(
    domain: str,
    backend: DNSBackend,
) -> list[IndexEntry]:
    """
    Read the agent index for a domain.

    Args:
        domain: Domain to read index from
        backend: DNS backend to use

    Returns:
        List of IndexEntry objects (empty if no index exists)
    """
    logger.debug("Reading index", domain=domain)

    try:
        async for record in backend.list_records(
            zone=domain,
            name_pattern=INDEX_RECORD_NAME,
            record_type="TXT",
        ):
            # Found the index record
            values = record.get("values", [])
            for value in values:
                # Strip quotes if present
                txt = value.strip('"').strip("'")
                entries = parse_index_txt(txt)
                if entries:
                    logger.debug(
                        "Index parsed",
                        domain=domain,
                        entry_count=len(entries),
                    )
                    return entries

    except Exception as e:
        logger.warning("Failed to read index", domain=domain, error=str(e))

    logger.debug("No index found", domain=domain)
    return []


async def read_index_via_dns(domain: str) -> list[IndexEntry]:
    """
    Read the agent index via a direct DNS TXT query (no backend/credentials needed).

    Queries _index._agents.{domain} TXT using the system resolver.

    Args:
        domain: Domain to read index from

    Returns:
        List of IndexEntry objects (empty if no index exists)
    """
    fqdn = f"{INDEX_RECORD_NAME}.{domain}"
    logger.debug("Reading index via DNS", fqdn=fqdn)

    try:
        resolver = dns.asyncresolver.Resolver()
        answers = await resolver.resolve(fqdn, "TXT")

        for rdata in answers:
            for txt_string in rdata.strings:
                txt = txt_string.decode("utf-8")
                entries = parse_index_txt(txt)
                if entries:
                    logger.debug(
                        "Index parsed via DNS",
                        domain=domain,
                        entry_count=len(entries),
                    )
                    return entries

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        logger.debug("No DNS index record found", fqdn=fqdn)
    except Exception as e:
        logger.warning("Failed to read index via DNS", fqdn=fqdn, error=str(e))

    return []


async def update_index(
    domain: str,
    backend: DNSBackend,
    add: list[IndexEntry] | None = None,
    remove: list[IndexEntry] | None = None,
    ttl: int = 3600,
    index_target: str | None = None,
    index_target_port: int = 443,
) -> IndexResult:
    """
    Update the agent index for a domain.

    Performs a read-modify-write operation to update the index.

    Under draft-mozleywilliams-dnsop-dnsaid-02 the canonical org index
    record is SVCB at ``_index._agents.{domain}`` pointing at a
    non-underscored TargetName. TXT remains a documented fallback
    (§TXT-fallback) for SVCB-less environments. dns-aid-core writes
    both when ``index_target`` is supplied (SVCB for spec-compliant
    consumers + TXT inline-listing for the rest); when ``index_target``
    is omitted the TXT inline-listing is the only record written.

    Args:
        domain: Domain to update index for.
        backend: DNS backend to use.
        add: Entries to add to the index.
        remove: Entries to remove from the index.
        ttl: TTL for the index record.
        index_target: Optional host that serves the org's JSON agent
            index over HTTPS. When provided, dns-aid-core writes an
            SVCB ServiceMode record at ``_index._agents.{domain}``
            pointing at this target alongside the TXT inline record.
            The host MUST NOT contain underscored labels (it carries
            a public x.509 cert; see draft-02 §Known Organization).
        index_target_port: Port for the SVCB ServiceMode write
            (default 443). Only relevant when ``index_target`` is set.

    Returns:
        IndexResult with operation outcome.
    """
    logger.info(
        "Updating index",
        domain=domain,
        add=[str(e) for e in (add or [])],
        remove=[str(e) for e in (remove or [])],
        index_target=index_target,
    )

    # Read current index
    current_entries = await read_index(domain, backend)
    was_empty = len(current_entries) == 0

    # Build new entry set
    entry_set = set(current_entries)

    # Add new entries
    for entry in add or []:
        entry_set.add(entry)

    # Remove entries
    for entry in remove or []:
        entry_set.discard(entry)

    # Convert back to list
    new_entries = list(entry_set)

    # Format the TXT value
    txt_value = format_index_txt(new_entries)

    # If the caller wants the draft-02 SVCB-primary form, validate the
    # TargetName up front (same rule as agent records — no underscores
    # because the target carries a public x.509 cert).
    if index_target is not None:
        validate_no_underscore_in_target(index_target)

    try:
        # Check zone exists
        if not await backend.zone_exists(domain):
            return IndexResult(
                domain=domain,
                entries=current_entries,
                success=False,
                message=f"Zone '{domain}' does not exist",
            )

        # Write the SVCB primary form first, when an index_target was
        # supplied. The SVCB record points at the index host; consumers
        # fetch the actual JSON-bodied index from there over HTTPS.
        if index_target is not None:
            svcb_target = index_target if index_target.endswith(".") else f"{index_target}."
            await backend.create_svcb_record(
                zone=domain,
                name=INDEX_RECORD_NAME,
                priority=SVCB_SERVICE_MODE,
                target=svcb_target,
                params={"alpn": "h2", "port": str(index_target_port)},
                ttl=ttl,
            )

        # Write the TXT inline index (always — kept as the §TXT-fallback
        # form for SVCB-less consumers, and as the carrier for
        # dns-aid-core's own enumeration of agents).
        await backend.create_txt_record(
            zone=domain,
            name=INDEX_RECORD_NAME,
            values=[txt_value],
            ttl=ttl,
        )

        logger.info(
            "Index updated",
            domain=domain,
            entry_count=len(new_entries),
            was_empty=was_empty,
            wrote_svcb=index_target is not None,
        )

        return IndexResult(
            domain=domain,
            entries=new_entries,
            success=True,
            message=f"Index updated with {len(new_entries)} entries",
            created=was_empty,
        )

    except Exception as e:
        logger.exception("Failed to update index", domain=domain, error=str(e))
        return IndexResult(
            domain=domain,
            entries=current_entries,
            success=False,
            message=f"Failed to update index: {e}",
        )


async def delete_index(
    domain: str,
    backend: DNSBackend,
) -> bool:
    """
    Delete the agent index for a domain.

    Args:
        domain: Domain to delete index from
        backend: DNS backend to use

    Returns:
        True if deleted, False if not found
    """
    logger.info("Deleting index", domain=domain)

    try:
        return await backend.delete_record(
            zone=domain,
            name=INDEX_RECORD_NAME,
            record_type="TXT",
        )
    except Exception as e:
        logger.warning("Failed to delete index", domain=domain, error=str(e))
        return False


async def sync_index(
    domain: str,
    backend: DNSBackend,
    ttl: int = 3600,
) -> IndexResult:
    """
    Sync the index with actual published agents.

    Scans DNS for all _agents.* SVCB records and updates the index
    to match what's actually published.

    Args:
        domain: Domain to sync index for
        backend: DNS backend to use
        ttl: TTL for the index record

    Returns:
        IndexResult with sync outcome
    """
    logger.info("Syncing index", domain=domain)

    # Check zone exists before scanning
    if not await backend.zone_exists(domain):
        logger.error("Zone does not exist", zone=domain)
        return IndexResult(
            domain=domain,
            entries=[],
            success=False,
            message=f"Zone '{domain}' does not exist or is not accessible",
        )

    # Under draft-02 the canonical agent SVCB lives at the flat name
    # ({name}.{domain}). The walkable AliasMode at {name}._agents is
    # the reliable enumeration handle. Protocol is no longer in the
    # FQDN — it lives in the `alpn` (or `bap`) SvcParam on the primary
    # record, so the indexer resolves the walkable, then reads the
    # primary record's SvcParams to recover the protocol.
    walkable_pattern = re.compile(r"^([a-z0-9-]+)\._agents$", re.IGNORECASE)
    legacy_pattern = re.compile(r"^_([a-z0-9-]+)\._([a-z0-9]+)\._agents$", re.IGNORECASE)

    discovered_entries: list[IndexEntry] = []

    def _protocol_from_primary(primary_records: dict[str, dict], name: str) -> str:
        """Read the agent protocol off the primary SVCB record.

        draft-02 §Known Agent: ``bap`` is the canonical carrier for the
        bulk-agent-protocol identifier; ``alpn`` is the back-compat
        carrier accepted for single-protocol publishers. Read whichever
        the record uses.
        """
        primary = primary_records.get(name)
        if not primary:
            return UNKNOWN_PROTOCOL
        params = primary.get("data", {}).get("params", {}) or {}
        alpn = params.get("bap") or params.get("alpn")
        if alpn:
            # alpn may be quoted; trim.
            return alpn.strip('"').split(",")[0].strip() or UNKNOWN_PROTOCOL
        return UNKNOWN_PROTOCOL

    try:
        # Single backend enumeration. Earlier the function fetched the
        # zone twice — once with no filter to build primary_records and
        # once with name_pattern="_agents" to enumerate agents — but the
        # second call returns a subset of the first. On real backends
        # (Route53 / Cloudflare / Infoblox) each `list_records` is a
        # paginated API round-trip, so doubling it doubles latency and
        # quota burn per sync. Iterate in memory instead.
        primary_records: dict[str, dict] = {}
        agent_records: list[dict] = []
        async for record in backend.list_records(zone=domain, record_type="SVCB"):
            rname = record.get("name", "")
            if not rname or rname == INDEX_RECORD_NAME:
                continue
            primary_records[rname] = record
            if "_agents" in rname:
                agent_records.append(record)

        for record in agent_records:
            record_name = record.get("name", "")

            # Try the draft-02 walkable AliasMode shape first.
            walkable_match = walkable_pattern.match(record_name)
            if walkable_match:
                name = walkable_match.group(1)
                protocol = _protocol_from_primary(primary_records, name)
                discovered_entries.append(IndexEntry(name=name, protocol=protocol))

                logger.debug(
                    "Discovered agent (draft-02 walkable)",
                    name=name,
                    protocol=protocol,
                )
                continue

            # Fall back to the legacy -01 shape.
            match = legacy_pattern.match(record_name)
            if match:
                name = match.group(1)
                protocol = match.group(2)
                discovered_entries.append(IndexEntry(name=name, protocol=protocol))

                logger.debug(
                    "Discovered agent",
                    name=name,
                    protocol=protocol,
                )

    except Exception as e:
        logger.error("Failed to scan for agents", domain=domain, error=str(e))
        return IndexResult(
            domain=domain,
            entries=[],
            success=False,
            message=f"Failed to scan for agents: {e}",
        )

    # Read current index for comparison
    current_entries = await read_index(domain, backend)
    current_set = set(current_entries)
    discovered_set = set(discovered_entries)

    added = discovered_set - current_set
    removed = current_set - discovered_set

    logger.info(
        "Sync complete",
        domain=domain,
        discovered=len(discovered_entries),
        current=len(current_entries),
        added=len(added),
        removed=len(removed),
    )

    # Update the index with discovered entries
    if discovered_entries or current_entries:
        # Only write if there's something to write or we need to clear it
        try:
            txt_value = format_index_txt(discovered_entries)

            await backend.create_txt_record(
                zone=domain,
                name=INDEX_RECORD_NAME,
                values=[txt_value],
                ttl=ttl,
            )

            return IndexResult(
                domain=domain,
                entries=discovered_entries,
                success=True,
                message=f"Synced index: {len(discovered_entries)} agents ({len(added)} added, {len(removed)} removed)",
                created=len(current_entries) == 0 and len(discovered_entries) > 0,
            )

        except Exception as e:
            logger.exception("Failed to write synced index", error=str(e))
            return IndexResult(
                domain=domain,
                entries=current_entries,
                success=False,
                message=f"Failed to write synced index: {e}",
            )

    return IndexResult(
        domain=domain,
        entries=[],
        success=True,
        message="No agents found to index",
    )
