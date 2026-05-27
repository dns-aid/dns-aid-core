# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Mock DNS backend for testing.

In-memory implementation that stores records without touching real DNS.
Useful for unit tests and local development.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

from dns_aid.backends.base import DNSBackend

if TYPE_CHECKING:
    from dns_aid.core.models import AgentRecord


class MockBackend(DNSBackend):
    """
    In-memory DNS backend for testing.

    Stores records in a dict structure. Simulates DNS operations
    without external dependencies.

    Example:
        >>> backend = MockBackend()
        >>> await backend.create_svcb_record(
        ...     zone="example.com",
        ...     name="_chat._a2a._agents",
        ...     priority=1,
        ...     target="chat.example.com.",
        ...     params={"alpn": "a2a", "port": "443"}
        ... )
        '_chat._a2a._agents.example.com'

        >>> # Records are stored in memory
        >>> backend.records["example.com"]["_chat._a2a._agents"]["SVCB"]
        [{'priority': 1, 'target': 'chat.example.com.', 'params': {...}, 'ttl': 3600}]
    """

    def __init__(self, zones: list[str] | None = None):
        """
        Initialize mock backend.

        Args:
            zones: List of zones that "exist". If None, all zones are valid.
        """
        # Structure: {zone: {name: {type: [records]}}}
        self.records: dict[str, dict[str, dict[str, list[dict]]]] = defaultdict(
            lambda: defaultdict(lambda: defaultdict(list))
        )
        self._zones: set[str] | None = set(zones) if zones else None

    @property
    def name(self) -> str:
        return "mock"

    async def create_svcb_record(
        self,
        zone: str,
        name: str,
        priority: int,
        target: str,
        params: dict[str, str],
        ttl: int = 3600,
    ) -> str:
        """Create SVCB record in memory."""
        fqdn = f"{name}.{zone}"

        record = {
            "priority": priority,
            "target": target,
            "params": params.copy(),
            "ttl": ttl,
        }

        # Replace existing or add new
        self.records[zone][name]["SVCB"] = [record]

        return fqdn

    async def create_txt_record(
        self,
        zone: str,
        name: str,
        values: list[str],
        ttl: int = 3600,
    ) -> str:
        """Create TXT record in memory."""
        fqdn = f"{name}.{zone}"

        record = {
            "values": values.copy(),
            "ttl": ttl,
        }

        # Replace existing or add new
        self.records[zone][name]["TXT"] = [record]

        return fqdn

    async def delete_record(
        self,
        zone: str,
        name: str,
        record_type: str,
    ) -> bool:
        """Delete record from memory."""
        if (
            zone in self.records
            and name in self.records[zone]
            and record_type in self.records[zone][name]
        ):
            del self.records[zone][name][record_type]
            return True
        return False

    async def list_records(
        self,
        zone: str,
        name_pattern: str | None = None,
        record_type: str | None = None,
    ) -> AsyncIterator[dict]:
        """List records from memory."""
        if zone not in self.records:
            return

        for name, types in self.records[zone].items():
            # Filter by name pattern (substring match like Route53)
            if name_pattern and name_pattern not in name:
                continue

            for rtype, records in types.items():
                # Filter by record type
                if record_type and rtype != record_type:
                    continue

                for record in records:
                    # Return values at top level for consistency with Route53
                    yield {
                        "name": name,
                        "fqdn": f"{name}.{zone}",
                        "type": rtype,
                        "ttl": record.get("ttl", 3600),
                        "values": record.get("values", []),
                        "data": record,  # Keep for backward compatibility
                    }

    async def zone_exists(self, zone: str) -> bool:
        """Check if zone exists (or all zones valid if not configured)."""
        if self._zones is None:
            return True
        return zone in self._zones

    async def get_record(
        self,
        zone: str,
        name: str,
        record_type: str,
    ) -> dict | None:
        """Get a specific record from memory."""
        try:
            records = self.records[zone][name][record_type]
            if not records:
                return None
            record = records[0]

            # Format values based on record type
            if record_type == "SVCB":
                # Format as "priority target params..."
                priority = record.get("priority", 1)
                target = record.get("target", "")
                params = record.get("params", {})
                param_str = " ".join(f'{k}="{v}"' for k, v in params.items())
                values = [f"{priority} {target} {param_str}".strip()]
            elif record_type == "TXT":
                values = record.get("values", [])
            else:
                values = record.get("values", [])

            return {
                "name": name,
                "fqdn": f"{name}.{zone}",
                "type": record_type,
                "ttl": record.get("ttl", 3600),
                "values": values,
                "data": record,
            }
        except (KeyError, IndexError):
            return None

    async def publish_agent(self, agent: AgentRecord) -> list[str]:
        """Publish with ALL SVCB params — no demotion.

        MockBackend accepts all params (like NIOS) to enable full protocol
        testing without private-use key restrictions.

        Consults the shared TXT-fallback gate first so the experimental
        fallback path is exercised consistently across backend
        implementations.
        """
        zone = agent.domain
        name = f"_{agent.name}._{agent.protocol.value}._agents"

        if self._txt_fallback_enabled():
            return await self._publish_via_txt_fallback(agent, zone, name)

        records: list[str] = []
        svcb_fqdn = await self.create_svcb_record(
            zone=zone,
            name=name,
            priority=1,
            target=agent.svcb_target,
            params=agent.to_svcb_params(),
            ttl=agent.ttl,
        )
        records.append(f"SVCB {svcb_fqdn}")

        txt_values = agent.to_txt_values()
        if txt_values:
            txt_fqdn = await self.create_txt_record(
                zone=zone,
                name=name,
                values=txt_values,
                ttl=agent.ttl,
            )
            records.append(f"TXT {txt_fqdn}")

        return records

    def get_svcb_record(self, zone: str, name: str) -> dict | None:
        """
        Get SVCB record data (helper for testing).

        Returns None if not found.
        """
        try:
            records = self.records[zone][name]["SVCB"]
            return records[0] if records else None
        except (KeyError, IndexError):
            return None

    def get_txt_record(self, zone: str, name: str) -> list[str] | None:
        """
        Get TXT record values (helper for testing).

        Returns None if not found.
        """
        try:
            records = self.records[zone][name]["TXT"]
            return records[0]["values"] if records else None
        except (KeyError, IndexError):
            return None

    def clear(self) -> None:
        """Clear all records (useful between tests)."""
        self.records.clear()
