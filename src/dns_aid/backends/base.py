# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Abstract base class for DNS backends.

All DNS provider implementations (Route53, Infoblox, etc.) must
implement this interface.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from dns_aid.core.models import AgentRecord

logger = structlog.get_logger(__name__)

# Standard SVCB SvcParamKeys accepted by all known DNS providers (RFC 9460).
# Private-use keys (key65280–key65534) are rejected by Route 53, Cloudflare,
# and Cloud DNS. NIOS and NS1 support them natively.
# DDNS returns None (auto-detect): tries native first, falls back to demotion.
#
# supports_private_svcb_keys property:
#   True  → pass all params to SVCB (NS1, NIOS)
#   False → demote custom params to TXT (Route53, Cloudflare, CloudDNS, BloxOne)
#   None  → try native, auto-fallback on server rejection (DDNS)
_STANDARD_SVCB_KEYS = frozenset(
    {
        "mandatory",
        "alpn",
        "no-default-alpn",
        "port",
        "ipv4hint",
        "ipv6hint",
        "ech",
    }
)


class DNSBackend(ABC):
    """
    Abstract interface for DNS providers.

    Implementations must handle:
    - Creating SVCB records for agent service binding
    - Creating TXT records for capabilities/metadata
    - Deleting records
    - Listing records in a zone

    Example:
        >>> backend = Route53Backend(zone_id="Z123...")
        >>> await backend.create_svcb_record(
        ...     zone="example.com",
        ...     name="_chat._a2a._agents",
        ...     priority=1,
        ...     target="chat.example.com.",
        ...     params={"alpn": "a2a", "port": "443"}
        ... )
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Backend identifier (e.g., 'route53', 'infoblox')."""
        ...

    @property
    def supports_private_svcb_keys(self) -> bool | None:
        """Whether this backend accepts private-use SVCB keys (key65280–key65534).

        Returns:
            ``True``  — backend accepts private keys natively (NS1, NIOS).
                        All params go directly to SVCB.
            ``False`` — backend rejects private keys (Route53, Cloudflare).
                        Custom params demoted to TXT.
            ``None``  — unknown, try native first, auto-fallback on error (DDNS).
                        First publish attempts full SVCB; if server rejects,
                        retries with standard params and demotes the rest.

        Override in subclasses to indicate support level.
        """
        return False

    def _txt_fallback_enabled(self) -> bool:
        """Return True iff this backend should write TXT-fallback instead of SVCB.

        Requires both:
        - ``self.supports_svcb`` is ``False`` (backend wraps a DNS system that
          can't write SVCB)
        - ``DNS_AID_EXPERIMENTAL_TXT_FALLBACK`` is truthy in the environment
          (operator opt-in)

        Used by :meth:`publish_agent` to decide whether to take the
        TXT-fallback write path. Backends that override ``publish_agent``
        should also consult this helper at the top of their override so the
        feature behaves consistently across backend implementations.
        """
        if self.supports_svcb:
            return False
        return os.environ.get("DNS_AID_EXPERIMENTAL_TXT_FALLBACK", "").lower() in (
            "1",
            "true",
            "yes",
        )

    async def _publish_via_txt_fallback(
        self, agent: AgentRecord, zone: str, name: str
    ) -> list[str]:
        """Write a TXT-encoded agent record for SVCB-less DNS deployments.

        Emits a single TXT RR containing the ``v=1 target=... port=...``
        body produced by :func:`dns_aid.core._txt_fallback.build_txt_fallback`,
        followed by the companion metadata values from
        :meth:`AgentRecord.to_txt_values` so downstream readers and ``dig``
        debuggers still see capability / version / description.
        """
        from dns_aid.core._txt_fallback import build_txt_fallback

        logger.info(
            "Publishing agent via TXT fallback (backend does not support SVCB)",
            backend=self.name,
            agent_fqdn=f"{name}.{zone}",
        )
        txt_values: list[str] = [build_txt_fallback(agent)]
        txt_values.extend(agent.to_txt_values())
        txt_fqdn = await self.create_txt_record(
            zone=zone,
            name=name,
            values=txt_values,
            ttl=agent.ttl,
        )
        records = [f"TXT {txt_fqdn} (fallback v=1)"]
        logger.info(
            "Agent published via TXT fallback",
            backend=self.name,
            records=records,
        )
        return records

    @property
    def supports_svcb(self) -> bool:
        """Whether this backend's underlying DNS system supports SVCB records at all.

        This is distinct from :attr:`supports_private_svcb_keys`, which is
        about *key encoding* inside a SVCB record. ``supports_svcb`` is about
        whether the backend can write SVCB records of any kind.

        Returns:
            ``True``  — backend writes SVCB records (default; all currently
                        bundled backends — Route53, Cloudflare, Google Cloud
                        DNS, NS1, NIOS, UDDI — return True).
            ``False`` — backend cannot write SVCB. The publisher will fall
                        back to a TXT-encoded agent record when the
                        ``DNS_AID_EXPERIMENTAL_TXT_FALLBACK`` env flag is set.

        Override in subclasses wrapping older DNS appliances, smaller hosted
        providers, or self-hosted DNS that hasn't adopted SVCB yet.
        """
        return True

    @abstractmethod
    async def create_svcb_record(
        self,
        zone: str,
        name: str,
        priority: int,
        target: str,
        params: dict[str, str],
        ttl: int = 3600,
    ) -> str:
        """
        Create an SVCB record for agent discovery.

        Args:
            zone: DNS zone (e.g., "example.com")
            name: Record name without zone (e.g., "_chat._a2a._agents")
            priority: SVCB priority (0 for alias, 1+ for service mode)
            target: Target hostname with trailing dot
            params: SVCB parameters (alpn, port, ipv4hint, etc.)
            ttl: Time-to-live in seconds

        Returns:
            FQDN of created record
        """
        ...

    @abstractmethod
    async def create_txt_record(
        self,
        zone: str,
        name: str,
        values: list[str],
        ttl: int = 3600,
    ) -> str:
        """
        Create a TXT record for agent capabilities.

        Args:
            zone: DNS zone
            name: Record name without zone
            values: List of TXT values
            ttl: Time-to-live in seconds

        Returns:
            FQDN of created record
        """
        ...

    @abstractmethod
    async def delete_record(
        self,
        zone: str,
        name: str,
        record_type: str,
    ) -> bool:
        """
        Delete a DNS record.

        Args:
            zone: DNS zone
            name: Record name without zone
            record_type: Record type (SVCB, TXT, etc.)

        Returns:
            True if deleted, False if not found
        """
        ...

    @abstractmethod
    def list_records(
        self,
        zone: str,
        name_pattern: str | None = None,
        record_type: str | None = None,
    ) -> AsyncIterator[dict]:
        """
        List DNS records in a zone.

        Args:
            zone: DNS zone
            name_pattern: Optional pattern to filter by name
            record_type: Optional filter by record type

        Yields:
            Dict with record details (name, type, ttl, values)
        """
        ...

    @abstractmethod
    async def zone_exists(self, zone: str) -> bool:
        """
        Check if a DNS zone exists and is accessible.

        Implementations MUST return False (not raise) on any error —
        network failures, authentication issues, or misconfigured
        settings (e.g., invalid DNS view) all mean the zone is
        effectively inaccessible.

        Args:
            zone: DNS zone to check

        Returns:
            True if zone exists and is accessible, False otherwise
        """
        ...

    async def get_record(
        self,
        zone: str,
        name: str,
        record_type: str,
    ) -> dict | None:
        """
        Get a specific DNS record by name and type.

        This method queries the backend API directly (not DNS resolution),
        providing reliable record existence checks for reconciliation.

        Args:
            zone: DNS zone (e.g., "example.com")
            name: Record name without zone (e.g., "_chat._a2a._agents")
            record_type: Record type (SVCB, TXT, etc.)

        Returns:
            Record dict with name, fqdn, type, ttl, values if found, None otherwise
        """
        # Default implementation using list_records - backends can override for efficiency
        async for record in self.list_records(zone, name_pattern=name, record_type=record_type):
            if record.get("name") == name or record.get("fqdn") == f"{name}.{zone}":
                return record
        return None

    async def publish_agent(self, agent: AgentRecord) -> list[str]:
        """Publish an agent to DNS.

        If :pyattr:`supports_private_svcb_keys` is ``True``, all SVCB
        params (including DNS-AID private-use keys like cap, policy_uri,
        realm) are written directly to the SVCB record.

        Otherwise, custom params are automatically demoted to the TXT
        record as ``dnsaid_keyNNNNN=value`` so the publish succeeds
        without data loss.

        Args:
            agent: Agent to publish

        Returns:
            List of created record descriptions
        """
        records: list[str] = []
        zone = agent.domain
        name = f"_{agent.name}._{agent.protocol.value}._agents"

        # ── TXT-fallback gate (experimental) ─────────────────────────────
        # When the underlying DNS system can't write SVCB at all, fall back
        # to a TXT-encoded agent record so SDK consumers can still discover
        # this agent. Off by default — operators must opt in via env flag
        # AND the backend must explicitly signal SVCB-unsupported, both to
        # avoid surprising publisher behaviour and to keep the experimental
        # path quiescent for the typical case.
        if self._txt_fallback_enabled():
            return await self._publish_via_txt_fallback(agent, zone, name)

        all_params = agent.to_svcb_params()
        support = self.supports_private_svcb_keys

        # Split standard vs custom params
        standard_params: dict[str, str] = {}
        custom_params: dict[str, str] = {}
        for key, value in all_params.items():
            if key in _STANDARD_SVCB_KEYS:
                standard_params[key] = value
            else:
                custom_params[key] = value

        if support is True:
            # Backend confirmed — pass ALL params to SVCB
            svcb_params = all_params
            demoted_params: dict[str, str] = {}
        elif support is None and custom_params:
            # Unknown (e.g., DDNS) — try native first, fallback on error
            try:
                svcb_fqdn = await self.create_svcb_record(
                    zone=zone,
                    name=name,
                    priority=1,
                    target=agent.svcb_target,
                    params=all_params,
                    ttl=agent.ttl,
                )
                records.append(f"SVCB {svcb_fqdn}")
                logger.info(
                    "Server accepted private-use SVCB keys natively",
                    backend=self.name,
                )
                svcb_params = None  # signal: already created
                demoted_params = {}
            except Exception:
                logger.info(
                    "Server rejected private-use SVCB keys; falling back to demotion",
                    backend=self.name,
                    demoted_keys=list(custom_params.keys()),
                )
                svcb_params = standard_params
                demoted_params = custom_params
        else:
            # Backend confirmed no support — demote
            svcb_params = standard_params
            demoted_params = custom_params
            if demoted_params:
                logger.warning(
                    "Backend does not support custom SVCB params; demoting to TXT",
                    backend=self.name,
                    demoted_keys=list(demoted_params.keys()),
                )

        # Create SVCB (skip if auto-detect already created it)
        if svcb_params is not None:
            svcb_fqdn = await self.create_svcb_record(
                zone=zone,
                name=name,
                priority=1,
                target=agent.svcb_target,
                params=svcb_params,
                ttl=agent.ttl,
            )
            records.append(f"SVCB {svcb_fqdn}")

        txt_values = agent.to_txt_values()
        for key, value in demoted_params.items():
            txt_values.append(f"dnsaid_{key}={value}")

        if txt_values:
            txt_fqdn = await self.create_txt_record(
                zone=zone,
                name=name,
                values=txt_values,
                ttl=agent.ttl,
            )
            records.append(f"TXT {txt_fqdn}")

        logger.info(
            "Agent published successfully",
            fqdn=f"{name}.{zone}",
            records=records,
        )
        return records
