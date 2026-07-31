# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
NS1 (IBM) DNS backend.

Creates DNS-AID records (SVCB, TXT) in NS1 managed zones.
Uses the NS1 REST API v1 with API key authentication.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from typing import Any

import httpx
import structlog

from dns_aid.backends.base import DNSBackend

logger = structlog.get_logger(__name__)

# NS1 supports private-use SVCB keys (key65280–key65534) natively.
# The supports_private_svcb_keys property tells the base class to pass
# all params directly to SVCB without demotion to TXT.

DEFAULT_BASE_URL = "https://api.nsone.net/v1"
"""NS1 REST API base URL.  Override via ``NS1_BASE_URL`` env var for
private/dedicated NS1 deployments or IBM SoftLayer DNS."""


class NS1Backend(DNSBackend):
    """
    NS1 (IBM) DNS backend using REST API v1.

    Creates and manages DNS-AID records in NS1 zones.

    Example:
        >>> backend = NS1Backend()
        >>> await backend.create_svcb_record(
        ...     zone="example.com",
        ...     name="_chat._a2a._agents",
        ...     priority=1,
        ...     target="chat.example.com.",
        ...     params={"alpn": "a2a", "port": "443"}
        ... )

    Environment Variables:
        NS1_API_KEY: NS1 API key with DNS edit permissions
        NS1_BASE_URL: API base URL (default: https://api.nsone.net/v1)
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
    ):
        """
        Initialize NS1 backend.

        Args:
            api_key: NS1 API key (defaults to NS1_API_KEY env var)
            base_url: API base URL (defaults to NS1_BASE_URL env var
                      or https://api.nsone.net/v1)
        """
        self._api_key = api_key or os.environ.get("NS1_API_KEY")
        self._base_url = (base_url or os.environ.get("NS1_BASE_URL", DEFAULT_BASE_URL)).rstrip("/")
        self._client: httpx.AsyncClient | None = None
        self._client_loop_id: int | None = None
        self._zone_cache: dict[str, dict] = {}

    @property
    def name(self) -> str:
        return "ns1"

    @property
    def supports_private_svcb_keys(self) -> bool:
        """NS1 accepts private-use SVCB keys (key65280–key65534) natively."""
        return True

    def _normalize(self, zone: str, name: str | None = None) -> tuple[str, str]:
        """Normalize zone and build FQDN.

        Returns:
            (domain, fqdn) tuple with trailing dots stripped.
        """
        domain = zone.lower().rstrip(".")
        fqdn = f"{name}.{domain}" if name else domain
        return domain, fqdn

    @staticmethod
    def _extract_values(answers: list[dict]) -> list[str]:
        """Extract rdata values from NS1 answer objects."""
        return [" ".join(str(p) for p in a.get("answer", [])) for a in answers]

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create httpx async client.

        Recreates client if the event loop has changed (e.g., when CLI
        uses multiple asyncio.run() calls).
        """
        import asyncio

        current_loop_id = id(asyncio.get_running_loop())

        if self._client is not None and self._client_loop_id != current_loop_id:
            import contextlib

            with contextlib.suppress(Exception):
                await self._client.aclose()
            self._client = None
            self._client_loop_id = None

        if self._client is None:
            if not self._api_key:
                raise ValueError(
                    "NS1 API key not configured. "
                    "Set NS1_API_KEY environment variable or pass api_key parameter."
                )
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                headers={
                    "X-NSONE-Key": self._api_key,
                    "Content-Type": "application/json",
                },
                timeout=30.0,
            )
            self._client_loop_id = current_loop_id
        return self._client

    async def _get_zone(self, zone: str) -> dict:
        """
        Get NS1 zone metadata.

        Args:
            zone: Domain name (e.g., "example.com")

        Returns:
            Zone metadata dict

        Raises:
            ValueError: If zone not found
        """
        domain = zone.lower().rstrip(".")

        if domain in self._zone_cache:
            return self._zone_cache[domain]

        client = await self._get_client()

        response = await client.get(f"/zones/{domain}")
        if response.status_code == 404:
            raise ValueError(f"No zone found for domain: {zone}")
        response.raise_for_status()

        data = response.json()
        self._zone_cache[domain] = data
        logger.debug("Found zone", domain=domain, zone=data.get("zone"))
        return data

    async def _upsert_record(
        self,
        domain: str,
        fqdn: str,
        record_type: str,
        request_data: dict[str, Any],
    ) -> httpx.Response:
        """Create or update a DNS record.

        NS1 API behavior:
          PUT  on nonexistent → 200 (creates record)
          PUT  on existing    → 400 "record already exists"
          POST on existing    → 200 (updates record, accepts answers/ttl only)
          POST on nonexistent → 404

        Strategy: PUT to create; on 400 (exists) → POST to update.
        """
        client = await self._get_client()
        path = f"/zones/{domain}/{fqdn}/{record_type}"

        # Try create via PUT
        response = await client.put(path, json=request_data)
        if response.status_code in (200, 201):
            return response

        # Record exists — update via POST with answers + ttl only
        if response.status_code == 400:
            update_data: dict[str, Any] = {"answers": request_data["answers"]}
            if "ttl" in request_data:
                update_data["ttl"] = request_data["ttl"]
            response = await client.post(path, json=update_data)

        response.raise_for_status()
        return response

    def _format_svcb_rdata(
        self,
        priority: int,
        target: str,
        params: dict[str, str],
    ) -> str:
        """
        Format SVCB record data as presentation format string.

        NS1 accepts SVCB records in standard presentation format.
        """
        if not target.endswith("."):
            target = f"{target}."

        param_parts = []
        for key, value in params.items():
            param_parts.append(f'{key}="{value}"')
        params_str = " ".join(param_parts)

        if params_str:
            return f"{priority} {target} {params_str}"
        return f"{priority} {target}"

    async def create_svcb_record(
        self,
        zone: str,
        name: str,
        priority: int,
        target: str,
        params: dict[str, str],
        ttl: int = 3600,
    ) -> str:
        """Create SVCB record in NS1."""
        await self._get_zone(zone)
        domain, fqdn = self._normalize(zone, name)

        logger.info(
            "Creating SVCB record",
            zone=zone,
            name=fqdn,
            priority=priority,
            target=target,
            params=params,
            ttl=ttl,
        )

        rdata = self._format_svcb_rdata(priority, target, params)

        request_data: dict[str, Any] = {
            "zone": domain,
            "domain": fqdn,
            "type": "SVCB",
            "ttl": ttl,
            "answers": [{"answer": [rdata]}],
        }

        await self._upsert_record(domain, fqdn, "SVCB", request_data)
        logger.info("SVCB record created", fqdn=fqdn)
        return fqdn

    async def create_txt_record(
        self,
        zone: str,
        name: str,
        values: list[str],
        ttl: int = 3600,
    ) -> str:
        """Create TXT record in NS1."""
        await self._get_zone(zone)
        domain, fqdn = self._normalize(zone, name)

        logger.info(
            "Creating TXT record",
            zone=zone,
            name=fqdn,
            values=values,
            ttl=ttl,
        )

        answers = [{"answer": [v]} for v in values]

        request_data: dict[str, Any] = {
            "zone": domain,
            "domain": fqdn,
            "type": "TXT",
            "ttl": ttl,
            "answers": answers,
        }

        await self._upsert_record(domain, fqdn, "TXT", request_data)
        logger.info("TXT record created", fqdn=fqdn)
        return fqdn

    # publish_agent() inherited from DNSBackend base class — passes ALL
    # SVCB params natively since supports_private_svcb_keys = True.

    async def delete_record(
        self,
        zone: str,
        name: str,
        record_type: str,
    ) -> bool:
        """Delete a DNS record from NS1."""
        await self._get_zone(zone)
        client = await self._get_client()
        domain, fqdn = self._normalize(zone, name)

        logger.info(
            "Deleting record",
            zone=zone,
            name=fqdn,
            type=record_type,
        )

        response = await client.delete(f"/zones/{domain}/{fqdn}/{record_type}")

        if response.status_code == 404:
            logger.warning("Record not found", fqdn=fqdn, type=record_type)
            return False

        response.raise_for_status()
        logger.info("Record deleted", fqdn=fqdn, type=record_type)
        return True

    async def list_records(
        self,
        zone: str,
        name_pattern: str | None = None,
        record_type: str | None = None,
    ) -> AsyncIterator[dict]:
        """List DNS records in NS1 zone.

        Always fetches fresh zone data to avoid returning stale records.
        """
        domain = zone.lower().rstrip(".")
        client = await self._get_client()

        logger.debug(
            "Listing records",
            zone=zone,
            name_pattern=name_pattern,
            record_type=record_type,
        )

        # Always fetch fresh zone data — cached data goes stale after
        # create/delete operations and the records list would be wrong.
        response = await client.get(f"/zones/{domain}")
        if response.status_code == 404:
            return
        response.raise_for_status()
        zone_data = response.json()

        records = zone_data.get("records", [])

        for record in records:
            rname = record.get("domain", "")
            rtype = record.get("type", "")

            if record_type and rtype != record_type:
                continue

            if name_pattern and name_pattern not in rname:
                continue

            # Fetch full record details for answers
            try:
                resp = await client.get(f"/zones/{domain}/{rname}/{rtype}")
                if resp.status_code != 200:
                    logger.debug(
                        "Skipping record (non-200 response)",
                        fqdn=rname,
                        type=rtype,
                        status=resp.status_code,
                    )
                    continue
                full_record = resp.json()
            except httpx.HTTPError as exc:
                logger.debug(
                    "Skipping record (HTTP error)",
                    fqdn=rname,
                    type=rtype,
                    error=str(exc),
                )
                continue

            values = self._extract_values(full_record.get("answers", []))
            short_name = rname.replace(f".{domain}", "") if rname != domain else "@"

            yield {
                "name": short_name,
                "fqdn": rname,
                "type": rtype,
                "ttl": full_record.get("ttl", 0),
                "values": values,
            }

    async def zone_exists(self, zone: str) -> bool:
        """Check if zone exists in NS1.

        Returns False (rather than raising) on any API or network error,
        since the zone is effectively inaccessible.
        """
        try:
            await self._get_zone(zone)
            return True
        except (ValueError, httpx.HTTPStatusError):
            return False
        except Exception as exc:
            logger.warning(
                "Failed to check zone existence in NS1",
                zone=zone,
                error=str(exc),
            )
            return False

    async def get_record(
        self,
        zone: str,
        name: str,
        record_type: str,
    ) -> dict | None:
        """
        Get a specific DNS record by querying NS1 API directly.

        More efficient than list_records for single record lookup.
        """
        await self._get_zone(zone)
        client = await self._get_client()
        domain, fqdn = self._normalize(zone, name)

        # A 404 is the one signal that means "record absent" — return None for it.
        # Every other failure (5xx, auth, network, a malformed body) MUST propagate:
        # swallowing it to None makes a transient error indistinguishable from
        # "record absent", which lets callers such as publisher._unpublish disarm
        # their masked-failure guard and de-index a still-live agent. Applies the
        # "only the real not-found signal returns None" contract that
        # CloudflareBackend.get_record also uses.
        response = await client.get(f"/zones/{domain}/{fqdn}/{record_type}")
        if response.status_code == 404:
            return None
        response.raise_for_status()
        data = response.json()

        return {
            "name": name,
            "fqdn": fqdn,
            "type": record_type,
            "ttl": data.get("ttl", 0),
            "values": self._extract_values(data.get("answers", [])),
        }

    async def list_zones(self) -> list[dict]:
        """List all zones accessible with the API key.

        Returns:
            List of zone info dicts with zone name, record count, and name servers.
        """
        client = await self._get_client()
        response = await client.get("/zones")
        response.raise_for_status()

        zones = []
        for z in response.json():
            zones.append(
                {
                    "name": z.get("zone", ""),
                    "record_count": len(z.get("records", [])),
                    "dns_servers": z.get("dns_servers", []),
                    "ttl": z.get("ttl", 0),
                }
            )
        return zones

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
            self._client_loop_id = None
