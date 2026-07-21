# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Cloudflare DNS backend.

Creates DNS-AID records (SVCB, TXT) in Cloudflare managed zones.
Supports zone ID or automatic zone lookup by domain name.
"""

from __future__ import annotations

import os
import shlex
from collections.abc import AsyncIterator
from typing import Any

import httpx
import structlog

from dns_aid.backends.base import DNSBackend

logger = structlog.get_logger(__name__)

# Cloudflare API error code returned when an identical record already exists.
# Used to make create-then-update idempotent under concurrent publishes.
_CF_ERR_IDENTICAL_RECORD = 81058


def _quote_txt_value(value: str) -> str:
    """Wrap a single TXT value as one RFC 1035 <character-string>.

    Embedded backslashes and double quotes are escaped so the value survives
    Cloudflare's presentation-format parser as a single string.
    """
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _parse_txt_content(content: str) -> list[str]:
    """Parse a Cloudflare TXT ``content`` string into its character-strings.

    Cloudflare returns TXT rdata in DNS presentation format: one or more
    double-quoted (or bare) character-strings separated by whitespace, e.g.
    ``"cap=..." "version=1.0.0"``. ``shlex`` splits on whitespace while
    honouring quotes and backslash escapes, which matches DNS master-file
    semantics and inverts :func:`_quote_txt_value`.
    """
    if not content:
        return []
    try:
        return shlex.split(content)
    except ValueError:
        # Unbalanced quotes (shouldn't happen from Cloudflare) — fall back to
        # returning the raw content as a single value rather than raising.
        logger.debug("Unparseable TXT content; returning raw", content=content)
        return [content]


class CloudflareBackend(DNSBackend):
    """
    Cloudflare DNS backend using REST API v4.

    Creates and manages DNS-AID records in Cloudflare zones.

    Example:
        >>> backend = CloudflareBackend()
        >>> await backend.create_svcb_record(
        ...     zone="example.com",
        ...     name="_chat._a2a._agents",
        ...     priority=1,
        ...     target="chat.example.com.",
        ...     params={"alpn": "a2a", "port": "443"}
        ... )

    Environment Variables:
        CLOUDFLARE_API_TOKEN: API token with DNS edit permissions
        CLOUDFLARE_ZONE_ID: Optional zone ID (otherwise looked up by domain)
    """

    def __init__(
        self,
        api_token: str | None = None,
        zone_id: str | None = None,
    ):
        """
        Initialize Cloudflare backend.

        Args:
            api_token: Cloudflare API token (defaults to CLOUDFLARE_API_TOKEN env var)
            zone_id: Optional zone ID. If not provided, will be looked up by domain.
        """
        self._api_token = api_token or os.environ.get("CLOUDFLARE_API_TOKEN")
        self._zone_id = zone_id or os.environ.get("CLOUDFLARE_ZONE_ID")
        self._client: httpx.AsyncClient | None = None
        self._client_loop_id: int | None = None  # Track which loop the client belongs to
        self._zone_cache: dict[str, str] = {}  # domain -> zone_id
        self._base_url = "https://api.cloudflare.com/client/v4"

    @property
    def name(self) -> str:
        return "cloudflare"

    @property
    def supports_private_svcb_keys(self) -> bool:
        """Cloudflare accepts private-use SVCB keys (key65280–key65534) natively.

        Verified against the Cloudflare API v4: the SVCB record ``data.value``
        field accepts RFC 9460 generic private-use SvcParamKeys in ``keyNNNNN``
        form (e.g. the DNS-AID ``key65400``–``key65409`` set for cap, cap-sha256,
        bap, policy, realm, ...). They are stored and served verbatim, so the
        base class passes all params straight to the SVCB record instead of
        demoting the DNS-AID custom keys to TXT.
        """
        return True

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create httpx async client.

        Note: Recreates client if the event loop has changed (e.g., when CLI
        uses multiple asyncio.run() calls). This is necessary because httpx
        clients are bound to the event loop they were created in.
        """
        import asyncio

        current_loop_id = id(asyncio.get_running_loop())

        # Check if we need to recreate the client due to loop change
        if self._client is not None and self._client_loop_id != current_loop_id:
            # Event loop has changed - close old client and create new one
            import contextlib

            with contextlib.suppress(Exception):
                await self._client.aclose()
            self._client = None
            self._client_loop_id = None

        if self._client is None:
            if not self._api_token:
                raise ValueError(
                    "Cloudflare API token not configured. "
                    "Set CLOUDFLARE_API_TOKEN environment variable or pass api_token parameter."
                )
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                headers={
                    "Authorization": f"Bearer {self._api_token}",
                    "Content-Type": "application/json",
                },
                timeout=30.0,
            )
            self._client_loop_id = current_loop_id
        return self._client

    async def _get_zone_id(self, zone: str) -> str:
        """
        Get Cloudflare zone ID for a domain.

        Args:
            zone: Domain name (e.g., "example.com")

        Returns:
            Zone ID

        Raises:
            ValueError: If zone not found
        """
        # Use configured zone ID if set
        if self._zone_id:
            return self._zone_id

        # Check cache
        domain = zone.lower().rstrip(".")
        if domain in self._zone_cache:
            return self._zone_cache[domain]

        client = await self._get_client()

        # List zones and find matching one
        response = await client.get("/zones", params={"name": domain})
        response.raise_for_status()
        data = response.json()

        if not data.get("success"):
            errors = data.get("errors", [])
            raise ValueError(f"Cloudflare API error: {errors}")

        zones = data.get("result", [])
        if not zones:
            raise ValueError(f"No zone found for domain: {zone}")

        zone_id = zones[0]["id"]
        self._zone_cache[domain] = zone_id
        logger.debug("Found zone ID", domain=domain, zone_id=zone_id)
        return zone_id

    async def _get_record_id(
        self,
        zone_id: str,
        fqdn: str,
        record_type: str,
    ) -> str | None:
        """
        Get record ID for a specific record.

        Args:
            zone_id: Cloudflare zone ID
            fqdn: Fully qualified domain name
            record_type: DNS record type (SVCB, TXT, etc.)

        Returns:
            Record ID if found, None otherwise
        """
        client = await self._get_client()

        response = await client.get(
            f"/zones/{zone_id}/dns_records",
            params={"name": fqdn, "type": record_type},
        )
        response.raise_for_status()
        data = response.json()

        records = data.get("result", [])
        if records:
            return records[0]["id"]
        return None

    def _format_svcb_data(
        self,
        priority: int,
        target: str,
        params: dict[str, str],
    ) -> dict[str, Any]:
        """
        Format SVCB record data for Cloudflare API.

        Cloudflare uses a structured data object for SVCB records.
        """
        # Ensure target has trailing dot for Cloudflare
        if not target.endswith("."):
            target = f"{target}."

        # Build the value string for SVCB params
        # Format: alpn="mcp" port="443"
        param_parts = []
        for key, value in params.items():
            param_parts.append(f'{key}="{value}"')
        value_str = " ".join(param_parts) if param_parts else ""

        return {
            "priority": priority,
            "target": target,
            "value": value_str,
        }

    async def _write_record(
        self,
        zone_id: str,
        fqdn: str,
        record_type: str,
        request_data: dict[str, Any],
        existing_id: str | None,
    ) -> str:
        """Create (POST) or update (PUT) a record; idempotent under both races.

        There is an unavoidable check-then-act window between looking up an
        existing record id (``_get_record_id``) and writing. A concurrent
        publisher can change the world in that window in two ways, and this
        method converges on the intended state for both:

        * **Create race** — we found no existing record and POST, but a racer
          created an identical one first. Cloudflare answers HTTP 400 with error
          code 81058 ("An identical record already exists"). For an idempotent
          upsert that is success, not failure, so we return the fqdn.
        * **Delete race** — we found an existing id and PUT, but a racer deleted
          it first, so the PUT 404s. We recreate the record with a POST.

        Any other non-success response raises ``ValueError`` carrying the
        Cloudflare error payload (more actionable than a bare ``HTTPStatusError``
        and uniform whether the failure arrives as a 4xx/5xx or as a 200 with
        ``success: false``).
        """
        client = await self._get_client()

        if existing_id:
            response = await client.put(
                f"/zones/{zone_id}/dns_records/{existing_id}",
                json=request_data,
            )
            # Delete race: the record vanished between lookup and update.
            if response.status_code == 404:
                logger.info(
                    "Record vanished before update; recreating",
                    fqdn=fqdn,
                    type=record_type,
                )
                response = await client.post(
                    f"/zones/{zone_id}/dns_records",
                    json=request_data,
                )
        else:
            response = await client.post(
                f"/zones/{zone_id}/dns_records",
                json=request_data,
            )

        try:
            data = response.json()
        except ValueError:
            # Non-JSON body (e.g. an edge 5xx returning HTML).
            data = {}

        # Create race: an identical record already exists — idempotent success.
        if response.status_code == 400 and any(
            e.get("code") == _CF_ERR_IDENTICAL_RECORD for e in (data.get("errors") or [])
        ):
            logger.info(
                "Record already exists; treating as idempotent success",
                fqdn=fqdn,
                type=record_type,
            )
            return fqdn

        if not data.get("success", False):
            errors = data.get("errors") or []
            raise ValueError(
                f"Failed to write {record_type} record (HTTP {response.status_code}): {errors}"
            )

        record_id = data["result"]["id"]
        logger.info("Record written", fqdn=fqdn, type=record_type, record_id=record_id)
        return fqdn

    async def create_svcb_record(
        self,
        zone: str,
        name: str,
        priority: int,
        target: str,
        params: dict[str, str],
        ttl: int = 3600,
    ) -> str:
        """Create SVCB record in Cloudflare."""
        zone_id = await self._get_zone_id(zone)

        # Build FQDN
        fqdn = f"{name}.{zone}".rstrip(".")

        logger.info(
            "Creating SVCB record",
            zone=zone,
            zone_id=zone_id,
            name=fqdn,
            priority=priority,
            target=target,
            params=params,
            ttl=ttl,
        )

        # Check if record exists (for update)
        existing_id = await self._get_record_id(zone_id, fqdn, "SVCB")

        # Prepare request data
        svcb_data = self._format_svcb_data(priority, target, params)
        request_data = {
            "type": "SVCB",
            "name": fqdn,
            "data": svcb_data,
            "ttl": ttl,
        }

        return await self._write_record(zone_id, fqdn, "SVCB", request_data, existing_id)

    async def create_txt_record(
        self,
        zone: str,
        name: str,
        values: list[str],
        ttl: int = 3600,
    ) -> str:
        """Create TXT record in Cloudflare."""
        zone_id = await self._get_zone_id(zone)

        # Build FQDN
        fqdn = f"{name}.{zone}".rstrip(".")

        logger.info(
            "Creating TXT record",
            zone=zone,
            zone_id=zone_id,
            name=fqdn,
            values=values,
            ttl=ttl,
        )

        # Check if record exists (for update)
        existing_id = await self._get_record_id(zone_id, fqdn, "TXT")

        # Each value must be its own RFC 1035 <character-string>. Cloudflare's
        # "content" field is DNS presentation format, so we wrap each value in
        # double quotes (escaping embedded quotes/backslashes). Space-joining
        # unquoted would collapse all values into a SINGLE character-string on
        # the wire, and the discoverer iterates character-strings one by one
        # (see core/discoverer.py) — merging them corrupts capability parsing
        # and any value containing a space. Mirrors the Route 53 backend.
        content = " ".join(_quote_txt_value(v) for v in values)

        request_data = {
            "type": "TXT",
            "name": fqdn,
            "content": content,
            "ttl": ttl,
        }

        return await self._write_record(zone_id, fqdn, "TXT", request_data, existing_id)

    # publish_agent() is inherited from DNSBackend. Because
    # supports_private_svcb_keys is True, the base class writes DNS-AID's
    # private-use SVCB keys directly to the SVCB record (no TXT demotion).

    async def delete_record(
        self,
        zone: str,
        name: str,
        record_type: str,
    ) -> bool:
        """Delete a DNS record from Cloudflare."""
        zone_id = await self._get_zone_id(zone)
        client = await self._get_client()

        # Build FQDN
        fqdn = f"{name}.{zone}".rstrip(".")

        logger.info(
            "Deleting record",
            zone=zone,
            name=fqdn,
            type=record_type,
        )

        # Find the record
        record_id = await self._get_record_id(zone_id, fqdn, record_type)
        if not record_id:
            logger.warning("Record not found", fqdn=fqdn, type=record_type)
            return False

        # Delete the record
        response = await client.delete(f"/zones/{zone_id}/dns_records/{record_id}")
        response.raise_for_status()
        data = response.json()

        if not data.get("success"):
            errors = data.get("errors", [])
            logger.error("Failed to delete record", errors=errors)
            return False

        logger.info("Record deleted", fqdn=fqdn, type=record_type)
        return True

    async def list_records(
        self,
        zone: str,
        name_pattern: str | None = None,
        record_type: str | None = None,
    ) -> AsyncIterator[dict]:
        """List DNS records in Cloudflare zone."""
        zone_id = await self._get_zone_id(zone)
        client = await self._get_client()

        logger.debug(
            "Listing records",
            zone=zone,
            zone_id=zone_id,
            name_pattern=name_pattern,
            record_type=record_type,
        )

        # Build query params
        params: dict[str, Any] = {"per_page": 100}
        if record_type:
            params["type"] = record_type

        page = 1
        while True:
            params["page"] = page
            response = await client.get(f"/zones/{zone_id}/dns_records", params=params)
            response.raise_for_status()
            data = response.json()

            if not data.get("success"):
                break

            records = data.get("result", [])
            if not records:
                break

            for record in records:
                rname = record["name"]
                rtype = record["type"]

                # Filter by name pattern (simple substring match)
                if name_pattern and name_pattern not in rname:
                    continue

                # Extract values based on record type
                if rtype == "TXT":
                    values = _parse_txt_content(record.get("content", ""))
                elif rtype == "SVCB":
                    # SVCB records have structured data
                    svcb_data = record.get("data", {})
                    priority = svcb_data.get("priority", 0)
                    target = svcb_data.get("target", "")
                    value = svcb_data.get("value", "")
                    values = [f"{priority} {target} {value}".strip()]
                else:
                    values = [record.get("content", "")]

                yield {
                    "name": rname.replace(f".{zone}", ""),
                    "fqdn": rname,
                    "type": rtype,
                    "ttl": record.get("ttl", 0),
                    "values": values,
                    "id": record.get("id"),
                }

            # Check for more pages
            result_info = data.get("result_info", {})
            total_pages = result_info.get("total_pages", 1)
            if page >= total_pages:
                break
            page += 1

    async def zone_exists(self, zone: str) -> bool:
        """Check if zone exists in Cloudflare.

        Returns False (rather than raising) on any API or network error,
        since the zone is effectively inaccessible.
        """
        try:
            await self._get_zone_id(zone)
            return True
        except (ValueError, httpx.HTTPStatusError):
            return False
        except Exception as exc:
            logger.warning(
                "Failed to check zone existence in Cloudflare",
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
        Get a specific DNS record by querying Cloudflare API directly.

        More efficient than list_records for single record lookup.
        """
        zone_id = await self._get_zone_id(zone)
        client = await self._get_client()

        # Build FQDN
        fqdn = f"{name}.{zone}".rstrip(".")

        response = await client.get(
            f"/zones/{zone_id}/dns_records",
            params={"name": fqdn, "type": record_type},
        )
        # A successful query for a non-existent record returns an empty result
        # set, not an error. Only that means "not found" — auth, network, or
        # server errors must propagate rather than be masked as a missing
        # record (which would let reconciliation silently recreate/overwrite).
        response.raise_for_status()
        data = response.json()

        records = data.get("result", [])
        if not records:
            return None

        record = records[0]

        # Extract values based on record type
        if record_type == "TXT":
            values = _parse_txt_content(record.get("content", ""))
        elif record_type == "SVCB":
            svcb_data = record.get("data", {})
            priority = svcb_data.get("priority", 0)
            target = svcb_data.get("target", "")
            value = svcb_data.get("value", "")
            values = [f"{priority} {target} {value}".strip()]
        else:
            values = [record.get("content", "")]

        return {
            "name": name,
            "fqdn": fqdn,
            "type": record_type,
            "ttl": record.get("ttl", 0),
            "values": values,
            "id": record.get("id"),
        }

    async def list_zones(self) -> list[dict]:
        """
        List all zones accessible with the API token.

        Returns:
            List of zone info dicts with id, name, status
        """
        client = await self._get_client()
        zones = []

        page = 1
        while True:
            response = await client.get("/zones", params={"page": page, "per_page": 50})
            response.raise_for_status()
            data = response.json()

            if not data.get("success"):
                break

            for z in data.get("result", []):
                zones.append(
                    {
                        "id": z["id"],
                        "name": z["name"],
                        "status": z["status"],
                        "name_servers": z.get("name_servers", []),
                    }
                )

            result_info = data.get("result_info", {})
            total_pages = result_info.get("total_pages", 1)
            if page >= total_pages:
                break
            page += 1

        return zones

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
