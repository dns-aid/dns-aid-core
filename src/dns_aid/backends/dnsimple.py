# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
DNSimple DNS backend.

Creates DNS-AID records (SVCB, TXT) in DNSimple zones.
Uses the DNSimple API v2 with an API access token.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import httpx
import structlog

from dns_aid.backends.base import DNSBackend

logger = structlog.get_logger(__name__)

DEFAULT_BASE_URL = "https://api.dnsimple.com"
"""DNSimple API base URL.  Override via ``DNSIMPLE_BASE_URL`` env var to use
the sandbox environment (https://api.sandbox.dnsimple.com)."""


def _decode_txt_content(content: str) -> str:
    """
    Decode TXT content from DNS presentation format.

    Join the quoted character-strings and unescape "\\X" to "X".
    Content that does not start with a quote is returned unchanged.
    """
    if not content.startswith('"'):
        return content

    out: list[str] = []
    in_quotes = False
    i = 0
    while i < len(content):
        c = content[i]
        if c == "\\" and i + 1 < len(content):
            out.append(content[i + 1])
            i += 2
            continue
        if c == '"':
            in_quotes = not in_quotes
        elif in_quotes:
            out.append(c)
        i += 1
    return "".join(out)


class DNSimpleBackend(DNSBackend):
    """
    DNSimple DNS backend using API v2.

    Creates and manages DNS-AID records in DNSimple zones.

    Example:
        >>> backend = DNSimpleBackend()
        >>> await backend.create_svcb_record(
        ...     zone="example.com",
        ...     name="_chat._a2a._agents",
        ...     priority=1,
        ...     target="chat.example.com.",
        ...     params={"alpn": "a2a", "port": "443"}
        ... )

    Environment Variables:
        DNSIMPLE_TOKEN: DNSimple API access token
        DNSIMPLE_ACCOUNT_ID: DNSimple account ID (optional for account tokens)
        DNSIMPLE_BASE_URL: API base URL (default: https://api.dnsimple.com)
    """

    def __init__(
        self,
        token: str | None = None,
        account_id: str | None = None,
        base_url: str | None = None,
    ):
        """
        Initialize DNSimple backend.

        Args:
            token: DNSimple API access token (defaults to DNSIMPLE_TOKEN env var)
            account_id: DNSimple account ID (defaults to DNSIMPLE_ACCOUNT_ID
                        env var; if not set, it is resolved from /v2/whoami)
            base_url: API base URL (defaults to DNSIMPLE_BASE_URL env var
                      or https://api.dnsimple.com)
        """
        self._token = token or os.environ.get("DNSIMPLE_TOKEN")
        self._account_id = account_id or os.environ.get("DNSIMPLE_ACCOUNT_ID")
        self._base_url = (base_url or os.environ.get("DNSIMPLE_BASE_URL", DEFAULT_BASE_URL)).rstrip(
            "/"
        )
        self._client: httpx.AsyncClient | None = None
        self._client_loop_id: int | None = None
        self._zone_cache: dict[str, dict] = {}

    @property
    def name(self) -> str:
        return "dnsimple"

    @property
    def supports_private_svcb_keys(self) -> bool:
        """DNSimple accepts private-use SVCB keys (key65280–key65534) natively."""
        return True

    def _normalize(self, zone: str, name: str | None = None) -> tuple[str, str]:
        """Normalize zone and build FQDN.

        Returns:
            (domain, fqdn) tuple with trailing dots stripped.
        """
        domain = zone.lower().rstrip(".")
        fqdn = f"{name}.{domain}" if name else domain
        return domain, fqdn

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
            if not self._token:
                raise ValueError(
                    "DNSimple API token not configured. "
                    "Set DNSIMPLE_TOKEN environment variable or pass token parameter."
                )
            from dns_aid import __version__

            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                headers={
                    "Authorization": f"Bearer {self._token}",
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "User-Agent": f"dns-aid/{__version__}",
                },
                timeout=30.0,
            )
            self._client_loop_id = current_loop_id
        return self._client

    async def _get_account_id(self) -> str:
        """
        Get the DNSimple account ID.

        Uses the configured account ID. If none is configured, gets it from
        the /v2/whoami endpoint and keeps it for later calls.

        Returns:
            Account ID as a string

        Raises:
            ValueError: If the token is not an account token and no account
                ID is configured
        """
        if self._account_id:
            return self._account_id

        client = await self._get_client()
        response = await client.get("/v2/whoami")
        response.raise_for_status()

        account = response.json().get("data", {}).get("account")
        if not account:
            raise ValueError(
                "DNSimple account ID not configured and the token is not an "
                "account token. Set DNSIMPLE_ACCOUNT_ID environment variable "
                "or pass account_id parameter."
            )

        self._account_id = str(account["id"])
        logger.debug("Resolved DNSimple account", account_id=self._account_id)
        return self._account_id

    async def _get_zone(self, zone: str) -> dict:
        """
        Get DNSimple zone metadata.

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

        account_id = await self._get_account_id()
        client = await self._get_client()

        response = await client.get(f"/v2/{account_id}/zones/{domain}")
        if response.status_code == 404:
            raise ValueError(f"No zone found for domain: {zone}")
        response.raise_for_status()

        data = response.json()["data"]
        self._zone_cache[domain] = data
        logger.debug("Found zone", domain=domain, zone_id=data.get("id"))
        return data

    async def _records_path(self, domain: str) -> str:
        """Return the API path for the records of a zone."""
        account_id = await self._get_account_id()
        return f"/v2/{account_id}/zones/{domain}/records"

    async def _get_records(self, domain: str, params: dict, missing_ok: bool = False) -> list[dict]:
        """
        Get all records in a zone that match the query params.

        Follows all result pages.

        Args:
            domain: Normalized zone name (e.g., "example.com")
            params: Query params (filters) for the records request
            missing_ok: If True, a 404 response gives an empty list

        Returns:
            List of DNSimple record dicts
        """
        path = await self._records_path(domain)
        client = await self._get_client()

        records: list[dict] = []
        page = 1
        while True:
            response = await client.get(path, params={**params, "page": page, "per_page": 100})
            if missing_ok and response.status_code == 404:
                return records
            response.raise_for_status()
            body = response.json()
            records.extend(body.get("data", []))
            total_pages = body.get("pagination", {}).get("total_pages", 1)
            if page >= total_pages:
                return records
            page += 1

    async def _find_records(self, domain: str, name: str, record_type: str) -> list[dict]:
        """
        Find all records in a zone with the given name and type.

        Args:
            domain: Normalized zone name (e.g., "example.com")
            name: Record name relative to the zone
            record_type: Record type (e.g., "SVCB", "TXT")

        Returns:
            List of DNSimple record dicts
        """
        return await self._get_records(domain, {"name": name, "type": record_type})

    async def _delete_records(self, domain: str, records: list[dict]) -> None:
        """
        Delete the given records from a zone.

        A 404 response is not an error: the record is already gone.
        """
        path = await self._records_path(domain)
        client = await self._get_client()

        for record in records:
            response = await client.delete(f"{path}/{record['id']}")
            if response.status_code == 404:
                continue
            response.raise_for_status()

    async def _replace_records(
        self,
        domain: str,
        name: str,
        record_type: str,
        contents: list[str],
        ttl: int,
    ) -> None:
        """
        Replace all records with the given name and type.

        The DNSimple API has no atomic replace operation. Thus, do the
        changes in an order that keeps the existing records if the API
        refuses a change:

        1. Keep each existing record that has a new value. Update its TTL
           if necessary.
        2. Update the other existing records in place with the remaining
           new values.
        3. Create one record for each new value that is still remaining.
        4. Delete the existing records that are not necessary.

        If a step 1-3 request fails, undo the changes of steps 1-3 and
        raise the error. The API refuses a record that is equal to an
        existing record. Step 1 prevents this error.
        """
        existing = await self._find_records(domain, name, record_type)

        remaining = list(contents)
        unmatched: list[dict] = []
        updates: list[tuple[dict, dict]] = []
        for record in existing:
            value = self._record_value(record)
            if value in remaining:
                remaining.remove(value)
                if record.get("ttl") != ttl:
                    updates.append((record, {"ttl": ttl}))
            else:
                unmatched.append(record)

        for record, content in zip(unmatched, remaining, strict=False):
            updates.append((record, {"content": content, "ttl": ttl}))
        creates = remaining[len(unmatched) :]
        deletes = unmatched[len(remaining) :]

        path = await self._records_path(domain)
        client = await self._get_client()

        updated: list[dict] = []
        created: list[dict] = []
        try:
            for record, payload in updates:
                response = await client.patch(f"{path}/{record['id']}", json=payload)
                response.raise_for_status()
                updated.append(record)
            for content in creates:
                response = await client.post(
                    path,
                    json={"name": name, "type": record_type, "content": content, "ttl": ttl},
                )
                response.raise_for_status()
                created.append(response.json()["data"])
        except Exception:
            await self._undo_replace(domain, updated, created)
            raise

        await self._delete_records(domain, deletes)

    async def _undo_replace(self, domain: str, updated: list[dict], created: list[dict]) -> None:
        """
        Undo the changes of a failed replacement.

        Delete the created records and set the updated records back to
        their old content and TTL. Send the old content as the API gave it.
        Do not send the decoded TXT value: the API reads a value that starts
        with a quote as serialized TXT content, thus a decoded value that has
        literal quotes would change. Log a failure, but do not raise it, so
        that the caller can raise the first error.
        """
        path = await self._records_path(domain)
        client = await self._get_client()

        for record in created:
            try:
                response = await client.delete(f"{path}/{record['id']}")
                if response.status_code != 404:
                    response.raise_for_status()
            except Exception as exc:
                logger.error(
                    "Failed to delete record after failed replacement",
                    domain=domain,
                    record_id=record.get("id"),
                    error=str(exc),
                )

        for record in updated:
            try:
                response = await client.patch(
                    f"{path}/{record['id']}",
                    json={"content": record.get("content"), "ttl": record.get("ttl")},
                )
                response.raise_for_status()
            except Exception as exc:
                logger.error(
                    "Failed to restore record after failed replacement",
                    domain=domain,
                    record_id=record.get("id"),
                    error=str(exc),
                )

    @staticmethod
    def _record_value(record: dict) -> str:
        """Return the value of an API record. Decode TXT content."""
        content = record.get("content", "")
        if record.get("type") == "TXT":
            return _decode_txt_content(content)
        return content

    def _group_records(self, domain: str, records: list[dict]) -> list[dict]:
        """Group API records by (name, type) in first-seen order."""
        groups: dict[tuple[str, str], dict] = {}
        for record in records:
            name = record.get("name", "")
            rtype = record.get("type", "")
            group = groups.get((name, rtype))
            if group is None:
                group = {
                    "name": name or "@",
                    "fqdn": self._normalize(domain, name)[1],
                    "type": rtype,
                    "ttl": record.get("ttl"),
                    "values": [],
                }
                groups[(name, rtype)] = group
            group["values"].append(self._record_value(record))
        return list(groups.values())

    @staticmethod
    def _format_svcb_content(priority: int, target: str, params: dict[str, str]) -> str:
        """
        Format SVCB record content as a presentation format string.

        The DNSimple API refuses a target with a trailing dot ("Target can't
        have empty labels"). Thus, remove the trailing dot. Keep the root
        target "." as it is.

        The DNSimple API refuses a backslash in a param value ("must not
        contain backslashes"). A double quote in a param value stops the
        quoted string, also when it is escaped. Thus, the API cannot keep a
        param value that has one of these characters. Refuse such a value
        before a request is sent, so that the existing records do not change.

        Raises:
            ValueError: If a param value has a backslash or a double quote
        """
        if target != "." and target.endswith("."):
            target = target[:-1]

        for key, value in params.items():
            if "\\" in value or '"' in value:
                raise ValueError(
                    f"DNSimple does not accept a backslash or a double quote in an "
                    f"SVCB param value: {key}={value!r}"
                )

        params_str = " ".join(f'{key}="{value}"' for key, value in params.items())

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
        """Create SVCB record in DNSimple."""
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

        content = self._format_svcb_content(priority, target, params)
        await self._replace_records(domain, name, "SVCB", [content], ttl)
        logger.info("SVCB record created", fqdn=fqdn)
        return fqdn

    async def create_txt_record(
        self,
        zone: str,
        name: str,
        values: list[str],
        ttl: int = 3600,
    ) -> str:
        """Create TXT record in DNSimple.

        Creates one API record for each value. The content is the raw value;
        the DNSimple API adds the quotes.
        """
        await self._get_zone(zone)
        domain, fqdn = self._normalize(zone, name)

        logger.info(
            "Creating TXT record",
            zone=zone,
            name=fqdn,
            values=values,
            ttl=ttl,
        )

        await self._replace_records(domain, name, "TXT", values, ttl)
        logger.info("TXT record created", fqdn=fqdn)
        return fqdn

    async def delete_record(
        self,
        zone: str,
        name: str,
        record_type: str,
    ) -> bool:
        """Delete all DNS records with the given name and type from DNSimple."""
        await self._get_zone(zone)
        domain, fqdn = self._normalize(zone, name)

        logger.info(
            "Deleting record",
            zone=zone,
            name=fqdn,
            type=record_type,
        )

        records = await self._find_records(domain, name, record_type)
        if not records:
            logger.warning("Record not found", fqdn=fqdn, type=record_type)
            return False

        await self._delete_records(domain, records)
        logger.info("Record deleted", fqdn=fqdn, type=record_type)
        return True

    async def list_records(
        self,
        zone: str,
        name_pattern: str | None = None,
        record_type: str | None = None,
    ) -> AsyncIterator[dict]:
        """List DNS records in DNSimple zone.

        Yields one dict for each (name, type) group. A 404 for the zone
        yields nothing.
        """
        domain, _ = self._normalize(zone)
        params = {"type": record_type} if record_type else {}
        records = await self._get_records(domain, params, missing_ok=True)

        for group in self._group_records(domain, records):
            if name_pattern and name_pattern not in group["fqdn"]:
                continue
            yield group

    async def zone_exists(self, zone: str) -> bool:
        """Check if zone exists in DNSimple.

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
                "Failed to check zone existence in DNSimple",
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
        """Get a specific DNS record with one filtered DNSimple API lookup."""
        domain, _ = self._normalize(zone)

        # Only the real not-found signal (no matching records) returns None.
        # Every other failure MUST propagate: if we swallow it to None, a
        # transient error looks like "record absent", which disarms the
        # masked-failure guard of publisher._unpublish.
        records = await self._find_records(domain, name, record_type)
        if not records:
            return None
        return self._group_records(domain, records)[0]

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
            self._client_loop_id = None
