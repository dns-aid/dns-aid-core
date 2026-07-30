# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Cloudflare DNS backend.

Creates DNS-AID records (SVCB, TXT) in Cloudflare managed zones.
Supports zone ID or automatic zone lookup by domain name.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator
from typing import Any

import httpx
import structlog

from dns_aid.backends.base import DNSBackend

logger = structlog.get_logger(__name__)

# Cloudflare API error code returned when an identical record already exists.
# Used to make create-then-update idempotent under concurrent publishes.
_CF_ERR_IDENTICAL_RECORD = 81058

# Cloudflare rate-limiting: the documented cap is 1,200 requests per 5-minute
# window. All API traffic routes through ``_request`` so a 429 is retried
# uniformly — honouring ``Retry-After`` when present, otherwise backing off
# exponentially from ``_CF_RETRY_BASE_DELAY`` up to ``_CF_MAX_RETRY_DELAY``.
_CF_MAX_RETRIES = 3
_CF_RETRY_BASE_DELAY = 1.0
_CF_MAX_RETRY_DELAY = 30.0


def _escape_dns_char_string(value: str) -> str:
    """Escape backslashes and double quotes for a DNS presentation-format string.

    Shared by the TXT and SVCB writers so a value carrying a ``"`` or ``\\``
    survives Cloudflare's presentation-format parser as a single, intact token
    rather than terminating the quoted string early.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _quote_txt_value(value: str) -> str:
    """Wrap a single TXT value as one RFC 1035 <character-string>.

    Embedded backslashes and double quotes are escaped so the value survives
    Cloudflare's presentation-format parser as a single string.
    """
    return f'"{_escape_dns_char_string(value)}"'


def _parse_txt_content(content: str) -> list[str]:
    """Parse a Cloudflare TXT ``content`` string into its character-strings.

    Cloudflare returns TXT rdata in DNS presentation format (RFC 1035 §5.1):
    one or more double-quoted (or bare) ``<character-string>`` tokens separated
    by whitespace, e.g. ``"cap=..." "version=1.0.0"``. This is a DNS master-file
    tokenizer, not a shell one — ``shlex`` was wrong for two live cases: a bare
    apostrophe (``it's fine``) raised ``ValueError`` (dumping the whole blob back
    as a single value), and Cloudflare returns non-ASCII octets as ``\\DDD``
    decimal escapes that ``shlex`` left mangled. This tokenizer:

    * splits on unquoted whitespace while honouring double-quoted tokens,
    * decodes ``\\DDD`` (three decimal digits) to the corresponding octet and
      ``\\X`` to the literal ``X`` (inverting :func:`_escape_dns_char_string`),
    * accumulates decoded octets per token and UTF-8 decodes them together, so a
      multi-byte character split across several ``\\DDD`` escapes round-trips,
    * never raises — an unterminated quote simply ends the final token.

    Matches the read-back behaviour of the Akamai backend and drops the shell
    dependency entirely.
    """
    if not content:
        return []

    values: list[str] = []
    buf = bytearray()
    in_quotes = False
    have_token = False  # a token is "open" (covers a quoted empty string)
    i = 0
    n = len(content)

    def flush() -> None:
        nonlocal have_token
        if have_token:
            values.append(buf.decode("utf-8", errors="replace"))
            buf.clear()
            have_token = False

    while i < n:
        c = content[i]

        if c == "\\" and i + 1 < n:
            nxt = content[i + 1]
            # \DDD decimal octet escape: exactly three ASCII digits, value
            # 0–255. Use isascii()+isdecimal() rather than isdigit() — the
            # latter is True for characters int() can't parse (superscripts) and
            # for non-ASCII/full-width digits, which would either crash or
            # silently misdecode. RFC 1035 \DDD is strictly ASCII decimal.
            esc = content[i + 1 : i + 4]
            if len(esc) == 3 and esc.isascii() and esc.isdecimal() and int(esc) <= 255:
                buf.append(int(esc))
                i += 4
            else:
                # \X — emit the escaped character literally.
                buf.extend(nxt.encode("utf-8"))
                i += 2
            have_token = True
            continue

        if c == '"':
            in_quotes = not in_quotes
            have_token = True
            i += 1
            continue

        if c.isspace() and not in_quotes:
            flush()
            i += 1
            continue

        buf.extend(c.encode("utf-8"))
        have_token = True
        i += 1

    flush()
    return values


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

    @staticmethod
    def _retry_after_seconds(response: httpx.Response) -> float | None:
        """Return the ``Retry-After`` delay in seconds, if the header is usable.

        Cloudflare sends ``Retry-After`` as an integer number of seconds. A
        missing or unparseable header returns ``None`` so the caller falls back
        to exponential backoff.
        """
        raw = response.headers.get("Retry-After")
        if raw is None:
            return None
        try:
            return max(0.0, float(raw))
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _is_rate_limited(response: httpx.Response) -> bool:
        """Report whether a response signals Cloudflare rate limiting.

        A genuine throttle is HTTP 429. As defence-in-depth we also treat an
        HTTP 200 body carrying a ``success: false`` rate-limit error as
        throttled, in case a limit ever surfaces as something other than a clean
        429. Non-200 responses are left untouched — parsing an error body here
        would undermine the ``get_record`` contract that only an empty result
        set means "not found" while auth/network/server errors propagate.
        """
        if response.status_code == 429:
            return True
        if response.status_code != 200:
            return False
        try:
            data = response.json()
        except Exception:
            return False
        if not isinstance(data, dict) or data.get("success", True):
            return False
        errors = data.get("errors") or []
        return any(
            "rate limit" in str(e.get("message", "")).lower() for e in errors if isinstance(e, dict)
        )

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """Issue an HTTP request, transparently retrying on rate limiting.

        All Cloudflare API traffic (reads, writes, deletes) routes through here
        so a 429 is handled the same way everywhere. On a rate-limited response
        we honour ``Retry-After`` when present, otherwise back off exponentially
        — both bounded by :data:`_CF_MAX_RETRY_DELAY` so a hostile or
        misconfigured ``Retry-After`` cannot stall the publish path — for up to
        :data:`_CF_MAX_RETRIES` retries. If the limit still has not cleared we
        raise, rather than hand back a throttled body: otherwise a persistent
        200 ``success: false`` rate-limit response would parse to an empty
        result and be misread by ``get_record``/``list_*`` as "not found" or an
        empty zone. Other status interpretation (``raise_for_status``, the 81058
        idempotency check, ``success`` parsing) stays at the call sites.
        """
        client = await self._get_client()
        send = getattr(client, method.lower())
        delay = _CF_RETRY_BASE_DELAY

        response = await send(path, **kwargs)
        for attempt in range(_CF_MAX_RETRIES):
            if not self._is_rate_limited(response):
                return response
            header_wait = self._retry_after_seconds(response)
            if header_wait is None:
                wait = delay
                delay = min(delay * 2, _CF_MAX_RETRY_DELAY)
            else:
                wait = min(header_wait, _CF_MAX_RETRY_DELAY)
            logger.warning(
                "Cloudflare rate limited; backing off before retry",
                method=method,
                path=path,
                attempt=attempt + 1,
                max_retries=_CF_MAX_RETRIES,
                wait_seconds=wait,
            )
            await asyncio.sleep(wait)
            response = await send(path, **kwargs)

        if self._is_rate_limited(response):
            raise ValueError(
                f"Cloudflare rate limit not cleared after {_CF_MAX_RETRIES} retries "
                f"({method} {path}); giving up rather than masking as an empty result"
            )
        return response

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

        # List zones and find matching one
        response = await self._request("GET", "/zones", params={"name": domain})
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
        response = await self._request(
            "GET",
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
        # publish_agent's params are already validated at the model boundary
        # (validate_svcparam_value rejects embedded quotes/backslashes/control
        # chars), but create_svcb_record is public and can be called directly
        # with an arbitrary params dict, so escape here for defense-in-depth —
        # symmetric with the TXT writer.
        param_parts = []
        for key, value in params.items():
            param_parts.append(f'{key}="{_escape_dns_char_string(value)}"')
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

        The 81058 idempotency shortcut applies **only to a POST**. Cloudflare
        permits multiple records at one name and ``_get_record_id`` returns the
        first, so a PUT that hits 81058 means the update collided with a
        *different* record at the same name — the record we targeted was *not*
        changed. Treating that as success would tell the caller we wrote when we
        did not, so on a PUT 81058 falls through and raises.

        Any other non-success response raises ``ValueError`` carrying the
        Cloudflare error payload (more actionable than a bare ``HTTPStatusError``
        and uniform whether the failure arrives as a 4xx/5xx or as a 200 with
        ``success: false``).
        """
        # Track whether the response we ultimately interpret came from a POST,
        # since 81058 is only idempotent success for a create (see docstring).
        wrote_via_post: bool

        if existing_id:
            response = await self._request(
                "PUT",
                f"/zones/{zone_id}/dns_records/{existing_id}",
                json=request_data,
            )
            wrote_via_post = False
            # Delete race: the record vanished between lookup and update.
            if response.status_code == 404:
                logger.info(
                    "Record vanished before update; recreating",
                    fqdn=fqdn,
                    type=record_type,
                )
                response = await self._request(
                    "POST",
                    f"/zones/{zone_id}/dns_records",
                    json=request_data,
                )
                wrote_via_post = True
        else:
            response = await self._request(
                "POST",
                f"/zones/{zone_id}/dns_records",
                json=request_data,
            )
            wrote_via_post = True

        try:
            data = response.json()
        except ValueError:
            # Non-JSON body (e.g. an edge 5xx returning HTML).
            data = {}

        # Create race: an identical record already exists — idempotent success,
        # but only for a POST. A PUT hitting 81058 collided with a different
        # record at the same name and did not apply, so let it raise below.
        if (
            wrote_via_post
            and response.status_code == 400
            and any(e.get("code") == _CF_ERR_IDENTICAL_RECORD for e in (data.get("errors") or []))
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

        # A success response should always carry result.id, but guard against a
        # null/absent result rather than raising KeyError on a surprising body.
        record_id = (data.get("result") or {}).get("id")
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
        # and any value containing a space. Like the Route 53 backend's
        # per-value quoting, but additionally escaping embedded quotes and
        # backslashes (which Route 53's writer does not).
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
        response = await self._request("DELETE", f"/zones/{zone_id}/dns_records/{record_id}")
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
            response = await self._request("GET", f"/zones/{zone_id}/dns_records", params=params)
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

        # Build FQDN
        fqdn = f"{name}.{zone}".rstrip(".")

        response = await self._request(
            "GET",
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
        zones = []

        page = 1
        while True:
            response = await self._request("GET", "/zones", params={"page": page, "per_page": 50})
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
