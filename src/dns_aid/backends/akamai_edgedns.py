# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Akamai Edge DNS backend.

Creates DNS-AID records (SVCB, TXT) via the Akamai Edge DNS API v2.
Uses EdgeGrid authentication from the ``edgegrid-python`` package.

Akamai Edge DNS supports private-use SVCB keys (key65280-key65534)
natively, so all DNS-AID custom SvcParams are written directly on the
SVCB record without demotion to TXT.

API Documentation: https://techdocs.akamai.com/edge-dns/reference/api
"""

from __future__ import annotations

import asyncio
import contextlib
import json as json_module
import os
import random
import re
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import quote, urlencode

import httpx
import structlog

from dns_aid.backends.base import DNSBackend

logger = structlog.get_logger(__name__)

# Record types supported by DNS-AID via the Edge DNS API.
_SUPPORTED_RECORD_TYPES = {"SVCB", "TXT"}

# OS-entropy RNG for retry jitter (satisfies bandit B311; jitter itself is not
# security-sensitive, but SystemRandom avoids the shared global PRNG state).
_jitter = random.SystemRandom()


class AkamaiEdgeDNSBackend(DNSBackend):
    """
    Akamai Edge DNS backend using the Config DNS API v2.

    Creates and manages DNS-AID records in Akamai Edge DNS zones.
    Authentication uses the EdgeGrid signing protocol via ``edgegrid-python``.

    Credentials can be supplied via environment variables or an ``.edgerc``
    file (the standard Akamai credential store).

    Example:
        >>> backend = AkamaiEdgeDNSBackend()
        >>> await backend.create_svcb_record(
        ...     zone="example.com",
        ...     name="_chat._a2a._agents",
        ...     priority=1,
        ...     target="chat.example.com.",
        ...     params={"alpn": "a2a", "port": "443"}
        ... )

    Environment Variables:
        AKAMAI_HOST: EdgeGrid API hostname (e.g., akab-xxx.luna.akamaiapis.net)
        AKAMAI_CLIENT_TOKEN: EdgeGrid client token
        AKAMAI_CLIENT_SECRET: EdgeGrid client secret
        AKAMAI_ACCESS_TOKEN: EdgeGrid access token
        AKAMAI_EDGERC: Path to .edgerc file (default: ~/.edgerc)
        AKAMAI_EDGERC_SECTION: Section within .edgerc (default: default)
    """

    # Map DNS-AID draft custom names to private-use keyNNNNN aliases.
    _CUSTOM_PARAM_TO_NUMERIC_KEY = {
        "cap": "key65400",
        "cap-sha256": "key65401",
        "bap": "key65402",
        "policy": "key65403",
        "realm": "key65404",
        "sig": "key65405",
        "connect-class": "key65406",
        "connect-meta": "key65407",
        "enroll-uri": "key65408",
    }
    _NUMERIC_KEY_TO_CUSTOM_PARAM = {
        value: key for key, value in _CUSTOM_PARAM_TO_NUMERIC_KEY.items()
    }
    _KEY_NNNNN_RE = re.compile(r"^key[1-9][0-9]{0,4}$")

    # Akamai serializes modifications per zone; a concurrent write to the same
    # zone returns 409 concurrentZoneModification. Retry the same request up to
    # this many times with exponential backoff + jitter before surfacing it.
    _MAX_ZONE_LOCK_RETRIES = 5
    _ZONE_LOCK_BASE_DELAY = 0.5  # seconds (doubles each attempt, plus jitter)

    def __init__(
        self,
        host: str | None = None,
        client_token: str | None = None,
        client_secret: str | None = None,
        access_token: str | None = None,
        edgerc_path: str | None = None,
        edgerc_section: str | None = None,
    ):
        """
        Initialize Akamai Edge DNS backend.

        Args:
            host: EdgeGrid API host (defaults to AKAMAI_HOST env var or .edgerc)
            client_token: EdgeGrid client token (defaults to AKAMAI_CLIENT_TOKEN)
            client_secret: EdgeGrid client secret (defaults to AKAMAI_CLIENT_SECRET)
            access_token: EdgeGrid access token (defaults to AKAMAI_ACCESS_TOKEN)
            edgerc_path: Path to .edgerc file (defaults to AKAMAI_EDGERC or ~/.edgerc)
            edgerc_section: Section in .edgerc (defaults to AKAMAI_EDGERC_SECTION or "default")
        """
        self._host = host or os.environ.get("AKAMAI_HOST")
        self._client_token = client_token or os.environ.get("AKAMAI_CLIENT_TOKEN")
        self._client_secret = client_secret or os.environ.get("AKAMAI_CLIENT_SECRET")
        self._access_token = access_token or os.environ.get("AKAMAI_ACCESS_TOKEN")
        self._edgerc_path = edgerc_path or os.environ.get("AKAMAI_EDGERC", "~/.edgerc")
        self._edgerc_section = edgerc_section or os.environ.get("AKAMAI_EDGERC_SECTION", "default")
        self._auth: Any = None
        self._client: httpx.AsyncClient | None = None
        self._client_loop_id: int | None = None
        self._zone_cache: dict[str, bool] = {}
        # Per-zone write locks (lazily created; reset on event-loop change).
        self._zone_write_locks: dict[str, asyncio.Lock] = {}

    @property
    def name(self) -> str:
        return "akamai-edgedns"

    @property
    def supports_private_svcb_keys(self) -> bool:
        """Akamai Edge DNS accepts private-use SVCB keys natively."""
        return True

    # ------------------------------------------------------------------
    # Auth & HTTP
    # ------------------------------------------------------------------

    def _ensure_auth(self) -> None:
        """Lazily initialize EdgeGrid authentication."""
        if self._auth is not None:
            return

        # Explicit env vars take precedence over .edgerc file
        env_vals = [self._host, self._client_token, self._client_secret, self._access_token]
        have_any = any(env_vals)
        have_all = all(env_vals)

        if have_any and not have_all:
            env_names = [
                "AKAMAI_HOST",
                "AKAMAI_CLIENT_TOKEN",
                "AKAMAI_CLIENT_SECRET",
                "AKAMAI_ACCESS_TOKEN",
            ]
            missing = [name for name, val in zip(env_names, env_vals, strict=True) if not val]
            raise ValueError(
                f"Partial Akamai credentials detected — {missing} not set. "
                "Provide all four AKAMAI_* variables or use ~/.edgerc instead."
            )

        if have_all:
            from akamai.edgegrid import EdgeGridAuth

            self._auth = EdgeGridAuth(
                client_token=self._client_token,
                client_secret=self._client_secret,
                access_token=self._access_token,
            )
            return

        # Fall back to .edgerc file
        try:
            from akamai.edgegrid import EdgeGridAuth, EdgeRc

            edgerc = EdgeRc(os.path.expanduser(self._edgerc_path))
            section = self._edgerc_section
            if not self._host:
                self._host = edgerc.get(section, "host")
            self._auth = EdgeGridAuth.from_edgerc(edgerc, section)
        except Exception as exc:
            raise ValueError(
                "Akamai EdgeDNS credentials not configured. "
                "Set AKAMAI_HOST, AKAMAI_CLIENT_TOKEN, AKAMAI_CLIENT_SECRET, "
                "and AKAMAI_ACCESS_TOKEN environment variables, or configure ~/.edgerc. "
                "See https://techdocs.akamai.com/developer/docs/set-up-authentication-credentials"
            ) from exc

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create httpx async client with event-loop tracking.

        Note: this client intentionally carries no auth headers. EdgeGrid
        requires a per-request HMAC signature over method + URL + body, so
        signing happens inside ``_request()`` via ``_sign_request()`` rather
        than at client construction time. Do not move auth here.
        """
        current_loop_id = id(asyncio.get_running_loop())

        # Recreate client if the event loop changed (e.g., multiple asyncio.run() calls)
        if self._client is not None and self._client_loop_id != current_loop_id:
            with contextlib.suppress(Exception):
                await self._client.aclose()
            self._client = None
            self._client_loop_id = None
            self._zone_write_locks.clear()  # locks are bound to the old loop

        if self._client is None:
            self._ensure_auth()
            self._client = httpx.AsyncClient(
                timeout=30.0,
                headers={"Accept": "application/json"},
            )
            self._client_loop_id = current_loop_id

        return self._client

    def _zone_write_lock(self, zone: str) -> asyncio.Lock:
        """Per-zone write lock.

        Akamai serializes modifications per zone, returning 409
        concurrentZoneModification for overlapping writes. Serialising our own
        concurrent writes to a zone avoids self-inflicted contention (the retry in
        ``_request`` then only has to absorb *cross-process* concurrency). Locks
        are event-loop-bound and reset with the client on loop change.
        """
        lock = self._zone_write_locks.get(zone)
        if lock is None:
            lock = asyncio.Lock()
            self._zone_write_locks[zone] = lock
        return lock

    def _sign_request(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: bytes | None = None,
    ) -> dict[str, str]:
        """Sign a request using EdgeGrid and return the signed headers.

        EdgeGridAuth implements the ``requests.auth.AuthBase`` interface, so
        we create a throw-away ``requests.PreparedRequest`` to compute the
        ``Authorization`` header, then hand those headers to httpx for the
        actual async I/O.  No HTTP call goes through ``requests``.
        """
        import requests as req_lib  # type: ignore[import-untyped]

        prepared = req_lib.Request(method, url, headers=headers, data=body).prepare()
        signed = self._auth(prepared)
        return dict(signed.headers)

    def _build_url(self, path: str) -> str:
        """Build full API URL from path."""
        host = (self._host or "").rstrip("/")
        if not host.startswith("https://"):
            host = f"https://{host}"
        return f"{host}{path}"

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_data: dict[str, Any] | None = None,
        params: dict[str, str] | None = None,
    ) -> dict[str, Any] | list[Any] | None:
        """Execute a signed API request."""
        client = await self._get_client()
        url = self._build_url(path)

        if params:
            url = f"{url}?{urlencode(params, doseq=True)}"

        body: bytes | None = None
        headers: dict[str, str] = {"Accept": "application/json"}
        if json_data is not None:
            body = json_module.dumps(json_data).encode("utf-8")
            headers["Content-Type"] = "application/json"

        # Akamai serializes writes per zone. A fan-out of record-set writes (many
        # agents, or the two writes per publish_agent) draws 409
        # concurrentZoneModification — a transient optimistic-lock, not a real
        # conflict. Retry the SAME request with exponential backoff + jitter. A
        # genuine "already exists" 409 on POST is converged to PUT (upsert) instead.
        attempt = 0
        while True:
            # Re-sign each attempt: the EdgeGrid HMAC is time-bounded.
            signed_headers = self._sign_request(method, url, headers, body)

            try:
                response = await client.request(
                    method,
                    url,
                    content=body,
                    headers=signed_headers,
                )
            except httpx.HTTPError as exc:
                raise ValueError(
                    f"Akamai Edge DNS transport error ({method} {path}): {exc}"
                ) from exc

            if response.status_code == 409:
                if "concurrentZoneModification" in response.text:
                    if attempt < self._MAX_ZONE_LOCK_RETRIES:
                        delay = self._ZONE_LOCK_BASE_DELAY * (2**attempt) + _jitter.uniform(0, 0.25)
                        logger.debug(
                            "Akamai zone busy; retrying after concurrentZoneModification",
                            method=method,
                            path=path,
                            attempt=attempt + 1,
                            delay_s=round(delay, 3),
                        )
                        await asyncio.sleep(delay)
                        attempt += 1
                        continue
                    # Retries exhausted — fall through to raise_for_status below.
                elif method == "POST" and "/names/" in path:
                    # Genuine "already exists" 409 on a single record set — converge to
                    # an update. Guarded to single-record paths: never auto-convert a
                    # bulk ``/recordsets`` POST, because PUT on that path replaces the
                    # ENTIRE zone's record sets.
                    return await self._request("PUT", path, json_data=json_data, params=params)

            # 404 on reads/deletes = not found - None; on writes = zone/resource missing - raise
            if response.status_code == 404:
                if method in ("POST", "PUT", "PATCH"):
                    raise ValueError(
                        f"Akamai Edge DNS zone or resource not found ({method} {path}). "
                        "Ensure the zone exists and credentials have write access."
                    )
                return None

            try:
                response.raise_for_status()
            except httpx.HTTPStatusError as exc:
                body_text = exc.response.text[:500]
                logger.error(
                    "Akamai Edge DNS API error",
                    method=method,
                    path=path,
                    status_code=exc.response.status_code,
                    response_body=body_text,
                )
                raise ValueError(
                    f"Akamai Edge DNS API error ({method} {path}): "
                    f"status={exc.response.status_code} body={body_text}"
                ) from exc

            if not response.content:
                return {}

            return response.json()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _to_fqdn(name: str, zone: str) -> str:
        """Build fully qualified owner name for a record."""
        zone_clean = zone.rstrip(".")
        name_clean = name.rstrip(".")
        if name_clean.endswith(f".{zone_clean}"):
            return name_clean
        return f"{name_clean}.{zone_clean}"

    @staticmethod
    def _extract_name_from_fqdn(fqdn: str, zone: str) -> str:
        """Extract the record name by stripping the zone suffix."""
        zone_suffix = f".{zone.rstrip('.')}"
        fqdn_clean = fqdn.rstrip(".")
        if fqdn_clean.endswith(zone_suffix):
            return fqdn_clean.removesuffix(zone_suffix)
        return fqdn_clean

    @classmethod
    def _to_numeric_key(cls, key: str) -> str:
        """Map DNS-AID param names to numeric keyNNNNN for SVCB wire format."""
        normalized = key.strip().lower()
        if cls._KEY_NNNNN_RE.match(normalized):
            return normalized
        return cls._CUSTOM_PARAM_TO_NUMERIC_KEY.get(normalized, normalized)

    @classmethod
    def _from_numeric_key(cls, key: str) -> str:
        """Map numeric keyNNNNN back to DNS-AID param names."""
        normalized = key.strip().lower()
        return cls._NUMERIC_KEY_TO_CUSTOM_PARAM.get(normalized, normalized)

    @staticmethod
    def _escape_char_string(value: str) -> str:
        """Escape a value for a DNS presentation-format character-string.

        Backslash and double-quote are backslash-escaped (RFC 1035 §5.1) so a
        value containing ``"`` cannot break out of its quotes and inject extra
        rdata elements or SvcParams into the record.
        """
        return value.replace("\\", "\\\\").replace('"', '\\"')

    @staticmethod
    def _unescape_char_string(value: str) -> str:
        """Decode a presentation-format character-string (inverse of escape).

        Single left-to-right pass so adjacent escapes decode correctly.
        """
        out: list[str] = []
        i, n = 0, len(value)
        while i < n:
            if value[i] == "\\" and i + 1 < n:
                out.append(value[i + 1])
                i += 2
            else:
                out.append(value[i])
                i += 1
        return "".join(out)

    @staticmethod
    def _seg(value: str) -> str:
        """Percent-encode a single URL path segment (no separators pass through)."""
        return quote(value, safe="")

    @classmethod
    def _format_svcb_rdata(
        cls,
        priority: int,
        target: str,
        params: dict[str, str],
    ) -> str:
        """Format SVCB rdata in presentation format for the Edge DNS API."""
        # Ensure target has trailing dot per DNS presentation format
        if not target.endswith("."):
            target = f"{target}."

        # Map DNS-AID param names (cap, bap, …) to keyNNNNN for the wire format
        param_parts = []
        for key, value in params.items():
            mapped_key = cls._to_numeric_key(key)
            safe_value = cls._escape_char_string(value)
            param_parts.append(f'{mapped_key}="{safe_value}"')

        rdata = f"{priority} {target}"
        if param_parts:
            rdata += " " + " ".join(param_parts)
        return rdata

    # ------------------------------------------------------------------
    # DNSBackend interface
    # ------------------------------------------------------------------

    async def create_svcb_record(
        self,
        zone: str,
        name: str,
        priority: int,
        target: str,
        params: dict[str, str],
        ttl: int = 3600,
    ) -> str:
        """Create or update an SVCB record in Akamai Edge DNS."""
        fqdn = self._to_fqdn(name, zone)
        zone_clean = zone.rstrip(".")
        rdata = self._format_svcb_rdata(priority, target, params)

        logger.info(
            "Creating SVCB record",
            zone=zone_clean,
            name=fqdn,
            priority=priority,
            target=target,
            params=params,
            ttl=ttl,
        )

        payload = {
            "name": fqdn,
            "type": "SVCB",
            "ttl": ttl,
            "rdata": [rdata],
        }

        path = f"/config-dns/v2/zones/{self._seg(zone_clean)}/names/{self._seg(fqdn)}/types/SVCB"

        # Serialise our own writes per zone (Akamai locks the zone during any
        # modification); cross-process contention is still handled by the retry.
        async with self._zone_write_lock(zone_clean):
            # Upsert: Edge DNS uses POST for create, PUT for update
            existing = await self._request("GET", path)
            if existing is not None:
                await self._request("PUT", path, json_data=payload)
            else:
                await self._request("POST", path, json_data=payload)

        logger.info("SVCB record created", name=fqdn)
        return fqdn

    async def create_txt_record(
        self,
        zone: str,
        name: str,
        values: list[str],
        ttl: int = 3600,
    ) -> str:
        """Create or update a TXT record in Akamai Edge DNS."""
        fqdn = self._to_fqdn(name, zone)
        zone_clean = zone.rstrip(".")

        logger.info(
            "Creating TXT record",
            zone=zone_clean,
            name=fqdn,
            values=values,
            ttl=ttl,
        )

        payload = {
            "name": fqdn,
            "type": "TXT",
            "ttl": ttl,
            "rdata": [f'"{self._escape_char_string(v)}"' for v in values],
        }

        path = f"/config-dns/v2/zones/{self._seg(zone_clean)}/names/{self._seg(fqdn)}/types/TXT"

        async with self._zone_write_lock(zone_clean):
            # Upsert: Edge DNS uses POST for create, PUT for update
            existing = await self._request("GET", path)
            if existing is not None:
                await self._request("PUT", path, json_data=payload)
            else:
                await self._request("POST", path, json_data=payload)

        logger.info("TXT record created", name=fqdn)
        return fqdn

    async def delete_record(
        self,
        zone: str,
        name: str,
        record_type: str,
    ) -> bool:
        """Delete a DNS record from Akamai Edge DNS."""
        fqdn = self._to_fqdn(name, zone)
        zone_clean = zone.rstrip(".")
        rtype = record_type.upper()

        logger.info(
            "Deleting record",
            zone=zone_clean,
            name=fqdn,
            type=rtype,
        )

        path = f"/config-dns/v2/zones/{self._seg(zone_clean)}/names/{self._seg(fqdn)}/types/{self._seg(rtype)}"
        try:
            # _request returns None on 404 — record doesn't exist
            async with self._zone_write_lock(zone_clean):
                result = await self._request("DELETE", path)
        except Exception as exc:
            logger.exception(
                "Failed to delete record",
                name=fqdn,
                type=rtype,
                error=str(exc),
            )
            return False

        if result is None:
            logger.warning("Record not found", name=fqdn, type=rtype)
            return False

        logger.info("Record deleted", name=fqdn, type=rtype)
        return True

    async def list_records(
        self,
        zone: str,
        name_pattern: str | None = None,
        record_type: str | None = None,
    ) -> AsyncIterator[dict]:
        """List DNS records in an Akamai Edge DNS zone."""
        zone_clean = zone.rstrip(".")

        logger.debug(
            "Listing records",
            zone=zone_clean,
            name_pattern=name_pattern,
            record_type=record_type,
        )

        params: dict[str, str] = {"pageSize": "100"}
        if record_type:
            params["types"] = record_type.upper()

        page = 1
        while True:
            params["page"] = str(page)
            path = f"/config-dns/v2/zones/{self._seg(zone_clean)}/recordsets"
            data = await self._request("GET", path, params=params)

            if data is None or not isinstance(data, dict):
                break

            recordsets = data.get("recordsets", [])
            if not recordsets:
                break

            for rs in recordsets:
                fqdn = str(rs.get("name", "")).rstrip(".")
                rtype = str(rs.get("type", "")).upper()
                rdata_list = rs.get("rdata", [])

                if not fqdn:
                    continue

                # Filter by name pattern (simple substring match)
                if name_pattern and name_pattern not in fqdn:
                    continue

                ttl = int(rs.get("ttl", 0))
                values = rdata_list if rdata_list else []
                if rtype == "TXT":
                    values = [self._unescape_char_string(v.strip('"')) for v in values]

                yield {
                    "name": self._extract_name_from_fqdn(fqdn, zone_clean),
                    "fqdn": fqdn,
                    "type": rtype,
                    "ttl": ttl,
                    "values": values,
                    "id": f"{zone_clean}/{fqdn}/{rtype}",
                }

            # Trust the API's authoritative count when present; otherwise stop on a
            # short page rather than truncating at the first 100 (the old
            # metadata-absent "totalElements defaults to 0" bug).
            metadata = data.get("metadata", {})
            total = metadata.get("totalElements")
            page_size = metadata.get("pageSize", 100)
            if total is not None:
                if page * page_size >= total:
                    break
            elif len(recordsets) < 100:
                break
            page += 1

    async def get_record(
        self,
        zone: str,
        name: str,
        record_type: str,
    ) -> dict | None:
        """Get a specific DNS record by querying the Edge DNS API directly."""
        fqdn = self._to_fqdn(name, zone)
        zone_clean = zone.rstrip(".")
        rtype = record_type.upper()

        path = f"/config-dns/v2/zones/{self._seg(zone_clean)}/names/{self._seg(fqdn)}/types/{self._seg(rtype)}"
        data = await self._request("GET", path)

        if data is None or not isinstance(data, dict):
            return None

        rdata_list = data.get("rdata", [])
        ttl = int(data.get("ttl", 0))

        if rtype == "TXT":
            rdata_list = [self._unescape_char_string(v.strip('"')) for v in rdata_list]

        return {
            "name": self._extract_name_from_fqdn(fqdn, zone_clean),
            "fqdn": fqdn,
            "type": rtype,
            "ttl": ttl,
            "values": rdata_list,
            "id": f"{zone_clean}/{fqdn}/{rtype}",
        }

    async def zone_exists(self, zone: str) -> bool:
        """Check if zone exists in Akamai Edge DNS.

        Returns False (rather than raising) on any API or network error,
        since the zone is effectively inaccessible.
        """
        zone_clean = zone.rstrip(".")

        # Check cache
        if zone_clean in self._zone_cache:
            return self._zone_cache[zone_clean]

        try:
            path = f"/config-dns/v2/zones/{self._seg(zone_clean)}"
            result = await self._request("GET", path)
            exists = result is not None
            self._zone_cache[zone_clean] = exists
            return exists
        except Exception as exc:
            logger.warning(
                "Failed to check zone existence in Akamai Edge DNS",
                zone=zone_clean,
                error=str(exc),
            )
            return False

    async def list_zones(self) -> list[dict]:
        """List all zones accessible with the current credentials."""
        zones: list[dict] = []
        page = 1

        while True:
            params = {"page": str(page), "pageSize": "100"}
            data = await self._request("GET", "/config-dns/v2/zones", params=params)

            if data is None or not isinstance(data, dict):
                break

            page_zones = data.get("zones", [])
            for z in page_zones:
                zones.append(
                    {
                        "id": z.get("zone", ""),
                        "name": z.get("zone", "").rstrip("."),
                        "type": z.get("type", ""),
                        "contract_id": z.get("contractId", ""),
                    }
                )

            # Trust the API's authoritative count when present; otherwise stop on a
            # short page rather than truncating (metadata-absent safety).
            metadata = data.get("metadata", {})
            total = metadata.get("totalElements")
            page_size = metadata.get("pageSize", 100)
            if total is not None:
                if page * page_size >= total:
                    break
            elif len(page_zones) < 100:
                break
            page += 1

        return zones

    # publish_agent() inherited from base class — passes ALL SVCB params
    # natively since supports_private_svcb_keys = True.

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
            self._client_loop_id = None
