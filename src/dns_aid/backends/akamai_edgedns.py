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
import re
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import urlencode

import httpx
import structlog

from dns_aid.backends.base import DNSBackend

logger = structlog.get_logger(__name__)

# Record types supported by DNS-AID via the Edge DNS API.
_SUPPORTED_RECORD_TYPES = {"SVCB", "TXT"}


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
        have_env = all(
            [
                self._host,
                self._client_token,
                self._client_secret,
                self._access_token,
            ]
        )

        if have_env:
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
        """Get or create httpx async client with event-loop tracking."""
        current_loop_id = id(asyncio.get_running_loop())

        # Recreate client if the event loop changed (e.g., multiple asyncio.run() calls)
        if self._client is not None and self._client_loop_id != current_loop_id:
            with contextlib.suppress(Exception):
                await self._client.aclose()
            self._client = None
            self._client_loop_id = None

        if self._client is None:
            self._ensure_auth()
            self._client = httpx.AsyncClient(
                timeout=30.0,
                headers={"Accept": "application/json"},
            )
            self._client_loop_id = current_loop_id

        return self._client

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
        import requests as req_lib

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

        # Sign before sending — EdgeGrid HMAC covers method, URL, and body
        signed_headers = self._sign_request(method, url, headers, body)

        try:
            response = await client.request(
                method,
                url,
                content=body,
                headers=signed_headers,
            )
        except httpx.HTTPError as exc:
            raise RuntimeError(f"Akamai Edge DNS transport error ({method} {path}): {exc}") from exc

        # 404 = record/zone not found — return None instead of raising
        if response.status_code == 404:
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
            raise RuntimeError(
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
            param_parts.append(f'{mapped_key}="{value}"')

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
            "Creating SVCB record in Akamai Edge DNS",
            zone=zone_clean,
            fqdn=fqdn,
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

        path = f"/config-dns/v2/zones/{zone_clean}/names/{fqdn}/types/SVCB"

        # Upsert: Edge DNS uses POST for create, PUT for update
        existing = await self._request("GET", path)
        if existing is not None:
            await self._request("PUT", path, json_data=payload)
        else:
            await self._request("POST", path, json_data=payload)

        logger.info("SVCB record created", fqdn=fqdn)
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
        content = " ".join(values)

        logger.info(
            "Creating TXT record in Akamai Edge DNS",
            zone=zone_clean,
            fqdn=fqdn,
            values=values,
            ttl=ttl,
        )

        payload = {
            "name": fqdn,
            "type": "TXT",
            "ttl": ttl,
            "rdata": [content],
        }

        path = f"/config-dns/v2/zones/{zone_clean}/names/{fqdn}/types/TXT"

        # Upsert: Edge DNS uses POST for create, PUT for update
        existing = await self._request("GET", path)
        if existing is not None:
            await self._request("PUT", path, json_data=payload)
        else:
            await self._request("POST", path, json_data=payload)

        logger.info("TXT record created", fqdn=fqdn)
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
            "Deleting record from Akamai Edge DNS",
            zone=zone_clean,
            fqdn=fqdn,
            type=rtype,
        )

        path = f"/config-dns/v2/zones/{zone_clean}/names/{fqdn}/types/{rtype}"
        # _request returns None on 404 — record doesn't exist
        result = await self._request("DELETE", path)

        if result is None:
            logger.warning("Record not found", fqdn=fqdn, type=rtype)
            return False

        logger.info("Record deleted", fqdn=fqdn, type=rtype)
        return True

    async def list_records(
        self,
        zone: str,
        name_pattern: str | None = None,
        record_type: str | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        """List DNS records in an Akamai Edge DNS zone."""
        zone_clean = zone.rstrip(".")

        logger.debug(
            "Listing records in Akamai Edge DNS",
            zone=zone_clean,
            name_pattern=name_pattern,
            record_type=record_type,
        )

        params: dict[str, str] = {"pageSize": "100"}
        if record_type:
            params["types"] = record_type.upper()
        else:
            params["types"] = ",".join(sorted(_SUPPORTED_RECORD_TYPES))

        page = 1
        while True:
            params["page"] = str(page)
            path = f"/config-dns/v2/zones/{zone_clean}/recordsets"
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

                yield {
                    "name": self._extract_name_from_fqdn(fqdn, zone_clean),
                    "fqdn": fqdn,
                    "type": rtype,
                    "ttl": ttl,
                    "values": values,
                    "id": f"{zone_clean}/{fqdn}/{rtype}",
                }

            # Check for more pages
            metadata = data.get("metadata", {})
            total = metadata.get("totalElements", 0)
            page_size = metadata.get("pageSize", 100)
            if page * page_size >= total:
                break
            page += 1

    async def get_record(
        self,
        zone: str,
        name: str,
        record_type: str,
    ) -> dict[str, Any] | None:
        """Get a specific DNS record by querying the Edge DNS API directly."""
        fqdn = self._to_fqdn(name, zone)
        zone_clean = zone.rstrip(".")
        rtype = record_type.upper()

        path = f"/config-dns/v2/zones/{zone_clean}/names/{fqdn}/types/{rtype}"
        data = await self._request("GET", path)

        if data is None or not isinstance(data, dict):
            return None

        rdata_list = data.get("rdata", [])
        ttl = int(data.get("ttl", 0))

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
            path = f"/config-dns/v2/zones/{zone_clean}"
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
            self._zone_cache[zone_clean] = False
            return False

    async def list_zones(self) -> list[dict[str, Any]]:
        """List all zones accessible with the current credentials."""
        zones: list[dict[str, Any]] = []
        page = 1

        while True:
            params = {"page": str(page), "pageSize": "100"}
            data = await self._request("GET", "/config-dns/v2/zones", params=params)

            if data is None or not isinstance(data, dict):
                break

            for z in data.get("zones", []):
                zones.append(
                    {
                        "id": z.get("zone", ""),
                        "name": z.get("zone", "").rstrip("."),
                        "type": z.get("type", ""),
                        "contract_id": z.get("contractId", ""),
                    }
                )

            metadata = data.get("metadata", {})
            total = metadata.get("totalElements", 0)
            page_size = metadata.get("pageSize", 100)
            if page * page_size >= total:
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
