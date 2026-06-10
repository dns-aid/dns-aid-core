# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Infoblox BloxOne DDI backend for DNS-AID.

Creates DNS-AID records (SVCB, TXT) via the BloxOne Cloud API.
This is the cloud-native DDI platform from Infoblox.

API Documentation: https://csp.infoblox.com/apidoc/docs/DnsData
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import httpx
import structlog

from dns_aid.backends.base import DNSBackend

logger = structlog.get_logger(__name__)

# BloxOne API constants
DEFAULT_BASE_URL = "https://csp.infoblox.com"
API_VERSION = "/api/ddi/v1"


class InfobloxBloxOneBackend(DNSBackend):
    """
    Infoblox BloxOne DDI backend.

    Creates and manages DNS-AID records via BloxOne Cloud API.

    Example:
        >>> backend = InfobloxBloxOneBackend(
        ...     api_key=os.environ["INFOBLOX_API_KEY"],
        ...     dns_view="default"  # Optional: specify DNS view
        ... )
        >>> await backend.create_svcb_record(
        ...     zone="example.com",
        ...     name="_chat._a2a._agents",
        ...     priority=1,
        ...     target="chat.example.com.",
        ...     params={"alpn": "a2a", "port": "443"}
        ... )

    Environment Variables:
        INFOBLOX_API_KEY: API key for BloxOne authentication
        INFOBLOX_BASE_URL: Base URL (default: https://csp.infoblox.com)
        INFOBLOX_DNS_VIEW: DNS view name (default: "default")
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        dns_view: str | None = None,
        timeout: float = 30.0,
    ):
        """
        Initialize BloxOne backend.

        Args:
            api_key: BloxOne API key. Defaults to INFOBLOX_API_KEY env var.
            base_url: API base URL. Defaults to https://csp.infoblox.com
            dns_view: DNS view name (e.g., "default"). Defaults to INFOBLOX_DNS_VIEW env var.
            timeout: HTTP request timeout in seconds.
        """
        self._api_key = api_key or os.environ.get("INFOBLOX_API_KEY")
        if not self._api_key:
            raise ValueError(
                "Infoblox API key required. Set INFOBLOX_API_KEY environment variable "
                "or pass api_key parameter."
            )

        self._base_url = (base_url or os.environ.get("INFOBLOX_BASE_URL", DEFAULT_BASE_URL)).rstrip(
            "/"
        )
        self._dns_view = dns_view or os.environ.get("INFOBLOX_DNS_VIEW", "default")
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None
        self._client_loop_id: int | None = None  # Track which loop the client belongs to
        self._zone_cache: dict[str, dict] = {}  # domain -> zone info
        self._view_cache: dict[str, str] = {}  # view_name -> view_id

    @property
    def name(self) -> str:
        return "bloxone"

    @property
    def dns_view(self) -> str:
        """Get the configured DNS view name."""
        return self._dns_view

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create async HTTP client.

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

        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                headers={
                    "Authorization": f"Token {self._api_key}",
                    "Content-Type": "application/json",
                },
                timeout=self._timeout,
            )
            self._client_loop_id = current_loop_id
        return self._client

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def _request(
        self,
        method: str,
        endpoint: str,
        json: dict | None = None,
        params: dict | None = None,
    ) -> dict:
        """
        Make an API request to BloxOne.

        Args:
            method: HTTP method (GET, POST, PATCH, DELETE)
            endpoint: API endpoint (without base URL)
            json: Request body as dict
            params: Query parameters

        Returns:
            Response JSON as dict

        Raises:
            httpx.HTTPStatusError: On API errors
        """
        client = await self._get_client()
        url = f"{API_VERSION}{endpoint}"

        logger.debug(
            "BloxOne API request",
            method=method,
            url=url,
            params=params,
        )

        response = await client.request(
            method=method,
            url=url,
            json=json,
            params=params,
        )

        # Log response status
        logger.debug(
            "BloxOne API response",
            status=response.status_code,
            url=url,
        )

        response.raise_for_status()

        if response.status_code == 204:
            return {}

        return response.json()

    async def _get_view_id(self, view_name: str) -> str | None:
        """
        Get DNS view ID from view name.

        Args:
            view_name: DNS view name (e.g., "default")

        Returns:
            View ID or None if not found
        """
        if view_name in self._view_cache:
            return self._view_cache[view_name]

        response = await self._request(
            "GET",
            "/dns/view",
            params={"_filter": f'name=="{view_name}"'},
        )

        results = response.get("results", [])
        if results:
            view_id = results[0].get("id")
            self._view_cache[view_name] = view_id
            return view_id

        return None

    async def _get_zone_info(self, zone: str) -> dict:
        """
        Get zone information from BloxOne.

        Args:
            zone: Domain name (e.g., "example.com")

        Returns:
            Zone info dict with 'id', 'fqdn', etc.

        Raises:
            ValueError: If zone not found in the configured DNS view
        """
        # Check cache (include view in cache key)
        domain = zone.lower().rstrip(".")
        cache_key = f"{domain}:{self._dns_view}"
        if cache_key in self._zone_cache:
            return self._zone_cache[cache_key]

        # Build filter - always filter by fqdn
        filter_parts = [f'fqdn=="{domain}."']

        # Add view filter if view is specified (resolve name to ID first)
        if self._dns_view:
            view_id = await self._get_view_id(self._dns_view)
            if view_id:
                filter_parts.append(f'view=="{view_id}"')

        filter_str = " and ".join(filter_parts)

        # Query BloxOne for zones
        response = await self._request(
            "GET",
            "/dns/auth_zone",
            params={"_filter": filter_str},
        )

        results = response.get("results", [])
        if not results:
            raise ValueError(f"No zone found for domain: {zone} in DNS view: {self._dns_view}")

        zone_info = results[0]
        self._zone_cache[cache_key] = zone_info

        logger.debug(
            "Found BloxOne zone",
            domain=domain,
            zone_id=zone_info.get("id"),
            view=self._dns_view,
        )

        return zone_info

    def _format_svcb_rdata(
        self,
        priority: int,
        target: str,
        params: dict[str, str],
    ) -> dict:
        """
        Format SVCB rdata for BloxOne API.

        BloxOne SVCB rdata format uses only target_name.
        Priority defaults to 0 (alias mode) in BloxOne.

        Note: BloxOne currently supports basic SVCB without SVC params.
        For full SVCB with alpn/port params, use the TXT record for metadata.
        """
        # Ensure target has trailing dot
        if not target.endswith("."):
            target = f"{target}."

        # BloxOne only accepts target_name for SVCB
        # Priority and svc_params are not supported in current API
        return {
            "target_name": target,
        }

    async def _delete_existing_records(
        self, zone_id: str, name_in_zone: str, record_type: str
    ) -> int:
        """Delete every record at ``(name_in_zone, record_type)`` in the zone.

        DNS-AID owns the names it writes (agent owners and ``_index._agents``)
        and publishes exactly one record per ``(name, type)``. Removing any
        existing record(s) before a create makes the write idempotent (an
        upsert) and self-heals accidental duplicates left by earlier
        non-idempotent writes — matching the UPSERT contract other backends
        (e.g. Route53) already provide, and avoiding BloxOne ``409 Conflict``
        on repeated index updates and re-publishes.

        Returns the number of records deleted.
        """
        deleted = 0
        # Bounded loop: re-query from the top after each batch (deletions shift
        # pagination). The cap is a safety stop, far above any real fan-out.
        for _ in range(50):
            response = await self._request(
                "GET",
                "/dns/record",
                params={
                    "_filter": (
                        f'zone=="{zone_id}" and name_in_zone=="{name_in_zone}" '
                        f'and type=="{record_type}"'
                    ),
                    "_limit": "100",
                },
            )
            results = response.get("results", [])
            if not results:
                break
            for record in results:
                record_id = record.get("id")
                if record_id:
                    await self._request("DELETE", f"/{record_id}")
                    deleted += 1
            # A partial page means we have just deleted the last of them, so
            # there is nothing left to re-query. Only loop again if the page
            # was full (which a real DNS-AID name never reaches).
            if len(results) < 100:
                break
        if deleted:
            logger.debug(
                "Replaced existing record(s) before write",
                zone_id=zone_id,
                name=name_in_zone,
                type=record_type,
                deleted=deleted,
            )
        return deleted

    async def create_svcb_record(
        self,
        zone: str,
        name: str,
        priority: int,
        target: str,
        params: dict[str, str],
        ttl: int = 3600,
    ) -> str:
        """Create SVCB record in BloxOne."""
        zone_info = await self._get_zone_info(zone)
        zone_id = zone_info["id"]

        # Build record name (without zone suffix)
        # name comes as "_agent._mcp._agents"
        name_in_zone = name

        # Idempotent write (upsert): replace any existing SVCB at this name so
        # re-publishing an agent updates in place instead of accumulating
        # duplicate records (see _delete_existing_records).
        await self._delete_existing_records(zone_id, name_in_zone, "SVCB")

        # Build FQDN for logging
        fqdn = f"{name}.{zone}"

        # Format rdata
        rdata = self._format_svcb_rdata(priority, target, params)

        logger.info(
            "Creating SVCB record in BloxOne",
            zone=zone,
            name=name_in_zone,
            fqdn=fqdn,
            target=target,
            ttl=ttl,
        )

        # Create record via API
        payload = {
            "name_in_zone": name_in_zone,
            "zone": zone_id,
            "type": "SVCB",
            "rdata": rdata,
            "ttl": ttl,
            "comment": f"DNS-AID: SVCB record for {name}",
        }

        response = await self._request("POST", "/dns/record", json=payload)

        record_id = response.get("result", {}).get("id")
        logger.info(
            "SVCB record created in BloxOne",
            fqdn=fqdn,
            record_id=record_id,
        )

        return fqdn

    async def create_txt_record(
        self,
        zone: str,
        name: str,
        values: list[str],
        ttl: int = 3600,
    ) -> str:
        """Create TXT record in BloxOne."""
        zone_info = await self._get_zone_info(zone)
        zone_id = zone_info["id"]

        # Idempotent write (upsert): replace any existing TXT at this name.
        # Without this, repeated index updates (_index._agents) POST-create
        # duplicate TXT records and eventually 409 on BloxOne.
        await self._delete_existing_records(zone_id, name, "TXT")

        # Build FQDN
        fqdn = f"{name}.{zone}"

        # TXT rdata format: {"text": "value"}
        # For multiple values, create multiple TXT records or join
        # BloxOne supports multiple strings in a single TXT record
        rdata = {"text": " ".join(f'"{v}"' for v in values)}

        logger.info(
            "Creating TXT record in BloxOne",
            zone=zone,
            name=name,
            fqdn=fqdn,
            values=values,
            ttl=ttl,
        )

        payload = {
            "name_in_zone": name,
            "zone": zone_id,
            "type": "TXT",
            "rdata": rdata,
            "ttl": ttl,
            "comment": f"DNS-AID: TXT record for {name}",
        }

        response = await self._request("POST", "/dns/record", json=payload)

        record_id = response.get("result", {}).get("id")
        logger.info(
            "TXT record created in BloxOne",
            fqdn=fqdn,
            record_id=record_id,
        )

        return fqdn

    async def delete_record(
        self,
        zone: str,
        name: str,
        record_type: str,
    ) -> bool:
        """Delete a DNS record from BloxOne."""
        try:
            await self._get_zone_info(zone)  # Verify zone exists

            # Build FQDN to search
            fqdn = f"{name}.{zone}"
            if not fqdn.endswith("."):
                fqdn_search = f"{fqdn}."
            else:
                fqdn_search = fqdn

            logger.info(
                "Searching for record to delete",
                zone=zone,
                name=name,
                fqdn=fqdn_search,
                type=record_type,
            )

            # Find the record
            response = await self._request(
                "GET",
                "/dns/record",
                params={
                    "_filter": f'absolute_name_spec=="{fqdn_search}" and type=="{record_type}"',
                },
            )

            results = response.get("results", [])
            if not results:
                logger.warning(
                    "Record not found in BloxOne",
                    fqdn=fqdn,
                    type=record_type,
                )
                return False

            # Delete the record
            # record_id is full path like "dns/record/abc123", so use it directly
            record_id = results[0]["id"]
            await self._request("DELETE", f"/{record_id}")

            logger.info(
                "Record deleted from BloxOne",
                fqdn=fqdn,
                type=record_type,
                record_id=record_id,
            )
            return True

        except Exception as e:
            logger.exception("Failed to delete record from BloxOne", error=str(e))
            return False

    async def list_records(
        self,
        zone: str,
        name_pattern: str | None = None,
        record_type: str | None = None,
    ) -> AsyncIterator[dict]:
        """List DNS records in BloxOne zone."""
        zone_info = await self._get_zone_info(zone)
        zone_id = zone_info["id"]

        logger.debug(
            "Listing records in BloxOne",
            zone=zone,
            zone_id=zone_id,
            name_pattern=name_pattern,
            record_type=record_type,
        )

        # Build filter
        filters = [f'zone=="{zone_id}"']
        if record_type:
            filters.append(f'type=="{record_type}"')
        if name_pattern:
            # Use contains filter for pattern matching
            filters.append(f'name_in_zone~"{name_pattern}"')

        filter_str = " and ".join(filters)

        # Paginate through results
        offset = 0
        limit = 100

        while True:
            response = await self._request(
                "GET",
                "/dns/record",
                params={
                    "_filter": filter_str,
                    "_limit": str(limit),
                    "_offset": str(offset),
                },
            )

            results = response.get("results", [])
            if not results:
                break

            for record in results:
                # Extract record details
                rdata = record.get("rdata", {})
                values = []

                # Handle different record types
                rtype = record.get("type", "")
                if rtype == "TXT":
                    values = [rdata.get("text", "")]
                elif rtype == "SVCB":
                    target = rdata.get("target_name", "")
                    # BloxOne SVCB only supports alias mode (priority 0)
                    # The API doesn't return priority in rdata, but always uses 0
                    svc_params = rdata.get("svc_params", "")
                    values = [f"0 {target} {svc_params}".strip()]
                else:
                    # Generic handling
                    values = [str(rdata)]

                yield {
                    "name": record.get("name_in_zone", ""),
                    "fqdn": record.get("absolute_name_spec", "").rstrip("."),
                    "type": rtype,
                    "ttl": record.get("ttl", 0),
                    "values": values,
                    "id": record.get("id"),
                }

            offset += limit

    async def zone_exists(self, zone: str) -> bool:
        """Check if zone exists in BloxOne.

        Returns False (rather than raising) on any API or network error,
        since the zone is effectively inaccessible.
        """
        try:
            await self._get_zone_info(zone)
            return True
        except ValueError:
            return False
        except Exception as exc:
            logger.warning(
                "Failed to check zone existence in BloxOne",
                zone=zone,
                view=self._dns_view,
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
        Get a specific record by querying BloxOne API directly.
        """
        try:
            # Build FQDN to search
            fqdn = f"{name}.{zone}"
            if not fqdn.endswith("."):
                fqdn_search = f"{fqdn}."
            else:
                fqdn_search = fqdn

            # Query BloxOne API
            response = await self._request(
                "GET",
                "/dns/record",
                params={
                    "_filter": f'absolute_name_spec=="{fqdn_search}" and type=="{record_type}"',
                },
            )

            results = response.get("results", [])
            if not results:
                return None

            record = results[0]
            rdata = record.get("rdata", {})
            values = []

            # Handle different record types
            if record_type == "TXT":
                values = [rdata.get("text", "")]
            elif record_type == "SVCB":
                target = rdata.get("target_name", "")
                svc_params = rdata.get("svc_params", "")
                values = [f"0 {target} {svc_params}".strip()]
            else:
                values = [str(rdata)]

            return {
                "name": record.get("name_in_zone", ""),
                "fqdn": record.get("absolute_name_spec", "").rstrip("."),
                "type": record_type,
                "ttl": record.get("ttl", 0),
                "values": values,
                "id": record.get("id"),
            }

        except Exception as e:
            logger.debug(f"Record not found: {e}")
            return None

    async def list_zones(self) -> list[dict]:
        """
        List all authoritative zones in BloxOne.

        Returns:
            List of zone info dicts with id, name, etc.
        """
        response = await self._request("GET", "/dns/auth_zone")

        zones = []
        for zone in response.get("results", []):
            zones.append(
                {
                    "id": zone.get("id"),
                    "name": zone.get("fqdn", "").rstrip("."),
                    "fqdn": zone.get("fqdn", ""),
                    "comment": zone.get("comment", ""),
                    "dnssec_enabled": zone.get("dnssec_enabled", False),
                    "primary_type": zone.get("primary_type", ""),
                }
            )

        return zones

    # ------------------------------------------------------------------
    # BloxOne Threat Defense — Named List RPZ operations
    # ------------------------------------------------------------------

    TD_API_VERSION = "/api/atcfw/v1"

    async def _td_request(
        self,
        method: str,
        endpoint: str,
        json: dict | None = None,
        params: dict | None = None,
    ) -> dict:
        """Make a request to the BloxOne Threat Defense API.

        Uses ``/api/atcfw/v1`` base path instead of the DDI ``/api/ddi/v1``.
        """
        client = await self._get_client()
        url = f"{self.TD_API_VERSION}{endpoint}"

        logger.debug("BloxOne TD API request", method=method, url=url, params=params)

        response = await client.request(method=method, url=url, json=json, params=params)

        logger.debug("BloxOne TD API response", status=response.status_code, url=url)

        response.raise_for_status()

        if response.status_code == 204:
            return {}

        return response.json()

    async def create_or_update_named_list(
        self,
        name: str,
        items: list[str],
        description: str = "",
        confidence_level: str = "HIGH",
    ) -> dict:
        """Create or update a named list in BloxOne Threat Defense.

        Named lists are used for RPZ-style blocking in BloxOne TD.
        Each list contains domain names that trigger a policy action.

        Args:
            name: Named list name (e.g., ``dns-aid-rpz-blocked``).
            items: List of domain names to include.
            description: Human-readable description.
            confidence_level: Confidence level — HIGH, MEDIUM, LOW.

        Returns:
            Dict with ``id`` and ``name`` of the created/updated list.
        """
        # Check if named list already exists by listing and filtering locally
        # (TD API does not support DDI-style _filter on GET /named_lists)
        all_lists = await self._td_request("GET", "/named_lists")
        existing_list = None
        for nl in all_lists.get("results", []):
            if nl.get("name") == name:
                existing_list = nl
                break

        # Build items_described with per-item descriptions
        items_described = [
            {"item": item, "description": description or "DNS-AID policy"} for item in items
        ]

        payload = {
            "name": name,
            "type": "custom_list",
            "items_described": items_described,
            "description": description or f"DNS-AID managed named list: {name}",
            "confidence_level": confidence_level,
        }

        if existing_list:
            list_id = existing_list["id"]
            logger.info(
                "Updating BloxOne TD named list",
                name=name,
                list_id=list_id,
                item_count=len(items),
            )
            await self._td_request(
                "PUT",
                f"/named_lists/{list_id}",
                json=payload,
            )
            return {"id": list_id, "name": name, "updated": True}
        else:
            logger.info(
                "Creating BloxOne TD named list",
                name=name,
                item_count=len(items),
            )
            resp = await self._td_request(
                "POST",
                "/named_lists",
                json=payload,
            )
            result = resp.get("results", resp)
            return {
                "id": result.get("id", ""),
                "name": name,
                "updated": False,
            }

    async def list_named_lists(
        self,
        name_filter: str | None = None,
    ) -> list[dict]:
        """List named lists in BloxOne Threat Defense.

        Args:
            name_filter: Optional name filter (exact match).

        Returns:
            List of named list dicts with id, name, item_count, etc.
        """
        response = await self._td_request("GET", "/named_lists")

        named_lists = []
        for nl in response.get("results", []):
            if name_filter and nl.get("name") != name_filter:
                continue
            named_lists.append(
                {
                    "id": nl.get("id"),
                    "name": nl.get("name"),
                    "type": nl.get("type"),
                    "item_count": nl.get("item_count", 0),
                    "description": nl.get("description", ""),
                    "confidence_level": nl.get("confidence_level", ""),
                }
            )

        return named_lists

    async def delete_named_list(self, list_id: str) -> bool:
        """Delete a named list from BloxOne Threat Defense.

        Args:
            list_id: The named list ID.

        Returns:
            True if deleted.
        """
        await self._td_request("DELETE", f"/named_lists/{list_id}")
        logger.info("Deleted BloxOne TD named list", list_id=list_id)
        return True

    # ------------------------------------------------------------------
    # BloxOne Threat Defense — Security Policy operations
    # ------------------------------------------------------------------

    async def list_security_policies(self) -> list[dict]:
        """List all TD security policies.

        Returns:
            List of policy dicts with id, name, description, rule_count, is_default.
        """
        response = await self._td_request("GET", "/security_policies")
        policies = []
        for p in response.get("results", []):
            policies.append(
                {
                    "id": p.get("id"),
                    "name": p.get("name"),
                    "description": p.get("description", ""),
                    "rule_count": len(p.get("rules", [])),
                    "is_default": p.get("is_default", False),
                }
            )
        return policies

    async def get_security_policy(self, policy_id: int) -> dict:
        """Get a security policy by ID.

        Args:
            policy_id: The security policy ID.

        Returns:
            Full policy dict with rules and metadata.
        """
        response = await self._td_request("GET", f"/security_policies/{policy_id}")
        return response.get("results", response)

    async def bind_named_list_to_policy(
        self,
        named_list_name: str,
        policy_id: int | None = None,
        action: str = "action_block",
    ) -> dict:
        """Add a named list as a block/allow rule in a TD security policy.

        If ``policy_id`` is None, uses the default global policy.

        Args:
            named_list_name: Name of the named list to bind.
            policy_id: Security policy ID. None = default global policy.
            action: TD action — ``action_block``, ``action_allow``, ``action_redirect``.

        Returns:
            Dict with policy_id, rule_count, and status.
        """
        # Find default policy if not specified
        if policy_id is None:
            policies = await self.list_security_policies()
            default = next((p for p in policies if p["is_default"]), None)
            if not default:
                raise ValueError("No default security policy found. Specify --td-policy-id.")
            policy_id = default["id"]
            logger.info(
                "td.using_default_policy",
                policy_id=policy_id,
                policy_name=default["name"],
            )

        # Get current policy
        policy = await self.get_security_policy(policy_id)
        original_rules = policy.get("rules", [])

        # Check if rule already exists — same name AND same action
        for rule in original_rules:
            if rule.get("data") == named_list_name and rule.get("action") == action:
                logger.info(
                    "td.rule_already_exists",
                    named_list=named_list_name,
                    policy_id=policy_id,
                )
                return {
                    "policy_id": policy_id,
                    "policy_name": policy.get("name"),
                    "rule_count": len(original_rules),
                    "action": "already_bound",
                }

        # Remove any existing rules for this named list (action may have changed)
        # e.g., switching from action_log → action_block
        cleaned_rules = [r for r in original_rules if r.get("data") != named_list_name]
        if len(cleaned_rules) < len(original_rules):
            logger.info(
                "td.replacing_rule",
                named_list=named_list_name,
                old_count=len(original_rules),
                new_count=len(cleaned_rules),
            )

        # Prepend our rule (evaluated first)
        new_rule = {"action": action, "data": named_list_name, "type": "custom_list"}
        updated_rules = [new_rule] + cleaned_rules

        update_payload = {
            "name": policy["name"],
            "description": policy.get("description", ""),
            "default_action": policy.get("default_action", "action_allow"),
            "rules": updated_rules,
        }

        await self._td_request("PUT", f"/security_policies/{policy_id}", json=update_payload)

        logger.info(
            "td.rule_bound",
            named_list=named_list_name,
            policy_id=policy_id,
            policy_name=policy.get("name"),
            action=action,
            rule_count=len(updated_rules),
        )

        return {
            "policy_id": policy_id,
            "policy_name": policy.get("name"),
            "rule_count": len(updated_rules),
            "action": "bound",
        }

    async def unbind_named_list_from_policy(
        self,
        named_list_name: str,
        policy_id: int | None = None,
    ) -> dict:
        """Remove a named list rule from a TD security policy.

        Args:
            named_list_name: Name of the named list to unbind.
            policy_id: Security policy ID. None = default global policy.

        Returns:
            Dict with policy_id, rule_count, and status.
        """
        if policy_id is None:
            policies = await self.list_security_policies()
            default = next((p for p in policies if p["is_default"]), None)
            if not default:
                raise ValueError("No default security policy found.")
            policy_id = default["id"]

        policy = await self.get_security_policy(policy_id)
        original_rules = policy.get("rules", [])

        # Remove rules matching our named list
        filtered_rules = [r for r in original_rules if r.get("data") != named_list_name]

        if len(filtered_rules) == len(original_rules):
            return {
                "policy_id": policy_id,
                "policy_name": policy.get("name"),
                "rule_count": len(original_rules),
                "action": "not_found",
            }

        update_payload = {
            "name": policy["name"],
            "description": policy.get("description", ""),
            "default_action": policy.get("default_action", "action_allow"),
            "rules": filtered_rules,
        }

        await self._td_request("PUT", f"/security_policies/{policy_id}", json=update_payload)

        logger.info(
            "td.rule_unbound",
            named_list=named_list_name,
            policy_id=policy_id,
            removed=len(original_rules) - len(filtered_rules),
        )

        return {
            "policy_id": policy_id,
            "policy_name": policy.get("name"),
            "rule_count": len(filtered_rules),
            "action": "unbound",
        }

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
