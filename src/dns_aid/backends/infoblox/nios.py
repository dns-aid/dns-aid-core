# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Infoblox NIOS (on-premises) backend for DNS-AID.

Creates DNS-AID records via the NIOS WAPI (Web API).
This is the traditional on-premises DDI platform from Infoblox.

API Documentation: https://docs.infoblox.com/display/nios/WAPI+Versioning

Original implementation by Ingmar Van Glabbeek (PR #20).
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
from collections.abc import AsyncIterator
from typing import Any

import httpx
import structlog

from dns_aid.backends.base import DNSBackend

logger = structlog.get_logger(__name__)

# Record types supported by DNS-AID via NIOS WAPI.
_SUPPORTED_RECORD_TYPES = {"SVCB", "TXT"}


class InfobloxNIOSBackend(DNSBackend):
    """
    Infoblox NIOS WAPI backend (on-premises).

    Environment Variables:
        NIOS_HOST: NIOS Grid Master hostname
        NIOS_USERNAME: WAPI username
        NIOS_PASSWORD: WAPI password
        NIOS_WAPI_VERSION: WAPI version (default: 2.13.7)
        NIOS_VERIFY_SSL: Verify SSL certificates (default: true)
        NIOS_DNS_VIEW: DNS view name (default: default)
        NIOS_TIMEOUT: HTTP request timeout in seconds (default: 30.0)
    """

    # ``bap`` was historically split as a multi-value key when the
    # field carried comma-separated protocols. draft-02 §5.1 makes it
    # a single scalar (bare ``mcp`` or versioned ``mcp=1.0``); the
    # ``=`` in a versioned value would also re-expand on a split, so
    # we keep bap out of the split set even though current scalar
    # values would be harmless to split.
    _SPLIT_VALUE_KEYS = {"alpn", "ipv4hint", "ipv6hint"}
    # NIOS only accepts registered SVC keys or keyNNNNN numeric keys.
    # Map draft custom names to private-use keyNNNNN aliases for compatibility.
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
        username: str | None = None,
        password: str | None = None,
        wapi_version: str | None = None,
        verify_ssl: bool | None = None,
        dns_view: str | None = None,
        timeout: float | None = None,
    ):
        """Initialize NIOS backend."""
        self._host = (host or os.environ.get("NIOS_HOST", "")).strip()
        self._username = (username or os.environ.get("NIOS_USERNAME", "")).strip()
        password_value = password or os.environ.get("NIOS_PASSWORD")
        self._wapi_version = (
            wapi_version or os.environ.get("NIOS_WAPI_VERSION") or "2.13.7"
        ).strip()

        env_verify_ssl = os.environ.get("NIOS_VERIFY_SSL")
        if verify_ssl is None:
            self._verify_ssl = self._parse_bool_env(env_verify_ssl, default=True)
        else:
            self._verify_ssl = verify_ssl

        self._dns_view = (dns_view or os.environ.get("NIOS_DNS_VIEW") or "default").strip()

        env_timeout = os.environ.get("NIOS_TIMEOUT")
        if timeout is None:
            self._timeout = float(env_timeout) if env_timeout else 30.0
        else:
            self._timeout = timeout

        if not self._host:
            raise ValueError("NIOS host required. Set NIOS_HOST or pass host parameter.")
        if not self._username:
            raise ValueError(
                "NIOS username required. Set NIOS_USERNAME or pass username parameter."
            )
        if not password_value:
            raise ValueError(
                "NIOS password required. Set NIOS_PASSWORD or pass password parameter."
            )
        self._password = password_value

        self._base_url = f"https://{self._host.rstrip('/')}/wapi/v{self._wapi_version}"
        self._client: httpx.AsyncClient | None = None
        self._client_loop_id: int | None = None
        self._zone_cache: dict[str, bool] = {}  # "zone:view" -> exists

    @staticmethod
    def _parse_bool_env(value: str | None, default: bool) -> bool:
        """Parse boolean environment variable values."""
        if value is None:
            return default

        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
        raise ValueError(f"Invalid boolean value: {value}")

    @property
    def name(self) -> str:
        return "nios"

    @property
    def supports_private_svcb_keys(self) -> bool:
        """NIOS accepts private-use SVCB keys (key65280–key65534) natively."""
        return True

    @property
    def dns_view(self) -> str:
        """Get configured DNS view."""
        return self._dns_view

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create async HTTP client for this event loop."""
        current_loop_id = id(asyncio.get_running_loop())

        if self._client is not None and self._client_loop_id != current_loop_id:
            logger.debug(
                "Event loop changed, recreating NIOS HTTP client",
                old_loop_id=self._client_loop_id,
                new_loop_id=current_loop_id,
            )
            with contextlib.suppress(Exception):
                await self._client.aclose()
            self._client = None
            self._client_loop_id = None

        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self._base_url,
                auth=(self._username, self._password),
                verify=self._verify_ssl,
                timeout=self._timeout,
                headers={"Content-Type": "application/json"},
            )
            self._client_loop_id = current_loop_id

        return self._client

    async def close(self) -> None:
        """Close underlying HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
            self._client_loop_id = None

    async def _request(
        self,
        method: str,
        endpoint: str,
        *,
        params: dict[str, str] | None = None,
        json: dict[str, Any] | None = None,
    ) -> dict[str, Any] | list[Any]:
        """Execute a WAPI request with centralized error handling."""
        client = await self._get_client()
        cleaned_endpoint = endpoint if endpoint.startswith("/") else f"/{endpoint}"

        try:
            response = await client.request(
                method=method,
                url=cleaned_endpoint,
                params=params,
                json=json,
            )
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            body = exc.response.text[:500]
            logger.error(
                "NIOS WAPI request failed",
                method=method,
                endpoint=cleaned_endpoint,
                status_code=exc.response.status_code,
                response_body=body,
            )
            raise RuntimeError(
                f"NIOS WAPI request failed ({method} {cleaned_endpoint}): "
                f"status={exc.response.status_code} body={body}"
            ) from exc
        except httpx.HTTPError as exc:
            logger.error(
                "NIOS WAPI transport error",
                method=method,
                endpoint=cleaned_endpoint,
                error=str(exc),
            )
            raise RuntimeError(
                f"NIOS WAPI transport error ({method} {cleaned_endpoint}): {exc}"
            ) from exc

        if not response.content:
            return {}

        content_type = response.headers.get("content-type", "")
        if "application/json" not in content_type:
            return {"raw": response.text}

        parsed = response.json()
        if isinstance(parsed, (dict, list)):
            return parsed

        return {"raw": parsed}

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
    def _normalize_target(target: str) -> str:
        """Normalize SVCB target for NIOS WAPI FQDN validation."""
        return target.strip().rstrip(".")

    @classmethod
    def _to_nios_svc_key(cls, key: str) -> str:
        """Map user-facing key names to NIOS-compatible keys."""
        normalized = key.strip().lower()
        if cls._KEY_NNNNN_RE.match(normalized):
            return normalized
        return cls._CUSTOM_PARAM_TO_NUMERIC_KEY.get(normalized, normalized)

    @classmethod
    def _from_nios_svc_key(cls, key: str) -> str:
        """Map NIOS keyNNNNN aliases back to user-facing key names."""
        normalized = key.strip().lower()
        return cls._NUMERIC_KEY_TO_CUSTOM_PARAM.get(normalized, normalized)

    @classmethod
    def _mandatory_keys(cls, params: dict[str, str]) -> set[str]:
        """Parse mandatory keys from SVCB params map."""
        raw = params.get("mandatory", "")
        keys = set()
        for item in raw.split(","):
            key = item.strip()
            if key:
                keys.add(cls._to_nios_svc_key(key))
        return keys

    @classmethod
    def _svc_parameters_from_params(cls, params: dict[str, str]) -> list[dict[str, Any]]:
        """Convert DNS-AID SVCB params into NIOS svc_parameters format."""
        mandatory_keys = cls._mandatory_keys(params)
        svc_parameters: list[dict[str, Any]] = []

        for key, value in params.items():
            if key == "mandatory":
                continue
            mapped_key = cls._to_nios_svc_key(key)

            key_for_split = cls._from_nios_svc_key(mapped_key)
            if key_for_split in cls._SPLIT_VALUE_KEYS:
                svc_value = [entry.strip() for entry in value.split(",") if entry.strip()]
            else:
                svc_value = [value]

            svc_parameters.append(
                {
                    "svc_key": mapped_key,
                    "svc_value": svc_value,
                    "mandatory": mapped_key in mandatory_keys,
                }
            )

        return svc_parameters

    @classmethod
    def _format_svc_parameters_for_value(cls, svc_parameters: Any) -> str:
        """Format NIOS svc_parameters list to SVCB presentation tokens."""
        if not isinstance(svc_parameters, list):
            return ""

        mandatory_keys: list[str] = []
        seen_mandatory: set[str] = set()
        param_parts: list[str] = []

        for item in svc_parameters:
            if not isinstance(item, dict):
                continue

            raw_key = str(item.get("svc_key", "")).strip()
            if not raw_key:
                continue
            key = cls._from_nios_svc_key(raw_key)

            raw_values = item.get("svc_value", [])
            if isinstance(raw_values, list):
                values = [str(value).strip() for value in raw_values if str(value).strip()]
            elif raw_values is None:
                values = []
            else:
                value = str(raw_values).strip()
                values = [value] if value else []

            if item.get("mandatory") and key not in seen_mandatory:
                mandatory_keys.append(key)
                seen_mandatory.add(key)

            if values:
                joined = ",".join(values).replace('"', r"\"")
                param_parts.append(f'{key}="{joined}"')

        if mandatory_keys:
            mandatory_value = ",".join(mandatory_keys).replace('"', r"\"")
            param_parts.insert(0, f'mandatory="{mandatory_value}"')

        return " ".join(param_parts)

    @staticmethod
    def _extract_name_from_fqdn(fqdn: str, zone: str) -> str:
        """Extract the record name by stripping the zone suffix from the FQDN.

        Returns the FQDN unchanged if it doesn't end with the zone suffix.
        """
        zone_suffix = f".{zone.rstrip('.')}"
        fqdn_clean = fqdn.rstrip(".")
        if fqdn_clean.endswith(zone_suffix):
            return fqdn_clean.removesuffix(zone_suffix)
        return fqdn_clean

    # ------------------------------------------------------------------
    # Record lookup helpers
    # ------------------------------------------------------------------

    async def _find_record_ref(self, zone: str, name: str, record_type: str) -> str | None:
        """Find record reference by owner name, type, and configured DNS view."""
        fqdn = self._to_fqdn(name, zone)
        params = {
            "name": fqdn,
            "view": self._dns_view,
        }

        results = await self._request("GET", f"record:{record_type.lower()}", params=params)
        if isinstance(results, list) and results:
            ref = results[0].get("_ref")
            if isinstance(ref, str):
                return ref

        return None

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
        """Create SVCB record in NIOS."""
        fqdn = self._to_fqdn(name, zone)
        svc_parameters = self._svc_parameters_from_params(params)

        # Mutable fields (allowed in both POST and PUT).
        mutable: dict[str, Any] = {
            "priority": priority,
            "target_name": self._normalize_target(target),
            "svc_parameters": svc_parameters,
            "ttl": ttl,
            "use_ttl": True,
            "comment": f"DNS-AID: SVCB record for {name}",
        }

        record_ref = await self._find_record_ref(zone, name, "svcb")

        if record_ref:
            logger.info(
                "Updating SVCB record in NIOS",
                fqdn=fqdn,
                record_ref=record_ref,
            )
            await self._request("PUT", record_ref, json=mutable)
        else:
            # Immutable fields (name, view) only on creation.
            payload = {"name": fqdn, "view": self._dns_view, **mutable}
            logger.info("Creating SVCB record in NIOS", fqdn=fqdn)
            await self._request("POST", "record:svcb", json=payload)

        return fqdn

    async def create_txt_record(
        self,
        zone: str,
        name: str,
        values: list[str],
        ttl: int = 3600,
    ) -> str:
        """Create TXT record in NIOS."""
        fqdn = self._to_fqdn(name, zone)

        # Mutable fields (allowed in both POST and PUT).
        mutable: dict[str, Any] = {
            "text": " ".join(f'"{value}"' for value in values),
            "ttl": ttl,
            "use_ttl": True,
            "comment": f"DNS-AID: TXT record for {name}",
        }

        record_ref = await self._find_record_ref(zone, name, "txt")

        if record_ref:
            logger.info(
                "Updating TXT record in NIOS",
                fqdn=fqdn,
                record_ref=record_ref,
            )
            await self._request("PUT", record_ref, json=mutable)
        else:
            # Immutable fields (name, view) only on creation.
            payload = {"name": fqdn, "view": self._dns_view, **mutable}
            logger.info("Creating TXT record in NIOS", fqdn=fqdn)
            await self._request("POST", "record:txt", json=payload)

        return fqdn

    async def delete_record(
        self,
        zone: str,
        name: str,
        record_type: str,
    ) -> bool:
        """Delete a DNS record from NIOS."""
        record_ref = await self._find_record_ref(zone, name, record_type)
        if not record_ref:
            logger.warning(
                "Record not found in NIOS",
                zone=zone,
                name=name,
                record_type=record_type,
            )
            return False

        await self._request("DELETE", record_ref)
        logger.info(
            "Deleted record from NIOS",
            zone=zone,
            name=name,
            record_type=record_type,
        )
        return True

    async def list_records(
        self,
        zone: str,
        name_pattern: str | None = None,
        record_type: str | None = None,
    ) -> AsyncIterator[dict[str, Any]]:
        """List DNS records in NIOS zone/view."""
        if record_type:
            upper = record_type.upper()
            if upper not in _SUPPORTED_RECORD_TYPES:
                logger.warning(
                    "Unsupported record type for NIOS list_records",
                    record_type=record_type,
                    supported=sorted(_SUPPORTED_RECORD_TYPES),
                )
                return
            supported_types = [upper]
        else:
            supported_types = sorted(_SUPPORTED_RECORD_TYPES)

        zone_clean = zone.rstrip(".")

        for rtype in supported_types:
            endpoint = f"record:{rtype.lower()}"
            params = {
                "zone": zone_clean,
                "view": self._dns_view,
            }

            results = await self._request("GET", endpoint, params=params)
            if not isinstance(results, list):
                continue

            for record in results:
                fqdn = str(record.get("name", "")).rstrip(".")
                if not fqdn:
                    continue

                if name_pattern and name_pattern not in fqdn:
                    continue

                values: list[str]
                ttl = int(record.get("ttl", 0))

                if rtype == "TXT":
                    values = [str(record.get("text", ""))]
                else:
                    priority = int(record.get("priority", 0))
                    target_name = str(record.get("target_name", ""))
                    svc_parameters_text = self._format_svc_parameters_for_value(
                        record.get("svc_parameters", [])
                    )
                    values = [f"{priority} {target_name} {svc_parameters_text}".strip()]

                yield {
                    "name": self._extract_name_from_fqdn(fqdn, zone_clean),
                    "fqdn": fqdn,
                    "type": rtype,
                    "ttl": ttl,
                    "values": values,
                    "id": record.get("_ref"),
                }

    async def get_record(
        self,
        zone: str,
        name: str,
        record_type: str,
    ) -> dict[str, Any] | None:
        """Get a specific record by querying NIOS WAPI directly."""
        fqdn = self._to_fqdn(name, zone)
        params = {
            "name": fqdn,
            "view": self._dns_view,
        }

        results = await self._request("GET", f"record:{record_type.lower()}", params=params)
        if not isinstance(results, list) or not results:
            return None

        record = results[0]
        zone_clean = zone.rstrip(".")
        record_fqdn = str(record.get("name", "")).rstrip(".")
        ttl = int(record.get("ttl", 0))
        rtype = record_type.upper()

        if rtype == "TXT":
            values = [str(record.get("text", ""))]
        else:
            priority = int(record.get("priority", 0))
            target_name = str(record.get("target_name", ""))
            svc_parameters_text = self._format_svc_parameters_for_value(
                record.get("svc_parameters", [])
            )
            values = [f"{priority} {target_name} {svc_parameters_text}".strip()]

        return {
            "name": self._extract_name_from_fqdn(record_fqdn, zone_clean),
            "fqdn": record_fqdn,
            "type": rtype,
            "ttl": ttl,
            "values": values,
            "id": record.get("_ref"),
        }

    async def zone_exists(self, zone: str) -> bool:
        """Check if authoritative zone exists in the configured DNS view.

        Returns False (rather than raising) when the configured DNS view
        does not exist on the NIOS grid or any other WAPI error occurs,
        since the zone is effectively inaccessible.
        """
        zone_name = zone.rstrip(".")
        cache_key = f"{zone_name}:{self._dns_view}"

        if cache_key in self._zone_cache:
            return self._zone_cache[cache_key]

        try:
            params = {
                "fqdn": zone_name,
                "view": self._dns_view,
            }

            results = await self._request("GET", "zone_auth", params=params)
            if isinstance(results, list) and len(results) > 0:
                self._zone_cache[cache_key] = True
                return True

            # Some NIOS deployments store/expect trailing-dot zone fqdn values.
            params["fqdn"] = f"{zone_name}."
            results = await self._request("GET", "zone_auth", params=params)
            exists = isinstance(results, list) and len(results) > 0
            self._zone_cache[cache_key] = exists
            return exists

        except RuntimeError as exc:
            error_msg = str(exc)
            if "not found" in error_msg.lower() and "view" in error_msg.lower():
                logger.error(
                    "DNS view does not exist on NIOS grid",
                    view=self._dns_view,
                    zone=zone_name,
                    hint="Check NIOS_DNS_VIEW setting. "
                    "Use list_zones() or the NIOS UI to see available views.",
                )
            else:
                logger.error(
                    "Failed to check zone existence",
                    zone=zone_name,
                    view=self._dns_view,
                    error=error_msg,
                )
            self._zone_cache[cache_key] = False
            return False

    async def list_zones(self) -> list[dict[str, Any]]:
        """List authoritative zones in the configured DNS view."""
        params = {
            "view": self._dns_view,
        }
        results = await self._request("GET", "zone_auth", params=params)

        if not isinstance(results, list):
            return []

        zones: list[dict[str, Any]] = []
        for zone in results:
            if not isinstance(zone, dict):
                continue

            fqdn = str(zone.get("fqdn", ""))
            zones.append(
                {
                    "id": zone.get("_ref"),
                    "name": fqdn.rstrip("."),
                    "fqdn": fqdn,
                    "view": zone.get("view", self._dns_view),
                    "comment": zone.get("comment", ""),
                    "disabled": bool(zone.get("disable", False)),
                    "zone_format": zone.get("zone_format", ""),
                }
            )

        return zones

    # ------------------------------------------------------------------
    # RPZ (Response Policy Zone) operations
    # ------------------------------------------------------------------

    _RPZ_CNAME_TARGETS: dict[str, str] = {
        "NXDOMAIN": "",  # canonical_name = empty → NXDOMAIN
        "NODATA": "",
        "PASSTHRU": "",
        "DROP": "",
    }

    async def create_rpz_cname_record(
        self,
        rpz_zone: str,
        owner: str,
        action: str,
        comment: str = "",
    ) -> str:
        """Create an RPZ CNAME record in NIOS.

        NIOS WAPI object: ``record:rpz:cname``

        The ``canonical`` field encodes the RPZ action:
          - NXDOMAIN: empty canonical
          - PASSTHRU: canonical = owner (identity CNAME)
          - NODATA:   NIOS uses record:rpz:cname:clientipaddress with empty rdata
          - DROP:     NIOS uses rpz-drop. target

        .. note:: **DROP→NXDOMAIN fallback**

           NIOS WAPI silently converts DROP to NXDOMAIN for
           ``record:rpz:cname`` objects.  The ``rpz-drop.`` canonical target
           is accepted by the API but the resolver behavior is identical to
           NXDOMAIN.  This is a NIOS platform limitation, not a dns-aid bug.
           If you need true DROP semantics (TCP RST / timeout), use bind-aid
           or a resolver that supports the full RPZ action set (e.g., Unbound).

        For simplicity we map everything through the ``rp_zone`` and
        ``canonical`` fields which NIOS interprets as RPZ directives.

        Args:
            rpz_zone: The RPZ zone FQDN (e.g., ``rpz.example.com``).
            owner: The trigger name (e.g., ``evil.com``).
            action: RPZ action — NXDOMAIN, PASSTHRU, DROP.
            comment: Audit comment for the record.

        Returns:
            The owner FQDN that was created/updated.
        """
        action_upper = action.upper()

        # Build the full owner name within the RPZ zone
        fqdn = f"{owner}.{rpz_zone}" if not owner.endswith(f".{rpz_zone}") else owner

        # Determine canonical name based on action
        if action_upper == "PASSTHRU":
            canonical = owner  # identity CNAME = passthru
        else:
            canonical = ""  # empty = NXDOMAIN (NIOS default for RPZ CNAME)

        # Check for existing record
        params = {
            "name": fqdn,
            "zone": rpz_zone,
        }
        existing = await self._request("GET", "record:rpz:cname", params=params)

        mutable: dict[str, Any] = {
            "canonical": canonical,
            "comment": comment or f"DNS-AID RPZ: {action_upper} {owner}",
        }

        if isinstance(existing, list) and existing:
            ref = existing[0].get("_ref")
            if ref:
                logger.info(
                    "Updating RPZ CNAME record in NIOS",
                    fqdn=fqdn,
                    action=action_upper,
                    ref=ref,
                )
                await self._request("PUT", ref, json=mutable)
                return fqdn

        # Create new record
        payload: dict[str, Any] = {
            "name": fqdn,
            "rp_zone": rpz_zone,
            "canonical": canonical,
            "comment": comment or f"DNS-AID RPZ: {action_upper} {owner}",
        }
        logger.info(
            "Creating RPZ CNAME record in NIOS",
            fqdn=fqdn,
            action=action_upper,
        )
        await self._request("POST", "record:rpz:cname", json=payload)
        return fqdn

    async def delete_rpz_cname_record(
        self,
        rpz_zone: str,
        owner: str,
    ) -> bool:
        """Delete an RPZ CNAME record from NIOS.

        Args:
            rpz_zone: The RPZ zone FQDN.
            owner: The trigger name to delete.

        Returns:
            True if deleted, False if not found.
        """
        fqdn = f"{owner}.{rpz_zone}" if not owner.endswith(f".{rpz_zone}") else owner
        params = {
            "name": fqdn,
            "zone": rpz_zone,
        }
        existing = await self._request("GET", "record:rpz:cname", params=params)

        if not isinstance(existing, list) or not existing:
            return False

        ref = existing[0].get("_ref")
        if not ref:
            return False

        await self._request("DELETE", ref)
        logger.info("Deleted RPZ CNAME record from NIOS", fqdn=fqdn)
        return True

    async def list_rpz_cname_records(
        self,
        rpz_zone: str,
    ) -> list[dict[str, Any]]:
        """List all RPZ CNAME records in an RPZ zone.

        Args:
            rpz_zone: The RPZ zone FQDN.

        Returns:
            List of RPZ records with name, canonical, and comment.
        """
        params = {
            "zone": rpz_zone,
            "_return_fields": "name,canonical,comment,disable",
        }
        results = await self._request("GET", "record:rpz:cname", params=params)

        if not isinstance(results, list):
            return []

        records: list[dict[str, Any]] = []
        for r in results:
            if not isinstance(r, dict):
                continue
            name = str(r.get("name", ""))
            canonical = str(r.get("canonical", ""))

            # Infer action from canonical
            if not canonical:
                action = "NXDOMAIN"
            elif canonical == name.removesuffix(f".{rpz_zone}"):
                action = "PASSTHRU"
            else:
                action = "NXDOMAIN"  # fallback

            records.append(
                {
                    "owner": name.removesuffix(f".{rpz_zone}"),
                    "fqdn": name,
                    "action": action,
                    "canonical": canonical,
                    "comment": r.get("comment", ""),
                    "disabled": bool(r.get("disable", False)),
                }
            )

        return records

    async def ensure_rpz_zone(self, rpz_zone: str) -> bool:
        """Ensure an RPZ zone exists in NIOS, creating it if needed.

        Args:
            rpz_zone: The RPZ zone FQDN.

        Returns:
            True if the zone exists or was created.
        """
        params = {
            "fqdn": rpz_zone,
        }
        existing = await self._request("GET", "zone_rp", params=params)

        if isinstance(existing, list) and existing:
            logger.debug("RPZ zone exists in NIOS", rpz_zone=rpz_zone)
            return True

        # Create the RPZ zone
        payload = {
            "fqdn": rpz_zone,
            "rpz_policy": "GIVEN",  # Use explicit records (not policy override)
            "comment": "DNS-AID managed RPZ zone",
        }
        logger.info("Creating RPZ zone in NIOS", rpz_zone=rpz_zone)
        await self._request("POST", "zone_rp", json=payload)
        return True

    # publish_agent() inherited from base class — passes ALL SVCB params
    # natively since supports_private_svcb_keys = True.

    async def __aenter__(self) -> InfobloxNIOSBackend:
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        """Async context manager exit."""
        await self.close()
