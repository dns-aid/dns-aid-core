# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
AWS Route 53 DNS backend.

Creates DNS-AID records (SVCB, TXT) in AWS Route 53 hosted zones.
Supports both zone ID and domain name for zone identification.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

import structlog

from dns_aid.backends.base import DNSBackend

if TYPE_CHECKING:
    from mypy_boto3_route53 import Route53Client


logger = structlog.get_logger(__name__)

# Private-use SVCB key demotion is handled by the DNSBackend base class.
# Route 53 rejects key65280–key65534 — base class demotes them to TXT.


class Route53Backend(DNSBackend):
    """
    AWS Route 53 DNS backend.

    Creates and manages DNS-AID records in Route 53 hosted zones.

    Example:
        >>> backend = Route53Backend(zone_id="ZEXAMPLEZONEID")
        >>> await backend.create_svcb_record(
        ...     zone="example.com",
        ...     name="_chat._a2a._agents",
        ...     priority=1,
        ...     target="chat.example.com.",
        ...     params={"alpn": "a2a", "port": "443"}
        ... )

        >>> # Or use domain name to auto-discover zone
        >>> backend = Route53Backend()
        >>> await backend.create_svcb_record(
        ...     zone="example.com",  # Will find zone ID automatically
        ...     ...
        ... )
    """

    def __init__(
        self,
        zone_id: str | None = None,
        region: str | None = None,
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
    ):
        """
        Initialize Route 53 backend.

        Args:
            zone_id: Optional hosted zone ID (e.g., "ZEXAMPLEZONEID").
                     If omitted, falls back to the ``ROUTE53_ZONE_ID``
                     environment variable; if neither is set, the zone is
                     looked up by domain name via ``ListHostedZonesByName``
                     (which requires the ``route53:ListHostedZones`` IAM
                     permission).
            region: AWS region (defaults to us-east-1 for Route 53)
            aws_access_key_id: AWS access key (defaults to env/credentials)
            aws_secret_access_key: AWS secret key (defaults to env/credentials)
        """
        self._zone_id = zone_id or os.environ.get("ROUTE53_ZONE_ID")
        self._region = region or os.environ.get("AWS_REGION", "us-east-1")
        self._aws_access_key_id = aws_access_key_id
        self._aws_secret_access_key = aws_secret_access_key
        self._client: Route53Client | None = None
        self._zone_cache: dict[str, str] = {}  # domain -> zone_id

    @property
    def name(self) -> str:
        return "route53"

    def _get_client(self) -> Route53Client:
        """Get or create boto3 Route 53 client."""
        if self._client is None:
            import boto3

            kwargs = {"region_name": self._region}
            if self._aws_access_key_id and self._aws_secret_access_key:
                kwargs["aws_access_key_id"] = self._aws_access_key_id
                kwargs["aws_secret_access_key"] = self._aws_secret_access_key

            self._client = boto3.client("route53", **kwargs)  # type: ignore[call-overload]

        return self._client

    async def _get_zone_id(self, zone: str) -> str:
        """
        Get Route 53 hosted zone ID for a domain.

        Args:
            zone: Domain name (e.g., "example.com")

        Returns:
            Zone ID (e.g., "ZEXAMPLEZONEID")

        Raises:
            ValueError: If zone not found
        """
        # Use configured zone ID if set
        if self._zone_id:
            return self._zone_id

        # Check cache
        if zone in self._zone_cache:
            return self._zone_cache[zone]

        # Normalize domain
        domain = zone.lower().rstrip(".")

        client = self._get_client()

        # List hosted zones and find matching one
        paginator = client.get_paginator("list_hosted_zones")

        for page in paginator.paginate():
            for hz in page["HostedZones"]:
                hz_name = hz["Name"].rstrip(".")
                if hz_name == domain:
                    # Extract zone ID (remove /hostedzone/ prefix)
                    zone_id = hz["Id"].replace("/hostedzone/", "")
                    self._zone_cache[zone] = zone_id
                    logger.debug("Found zone ID", domain=domain, zone_id=zone_id)
                    return zone_id

        raise ValueError(f"No hosted zone found for domain: {zone}")

    def _format_svcb_value(
        self,
        priority: int,
        target: str,
        params: dict[str, str],
    ) -> str:
        """
        Format SVCB record value for Route 53.

        Route 53 SVCB format: <priority> <target> [<params>...]

        Example: 1 chat.example.com. alpn="a2a" port="443"
        """
        # Ensure target has trailing dot
        if not target.endswith("."):
            target = f"{target}."

        # Build parameter string
        param_parts = []
        for key, value in params.items():
            # Route 53 uses key="value" format for SVCB params
            param_parts.append(f'{key}="{value}"')

        params_str = " ".join(param_parts)

        if params_str:
            return f"{priority} {target} {params_str}"
        else:
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
        """Create SVCB record in Route 53."""
        zone_id = await self._get_zone_id(zone)
        client = self._get_client()

        # Build FQDN
        fqdn = f"{name}.{zone}"
        if not fqdn.endswith("."):
            fqdn = f"{fqdn}."

        # Format SVCB value
        svcb_value = self._format_svcb_value(priority, target, params)

        logger.info(
            "Creating SVCB record",
            zone=zone,
            zone_id=zone_id,
            name=fqdn,
            value=svcb_value,
            ttl=ttl,
        )

        # Create change batch
        change_batch = {
            "Comment": f"DNS-AID: Create SVCB record for {name}",
            "Changes": [
                {
                    "Action": "UPSERT",
                    "ResourceRecordSet": {
                        "Name": fqdn,
                        "Type": "SVCB",
                        "TTL": ttl,
                        "ResourceRecords": [{"Value": svcb_value}],
                    },
                }
            ],
        }

        # Execute change
        response = client.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch=change_batch,  # type: ignore[arg-type]
        )

        change_id = response["ChangeInfo"]["Id"]
        logger.info("SVCB record created", fqdn=fqdn, change_id=change_id)

        return fqdn.rstrip(".")

    async def create_txt_record(
        self,
        zone: str,
        name: str,
        values: list[str],
        ttl: int = 3600,
    ) -> str:
        """Create TXT record in Route 53."""
        zone_id = await self._get_zone_id(zone)
        client = self._get_client()

        # Build FQDN
        fqdn = f"{name}.{zone}"
        if not fqdn.endswith("."):
            fqdn = f"{fqdn}."

        # TXT records need quoted values
        txt_values = [{"Value": f'"{v}"'} for v in values]

        logger.info(
            "Creating TXT record",
            zone=zone,
            zone_id=zone_id,
            name=fqdn,
            values=values,
            ttl=ttl,
        )

        # Create change batch
        change_batch = {
            "Comment": f"DNS-AID: Create TXT record for {name}",
            "Changes": [
                {
                    "Action": "UPSERT",
                    "ResourceRecordSet": {
                        "Name": fqdn,
                        "Type": "TXT",
                        "TTL": ttl,
                        "ResourceRecords": txt_values,
                    },
                }
            ],
        }

        # Execute change
        response = client.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch=change_batch,  # type: ignore[arg-type]
        )

        change_id = response["ChangeInfo"]["Id"]
        logger.info("TXT record created", fqdn=fqdn, change_id=change_id)

        return fqdn.rstrip(".")

    # publish_agent() inherited from DNSBackend base class — automatically
    # demotes private-use SVCB keys to TXT since Route 53 rejects them.

    async def delete_record(
        self,
        zone: str,
        name: str,
        record_type: str,
    ) -> bool:
        """Delete a DNS record from Route 53."""
        zone_id = await self._get_zone_id(zone)
        client = self._get_client()

        # Build FQDN
        fqdn = f"{name}.{zone}"
        if not fqdn.endswith("."):
            fqdn = f"{fqdn}."

        logger.info(
            "Deleting record",
            zone=zone,
            name=fqdn,
            type=record_type,
        )

        # First, get the existing record to know its value
        try:
            response = client.list_resource_record_sets(
                HostedZoneId=zone_id,
                StartRecordName=fqdn,
                StartRecordType=record_type,  # type: ignore[arg-type]
                MaxItems="1",
            )

            record_sets = response.get("ResourceRecordSets", [])
            if not record_sets:
                logger.warning("Record not found", fqdn=fqdn, type=record_type)
                return False

            record = record_sets[0]

            # Verify it's the exact record we want
            if record["Name"] != fqdn or record["Type"] != record_type:
                logger.warning("Record not found (mismatch)", fqdn=fqdn, type=record_type)
                return False

            # Delete the record
            change_batch = {
                "Comment": f"DNS-AID: Delete {record_type} record for {name}",
                "Changes": [
                    {
                        "Action": "DELETE",
                        "ResourceRecordSet": record,
                    }
                ],
            }

            client.change_resource_record_sets(
                HostedZoneId=zone_id,
                ChangeBatch=change_batch,  # type: ignore[arg-type]
            )

            logger.info("Record deleted", fqdn=fqdn, type=record_type)
            return True

        except Exception as e:
            logger.exception("Failed to delete record", error=str(e))
            return False

    async def list_records(
        self,
        zone: str,
        name_pattern: str | None = None,
        record_type: str | None = None,
    ) -> AsyncIterator[dict]:
        """List DNS records in Route 53 zone."""
        zone_id = await self._get_zone_id(zone)
        client = self._get_client()

        logger.debug(
            "Listing records",
            zone=zone,
            zone_id=zone_id,
            name_pattern=name_pattern,
            record_type=record_type,
        )

        paginator = client.get_paginator("list_resource_record_sets")

        for page in paginator.paginate(HostedZoneId=zone_id):
            for record in page["ResourceRecordSets"]:
                rname = record["Name"].rstrip(".")
                rtype = record["Type"]

                # Filter by name pattern (simple substring match)
                if name_pattern and name_pattern not in rname:
                    continue

                # Filter by record type
                if record_type and rtype != record_type:
                    continue

                # Extract values
                values = []
                for rr in record.get("ResourceRecords", []):
                    values.append(rr["Value"])

                yield {
                    "name": rname.replace(f".{zone}", ""),
                    "fqdn": rname,
                    "type": rtype,
                    "ttl": record.get("TTL", 0),
                    "values": values,
                }

    async def zone_exists(self, zone: str) -> bool:
        """Check if zone exists in Route 53.

        Returns False (rather than raising) on any API or network error,
        since the zone is effectively inaccessible.
        """
        try:
            await self._get_zone_id(zone)
            return True
        except ValueError:
            return False
        except Exception as exc:
            logger.warning(
                "Failed to check zone existence in Route 53",
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
        Get a specific DNS record by querying Route 53 API directly.

        More efficient than list_records for single record lookup.
        """
        zone_id = await self._get_zone_id(zone)
        client = self._get_client()

        # Build FQDN
        fqdn = f"{name}.{zone}"
        if not fqdn.endswith("."):
            fqdn = f"{fqdn}."

        try:
            response = client.list_resource_record_sets(
                HostedZoneId=zone_id,
                StartRecordName=fqdn,
                StartRecordType=record_type,  # type: ignore[arg-type]
                MaxItems="1",
            )

            record_sets = response.get("ResourceRecordSets", [])
            if not record_sets:
                return None

            record = record_sets[0]

            # Verify it's the exact record we want
            if record["Name"] != fqdn or record["Type"] != record_type:
                return None

            # Extract values
            values = [rr["Value"] for rr in record.get("ResourceRecords", [])]

            return {
                "name": name,
                "fqdn": fqdn.rstrip("."),
                "type": record_type,
                "ttl": record.get("TTL", 0),
                "values": values,
            }

        except Exception as e:
            logger.debug("Record not found", fqdn=fqdn, type=record_type, error=str(e))
            return None

    async def list_zones(self) -> list[dict]:
        """
        List all hosted zones in the account.

        Returns:
            List of zone info dicts with id, name, record_count
        """
        client = self._get_client()
        zones = []

        paginator = client.get_paginator("list_hosted_zones")

        for page in paginator.paginate():
            for hz in page["HostedZones"]:
                zones.append(
                    {
                        "id": hz["Id"].replace("/hostedzone/", ""),
                        "name": hz["Name"].rstrip("."),
                        "record_count": hz["ResourceRecordSetCount"],
                        "private": hz["Config"].get("PrivateZone", False),
                    }
                )

        return zones

    async def get_change_status(self, change_id: str) -> str:
        """
        Get status of a change request.

        Args:
            change_id: Change ID from create/delete operation

        Returns:
            Status string: "PENDING" or "INSYNC"
        """
        client = self._get_client()

        response = client.get_change(Id=change_id)
        return response["ChangeInfo"]["Status"]

    async def wait_for_change(self, change_id: str, max_wait: int = 60) -> bool:
        """
        Wait for a change to propagate.

        Args:
            change_id: Change ID to wait for
            max_wait: Maximum seconds to wait

        Returns:
            True if change completed, False if timeout
        """
        import asyncio

        client = self._get_client()

        for _ in range(max_wait):
            response = client.get_change(Id=change_id)
            if response["ChangeInfo"]["Status"] == "INSYNC":
                return True
            await asyncio.sleep(1)

        return False
