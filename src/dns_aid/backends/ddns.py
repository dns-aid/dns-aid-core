# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
DDNS (Dynamic DNS) backend using RFC 2136.

Universal backend that works with any DNS server supporting Dynamic DNS updates,
including BIND, Windows DNS, PowerDNS, and other RFC 2136 compliant servers.

This provides a vendor-neutral alternative to API-based backends like Route53
and Infoblox.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path

import dns.name
import dns.query
import dns.rdatatype
import dns.resolver
import dns.tsigkeyring
import dns.update
import structlog

from dns_aid.backends.base import DNSBackend

logger = structlog.get_logger(__name__)


class DDNSBackend(DNSBackend):
    """
    RFC 2136 Dynamic DNS backend.

    Works with any DNS server that supports DDNS updates:
    - BIND9
    - Windows DNS Server
    - PowerDNS
    - Knot DNS
    - Any RFC 2136 compliant server

    Authentication is via TSIG (Transaction Signature) keys.

    Example:
        >>> backend = DDNSBackend(
        ...     server="ns1.example.com",
        ...     key_name="dns-aid-key",
        ...     key_secret="base64secret==",
        ...     key_algorithm="hmac-sha256"
        ... )
        >>> await backend.create_svcb_record(
        ...     zone="example.com",
        ...     name="_chat._a2a._agents",
        ...     priority=1,
        ...     target="chat.example.com.",
        ...     params={"alpn": "a2a", "port": "443"}
        ... )

    Environment Variables:
        DDNS_SERVER: DNS server hostname or IP
        DDNS_KEY_NAME: TSIG key name
        DDNS_KEY_SECRET: TSIG key secret (base64)
        DDNS_KEY_ALGORITHM: TSIG algorithm (default: hmac-sha256)
        DDNS_PORT: DNS server port (default: 53)
        DDNS_TIMEOUT: Query timeout in seconds (default: 10)
    """

    SUPPORTED_ALGORITHMS = [
        "hmac-sha256",
        "hmac-sha384",
        "hmac-sha512",
        "hmac-sha224",
        "hmac-md5",
    ]

    def __init__(
        self,
        server: str | None = None,
        key_name: str | None = None,
        key_secret: str | None = None,
        key_algorithm: str | None = None,
        port: int | None = None,
        timeout: float | None = None,
        key_file: str | Path | None = None,
    ):
        """
        Initialize DDNS backend.

        Args:
            server: DNS server hostname or IP address
            key_name: TSIG key name
            key_secret: TSIG key secret (base64 encoded)
            key_algorithm: TSIG algorithm (default: hmac-sha256)
            port: DNS server port (default: 53)
            timeout: Query timeout in seconds (default: 10)
            key_file: Path to TSIG key file (alternative to key_name/key_secret)
        """
        self.server = server or os.environ.get("DDNS_SERVER")
        self.port = port if port is not None else int(os.environ.get("DDNS_PORT", "53"))
        self.timeout = (
            timeout if timeout is not None else float(os.environ.get("DDNS_TIMEOUT", "10"))
        )

        # Load TSIG key
        if key_file:
            self._load_key_file(Path(key_file))
        else:
            self.key_name = key_name or os.environ.get("DDNS_KEY_NAME")
            self.key_secret = key_secret or os.environ.get("DDNS_KEY_SECRET")
            self.key_algorithm = key_algorithm or os.environ.get(
                "DDNS_KEY_ALGORITHM", "hmac-sha256"
            )

        # Validate configuration
        if not self.server:
            raise ValueError("DDNS server not configured. Set DDNS_SERVER or pass server=")

        if not self.key_name or not self.key_secret:
            raise ValueError(
                "TSIG key not configured. Set DDNS_KEY_NAME/DDNS_KEY_SECRET or pass key_name/key_secret"
            )

        if self.key_algorithm not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(
                f"Unsupported TSIG algorithm: {self.key_algorithm}. "
                f"Supported: {self.SUPPORTED_ALGORITHMS}"
            )

        # Create TSIG keyring
        self._keyring = dns.tsigkeyring.from_text({self.key_name: self.key_secret})
        self._algorithm = dns.name.from_text(f"{self.key_algorithm}.")

        logger.debug(
            "DDNS backend initialized",
            server=self.server,
            port=self.port,
            key_name=self.key_name,
            algorithm=self.key_algorithm,
        )

    def _load_key_file(self, key_file: Path) -> None:
        """Load TSIG key from file (BIND key file format)."""
        if not key_file.exists():
            raise FileNotFoundError(f"TSIG key file not found: {key_file}")

        content = key_file.read_text()

        # Parse BIND key file format:
        # key "keyname" {
        #     algorithm hmac-sha256;
        #     secret "base64secret==";
        # };
        import re

        key_match = re.search(r'key\s+"([^"]+)"', content)
        algo_match = re.search(r"algorithm\s+([^;]+);", content)
        secret_match = re.search(r'secret\s+"([^"]+)"', content)

        if not all([key_match, algo_match, secret_match]):
            raise ValueError(f"Invalid TSIG key file format: {key_file}")

        self.key_name = key_match.group(1)
        self.key_algorithm = algo_match.group(1).strip()
        self.key_secret = secret_match.group(1)

    @property
    def name(self) -> str:
        return "ddns"

    @property
    def supports_private_svcb_keys(self) -> bool | None:
        """Unknown — depends on the target DNS server.

        BIND, PowerDNS, and Knot accept private-use SVCB keys.
        Windows DNS and older servers may not.

        Returns ``None`` so the base class tries native first and
        automatically falls back to TXT demotion if the server rejects.
        """
        return None

    def _format_svcb_rdata(self, priority: int, target: str, params: dict[str, str]) -> str:
        """Format SVCB record data string."""
        # Ensure target has trailing dot
        if not target.endswith("."):
            target = f"{target}."

        # Build parameter string
        param_parts = []
        for key, value in params.items():
            if key == "mandatory":
                # mandatory parameter is special - comma-separated list
                param_parts.append(f'{key}="{value}"')
            else:
                param_parts.append(f'{key}="{value}"')

        params_str = " ".join(param_parts)
        return f"{priority} {target} {params_str}"

    async def create_svcb_record(
        self,
        zone: str,
        name: str,
        priority: int,
        target: str,
        params: dict[str, str],
        ttl: int = 3600,
    ) -> str:
        """Create SVCB record via DDNS update."""
        fqdn = f"{name}.{zone}"

        # Build SVCB rdata
        rdata = self._format_svcb_rdata(priority, target, params)

        logger.info(
            "Creating SVCB record via DDNS",
            server=self.server,
            zone=zone,
            name=name,
            fqdn=fqdn,
            rdata=rdata,
            ttl=ttl,
        )

        # Create update message
        update = dns.update.Update(zone, keyring=self._keyring, keyalgorithm=self._algorithm)

        # Delete any existing SVCB records for this name, then add new one
        update.delete(name, dns.rdatatype.SVCB)
        update.add(name, ttl, dns.rdatatype.SVCB, rdata)

        # Send update
        try:
            response = dns.query.tcp(update, self.server, port=self.port, timeout=self.timeout)
            rcode = response.rcode()
            if rcode != dns.rcode.NOERROR:
                raise RuntimeError(f"DDNS update failed: {dns.rcode.to_text(rcode)}")

            logger.info("SVCB record created via DDNS", fqdn=fqdn)
            return fqdn

        except dns.query.BadResponse as e:
            logger.error("DDNS update failed", error=str(e), fqdn=fqdn)
            raise RuntimeError(f"DDNS update failed: {e}") from e

    async def create_txt_record(
        self,
        zone: str,
        name: str,
        values: list[str],
        ttl: int = 3600,
    ) -> str:
        """Create TXT record via DDNS update."""
        fqdn = f"{name}.{zone}"

        logger.info(
            "Creating TXT record via DDNS",
            server=self.server,
            zone=zone,
            name=name,
            fqdn=fqdn,
            values=values,
            ttl=ttl,
        )

        # Create update message
        update = dns.update.Update(zone, keyring=self._keyring, keyalgorithm=self._algorithm)

        # Delete any existing TXT records for this name
        update.delete(name, dns.rdatatype.TXT)

        # Add each TXT value
        for value in values:
            # TXT records need to be quoted
            update.add(name, ttl, dns.rdatatype.TXT, f'"{value}"')

        # Send update
        try:
            response = dns.query.tcp(update, self.server, port=self.port, timeout=self.timeout)
            rcode = response.rcode()
            if rcode != dns.rcode.NOERROR:
                raise RuntimeError(f"DDNS update failed: {dns.rcode.to_text(rcode)}")

            logger.info("TXT record created via DDNS", fqdn=fqdn, values=values)
            return fqdn

        except dns.query.BadResponse as e:
            logger.error("DDNS update failed", error=str(e), fqdn=fqdn)
            raise RuntimeError(f"DDNS update failed: {e}") from e

    async def delete_record(
        self,
        zone: str,
        name: str,
        record_type: str,
    ) -> bool:
        """Delete DNS record via DDNS update."""
        fqdn = f"{name}.{zone}"

        logger.info(
            "Deleting record via DDNS",
            server=self.server,
            zone=zone,
            name=name,
            record_type=record_type,
        )

        # Create update message
        update = dns.update.Update(zone, keyring=self._keyring, keyalgorithm=self._algorithm)

        # Map record type string to dns.rdatatype
        rdtype = dns.rdatatype.from_text(record_type)
        update.delete(name, rdtype)

        # Send update
        try:
            response = dns.query.tcp(update, self.server, port=self.port, timeout=self.timeout)
            rcode = response.rcode()
            if rcode != dns.rcode.NOERROR:
                logger.warning(
                    "DDNS delete returned non-NOERROR",
                    rcode=dns.rcode.to_text(rcode),
                    fqdn=fqdn,
                )
                return False

            logger.info("Record deleted via DDNS", fqdn=fqdn, type=record_type)
            return True

        except dns.query.BadResponse as e:
            logger.error("DDNS delete failed", error=str(e), fqdn=fqdn)
            return False

    async def list_records(
        self,
        zone: str,
        name_pattern: str | None = None,
        record_type: str | None = None,
    ) -> AsyncIterator[dict]:
        """
        List DNS records by querying the DNS server.

        Note: DDNS protocol doesn't support listing records. This method
        queries specific record names. For full zone listing, use DNS zone
        transfer (AXFR) if permitted.
        """
        # If a specific name pattern is given, query it directly
        if name_pattern and "*" not in name_pattern and "?" not in name_pattern:
            fqdn = f"{name_pattern}.{zone}"
            types_to_query = [record_type] if record_type else ["SVCB", "TXT"]

            for rtype in types_to_query:
                try:
                    answers = dns.resolver.resolve(fqdn, rtype)
                    # Group all rdata at this (name, type) into the documented
                    # ``values`` list — one dict per RRset, NOT one dict per
                    # rdata. Matches the contract used by every other backend
                    # (Route53, Cloudflare, NS1, CloudDNS, BloxOne, NIOS, Mock).
                    # The previous shape (``data``: singular string, one dict
                    # per rdata) caused ``read_index()`` to skip existing
                    # entries, overwriting the index on each subsequent
                    # publish (issue #137).
                    values = [str(rdata) for rdata in answers]
                    if values:
                        yield {
                            "name": name_pattern,
                            "fqdn": fqdn,
                            "type": rtype,
                            "ttl": answers.rrset.ttl,
                            "values": values,
                        }
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    pass
                except Exception as e:
                    logger.warning(f"Failed to query {fqdn} {rtype}: {e}")

        else:
            # Cannot list arbitrary records without zone transfer
            logger.warning(
                "DDNS backend cannot list records without specific name pattern. "
                "Use name_pattern parameter or enable zone transfer (AXFR)."
            )

    async def zone_exists(self, zone: str) -> bool:
        """Check if zone exists by querying SOA record on configured server."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.server]
            resolver.port = self.port
            resolver.resolve(zone, "SOA")
            return True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return False
        except Exception as e:
            logger.warning(f"Failed to check zone {zone}: {e}")
            return False

    async def get_record(
        self,
        zone: str,
        name: str,
        record_type: str,
    ) -> dict | None:
        """
        Get a specific record by querying the DNS server directly.

        Uses the configured DDNS server for resolution.
        """
        fqdn = f"{name}.{zone}"

        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.server]
            resolver.port = self.port
            resolver.lifetime = self.timeout

            answers = resolver.resolve(fqdn, record_type)
            values = [str(rdata) for rdata in answers]

            return {
                "name": name,
                "fqdn": fqdn,
                "type": record_type,
                "ttl": answers.rrset.ttl,
                "values": values,
            }
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None
        except Exception as e:
            logger.debug(f"Failed to query {fqdn} {record_type}: {e}")
            return None

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
