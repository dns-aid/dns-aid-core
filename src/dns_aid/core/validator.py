# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
DNS-AID Validator: Verify agent DNS records and security.

Handles DNSSEC validation, DANE/TLSA verification, and endpoint health checks.

DNSSEC requirement posture (draft-mozleywilliams-dnsop-dnsaid-02 §6.2):

The draft uses the **SHOULD** posture, not MAY/MUST. Verbatim:

    "Consumers SHOULD authenticate the TLS endpoint of a DNS-AID agent
    using DANE TLSA records (RFC 6698) wherever both DNSSEC and TLSA
    are available."

DNS-AID records served without DNSSEC continue to verify under this
module — DNSSEC absence is not in itself a failure. When TLSA records
ARE present, DNSSEC absence makes the TLSA records untrustworthy
(RFC 6698 §10.1 — TLSA without DNSSEC offers no integrity guarantee).

When TLSA records are present without a validated DNSSEC chain the
validator treats DANE as untrustworthy: ``dane_valid`` is demoted to
``None`` and the +15 ``security_score`` credit is gated on
``dnssec_valid``, so an unsigned TLSA record cannot inflate the trust
score.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ssl
import time
from datetime import UTC

import dns.asyncresolver
import dns.flags
import dns.rdatatype
import dns.resolver
import httpx
import structlog

from dns_aid.core.models import DNSSECDetail, TLSDetail, VerifyResult

logger = structlog.get_logger(__name__)


async def verify(fqdn: str, *, verify_dane_cert: bool = False) -> VerifyResult:
    """
    Verify DNS-AID records for an agent.

    Checks:
    - DNS record exists
    - SVCB record is valid
    - DNSSEC chain is validated
    - DANE/TLSA certificate binding (if configured)
    - Endpoint is reachable

    Args:
        fqdn: Fully qualified domain name of agent record
              (e.g., "chat.example.com")
        verify_dane_cert: If True, perform full DANE certificate matching
                         (connect to endpoint and compare TLS cert against
                         TLSA record). Default False (existence check only).

    Returns:
        VerifyResult with security validation results
    """
    logger.info("Verifying agent DNS records", fqdn=fqdn)

    result = VerifyResult(fqdn=fqdn)

    # 1. Check SVCB record exists and is valid
    svcb_data = await _check_svcb_record(fqdn)
    if svcb_data:
        result.record_exists = True
        result.svcb_valid = svcb_data.get("valid", False)
        target = svcb_data.get("target")
        port = svcb_data.get("port", 443)
    else:
        target = None
        port = None

    # 2. Check DNSSEC validation (with detail)
    dnssec_detail = await _check_dnssec_detail(fqdn)
    result.dnssec_detail = dnssec_detail
    result.dnssec_valid = dnssec_detail.validated

    # 3. Check DANE/TLSA (if target is available)
    # Per IETF draft Section 4.4.1, DANE TLSA SHOULD be used to bind
    # endpoint certificates to DNSSEC-validated names.
    if target:
        result.dane_valid = await _check_dane(target, port, verify_cert=verify_dane_cert)

        # Update dane_note based on actual check performed
        if result.dane_valid is None:
            result.dane_note = "No TLSA record configured (DANE not enabled for this endpoint)"
        elif verify_dane_cert:
            if result.dane_valid:
                result.dane_note = "DANE certificate matching verified (TLSA 3 1 1 recommended)"
            else:
                result.dane_note = (
                    "DANE certificate mismatch — endpoint cert does not match TLSA record"
                )
        else:
            result.dane_note = (
                "TLSA record exists (advisory check only; "
                "use verify_dane_cert=True for full certificate matching)"
            )

        # DANE without DNSSEC carries no integrity guarantee — RFC 6698
        # §10.1 and draft-02 §Security Considerations both treat TLSA
        # without a validated chain as untrustworthy. Demote the outcome
        # to None (DANE state unknown), not just append to the note, so
        # downstream consumers — including security_score — don't credit
        # a TLSA record that hasn't been DNSSEC-validated.
        if result.dane_valid is not None and not result.dnssec_valid:
            result.dane_note += (
                " ⚠ DNSSEC not validated — DANE requires DNSSEC to be "
                "trustworthy; demoting DANE outcome to unknown"
            )
            result.dane_valid = None

    # 4. Check endpoint reachability
    if target and port:
        endpoint_result = await _check_endpoint(target, port)
        result.endpoint_reachable = endpoint_result.get("reachable", False)
        result.endpoint_latency_ms = endpoint_result.get("latency_ms")

    # 5. Check TLS detail
    if target and port:
        result.tls_detail = await _check_tls(target, port)

    logger.info(
        "Verification complete",
        fqdn=fqdn,
        score=result.security_score,
        rating=result.security_rating,
    )

    return result


async def _check_svcb_record(fqdn: str) -> dict | None:
    """
    Check if SVCB record exists and is valid.

    Returns dict with target, port, and validity info, or None if not found.
    """
    try:
        resolver = dns.asyncresolver.Resolver()

        # Query SVCB record
        try:
            answers = await resolver.resolve(fqdn, "SVCB")
        except dns.resolver.NoAnswer:
            # Try HTTPS record as fallback
            try:
                answers = await resolver.resolve(fqdn, "HTTPS")
            except dns.resolver.NoAnswer:
                logger.debug("No SVCB/HTTPS record found", fqdn=fqdn)
                return None

        for rdata in answers:
            target = str(rdata.target).rstrip(".")

            # Extract port from params
            port = 443
            if hasattr(rdata, "params") and rdata.params:
                # Port param key is 3 in SVCB
                port_param = rdata.params.get(3)
                if port_param and hasattr(port_param, "port"):
                    port = port_param.port

            # SVCB is valid if it has a target
            is_valid = bool(target and target != ".")

            logger.debug(
                "SVCB record found",
                fqdn=fqdn,
                target=target,
                port=port,
                valid=is_valid,
            )

            return {
                "target": target,
                "port": port,
                "valid": is_valid,
                "priority": rdata.priority,
            }

    except dns.resolver.NXDOMAIN:
        logger.debug("FQDN does not exist", fqdn=fqdn)
    except Exception as e:
        logger.debug("SVCB query failed", fqdn=fqdn, error=str(e))

    return None


async def _check_dnssec(fqdn: str) -> bool:
    """
    Check if DNSSEC is validated for the FQDN.

    Limitation: This only checks the AD (Authenticated Data) flag in the DNS
    response from the configured recursive resolver. It does NOT perform
    independent DNSSEC chain validation (DNSKEY → DS → RRSIG). The AD flag
    is only trustworthy if the path to the resolver is secured (e.g., via
    localhost or DoT/DoH). A resolver on an untrusted network could spoof
    the AD flag.

    Returns True if DNSSEC AD (Authenticated Data) flag is set.
    """
    try:
        resolver = dns.asyncresolver.Resolver()

        # Enable DNSSEC validation
        resolver.use_edns(edns=0, ednsflags=dns.flags.DO)

        # Query with DNSSEC
        try:
            answer = await resolver.resolve(fqdn, "SVCB")

            # Check AD (Authenticated Data) flag in response
            if hasattr(answer.response, "flags"):
                ad_flag = answer.response.flags & dns.flags.AD
                if ad_flag:
                    logger.debug("DNSSEC validated", fqdn=fqdn)
                    return True

        except dns.resolver.NoAnswer:
            # Try TXT as fallback for DNSSEC check
            try:
                answer = await resolver.resolve(fqdn, "TXT")
                if hasattr(answer.response, "flags"):
                    ad_flag = answer.response.flags & dns.flags.AD
                    if ad_flag:
                        logger.debug("DNSSEC validated via TXT", fqdn=fqdn)
                        return True
            except Exception:
                pass

    except Exception as e:
        logger.debug("DNSSEC check failed", fqdn=fqdn, error=str(e))

    # Note: Many domains don't have DNSSEC enabled
    # This is not necessarily an error
    logger.debug("DNSSEC not validated", fqdn=fqdn)
    return False


# DNSSEC algorithm number → name mapping (RFC 8624)
_DNSSEC_ALGORITHM_MAP: dict[int, str] = {
    1: "RSAMD5",
    3: "DSA",
    5: "RSASHA1",
    6: "DSA-NSEC3-SHA1",
    7: "RSASHA1-NSEC3-SHA1",
    8: "RSASHA256",
    10: "RSASHA512",
    12: "ECC-GOST",
    13: "ECDSAP256SHA256",
    14: "ECDSAP384SHA384",
    15: "ED25519",
    16: "ED448",
}

# Algorithm strength classifications per RFC 8624 recommendations
_ALGORITHM_STRENGTH: dict[str, str] = {
    "RSAMD5": "weak",
    "DSA": "weak",
    "RSASHA1": "weak",
    "DSA-NSEC3-SHA1": "weak",
    "RSASHA1-NSEC3-SHA1": "weak",
    "RSASHA256": "acceptable",
    "RSASHA512": "acceptable",
    "ECC-GOST": "acceptable",
    "ECDSAP256SHA256": "strong",
    "ECDSAP384SHA384": "strong",
    "ED25519": "strong",
    "ED448": "strong",
}


async def _check_dnssec_detail(fqdn: str) -> DNSSECDetail:
    """
    Check DNSSEC validation and extract granular detail for trust scoring.

    Extracts algorithm from DNSKEY records, checks for NSEC3, measures
    chain depth by walking DS records up the tree, and checks the AD flag.

    Returns:
        DNSSECDetail with populated fields.
    """
    detail = DNSSECDetail()

    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.use_edns(edns=0, ednsflags=dns.flags.DO)

        # Check AD flag on SVCB (or TXT fallback)
        answer = None
        try:
            answer = await resolver.resolve(fqdn, "SVCB")
        except dns.resolver.NoAnswer:
            with contextlib.suppress(Exception):
                answer = await resolver.resolve(fqdn, "TXT")

        if answer and hasattr(answer.response, "flags"):
            ad_flag = bool(answer.response.flags & dns.flags.AD)
            detail.ad_flag = ad_flag
            detail.validated = ad_flag

        # Extract algorithm from DNSKEY records at the zone apex
        # Walk from the FQDN up to find the zone with DNSKEY
        parts = fqdn.rstrip(".").split(".")
        algorithm_name: str | None = None
        for i in range(len(parts)):
            zone = ".".join(parts[i:])
            try:
                dnskey_answer = await resolver.resolve(zone, "DNSKEY")
                for rdata in dnskey_answer:
                    alg_num = rdata.algorithm
                    algorithm_name = _DNSSEC_ALGORITHM_MAP.get(alg_num, f"UNKNOWN({alg_num})")
                    detail.algorithm = algorithm_name
                    detail.algorithm_strength = _ALGORITHM_STRENGTH.get(algorithm_name, "unknown")
                    break  # Use first DNSKEY found
                if algorithm_name:
                    break
            except Exception:  # nosec B112 — walking DNS tree, zone may lack DNSKEY
                continue

        # Check for NSEC3 records (query NSEC3PARAM at zone apex)
        for i in range(len(parts)):
            zone = ".".join(parts[i:])
            try:
                await resolver.resolve(zone, "NSEC3PARAM")
                detail.nsec3_present = True
                break
            except Exception:  # nosec B112 — walking DNS tree, zone may lack NSEC3PARAM
                continue

        # Measure chain depth by counting DS records from zone up to root
        chain_depth = 0
        for i in range(len(parts)):
            zone = ".".join(parts[i:])
            if not zone:
                continue
            try:
                await resolver.resolve(zone, "DS")
                chain_depth += 1
            except Exception:  # nosec B112 — walking DNS tree, zone may lack DS
                continue
        detail.chain_depth = chain_depth
        detail.chain_complete = chain_depth > 0 and detail.ad_flag

    except Exception as e:
        logger.debug("DNSSEC detail check failed", fqdn=fqdn, error=str(e))

    return detail


async def _check_tls(target: str, port: int) -> TLSDetail:
    """
    Connect to target:port via TLS and extract connection detail.

    Extracts TLS version, cipher suite, certificate validity,
    days remaining on cert, and checks for HSTS header.

    Returns:
        TLSDetail with populated fields.
    """
    detail = TLSDetail()

    try:
        ctx = ssl.create_default_context()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port, ssl=ctx),
            timeout=10.0,
        )

        try:
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object:
                detail.connected = True

                # TLS version
                detail.tls_version = ssl_object.version()

                # Cipher suite
                cipher_info = ssl_object.cipher()
                if cipher_info:
                    detail.cipher_suite = cipher_info[0]

                # Certificate info
                cert = ssl_object.getpeercert()
                if cert:
                    detail.cert_valid = True
                    # Calculate days remaining from notAfter
                    not_after = cert.get("notAfter")
                    if not_after:
                        try:
                            from datetime import datetime

                            # Parse SSL date format: 'Mon DD HH:MM:SS YYYY GMT'
                            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            expiry = expiry.replace(tzinfo=UTC)
                            now = datetime.now(UTC)
                            days_remaining = (expiry - now).days
                            detail.cert_days_remaining = days_remaining
                            if days_remaining < 0:
                                detail.cert_valid = False
                        except (ValueError, TypeError):
                            pass
        finally:
            writer.close()
            await writer.wait_closed()

        # Check HSTS via HTTP request
        try:
            async with httpx.AsyncClient(timeout=5.0, verify=True) as client:
                response = await client.head(f"https://{target}:{port}/")
                hsts_header = response.headers.get("strict-transport-security")
                if hsts_header:
                    detail.hsts_enabled = True
                    # Extract max-age
                    for part in hsts_header.split(";"):
                        part = part.strip()
                        if part.lower().startswith("max-age="):
                            with contextlib.suppress(ValueError, IndexError):
                                detail.hsts_max_age = int(part.split("=", 1)[1])
        except Exception:
            pass  # HSTS check is best-effort

    except Exception as e:
        logger.debug("TLS detail check failed", target=target, port=port, error=str(e))

    return detail


async def _check_dane(target: str, port: int, *, verify_cert: bool = False) -> bool | None:
    """
    Check DANE/TLSA record for the endpoint.

    When ``verify_cert`` is False (default), this only checks whether a TLSA
    record exists in DNS.  When True, it additionally connects to the endpoint
    via TLS, retrieves the certificate, and compares its digest against the
    TLSA association data.

    Args:
        target: Hostname of the endpoint.
        port: Port number.
        verify_cert: If True, perform full certificate matching against TLSA.

    Returns:
        True if TLSA record exists (and optionally cert matches)
        False if TLSA record exists but cert does NOT match (verify_cert=True)
        None if no TLSA record configured
    """
    # TLSA record format: _port._tcp.hostname
    tlsa_fqdn = f"_{port}._tcp.{target}"

    try:
        resolver = dns.asyncresolver.Resolver()
        answers = await resolver.resolve(tlsa_fqdn, "TLSA")

        for rdata in answers:
            logger.debug(
                "TLSA record found",
                fqdn=tlsa_fqdn,
                usage=rdata.usage,
                selector=rdata.selector,
                mtype=rdata.mtype,
            )

            if not verify_cert:
                # Advisory mode: TLSA exists → True
                return True

            # Full DANE cert matching
            try:
                cert_match = await _match_dane_cert(
                    target, port, rdata.selector, rdata.mtype, rdata.cert
                )
                if cert_match:
                    logger.info("DANE certificate match verified", fqdn=tlsa_fqdn)
                    return True
                else:
                    logger.warning("DANE certificate mismatch", fqdn=tlsa_fqdn)
                    return False
            except Exception as e:
                logger.warning(
                    "DANE certificate matching failed",
                    fqdn=tlsa_fqdn,
                    error=str(e),
                )
                return False

    except dns.resolver.NXDOMAIN:
        logger.debug("No TLSA record (DANE not configured)", fqdn=tlsa_fqdn)
    except dns.resolver.NoAnswer:
        logger.debug("No TLSA record", fqdn=tlsa_fqdn)
    except Exception as e:
        logger.debug("TLSA query failed", fqdn=tlsa_fqdn, error=str(e))

    return None  # Not configured


async def _match_dane_cert(
    target: str,
    port: int,
    selector: int,
    mtype: int,
    tlsa_data: bytes,
) -> bool:
    """
    Connect to ``target:port`` via TLS and compare cert against TLSA data.

    Args:
        target: Hostname to connect to.
        port: Port number.
        selector: TLSA selector — 0 = full cert, 1 = SubjectPublicKeyInfo.
        mtype: TLSA matching type — 0 = exact, 1 = SHA-256, 2 = SHA-512.
        tlsa_data: Certificate association data from the TLSA record.

    Returns:
        True if the presented certificate matches the TLSA record.
    """
    ctx = ssl.create_default_context()
    _, writer = await asyncio.open_connection(target, port, ssl=ctx)

    try:
        ssl_object = writer.get_extra_info("ssl_object")
        der_cert = ssl_object.getpeercert(binary_form=True)

        if selector == 1:
            # SPKI: extract SubjectPublicKeyInfo from DER certificate
            from cryptography.hazmat.primitives.serialization import (
                Encoding,
                PublicFormat,
            )
            from cryptography.x509 import load_der_x509_certificate

            x509_cert = load_der_x509_certificate(der_cert)
            cert_bytes = x509_cert.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            )
        else:
            # selector 0: full certificate DER bytes
            cert_bytes = der_cert

        if mtype == 1:
            computed = hashlib.sha256(cert_bytes).digest()
        elif mtype == 2:
            computed = hashlib.sha512(cert_bytes).digest()
        else:
            # mtype 0: exact match
            computed = cert_bytes

        return computed == tlsa_data
    finally:
        writer.close()
        await writer.wait_closed()


async def _check_endpoint(target: str, port: int) -> dict:
    """
    Check if endpoint is reachable.

    Returns dict with reachable status and latency.
    """
    endpoint = f"https://{target}:{port}"

    try:
        start_time = time.perf_counter()

        async with httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=True,
            verify=True,
        ) as client:
            # Try health endpoint first, then root
            for path in ["/health", "/.well-known/agent-card.json", "/"]:
                try:
                    response = await client.get(f"{endpoint}{path}")
                    latency_ms = (time.perf_counter() - start_time) * 1000

                    if response.status_code < 500:
                        logger.debug(
                            "Endpoint reachable",
                            endpoint=endpoint,
                            path=path,
                            status=response.status_code,
                            latency_ms=f"{latency_ms:.2f}",
                        )
                        return {
                            "reachable": True,
                            "latency_ms": latency_ms,
                            "status_code": response.status_code,
                        }
                except httpx.HTTPError:
                    continue

    except httpx.ConnectError as e:
        logger.debug("Endpoint connection failed", endpoint=endpoint, error=str(e))
    except httpx.TimeoutException:
        logger.debug("Endpoint timeout", endpoint=endpoint)
    except Exception as e:
        logger.debug("Endpoint check failed", endpoint=endpoint, error=str(e))

    return {"reachable": False}
