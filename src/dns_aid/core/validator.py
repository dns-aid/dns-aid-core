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
import os
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


def _response_carries_rrsig(response) -> bool:
    """Whether the answer section carried RRSIG records.

    Diagnostic only, never a trust signal. Seeing an RRSIG proves the zone
    signs its records; it proves nothing about whether *this* answer is
    authentic, because an attacker able to spoof the answer can spoof an RRSIG
    beside it. Only a validating resolver's AD flag (or full chain validation)
    can speak to authenticity.

    Its value is telling two very different situations apart when the AD flag
    is absent: a genuinely unsigned zone, versus a signed zone behind a
    resolver that does not validate. The first is the zone owner's problem, the
    second is the caller's, and reporting both as "unvalidated" left an
    operator no way to know which one they had.
    """
    try:
        for rrset in getattr(response, "answer", []) or []:
            if rrset.rdtype == dns.rdatatype.RRSIG or getattr(rrset, "covers", None):
                return True
    except Exception:  # nosec B110 — diagnostic only; never gates a trust decision
        pass
    return False


async def _check_dnssec(fqdn: str) -> bool:
    """
    Check if DNSSEC is validated for the FQDN.

    Thin wrapper over :func:`_check_dnssec_with_evidence`, kept so the existing
    contract (a single bool driving ``require_dnssec`` and ``min_dnssec``) is
    unchanged.

    Limitation: This only checks the AD (Authenticated Data) flag in the DNS
    response from the configured recursive resolver. It does NOT perform
    independent DNSSEC chain validation (DNSKEY → DS → RRSIG). The AD flag
    is only trustworthy if the path to the resolver is secured (e.g., via
    localhost or DoT/DoH). A resolver on an untrusted network could spoof
    the AD flag.

    Returns True if DNSSEC AD (Authenticated Data) flag is set.
    """
    validated, _signed = await _check_dnssec_with_evidence(fqdn)
    return validated


async def _check_dnssec_with_evidence(fqdn: str) -> tuple[bool, bool]:
    """Check DNSSEC and report what evidence was seen.

    Returns ``(validated, zone_signs_records)``. The first is the AD flag and
    is the only value any trust decision may use. The second records whether
    RRSIGs appeared in the response, which distinguishes an unsigned zone from
    a signed zone behind a non-validating resolver.

    Both come from one query: the DO bit is already set, so the RRSIGs are in
    the response we fetch regardless.
    """
    signed = False
    try:
        resolver = dns.asyncresolver.Resolver()

        # Enable DNSSEC validation
        resolver.use_edns(edns=0, ednsflags=dns.flags.DO)

        # Query with DNSSEC
        try:
            answer = await resolver.resolve(fqdn, "SVCB")
            signed = _response_carries_rrsig(answer.response)

            # Check AD (Authenticated Data) flag in response
            if hasattr(answer.response, "flags"):
                ad_flag = answer.response.flags & dns.flags.AD
                if ad_flag:
                    logger.debug("DNSSEC validated", fqdn=fqdn)
                    return True, signed

        except dns.resolver.NoAnswer:
            # Try TXT as fallback for DNSSEC check
            try:
                answer = await resolver.resolve(fqdn, "TXT")
                signed = signed or _response_carries_rrsig(answer.response)
                if hasattr(answer.response, "flags"):
                    ad_flag = answer.response.flags & dns.flags.AD
                    if ad_flag:
                        logger.debug("DNSSEC validated via TXT", fqdn=fqdn)
                        return True, signed
            except Exception:
                pass

    except Exception as e:
        logger.debug("DNSSEC check failed", fqdn=fqdn, error=str(e))

    # Note: Many domains don't have DNSSEC enabled
    # This is not necessarily an error
    logger.debug("DNSSEC not validated", fqdn=fqdn, zone_signs_records=signed)
    return False, signed


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
            with contextlib.suppress(Exception):
                await asyncio.wait_for(writer.wait_closed(), timeout=DANE_SHUTDOWN_TIMEOUT)

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

    Every association in the RRset is tried: the certificate is valid if it
    matches ANY of them (RFC 6698; RFC 7671 Section 5.1). This is what allows a
    certificate rollover to publish the outgoing and incoming pins side by side
    (RFC 7671 Section 8.1) without verification depending on RRset ordering.

    Args:
        target: Hostname of the endpoint.
        port: Port number.
        verify_cert: If True, perform full certificate matching against TLSA.

    Returns:
        True if TLSA record exists (and, with ``verify_cert``, some association
        matched the presented certificate)
        False if TLSA records exist and EVERY association was compared and
        none matched (verify_cert=True)
        None if no TLSA record is configured, or none could be evaluated
        because every comparison errored -- unknown, not a mismatch
    """
    # TLSA record format: _port._tcp.hostname
    tlsa_fqdn = f"_{port}._tcp.{target}"

    try:
        resolver = dns.asyncresolver.Resolver()
        # Ask for the DNSSEC records so the AD flag on the reply is meaningful.
        resolver.use_edns(0, dns.flags.DO, 4096)
        answers = await resolver.resolve(tlsa_fqdn, "TLSA")

        # RFC 6698 Section 4.1 and Section 10.1: the TLSA RRset ITSELF must be
        # DNSSEC-validated. Unauthenticated TLSA data offers no integrity
        # guarantee, so a match against it proves nothing.
        #
        # This used to be gated on the agent's SVCB owner name instead, which is
        # a different name in a different zone whenever the target is off-zone.
        # A signed zone pointing at an unsigned CDN -- pay.trusted.com ->
        # edge.cdn-provider.net -- let anyone who could forge the CDN zone serve
        # a TLSA pinning their own certificate and collect dane_verified=True,
        # because the gate was checking trusted.com. The gate has to travel with
        # the data it is authenticating.
        tlsa_authenticated = bool(answers.response.flags & dns.flags.AD)
        if not tlsa_authenticated:
            logger.warning(
                "TLSA RRset is not DNSSEC-authenticated; DANE result is unknown",
                fqdn=tlsa_fqdn,
            )
            return None

        # A TLSA RRset may hold several associations and the certificate is
        # valid if it matches ANY of them (RFC 6698; RFC 7671 Section 5.1).
        # Publishing two associations is precisely how a key or certificate
        # rollover is staged (RFC 7671 Section 8.1) -- the outgoing and
        # incoming pins overlap for the duration. Returning on the first
        # non-match would make the outcome depend on RRset ordering, which is
        # not stable, and would break rollovers; so a non-match advances to the
        # next association and only an exhausted RRset is a failure.
        associations = list(answers)
        if not associations:
            return None

        if not verify_cert:
            # Advisory mode: existence is the whole answer, so nothing is dialled.
            logger.debug("TLSA record found", fqdn=tlsa_fqdn, count=len(associations))
            return True

        # Verdict model, written before the code because the previous
        # incremental versions each got a different corner wrong.
        #
        #   usable        association this verifier can actually evaluate
        #   matched       some usable association matched the certificate
        #   refuted       a usable association was compared and did not match
        #   unevaluated   a usable association could not be compared at all
        #
        #   matched                      -> True
        #   not matched, unevaluated > 0 -> None   (one of them might have matched)
        #   not matched, refuted > 0     -> False
        #   nothing usable               -> None   (as if no TLSA were published)
        #
        # An unevaluated association can never produce False, because a
        # verdict of "this certificate does not match" must mean every usable
        # association was actually checked.
        usable = [r for r in associations if _is_usable_association(r.usage, r.selector, r.mtype)]
        skipped = len(associations) - len(usable)
        if skipped:
            logger.debug(
                "ignoring TLSA associations this verifier cannot evaluate",
                fqdn=tlsa_fqdn,
                skipped=skipped,
            )
        if not usable:
            # Every association pinned a trust anchor or used a code point we
            # do not implement. RFC 7671 Section 5.1 makes those unusable, which
            # leaves nothing to check -- the same position as no TLSA record.
            logger.warning("no usable TLSA association published", fqdn=tlsa_fqdn)
            return None

        unevaluated = 0
        if len(usable) > MAX_TLSA_ASSOCIATIONS:
            # RRset size is attacker-influenceable. Comparison is in-memory, so
            # this bounds CPU rather than connections. Records dropped here were
            # never compared, so they count as unevaluated and can only ever
            # soften the verdict to None -- never harden it to False.
            unevaluated += len(usable) - MAX_TLSA_ASSOCIATIONS
            logger.warning(
                "TLSA RRset truncated for evaluation",
                fqdn=tlsa_fqdn,
                total=len(usable),
                evaluated=MAX_TLSA_ASSOCIATIONS,
            )
            usable = usable[:MAX_TLSA_ASSOCIATIONS]

        # Usage 1 (PKIX-EE) and usage 3 (DANE-EE) both pin the end-entity
        # certificate, so ONE retrieval serves every association. Usage 1 only
        # adds the requirement that the certificate also pass PKIX. Fetching per
        # association turned one hung endpoint into one hang per record, and
        # fetching per mode let an attacker who reset the second connection
        # downgrade a definite mismatch to "unknown".
        try:
            der_cert = await _fetch_peer_cert(target, port, pkix=False)
        except Exception as e:  # noqa: BLE001 - any retrieval failure is unknown
            logger.warning("DANE certificate retrieval failed", fqdn=tlsa_fqdn, error=str(e))
            return None

        # PKIX status is probed lazily: only if a usage-1 association is present
        # and nothing has matched without it. Most deployments publish DANE-EE
        # only, so this costs no second connection at all.
        pkix_ok: bool | None = None
        pkix_probed = False
        pkix_der: bytes | None = None

        async def _pkix_status() -> bool | None:
            """True/False when determinable, None when it could not be decided."""
            nonlocal pkix_ok, pkix_probed, pkix_der
            if pkix_probed:
                return pkix_ok
            pkix_probed = True
            try:
                # Keep the certificate, not just the outcome. The pin was matched
                # on a separate connection, and only comparing both against the
                # same DER proves one certificate did both jobs.
                pkix_der = await _fetch_peer_cert(target, port, pkix=True)
                pkix_ok = True
            except ssl.SSLCertVerificationError as e:
                # The peer's certificate did not validate. This is NOT reported
                # as a definite negative: the same exception covers a missing or
                # empty local trust store and clock skew, so treating it as
                # proof about the peer would report every PKIX-usage record as a
                # mismatch on a container without CA certificates.
                logger.warning(
                    "certificate did not pass PKIX validation; "
                    "treating usage-1 associations as unevaluated",
                    fqdn=tlsa_fqdn,
                    error=str(e),
                )
                pkix_ok = None
            except Exception as e:  # noqa: BLE001 - transport failure is unknown
                logger.warning("PKIX probe failed", fqdn=tlsa_fqdn, error=str(e))
                pkix_ok = None
            return pkix_ok

        refuted = 0
        for rdata in usable:
            try:
                cert_match = _association_matches(der_cert, rdata.selector, rdata.mtype, rdata.cert)
            except Exception as e:  # noqa: BLE001 - malformed association data
                logger.warning(
                    "TLSA association could not be evaluated",
                    fqdn=tlsa_fqdn,
                    usage=rdata.usage,
                    selector=rdata.selector,
                    mtype=rdata.mtype,
                    error=str(e),
                )
                unevaluated += 1
                continue

            if not cert_match:
                # Deliberately refuted, not unevaluated, even for usage 1 where
                # the authoritative certificate is the one that chained.
                #
                # Probing PKIX on a miss and letting the second connection
                # rescue the association would let a hostile endpoint downgrade
                # a mismatch to unknown by resetting that connection -- and
                # False is the only DANE outcome an operator alerts on. A split
                # or mid-rollover deployment can therefore see a spurious False,
                # which is a fail-safe false alarm; the alternative is suppressed
                # detection. See test_a_second_connection_cannot_be_used_to_
                # downgrade_a_mismatch.
                refuted += 1
                continue

            if rdata.usage == 1:
                # PKIX-EE: the pin matches, but the certificate must also chain.
                if await _pkix_status() is not True:
                    unevaluated += 1
                    continue
                # RFC 6698 section 2.1.1 binds ONE end-entity certificate: the
                # same certificate must match the association and pass PKIX. The
                # pin was matched on the unverified connection and the chain
                # proved on a second, verified one, so a multi-homed or mid-
                # rollover endpoint could satisfy each half with a different
                # certificate and collect a pass for neither. Compare the pin
                # against the certificate that actually chained.
                try:
                    same_cert = pkix_der is not None and _association_matches(
                        pkix_der, rdata.selector, rdata.mtype, rdata.cert
                    )
                except Exception as e:  # noqa: BLE001 - malformed association data
                    logger.warning(
                        "usage-1 re-comparison could not be evaluated",
                        fqdn=tlsa_fqdn,
                        error=str(e),
                    )
                    unevaluated += 1
                    continue
                if not same_cert:
                    # Unevaluated, not refuted. Two observations of a load-
                    # balanced endpoint are not proof about one server, so this
                    # cannot conclude -- it only withholds the pass.
                    logger.warning(
                        "usage-1 association matched an unvalidated certificate but not "
                        "the one that passed PKIX; treating as unevaluated",
                        fqdn=tlsa_fqdn,
                    )
                    unevaluated += 1
                    continue

            logger.info("DANE certificate match verified", fqdn=tlsa_fqdn, usage=rdata.usage)
            return True

        if unevaluated:
            logger.warning(
                "DANE verification inconclusive",
                fqdn=tlsa_fqdn,
                unevaluated=unevaluated,
                refuted=refuted,
            )
            return None

        logger.warning(
            "DANE certificate mismatch (no TLSA association matched)",
            fqdn=tlsa_fqdn,
            refuted=refuted,
        )
        return False

    except dns.resolver.NXDOMAIN:
        logger.debug("No TLSA record (DANE not configured)", fqdn=tlsa_fqdn)
    except dns.resolver.NoAnswer:
        logger.debug("No TLSA record", fqdn=tlsa_fqdn)
    except Exception as e:
        logger.debug("TLSA query failed", fqdn=tlsa_fqdn, error=str(e))

    return None  # Not configured


# A TLSA RRset is attacker-influenceable and a TCP answer can carry hundreds of
# associations. The peer certificate does not vary between them -- only the
# usage field selects which of two TLS contexts retrieves it -- so the
# certificate is fetched at most once per mode and every association is then
# compared in memory. Fetching per association turned one hung connection into
# one hang per record.
DANE_CONNECT_TIMEOUT = 10.0
DANE_SHUTDOWN_TIMEOUT = 5.0
MAX_TLSA_ASSOCIATIONS = 32

# Ports the DANE probe will dial. target AND port both come off a forgeable SVCB
# record, so a host-only SSRF guard still let discovery complete a TLS handshake
# to any public host on any port, at MAX_CONCURRENT_DANE fan-out, from the
# victim's address -- a distributed port scanner attributed to every consumer
# that resolves the attacker's zone, with refused-vs-timeout as the oracle.
#
# Allow-list rather than block-list, the same lesson the IP predicate taught:
# enumerating the bad values missed CGNAT and multicast. Override with
# DNS_AID_DANE_ALLOWED_PORTS as a comma-separated list, or "any" to disable.
_DEFAULT_DANE_PORTS = frozenset({443, 853, 8443})


def _dane_port_allowed(port: int) -> bool:
    raw = os.environ.get("DNS_AID_DANE_ALLOWED_PORTS", "").strip()
    if raw.lower() == "any":
        return True
    if raw:
        try:
            return port in {int(p) for p in raw.split(",") if p.strip()}
        except ValueError:
            logger.warning("DNS_AID_DANE_ALLOWED_PORTS is malformed; using the default set")
    return port in _DEFAULT_DANE_PORTS


async def _fetch_peer_cert(target: str, port: int, *, pkix: bool) -> bytes:
    """Retrieve the peer certificate once, in DER form.

    ``pkix`` selects the retrieval mode. PKIX-TA(0) / PKIX-EE(1) additionally
    require normal PKIX and hostname validation. DANE-TA(2) / DANE-EE(3) do not
    chain to a public CA -- that is the point of DANE -- so the certificate is
    retrieved without that enforcement before the association is compared.
    """

    # Every other network sink in this package validates before dialling
    # (jwks, cap_fetcher, a2a_card, http_index, catalog_pointer). This one did
    # not, and target/port come verbatim off a forgeable SVCB record -- so DANE
    # was a blind internal port scanner: 169.254.169.254 and RFC1918 were
    # reachable, with an immediate-refusal versus 10s-timeout latency oracle,
    # at MAX_CONCURRENT_DANE fan-out and two connections per agent.
    #
    # A forged answer is not even required: a publisher who DNSSEC-signs their
    # own _443._tcp.<name> and points <name> at a metadata address passes the
    # TLSA authenticity gate legitimately.
    #
    # The caller maps a raised exception to None (unknown), which is the right
    # verdict for an endpoint we decline to dial.
    from dns_aid.utils.url_safety import validate_fetch_url_async, vetted_ip_for

    if not _dane_port_allowed(port):
        raise ConnectionError(
            f"DANE probe refused for port {port}; allowed {sorted(_DEFAULT_DANE_PORTS)} "
            "(override with DNS_AID_DANE_ALLOWED_PORTS)"
        )

    probe_url = f"https://{target}:{port}/"
    await validate_fetch_url_async(probe_url)
    # Dial the address that was actually vetted. Connecting to the name would
    # resolve a second time, and only the first resolution was checked --
    # a one-second TTL flipping public to loopback between them retrieved an
    # internal service's certificate. server_hostname keeps SNI and, for
    # pkix=True, hostname verification pointed at the real name.
    dial_host = vetted_ip_for(probe_url) or target
    if pkix:
        ctx = ssl.create_default_context()
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    # Bound the connect. Without this a target that black-holes hangs the whole
    # verification, and _verify_agents_dane walks agents sequentially.
    _, writer = await asyncio.wait_for(
        asyncio.open_connection(dial_host, port, ssl=ctx, server_hostname=target),
        timeout=DANE_CONNECT_TIMEOUT,
    )
    try:
        ssl_object = writer.get_extra_info("ssl_object")
        if ssl_object is None:
            raise ConnectionError("TLS transport exposed no ssl_object")
        der = ssl_object.getpeercert(binary_form=True)
        if not der:
            # getpeercert is typed bytes | None. mypy cannot catch this here
            # (no_strict_optional), and a None reaching the comparison either
            # raises or silently participates as a compared association
            # depending on the matching type.
            raise ConnectionError("peer presented no certificate")
        return der
    finally:
        # The certificate is already in hand, so teardown must not be able to
        # replace a successful return. StreamReaderProtocol.connection_lost sets
        # the exception on the close waiter, so a peer that sends RST instead of
        # close_notify made wait_closed re-raise out of this finally and threw
        # the result away -- letting a hostile endpoint suppress its own DANE
        # verdict. Teardown is also bounded here: wait_closed on a TLS transport
        # is otherwise governed by SSL_SHUTDOWN_TIMEOUT (30s), not by
        # DANE_CONNECT_TIMEOUT.
        writer.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(writer.wait_closed(), timeout=DANE_SHUTDOWN_TIMEOUT)


# RFC 6698 Section 2.1 defines the usable code points. RFC 7671 Section 5.1
# requires an association carrying anything else to be treated as unusable and
# ignored rather than evaluated, so an unrecognised value can neither satisfy
# nor fail the check.
# Usage 0 (PKIX-TA) and 2 (DANE-TA) pin a trust anchor somewhere in the chain.
# This verifier compares only the end-entity certificate, so it cannot evaluate
# them and must report them as unusable rather than as a mismatch -- declaring
# them usable made a conformant `2 1 1` deployment look like a failed check.
_USABLE_TLSA_USAGES = frozenset({1, 3})
_USABLE_TLSA_SELECTORS = frozenset({0, 1})
_USABLE_TLSA_MATCHING_TYPES = frozenset({0, 1, 2})


def _is_usable_association(usage: int, selector: int, mtype: int) -> bool:
    """Whether this association can be evaluated at all (RFC 7671 Section 5.1)."""
    return (
        usage in _USABLE_TLSA_USAGES
        and selector in _USABLE_TLSA_SELECTORS
        and mtype in _USABLE_TLSA_MATCHING_TYPES
    )


def _association_matches(der_cert: bytes, selector: int, mtype: int, tlsa_data: bytes) -> bool:
    """Compare one TLSA association against an already-retrieved certificate.

    Pure and in-memory, so a large RRset costs CPU rather than connections.
    """
    if selector == 1:
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from cryptography.x509 import load_der_x509_certificate

        cert_bytes = (
            load_der_x509_certificate(der_cert)
            .public_key()
            .public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        )
    else:
        cert_bytes = der_cert

    if mtype == 1:
        computed = hashlib.sha256(cert_bytes).digest()
    elif mtype == 2:
        computed = hashlib.sha512(cert_bytes).digest()
    else:
        computed = cert_bytes

    return computed == tlsa_data


async def _match_dane_cert(
    target: str,
    port: int,
    usage: int,
    selector: int,
    mtype: int,
    tlsa_data: bytes,
) -> bool:
    """
    Connect to ``target:port`` via TLS and compare cert against TLSA data.

    Honors the TLSA certificate ``usage`` per RFC 6698: PKIX-TA(0) / PKIX-EE(1)
    additionally require the certificate to pass normal PKIX + hostname
    validation; DANE-TA(2) / DANE-EE(3) do NOT chain to a public CA (that is the
    point of DANE), so the peer certificate is retrieved WITHOUT PKIX/hostname
    enforcement before the TLSA association is compared.

    Args:
        target: Hostname to connect to.
        port: Port number.
        usage: TLSA usage — 0 = PKIX-TA, 1 = PKIX-EE, 2 = DANE-TA, 3 = DANE-EE.
        selector: TLSA selector — 0 = full cert, 1 = SubjectPublicKeyInfo.
        mtype: TLSA matching type — 0 = exact, 1 = SHA-256, 2 = SHA-512.
        tlsa_data: Certificate association data from the TLSA record.

    Returns:
        True if the presented certificate matches the TLSA record.
    """
    der_cert = await _fetch_peer_cert(target, port, pkix=usage not in (2, 3))
    return _association_matches(der_cert, selector, mtype, tlsa_data)


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
