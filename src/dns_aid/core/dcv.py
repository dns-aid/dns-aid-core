# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
DNS-based Domain Control Validation (DCV) for agent identity assertion.

Implements the challenge-response pattern from:
- IETF draft-mozleywilliams-dnsop-dnsaid-02  (bnd-req binding extension)
- draft-ietf-dnsop-domain-verification-techniques-12  (TXT record wire format)

Two primary use cases:
  1. Anonymous / NAT agent asserting org affiliation — Org A issues a challenge;
     the claiming agent places it in the org's DNS zone using its own credentials.
  2. Registry / directory anti-impersonation — a directory requires proof of zone
     control before listing an agent as org-verified.

Wire format (DCV-techniques §6.1.2 ABNF, space-separated key=value):
    token=<base32>  [bnd-req=svc:<agent>@<issuer>]  expiry=<RFC3339>

Challenge owner name: _agents-challenge.{domain}

Role split:
  Challenger side — issue() + verify(): no DNS write credentials required.
  Claimant side  — place() + revoke(): require backend write credentials.
"""

from __future__ import annotations

import base64
import hmac
import ipaddress
import re
import secrets
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import dns.asyncresolver
import dns.exception
import dns.flags
import dns.resolver
import structlog
from pydantic import BaseModel, Field

from dns_aid.utils.validation import (
    validate_agent_name,
    validate_domain,
    validate_port,
    validate_ttl,
)

if TYPE_CHECKING:
    from dns_aid.backends.base import DNSBackend

logger = structlog.get_logger(__name__)

CHALLENGE_LABEL = "_agents-challenge"
TOKEN_PATTERN = re.compile(r"^[a-z2-7]{32}$")
MAX_CHALLENGE_RECORDS = 10
MAX_DCV_TTL_SECONDS = 86400  # 24 h — sane cap for a security challenge


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class DCVChallenge(BaseModel):
    """Issued DCV challenge — delivered to the claimant out-of-band."""

    token: str = Field(description="Base32-encoded nonce to place in DNS")
    domain: str = Field(description="Domain being challenged")
    fqdn: str = Field(description="Full owner name of the TXT record")
    txt_value: str = Field(description="Verbatim TXT RDATA to place in the zone")
    expiry: datetime = Field(description="UTC expiry time for this challenge")
    bnd_req: str | None = Field(
        default=None,
        description="Binding request scope — svc:<agent>@<issuer> — optional",
    )


class DCVVerifyResult(BaseModel):
    """Result of verifying a DCV challenge."""

    verified: bool
    domain: str
    token: str
    fqdn: str
    expired: bool = False
    dnssec_validated: bool = False
    error: str | None = None


class DCVPlaceResult(BaseModel):
    """Result of writing a DCV challenge to DNS."""

    fqdn: str = Field(description="Full owner name where the challenge was placed")
    domain: str = Field(description="Zone domain")
    expires_at: datetime = Field(description="UTC time when the placed challenge expires")


class DCVRevokeResult(BaseModel):
    """Result of revoking a DCV challenge."""

    removed: bool = Field(description="True if the challenge record was deleted")
    domain: str = Field(description="Zone domain")
    fqdn: str = Field(description="Full owner name that was targeted for deletion")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _generate_token() -> str:
    """20 bytes of entropy, lowercase base32 (no padding) — DNS-label safe."""
    return base64.b32encode(secrets.token_bytes(20)).decode().lower().rstrip("=")


def _build_txt_value(
    token: str, expiry: datetime, bnd_req: str | None, domain: str | None = None
) -> str:
    """Produce a DCV-techniques-compliant space-separated key=value string."""
    expiry = expiry.astimezone(UTC)  # normalize — rejects naive datetimes
    expiry_str = expiry.strftime("%Y-%m-%dT%H:%M:%SZ")
    parts = [f"token={token}"]
    if domain:
        # domain= binds the token to the zone; prevents cross-domain token replay
        parts.append(f"domain={domain}")
    if bnd_req:
        parts.append(f"bnd-req={bnd_req}")
    parts.append(f"expiry={expiry_str}")
    return " ".join(parts)


def _parse_txt_value(txt: str) -> dict[str, str]:
    """
    Parse space-separated key=value pairs (DCV-techniques §6.1.2 ABNF).

    Strips one layer of RFC-1035-style outer quotes added by some backends
    (e.g. Cloudflare wraps the entire content in literal '"..."').
    Bare-value (no 'token=' prefix) tokens are NOT accepted; explicit key=
    is required per our wire format.
    Duplicate keys: first occurrence wins.
    """
    txt = txt.strip()
    # Strip exactly one layer of surrounding quotes — don't recurse
    if len(txt) >= 2 and txt[0] == '"' and txt[-1] == '"':
        txt = txt[1:-1]

    result: dict[str, str] = {}
    for part in txt.strip().split():
        if "=" in part:
            k, _, v = part.partition("=")
            k = k.lower()
            if k not in result:  # first-wins for duplicate keys
                result[k] = v
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def issue(
    domain: str,
    *,
    agent_name: str | None = None,
    issuer_domain: str | None = None,
    ttl_seconds: int = 3600,
) -> DCVChallenge:
    """
    Generate a stateless DCV challenge.

    The challenger calls this, then delivers the returned DCVChallenge to the
    claimant out-of-band (A2A message, MCP tool response, etc.).  Nothing is
    written to DNS here — placement is the claimant's job.

    Args:
        domain:        Domain the claimant must prove control of.
        agent_name:    Optional agent name to scope the bnd-req field.
                       Must be a valid DNS-AID agent name (lowercase alphanum, hyphens).
        issuer_domain: Optional issuer domain to scope the bnd-req field.
        ttl_seconds:   Challenge validity window in seconds (30–86400, default: 3600).

    Returns:
        DCVChallenge containing token, fqdn, txt_value, and expiry.

    IMPORTANT: The caller MUST invoke revoke(domain, token=...) immediately
    after a successful verify() to prevent token reuse within the validity window.
    """
    domain = validate_domain(domain)
    if not (30 <= ttl_seconds <= MAX_DCV_TTL_SECONDS):
        raise ValueError(
            f"ttl_seconds must be between 30 and {MAX_DCV_TTL_SECONDS} (got {ttl_seconds})"
        )

    bnd_req = None
    if agent_name and issuer_domain:
        agent_name = validate_agent_name(agent_name)
        issuer_domain_val = validate_domain(issuer_domain)
        bnd_req = f"svc:{agent_name}@{issuer_domain_val}"

    token = _generate_token()
    expiry = datetime.now(UTC) + timedelta(seconds=ttl_seconds)
    fqdn = f"{CHALLENGE_LABEL}.{domain}"
    txt_value = _build_txt_value(token, expiry, bnd_req, domain=domain)

    logger.debug("DCV challenge issued", domain=domain, fqdn=fqdn, bnd_req=bnd_req)

    return DCVChallenge(
        token=token,
        domain=domain,
        fqdn=fqdn,
        txt_value=txt_value,
        expiry=expiry,
        bnd_req=bnd_req,
    )


async def place(
    domain: str,
    token: str,
    *,
    bnd_req: str | None = None,
    expiry_seconds: int = 3600,
    ttl: int = 300,
    backend: DNSBackend | None = None,
) -> DCVPlaceResult:
    """
    Write the DCV challenge TXT record to DNS via the configured backend.

    The claimant calls this using their own dns-aid backend credentials,
    proving they have write access to the domain's zone.

    NOTE: Trust model — the claimant still controls the placed expiry value.
    Callers SHOULD derive expiry_seconds from the issued DCVChallenge.expiry
    (i.e., from the challenger's clock) rather than choosing their own window.
    A future revision may move expiry off this surface entirely.

    Args:
        domain:         Zone to write the challenge into.
        token:          Token received from the challenger (32-char base32).
        bnd_req:        Optional binding scope to include (pass through from challenge).
        expiry_seconds: How long the placed record should be valid (30–86400, default: 3600).
                        Prefer aligning with the issued DCVChallenge.expiry — see note above.
        ttl:            DNS record TTL in seconds (default: 300 — short, for quick cleanup).
        backend:        DNS backend instance; defaults to DNS_AID_BACKEND env var.

    Returns:
        DCVPlaceResult with fqdn, domain, and expiry time.
    """
    from dns_aid.core.publisher import get_default_backend

    domain = validate_domain(domain)
    ttl = validate_ttl(ttl)
    if not TOKEN_PATTERN.fullmatch(token):
        raise ValueError("token must be a 32-character lowercase base32 string")
    if not (30 <= expiry_seconds <= MAX_DCV_TTL_SECONDS):
        raise ValueError(
            f"expiry_seconds must be between 30 and {MAX_DCV_TTL_SECONDS} (got {expiry_seconds})"
        )

    dns_backend = backend or get_default_backend()
    expiry = datetime.now(UTC) + timedelta(seconds=expiry_seconds)
    txt_value = _build_txt_value(token, expiry, bnd_req, domain=domain)
    fqdn = f"{CHALLENGE_LABEL}.{domain}"

    logger.info("Placing DCV challenge", domain=domain, fqdn=fqdn)

    await dns_backend.create_txt_record(
        zone=domain,
        name=CHALLENGE_LABEL,
        values=[txt_value],
        ttl=ttl,
    )

    logger.info("DCV challenge placed", fqdn=fqdn)
    return DCVPlaceResult(fqdn=fqdn, domain=domain, expires_at=expiry)


async def verify(
    domain: str,
    token: str,
    *,
    nameserver: str | None = None,
    port: int = 53,
    expected_bnd_req: str | None = None,
    require_dnssec: bool = False,
) -> DCVVerifyResult:
    """
    Resolve _agents-challenge.{domain} and verify the token is present and unexpired.

    The challenger calls this after the claimant has placed the record.
    No backend credentials required — pure DNS resolution.

    Fail-closed contract:
    - Missing expiry= field → verified=False
    - Malformed expiry= value → verified=False
    - Bare token (no 'token=' prefix) → not matched
    - domain= mismatch (if present) → record skipped
    - Invalid nameserver IP → DCVVerifyResult with error (no exception raised)
    - require_dnssec=True + no AD flag → verified=False

    Args:
        domain:           Domain to check.
        token:            Token originally issued by the challenger.
        nameserver:       Optional nameserver IP address to query directly.
                          Must be a valid IP address (use for testbeds only).
                          SECURITY: This is operator-trusted — any syntactically
                          valid IP is accepted, including link-local (169.254/16),
                          loopback (127/8), and RFC1918 private ranges.  Do NOT
                          expose this parameter to untrusted callers; the MCP
                          tool surface intentionally omits it.
        port:             DNS port (default: 53).
        expected_bnd_req: When supplied, the record's bnd-req field must match
                          exactly (prevents cross-vendor token reuse, DCV hazard H2).
        require_dnssec:   When True, the upstream resolver must set the AD flag
                          (DNSSEC validated).  Incompatible with nameserver=.

    Returns:
        DCVVerifyResult with verified=True on success.

    NOTE: After a successful verify(), the caller MUST call revoke() immediately
    to prevent token reuse. This function does not consume the token.
    """
    domain = validate_domain(domain)
    validate_port(port)

    fqdn = f"{CHALLENGE_LABEL}.{domain}"

    if nameserver is not None:
        try:
            ipaddress.ip_address(nameserver)
        except ValueError:
            return DCVVerifyResult(
                verified=False,
                domain=domain,
                token=token,
                fqdn=fqdn,
                error=f"Invalid nameserver: must be an IP address, got {nameserver!r}",
            )

    # require_dnssec is incompatible with a direct authoritative nameserver —
    # authoritatives don't perform recursive validation and won't set AD=1.
    if require_dnssec and nameserver:
        logger.warning(
            "DNSSEC cannot be validated via a direct authoritative nameserver — skipping",
            domain=domain,
        )
        require_dnssec = False

    logger.debug(
        "DCV verify",
        domain=domain,
        fqdn=fqdn,
        nameserver=nameserver,
        require_dnssec=require_dnssec,
    )

    resolver = dns.asyncresolver.Resolver()
    resolver.cache = None  # bypass OS-level DNS cache; stale positives survive revoke
    resolver.lifetime = 4.0
    if require_dnssec:
        resolver.use_edns(0, dns.flags.DO, 4096)  # request DNSSEC from upstream
    if nameserver:
        resolver.nameservers = [nameserver]
        resolver.port = port

    try:
        answers = await resolver.resolve(fqdn, "TXT")
    except dns.resolver.NXDOMAIN:
        logger.warning("DCV verification failed", domain=domain, fqdn=fqdn, reason="NXDOMAIN")
        return DCVVerifyResult(
            verified=False,
            domain=domain,
            token=token,
            fqdn=fqdn,
            error="No challenge record found (NXDOMAIN)",
        )
    except dns.resolver.NoAnswer:
        logger.warning("DCV verification failed", domain=domain, fqdn=fqdn, reason="NoAnswer")
        return DCVVerifyResult(
            verified=False,
            domain=domain,
            token=token,
            fqdn=fqdn,
            error="No TXT records at challenge name",
        )
    except dns.exception.DNSException as e:
        logger.warning("DCV verification failed", domain=domain, fqdn=fqdn, reason=str(e))
        return DCVVerifyResult(
            verified=False,
            domain=domain,
            token=token,
            fqdn=fqdn,
            error=str(e),
        )

    if len(answers) > MAX_CHALLENGE_RECORDS:
        logger.warning(
            "DCV verification failed — too many challenge records",
            domain=domain,
            count=len(answers),
        )
        return DCVVerifyResult(
            verified=False,
            domain=domain,
            token=token,
            fqdn=fqdn,
            error=f"Too many challenge records (limit: {MAX_CHALLENGE_RECORDS})",
        )

    # DNSSEC: check AD flag before inspecting record content.
    # AD=1 means the upstream recursive resolver validated the DNSSEC chain.
    dnssec_validated = False
    if require_dnssec:
        try:
            ad_set = bool(answers.response.flags & dns.flags.AD)
        except AttributeError:
            ad_set = False
        if not ad_set:
            logger.warning("DNSSEC AD flag not set", domain=domain, fqdn=fqdn)
            return DCVVerifyResult(
                verified=False,
                domain=domain,
                token=token,
                fqdn=fqdn,
                error="DNSSEC validation required but AD flag not set by resolver",
            )
        dnssec_validated = True

    now = datetime.now(UTC)
    expired_match: str | None = None  # best expired match for informative error

    for rdata in answers:
        # Multi-string TXT records concatenated per DCV-techniques §6.1
        txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
        parsed = _parse_txt_value(txt)

        # Constant-time comparison — mitigates timing side-channel on token prefix.
        # str() coercion guards against non-string token arguments.
        if not hmac.compare_digest(parsed.get("token", ""), str(token)):
            continue

        # Require explicit expiry= — fail closed if absent
        expiry_str = parsed.get("expiry", "")
        if not expiry_str:
            logger.warning(
                "DCV record missing expiry field — treating as invalid",
                domain=domain,
                fqdn=fqdn,
            )
            continue

        try:
            expiry_dt = datetime.fromisoformat(expiry_str)
        except ValueError:
            logger.warning(
                "DCV record malformed expiry — treating as invalid",
                domain=domain,
                fqdn=fqdn,
                expiry=expiry_str,
            )
            continue

        if now > expiry_dt:
            # Keep as fallback for informative error; continue looking
            if expired_match is None:
                expired_match = expiry_str
            continue

        # Domain binding: if the record carries a domain= field, it must match the
        # queried domain.  Records written by older clients may omit domain=; those
        # are allowed through with a warning to preserve backward compatibility.
        record_domain = parsed.get("domain", "")
        if record_domain and not hmac.compare_digest(record_domain, domain):
            logger.warning(
                "DCV domain mismatch — skipping record",
                domain=domain,
                fqdn=fqdn,
                record_domain=record_domain,
            )
            continue

        # Enforce bnd-req when caller supplies a non-empty expected value.
        # Empty string treated as None — no check performed.
        if expected_bnd_req:
            record_bnd_req = parsed.get("bnd-req", "")
            if not hmac.compare_digest(record_bnd_req, expected_bnd_req):
                logger.warning(
                    "DCV bnd-req mismatch",
                    domain=domain,
                    fqdn=fqdn,
                )
                continue

        logger.info("DCV verified", domain=domain, fqdn=fqdn)
        return DCVVerifyResult(
            verified=True,
            domain=domain,
            token=token,
            fqdn=fqdn,
            dnssec_validated=dnssec_validated,
        )

    # No valid unexpired match found
    if expired_match is not None:
        logger.warning(
            "DCV verification failed — challenge expired",
            domain=domain,
            fqdn=fqdn,
            expiry=expired_match,
        )
        return DCVVerifyResult(
            verified=False,
            domain=domain,
            token=token,
            fqdn=fqdn,
            expired=True,
            error=f"Challenge expired at {expired_match}",
        )

    logger.warning(
        "DCV verification failed — token not found",
        domain=domain,
        fqdn=fqdn,
    )
    return DCVVerifyResult(
        verified=False,
        domain=domain,
        token=token,
        fqdn=fqdn,
        error="Token not found in any challenge record",
    )


async def revoke(
    domain: str,
    *,
    token: str,
    backend: DNSBackend | None = None,
) -> DCVRevokeResult:
    """
    Delete the DCV challenge TXT record from DNS.

    Should be called immediately after successful verification to prevent token reuse.
    The token is verified to be present in DNS before deletion — this avoids racing
    with a concurrent challenger's revoke() call.

    NOTE: The check-then-delete is not atomic (TOCTOU). If two parties call revoke()
    simultaneously with the same token, both may confirm the record exists before
    either deletes it. The caller should treat revoke() as best-effort hygiene;
    the expiry= field is the true security gate.

    Args:
        domain:  Zone to remove the challenge from.
        token:   Token to be revoked (must match what is in DNS).
        backend: DNS backend instance; defaults to DNS_AID_BACKEND env var.

    Returns:
        DCVRevokeResult with removed=True if deleted, removed=False if not found or failed.
    """
    from dns_aid.core.publisher import get_default_backend

    domain = validate_domain(domain)
    fqdn = f"{CHALLENGE_LABEL}.{domain}"
    if not TOKEN_PATTERN.fullmatch(token):
        raise ValueError("token must be a 32-character lowercase base32 string")

    # Confirm our token is present before deleting — reduces cross-challenger races
    check = await verify(domain, token)
    if not check.verified:
        logger.warning(
            "DCV revoke: token not found in DNS, skipping deletion",
            domain=domain,
            reason=check.error,
        )
        return DCVRevokeResult(removed=False, domain=domain, fqdn=fqdn)

    dns_backend = backend or get_default_backend()

    logger.info("Revoking DCV challenge", domain=domain, fqdn=fqdn)

    deleted = await dns_backend.delete_record(
        zone=domain,
        name=CHALLENGE_LABEL,
        record_type="TXT",
    )

    if deleted:
        logger.info("DCV challenge revoked", fqdn=fqdn)
    else:
        logger.warning("DCV challenge not found or already removed", fqdn=fqdn)

    return DCVRevokeResult(removed=deleted, domain=domain, fqdn=fqdn)
