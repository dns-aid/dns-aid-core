# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
JWS Signature Support for DNS-AID.

Provides an application-layer verification alternative when DNSSEC is not available.
Publishers sign SVCB record content with their private key and include the signature
in a `sig` parameter. Verifiers fetch the public key from `.well-known/dns-aid-jwks.json`.

Key format: ECDSA P-256 (ES256) for compact signatures suitable for DNS records.

Usage:
    # Publisher: Generate keypair
    private_key, public_key = generate_keypair()
    jwks = export_jwks(public_key, kid="dns-aid-2024")

    # Publisher: Sign record
    signature = sign_record(payload, private_key)

    # Verifier: Verify signature
    is_valid = await verify_record_signature(domain, payload, signature)
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import time
import warnings
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

import structlog
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)

logger = structlog.get_logger(__name__)

# JWKS well-known endpoint path
JWKS_WELL_KNOWN_PATH = "/.well-known/dns-aid-jwks.json"

# The JWKS is served from a dedicated host derived from the publishing zone,
# not from the zone apex.
#
# Deriving the location rather than accepting a pointer is deliberate. This
# path runs precisely when the DNS answer is NOT authenticated, so a pointer
# carried in the record could not be trusted to name the key: an attacker able
# to forge the record could forge the pointer, serve their own JWKS, and sign
# with their own key -- and signing the pointer would not help, because the
# attacker controls both halves. A derived name cannot be steered at all, and
# it is inside the publisher's registrable domain by construction, so no
# public-suffix check is needed.
#
# A dedicated host (rather than the apex) is what keeps this deployable: it is
# a fresh name that may CNAME to a gateway, CDN, or bucket, whereas a zone apex
# may not. Zones that exist only to carry agent records need no web presence.
# Same reasoning and shape as MTA-STS (RFC 8461 Section 3.1), which requires
# mta-sts.<domain> rather than the apex.
#
# An underscore label is not an option here: CA/Browser Forum baseline
# requirements bar underscores from certificate dNSName SANs, and this host is
# fetched over HTTPS. (`_agents` is DNS-only, so it correctly keeps its
# underscore; this host cannot.)
# TRUST LIMIT of the JWS fallback, stated where the location is defined.
#
# The document is fetched over HTTPS from a name INSIDE the zone the fallback
# exists to protect, so its authenticity rests on WebPKI for that name. An
# attacker with zone-level DNS control -- the adversary this fallback is meant to
# stop -- can satisfy an ACME DNS-01 or HTTP-01 challenge for dns-aid.<zone>,
# obtain a DV certificate, and serve their own JWKS. Against that adversary JWS
# reduces to WebPKI rather than being an independent anchor.
#
# It remains worthwhile against a weaker attacker (off-path spoofing, a poisoned
# cache, a compromised resolver) who cannot also obtain a certificate. Closing
# the gap needs an out-of-band pin -- a TLSA record for the JWKS host, a key
# fingerprint carried in the SVCB record, or trust-on-first-use with change
# alerting -- and that is a protocol decision, not a local change.
JWKS_HOST_PREFIX = "dns-aid"


class SignatureStatus(StrEnum):
    """Why signature verification reached the answer it did.

    ``signature_verified`` is deliberately tri-state, and the distinction it
    cannot express on its own is why this exists: a JWKS that could not be
    fetched is *unknown*, not *forged*. Reporting an unreachable key document
    as a failed signature turns a CDN blip into an apparent attack, and --
    worse -- turns a genuine attack into something operators learn to ignore.

    The operationally important pair is EXPIRED versus INVALID. Both mean "do
    not trust this record", but the first is answered by re-publishing and the
    second by investigating; collapsing them into one boolean leaves the
    operator no way to tell which they are looking at.
    """

    VERIFIED = "verified"
    # The signature verified, but covers only fqdn/target/port/alpn -- cap,
    # cap-sha256, policy, realm and well-known are NOT attested. The attacker
    # chooses which genuine signature to replay, so they choose one without the
    # svcb claim; reporting that as plain "verified" is a false statement about
    # what was proven, whatever require_signed_params is set to.
    VERIFIED_ENDPOINT_ONLY = "verified_endpoint_only"  # signature valid AND bound to this record
    INVALID = "invalid"  # a key was retrieved; the signature did not verify
    UNBOUND = "unbound"  # signature valid but describes a different record
    EXPIRED = "expired"  # signature lapsed; re-publish
    NO_KEY = "no_key"  # no JWKS reachable / no key matched -- unknown
    NOT_SIGNED = "not_signed"
    # Verification was requested for this record but did not run -- the aggregate
    # budget ran out first. Distinct from NOT_SIGNED (no signature) and from an
    # unset status (never in scope), because a caller that asked for
    # verification and silently received nothing cannot tell the difference.
    NOT_CHECKED = "not_checked"  # record carries no sig parameter
    SKIPPED_DNSSEC = "skipped_dnssec"  # authenticated by DNSSEC; JWS not needed


def jwks_urls(zone: str) -> list[str]:
    """Candidate JWKS locations for a publishing zone, in preference order.

    The derived host is authoritative. The zone apex is retained as a
    deprecated fallback so deployments that published a JWKS before the host
    was introduced keep verifying.
    """
    zone = zone.rstrip(".")
    return [
        f"https://{JWKS_HOST_PREFIX}.{zone}{JWKS_WELL_KNOWN_PATH}",
        f"https://{zone}{JWKS_WELL_KNOWN_PATH}",  # deprecated
    ]


# Cache for JWKS documents (domain -> (jwks, expiry))
_jwks_cache: dict[str, tuple[dict[str, Any], float]] = {}
JWKS_CACHE_TTL = 3600  # 1 hour

# A JWKS with a handful of P-256 keys is well under 64 KB. Bound the fetched
# document size so a hostile endpoint can't return an unbounded body, and
# bound the per-process cache so bulk cross-domain discovery can't grow it
# without limit.
_MAX_JWKS_RESPONSE_BYTES = 64 * 1024
_JWKS_CACHE_MAX = 512

# When a signature names a `kid` the cached document does not carry, the key may
# have been rolled in since the document was fetched, so one forced refresh is
# worth a round trip. But a `kid` that is simply never served -- a publisher
# whose JWKS does not carry the key they signed with, or an attacker-chosen
# value, since `sig` comes off an unauthenticated DNS record -- would otherwise
# force a refetch on EVERY verification, silently converting a one-hour cache
# into a fetch per lookup with no error surfaced.
#
# The budget is per DOMAIN. `kid` comes off an unauthenticated DNS record, so it
# is attacker-chosen per lookup: keying the budget by (domain, kid) meant every
# fresh value arrived with an unspent budget and forced its own refetch, which
# is the per-lookup amplification the budget exists to prevent.
#
# The cost of a per-domain budget is that a bogus kid can delay a genuine
# rollover by up to one window. That is bounded and self-healing, whereas
# unbounded refetching is not, and the fallback below means a rollover is still
# picked up as soon as the ordinary cache expires.
#
# A monotonic clock: this is an elapsed-time budget, and a wall-clock step
# backwards would otherwise block refreshes for the size of the jump.
_jwks_forced_refresh: dict[str, float] = {}

# Zones whose JWKS could not be fetched, and when to stop believing that.
# Successes were cached and failures were not, so a zone publishing N signed
# agents against an unreachable JWKS host paid two candidate URLs at 10s each,
# N times over, inside one discovery. Six agents already exceeded the MCP
# server's 120s per-call cap, at which point the caller lost every result rather
# than just the signature column. Kept deliberately short: an outage should cost
# one timeout per zone, not suppress verification for a whole cache window.
JWKS_NEGATIVE_TTL = 30.0
_jwks_negative: dict[str, float] = {}

# One in-flight fetch per zone. The concurrency cap starts 16 verifications at
# once; they all missed the cache, all missed the negative cache, and all
# fetched, so "one fetch per zone, not one per agent" was false for the batch
# and the negative cache could not help -- nothing had been written yet.
_jwks_inflight: dict[str, asyncio.Lock] = {}


# 90 days. The one default for signature validity, defined here beside the payload
# that carries it. publisher.py re-exports it. Two independent defaults meant a
# direct RecordPayload caller silently got 1 day while the CLI got 90, and the
# whole point of this change is that validity should not be a surprise.
# Every DNS-AID SvcParam except `sig` itself, mapped to the AgentRecord field
# that carries it. Derived from DNS_AID_KEY_MAP so a new key cannot be added to
# the record without a decision about whether the signature covers it -- see
# test_svcb_claim.py, which fails when the two drift.
#
# Why this exists: the payload originally bound only fqdn, target, port and
# alpn. Everything else -- cap, cap-sha256, policy, realm, well-known -- sat
# outside the signature, so an attacker spoofing an unsigned zone could replay a
# genuine sig verbatim, keep those four fields byte-identical, and swap cap and
# cap-sha256 for a document of their own. The record still reported `verified`,
# and the capability fetch then digest-checked the attacker's document against
# the attacker's digest.
SIGNED_PARAM_FIELDS: dict[str, str] = {
    "cap": "cap_uri",
    "cap-sha256": "cap_sha256",
    "bap": "bap",
    "policy": "policy_uri",
    "realm": "realm",
    "connect-class": "connect_class",
    "connect-meta": "connect_meta",
    "enroll-uri": "enroll_uri",
    "well-known": "well_known_path",
}


def _cache_key(domain: str) -> str:
    """Normalise a zone for cache lookups.

    DNS labels are case-insensitive (RFC 4343) and a trailing dot names the same
    zone, so `example.com`, `Example.com` and `example.com.` are one thing. Keying
    the caches on the raw string gave each spelling its own entry, which bypassed
    the positive cache, the negative cache AND the once-per-window forced-refresh
    budget at the same time. The budget had already been moved from (domain, kid)
    to domain to stop exactly that amplification; the key itself reopened it one
    layer up. `discover_agents_via_dns` takes `domain` straight from model output,
    so this needs no attacker at all.
    """
    return domain.rstrip(".").lower()


def svcb_digest(params: Mapping[str, str | None]) -> str:
    """Canonical SHA-256 over the DNS-AID SvcParams, base64url without padding.

    Absent and empty parameters are omitted rather than serialised as empty, so
    a record that never carried a parameter and one that carries it empty do not
    collide. Keys are sorted, so the digest does not depend on SvcParam ordering
    (which RFC 9460 does not fix on the wire).
    """
    # JSON, not "k=v" joined by newlines. That shape had no escaping, so a value
    # containing a newline forged a field boundary: {"cap": "u", "realm": "t"}
    # and {"cap": "u\nrealm=t"} hashed identically. Any param whose value is
    # partly caller- or tenant-influenced could then be split or merged while the
    # claim still validated -- defeating the binding it was added to provide.
    #
    # The svcb1: prefix domain-separates this encoding so a future change cannot
    # be confused with it.
    # `is not None`, not truthiness. An empty value and an absent one are
    # different states, and JSON keeps them distinct, so a param the publisher
    # never set cannot be injected as "" without breaking the claim.
    covered = {k: v for k, v in sorted(params.items()) if v is not None}
    raw = b"svcb1:" + json.dumps(
        covered, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def params_from_record(record: Any) -> dict[str, str | None]:
    """Read the covered SvcParams back off a discovered record."""
    return {name: getattr(record, field, None) for name, field in SIGNED_PARAM_FIELDS.items()}


DEFAULT_SIG_VALIDITY_SECONDS = 7_776_000


@dataclass
class RecordPayload:
    """
    Canonical payload for JWS signing.

    Contains the fields that uniquely identify an SVCB record.
    """

    fqdn: str
    target: str
    port: int
    alpn: str
    iat: int  # Issued at timestamp
    exp: int  # Expiration timestamp
    # Digest over the remaining DNS-AID SvcParams. Optional so that records
    # signed before this claim existed still verify: absent means the signature
    # covers only the four endpoint fields, which is reported rather than
    # silently treated as full coverage.
    svcb: str | None = None

    def to_json(self) -> str:
        """Serialize to canonical JSON (sorted keys, no whitespace)."""
        body: dict[str, Any] = {
            "fqdn": self.fqdn,
            "target": self.target,
            "port": self.port,
            "alpn": self.alpn,
            "iat": self.iat,
            "exp": self.exp,
        }
        # Omitted, not null, when there is no claim: a payload signed by an
        # older publisher must serialise byte-identically or its signature
        # stops verifying.
        if self.svcb is not None:
            body["svcb"] = self.svcb
        return json.dumps(body, sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_agent_record(
        cls,
        fqdn: str,
        target: str,
        port: int,
        protocol: str,
        validity_seconds: int | None = None,
        ttl_seconds: int | None = None,
        params: Mapping[str, str | None] | None = None,
    ) -> RecordPayload:
        """Create payload from agent record fields.

        ``validity_seconds`` is how long the assertion holds, which is not the
        DNS record TTL. The TTL governs resolver caching only.

        ``params`` are the DNS-AID SvcParams the signature should cover. Omit
        them only to reproduce a pre-claim signature.
        """
        # ttl_seconds was the parameter name through 0.27.0. It described the DNS
        # record TTL, which is what the signature validity was wrongly taken from.
        # Accepted for one minor so a downstream keyword call does not TypeError.
        # Sentinel default, so "supplied" is distinguishable from "equal to the
        # default". Comparing against the value missed the exact case the guard
        # was written for: a wrapper forwarding **kwargs whose own default is
        # DEFAULT_SIG_VALIDITY_SECONDS passed both, tripped nothing, and let the
        # deprecated name win -- producing a 1-hour signature where 90 days was
        # asked for, which surfaces an hour later as records that stop verifying.
        if ttl_seconds is not None and validity_seconds is not None:
            raise TypeError("pass validity_seconds or ttl_seconds, not both")
        if ttl_seconds is not None:
            warnings.warn(
                "ttl_seconds is deprecated and will be removed in 0.30.0; "
                "use validity_seconds. Signature validity is independent of the "
                "DNS record TTL.",
                DeprecationWarning,
                stacklevel=2,
            )
            validity_seconds = ttl_seconds
        if validity_seconds is None:
            validity_seconds = DEFAULT_SIG_VALIDITY_SECONDS

        now = int(time.time())
        return cls(
            fqdn=fqdn,
            target=target,
            port=port,
            alpn=protocol,
            iat=now,
            exp=now + validity_seconds,
            svcb=svcb_digest(params) if params is not None else None,
        )


def generate_keypair() -> tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    """
    Generate an ECDSA P-256 keypair for DNS-AID signing.

    Returns:
        Tuple of (private_key, public_key)

    Example:
        >>> private_key, public_key = generate_keypair()
        >>> # Save private key securely
        >>> pem = private_key.private_bytes(
        ...     encoding=serialization.Encoding.PEM,
        ...     format=serialization.PrivateFormat.PKCS8,
        ...     encryption_algorithm=serialization.NoEncryption()
        ... )
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key


def export_jwks(
    public_key: EllipticCurvePublicKey,
    kid: str = "dns-aid-default",
) -> dict[str, Any]:
    """
    Export a public key as a JWKS document.

    Args:
        public_key: The EC public key to export
        kid: Key identifier

    Returns:
        JWKS document dict

    Example:
        >>> _, public_key = generate_keypair()
        >>> jwks = export_jwks(public_key, kid="dns-aid-2024")
        >>> # Write to .well-known/dns-aid-jwks.json
    """
    # Get the public numbers
    numbers = public_key.public_numbers()

    # Convert to base64url encoding (no padding)
    x_bytes = numbers.x.to_bytes(32, byteorder="big")
    y_bytes = numbers.y.to_bytes(32, byteorder="big")

    x_b64 = base64.urlsafe_b64encode(x_bytes).rstrip(b"=").decode("ascii")
    y_b64 = base64.urlsafe_b64encode(y_bytes).rstrip(b"=").decode("ascii")

    return {
        "keys": [
            {
                "kty": "EC",
                "crv": "P-256",
                "kid": kid,
                "use": "sig",
                "alg": "ES256",
                "x": x_b64,
                "y": y_b64,
            }
        ]
    }


def export_jwks_multi(
    keys: list[tuple[EllipticCurvePublicKey, str]],
) -> dict[str, Any]:
    """Export several public keys as one JWKS document.

    A rollover needs the outgoing and incoming keys published together: records
    signed before the roll still name the old ``kid`` and must keep verifying
    until they are re-signed. Emitting a single key made every rotation a flag
    day, so this is what makes staged key changes possible at all.

    Args:
        keys: (public key, kid) pairs, in any order.

    Returns:
        JWKS document containing every supplied key.
    """
    merged: list[dict[str, Any]] = []
    for public_key, kid in keys:
        merged.extend(export_jwks(public_key, kid=kid)["keys"])
    return {"keys": merged}


def import_public_key_from_jwk(jwk: dict[str, Any]) -> EllipticCurvePublicKey:
    """
    Import a public key from a JWK dict.

    Hardened against algorithm/curve confusion: only an EC P-256 signing
    key is accepted, and the x/y coordinates must be exactly 32 bytes.
    ``public_key()`` additionally rejects a point that is not on the curve
    (invalid-curve attack). The JWKS source is attacker-influenceable, so
    these checks run before any key material is trusted.

    Args:
        jwk: JWK dict with ``kty="EC"``, ``crv="P-256"``, and x/y coords.

    Returns:
        EC public key.

    Raises:
        ValueError: if the JWK is not a P-256 EC signing key, or the
            coordinates are missing / malformed / wrong length.
    """
    if not isinstance(jwk, dict):
        raise ValueError("JWK must be a JSON object")
    if jwk.get("kty") != "EC":
        raise ValueError(f"unsupported JWK kty {jwk.get('kty')!r}; only 'EC' is supported")
    if jwk.get("crv") != "P-256":
        raise ValueError(f"unsupported JWK crv {jwk.get('crv')!r}; only 'P-256' is supported")
    use = jwk.get("use")
    if use is not None and use != "sig":
        raise ValueError(f"JWK 'use' is {use!r}, not a signing key")

    # Decode base64url (add padding if needed)
    def b64url_decode(s: str) -> bytes:
        padding = 4 - len(s) % 4
        if padding != 4:
            s += "=" * padding
        return base64.urlsafe_b64decode(s)

    try:
        x_bytes = b64url_decode(jwk["x"])
        y_bytes = b64url_decode(jwk["y"])
    except (KeyError, TypeError, ValueError) as e:
        # binascii.Error (bad base64) is a ValueError subclass.
        raise ValueError(f"invalid JWK coordinates: {e}") from e

    # P-256 field elements are exactly 32 bytes.
    if len(x_bytes) != 32 or len(y_bytes) != 32:
        raise ValueError("JWK x/y coordinates must be 32 bytes for P-256")

    x = int.from_bytes(x_bytes, byteorder="big")
    y = int.from_bytes(y_bytes, byteorder="big")

    # public_key() raises ValueError if (x, y) is not on the P-256 curve.
    public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
    return public_numbers.public_key()


def sign_record(
    payload: RecordPayload,
    private_key: EllipticCurvePrivateKey,
    kid: str | None = None,
) -> str:
    """
    Sign a record payload with the private key.

    Creates a compact JWS (header.payload.signature) suitable for
    inclusion in DNS SVCB `sig` parameter.

    Args:
        payload: The record payload to sign
        private_key: EC private key for signing
        kid: Optional key identifier, published in the protected header so
            verifiers can select the matching key during a rollover.

    Returns:
        Compact JWS string (base64url encoded)
    """
    # JWS Header. `kid` names the key that produced this signature so a
    # verifier can select it from a multi-key JWKS instead of trying every
    # key -- the difference between a rollover that overlaps cleanly and one
    # that is indistinguishable from a mismatch. Omitted when not supplied so
    # the header stays byte-identical to previously published signatures.
    header: dict[str, str] = {"alg": "ES256", "typ": "JWT"}
    if kid is not None:
        header["kid"] = kid
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")))

    # JWS Payload
    payload_b64 = _b64url_encode(payload.to_json())

    # Signing input
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    # Sign with ECDSA
    signature = private_key.sign(signing_input, ECDSA(hashes.SHA256()))

    # Convert DER signature to raw r||s format for JWS
    signature_raw = _der_to_raw_signature(signature)
    signature_b64 = _b64url_encode_bytes(signature_raw)

    return f"{header_b64}.{payload_b64}.{signature_b64}"


def verify_signature(
    jws: str,
    public_key: EllipticCurvePublicKey,
) -> tuple[bool, RecordPayload | None]:
    """
    Verify a JWS signature and extract the payload.

    Args:
        jws: Compact JWS string
        public_key: EC public key for verification

    Returns:
        Tuple of (is_valid, payload or None)
    """
    is_valid, payload, _status = verify_signature_detailed(jws, public_key)
    return is_valid, payload


def verify_signature_detailed(
    jws: str,
    public_key: EllipticCurvePublicKey,
) -> tuple[bool, RecordPayload | None, SignatureStatus]:
    """
    Verify a JWS signature, reporting why it reached its answer.

    Same checks as :func:`verify_signature`, but distinguishes a lapsed
    signature from a cryptographically bad one. Both are "do not trust", yet
    one is fixed by re-publishing and the other warrants investigation -- a
    bare boolean cannot tell an operator which they have.

    Args:
        jws: Compact JWS string
        public_key: EC public key for verification

    Returns:
        Tuple of (is_valid, payload or None, status)
    """
    try:
        parts = jws.split(".")
        if len(parts) != 3:
            return False, None, SignatureStatus.INVALID

        header_b64, payload_b64, signature_b64 = parts

        # Enforce the algorithm declared in the protected header. Only ES256
        # is supported; reject "none", RSA, or any other alg to close
        # algorithm-confusion attacks (the key source is attacker-influenced).
        header = json.loads(_b64url_decode(header_b64))
        if not isinstance(header, dict) or header.get("alg") != "ES256":
            logger.debug(
                "Unsupported or missing JWS alg",
                alg=header.get("alg") if isinstance(header, dict) else None,
            )
            return False, None, SignatureStatus.INVALID

        # Reconstruct signing input
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

        # Decode signature
        signature_raw = _b64url_decode_bytes(signature_b64)
        signature_der = _raw_to_der_signature(signature_raw)

        # Verify
        public_key.verify(signature_der, signing_input, ECDSA(hashes.SHA256()))

        # Decode and validate payload
        payload_json = _b64url_decode(payload_b64)
        payload_dict = json.loads(payload_json)

        # Check expiration
        if payload_dict.get("exp", 0) < time.time():
            # Lapsed, not forged: the publisher must re-sign. Reported
            # separately so an operator is not sent hunting for an attacker.
            logger.warning("Signature expired", exp=payload_dict.get("exp"))
            return False, None, SignatureStatus.EXPIRED

        payload = RecordPayload(
            fqdn=payload_dict["fqdn"],
            target=payload_dict["target"],
            port=payload_dict["port"],
            alpn=payload_dict["alpn"],
            iat=payload_dict["iat"],
            exp=payload_dict["exp"],
            svcb=payload_dict.get("svcb"),
        )

        return True, payload, SignatureStatus.VERIFIED

    except Exception as e:
        logger.debug("Signature verification failed", error=str(e))
        return False, None, SignatureStatus.INVALID


async def fetch_jwks(domain: str) -> dict[str, Any] | None:
    """
    Fetch JWKS from a domain's well-known endpoint.

    Includes caching to avoid repeated requests.

    Args:
        domain: Domain to fetch JWKS from

    Returns:
        JWKS document or None if fetch failed
    """
    # Check cache
    now = time.time()
    cached = _jwks_cache.get(_cache_key(domain))
    if cached is not None:
        jwks, expiry = cached
        if now < expiry:
            return jwks
        _jwks_cache.pop(_cache_key(domain), None)  # expired — drop it

    key = _cache_key(domain)
    lock = _jwks_inflight.get(key)
    if lock is None:
        while len(_jwks_inflight) >= _JWKS_CACHE_MAX:
            _jwks_inflight.pop(next(iter(_jwks_inflight)), None)
        lock = _jwks_inflight.setdefault(key, asyncio.Lock())
    async with lock:
        # Re-read under the lock: a concurrent caller may have filled either
        # cache while this one waited.
        cached = _jwks_cache.get(key)
        if cached is not None and time.time() < cached[1]:
            return cached[0]
        return await _fetch_jwks_locked(domain)


async def _fetch_jwks_locked(domain: str) -> dict[str, Any] | None:
    """The body of :func:`fetch_jwks`, serialised per zone by its caller."""
    now = time.time()
    negative_until = _jwks_negative.get(_cache_key(domain))
    if negative_until is not None:
        if now < negative_until:
            logger.debug("JWKS recently unreachable for this zone; not retrying yet", domain=domain)
            return None
        _jwks_negative.pop(_cache_key(domain), None)

    # Fetch from the derived host, falling back to the deprecated apex
    # location. This input stamps trust (signature_verified), so every
    # candidate goes through the same SSRF guard and streaming size cap as any
    # other untrusted fetch — no raw httpx.get, no unbounded .json(), and no
    # cross-host redirects.
    candidates = jwks_urls(domain)

    for index, url in enumerate(candidates):
        is_deprecated = index > 0
        jwks = await _fetch_jwks_from(url, domain)
        if jwks is None:
            continue

        if is_deprecated:
            logger.warning(
                "JWKS served from the deprecated zone-apex location; "
                "publish it at the derived host instead",
                domain=domain,
                url=url,
                expected=candidates[0],
            )

        _cache_jwks(domain, jwks)
        logger.info("JWKS fetched successfully", domain=domain, url=url)
        return jwks

    logger.warning("No JWKS available at any known location", domain=domain, tried=candidates)
    while len(_jwks_negative) >= _JWKS_CACHE_MAX:
        _jwks_negative.pop(next(iter(_jwks_negative)), None)
    # Stamped from a FRESH clock reading. `now` was taken before the fetch, and
    # the fetch is two candidate URLs at up to 15s each, so a slow failure wrote
    # an entry that had already expired at the moment it was inserted -- the
    # cache never suppressed anything and every agent paid the full timeout.
    _jwks_negative[_cache_key(domain)] = time.time() + JWKS_NEGATIVE_TTL
    return None


def _cache_jwks(domain: str, jwks: dict[str, Any]) -> None:
    """Store a fetched document, bounding cache growth by FIFO eviction."""
    while len(_jwks_cache) >= _JWKS_CACHE_MAX:
        _jwks_cache.pop(next(iter(_jwks_cache)), None)
    _jwks_cache[_cache_key(domain)] = (jwks, time.time() + JWKS_CACHE_TTL)


async def _fetch_jwks_uncached(domain: str) -> dict[str, Any] | None:
    """Fetch the document past the cache without disturbing the cached entry.

    Used by the unmatched-kid refetch. Evicting the cached entry first meant one
    unmatched kid invalidated the document for every concurrent lookup of the
    same domain, so an attacker-chosen kid degraded everyone else's cache hit
    rate as well as its own.
    """
    candidates = jwks_urls(domain)
    for index, url in enumerate(candidates):
        jwks = await _fetch_jwks_from(url, domain)
        if jwks is not None:
            if index > 0:
                # Same nudge the ordinary fetch emits. Without it a key rollover
                # picked up through this path silently adopts an apex-served
                # document, and anyone able to write to the zone apex mints keys
                # that authenticate records for the whole zone.
                logger.warning(
                    "JWKS served from the deprecated zone-apex location; "
                    "publish it at the derived host instead",
                    domain=domain,
                    url=url,
                    expected=candidates[0],
                )
            return jwks
    return None


async def _fetch_jwks_from(url: str, domain: str) -> dict[str, Any] | None:
    """Fetch and parse a JWKS document from one candidate URL."""
    logger.debug("Fetching JWKS", url=url)

    from dns_aid.utils.url_safety import (
        ResponseTooLargeError,
        UnsafeURLError,
        safe_fetch_bytes,
        validate_fetch_url_async,
    )

    try:
        await validate_fetch_url_async(url)
    except UnsafeURLError as e:
        logger.warning("JWKS URL blocked by SSRF protection", url=url, error=str(e))
        return None

    try:
        body = await safe_fetch_bytes(
            url,
            max_bytes=_MAX_JWKS_RESPONSE_BYTES,
            timeout=10.0,
            follow_redirects=False,
        )
        if body is None:
            logger.debug("JWKS fetch failed (non-200)", url=url)
            return None

        jwks = json.loads(body)
        if not isinstance(jwks, dict):
            logger.warning("JWKS document is not a JSON object", url=url)
            return None

        return jwks

    except ResponseTooLargeError as e:
        logger.warning("JWKS document too large", url=url, error=str(e))
        return None
    except Exception as e:
        logger.debug("Failed to fetch JWKS", url=url, error=str(e))
        return None


async def verify_record_signature(
    domain: str,
    jws: str,
) -> tuple[bool, RecordPayload | None]:
    """
    Verify a record signature by fetching JWKS from the domain.

    This is the main entry point for verifiers.

    Args:
        domain: Domain to fetch JWKS from
        jws: The JWS signature to verify

    Returns:
        Tuple of (is_valid, payload or None)
    """
    is_valid, payload, _status = await verify_record_signature_detailed(domain, jws)
    return is_valid, payload


def _jws_kid(jws: str) -> str | None:
    """Read the key identifier out of a compact JWS protected header."""
    try:
        header = json.loads(_b64url_decode(jws.split(".")[0]))
    except Exception:
        return None
    kid = header.get("kid") if isinstance(header, dict) else None
    return kid if isinstance(kid, str) else None


def _candidate_keys(jwks: dict[str, Any], kid: str | None) -> list[dict[str, Any]]:
    """Order the key set for verification, preferring an exact ``kid`` match.

    Selecting by ``kid`` is what makes an overlapping key rollover possible:
    the outgoing and incoming keys sit in the document together and each
    signature names the one that produced it. Without it every signature is
    tried against every key, so a rollover is indistinguishable from a
    mismatch and nothing can be attributed to a signer.

    Signatures published before ``kid`` was emitted carry no identifier, so the
    unfiltered set is still tried -- older records keep verifying.
    """
    keys = [k for k in jwks.get("keys", []) if isinstance(k, dict)]
    if kid is None:
        return keys
    # Strict at this level: an empty result is the signal that the named key is
    # absent from the document we hold, which distinguishes "rolled in since we
    # cached" from "this signature is bad" and is what triggers the refresh.
    #
    # The caller deliberately retries with kid=None once the refresh has been
    # attempted. RFC 7515 Section 4.1.4 makes kid a hint rather than a
    # constraint, so a publisher whose JWKS omits kid entirely, and signatures
    # published before kid was emitted, must still verify. So kid narrows the
    # search and orders the work; it does not by itself bind a signature to one
    # key.
    return [k for k in keys if k.get("kid") == kid]


def _is_positive(result: tuple | None) -> bool:
    """Whether a verification attempt reached a real cryptographic conclusion.

    A success is obvious. EXPIRED counts too: a key verified the signature bytes
    and only the exp claim had lapsed. Discarding that collapsed a re-publish
    prompt into "no key document reachable", losing the distinction
    SignatureStatus exists to draw.
    """
    return result is not None and (result[0] or result[2] is SignatureStatus.EXPIRED)


def _short_kid(kid: str | None) -> str | None:
    """kid is attacker-chosen and bounded only by DNS record size.

    Truncated at the log site so a publisher cannot turn every lookup into a
    multi-kilobyte log line across every consumer that resolves the zone.
    """
    if kid is None:
        return None
    # Truncation alone was not enough. kid is a JSON string off an
    # unauthenticated record, so a newline inside the first 64 characters let an
    # attacker emit a syntactically perfect forged log line -- asserting a
    # successful verification for a domain never verified, and pushing their own
    # failure line out of view. Anything grepping these logs was attacker-writable.
    safe = "".join(c if c.isprintable() else "?" for c in kid)
    return safe if len(safe) <= 64 else safe[:64] + "...(truncated)"


async def verify_record_signature_detailed(
    domain: str,
    jws: str,
) -> tuple[bool, RecordPayload | None, SignatureStatus]:
    """
    Verify a record signature against the zone's JWKS, reporting why.

    Distinguishes an unreachable key document (``NO_KEY`` -- unknown) from a
    signature that was actually checked and rejected (``INVALID``) and from one
    that simply lapsed (``EXPIRED``). Collapsing these into a single ``False``
    made a network fault look identical to an attack.

    Args:
        domain: Publishing zone whose JWKS authenticates the record.
        jws: The compact JWS carried in the record's ``sig`` parameter.

    Returns:
        Tuple of (is_valid, payload or None, status)
    """
    kid = _jws_kid(jws)

    jwks = await fetch_jwks(domain)
    if not jwks or "keys" not in jwks:
        # Nothing was verified. This is not evidence against the record.
        logger.warning("No JWKS available", domain=domain, kid=_short_kid(kid))
        return False, None, SignatureStatus.NO_KEY

    # `kid` narrows the search first, then the whole set is tried. RFC 7515
    # Section 4.1.4 makes kid a hint rather than a constraint, and RFC 7517
    # makes it optional in the JWKS, so a publisher whose document omits kid
    # entirely -- or who signs with a kid they did not publish -- must still
    # verify against the keys they actually serve. Treating kid as binding
    # rejected exactly those deployments with NO_KEY while the correct key sat
    # in the document.
    rejected_by_a_real_key = False
    result = _verify_against(jwks, jws, kid, domain)
    if result is None and kid is not None:
        # The named key is not in this document. Try the rest, but only ACCEPT a
        # success: if another key verifies, the kid was merely a stale or
        # unpublished hint and the signature is genuine. If none does, the
        # honest report is still "the named key was never found" -- other keys
        # rejecting a signature they never issued is expected, not evidence of
        # forgery, and reporting INVALID there would recreate the
        # unverifiable-reads-as-forgery inversion.
        fallback = _verify_against(jwks, jws, None, domain)
        if _is_positive(fallback):
            result = fallback
        elif fallback is not None:
            # Keys were imported, tried, and rejected this signature. That is a
            # cryptographic conclusion; hold on to it.
            rejected_by_a_real_key = True

    # Nothing in the cached document verified. If a kid was named, the key may
    # have rolled in since the document was cached, so one refetch per domain
    # per window is worth the round trip.
    if result is None and kid is not None:
        now = time.monotonic()
        last_forced = _jwks_forced_refresh.get(_cache_key(domain), float("-inf"))
        if now - last_forced >= JWKS_CACHE_TTL:
            logger.debug("refetching JWKS for an unmatched kid", domain=domain, kid=_short_kid(kid))
            # Reserve the window BEFORE the await. Reading the budget here and
            # stamping it after the fetch left an await in between, so every
            # coroutine that arrived first saw an unspent budget: 25 concurrent
            # lookups for one domain produced 25 refetches, each up to two
            # candidate URLs at 10s, aimed at the victim's JWKS host. A
            # pessimistic reservation costs at most one skipped refetch under a
            # genuine race, which the next lookup picks up.
            while len(_jwks_forced_refresh) >= _JWKS_CACHE_MAX:
                _jwks_forced_refresh.pop(next(iter(_jwks_forced_refresh)), None)
            _jwks_forced_refresh.pop(_cache_key(domain), None)  # re-insert: evict by recency
            _jwks_forced_refresh[_cache_key(domain)] = now
            # Fetch past the cache without evicting it. Popping the entry made
            # one unmatched kid invalidate the document for every concurrent
            # lookup of the same domain.
            refreshed = await _fetch_jwks_uncached(domain)
            if refreshed and "keys" in refreshed:
                _cache_jwks(domain, refreshed)
                result = _verify_against(refreshed, jws, kid, domain)
                if result is None:
                    fallback = _verify_against(refreshed, jws, None, domain)
                    if _is_positive(fallback):
                        result = fallback
                    elif fallback is not None:
                        rejected_by_a_real_key = True
        else:
            logger.debug(
                "kid unmatched; refetch budget already spent for this domain",
                domain=domain,
                kid=_short_kid(kid),
            )

    if result is None and kid is not None:
        # kid comes off the unauthenticated record, so an attacker picks it. If an
        # absent kid always meant NO_KEY, every forgery would report the one status
        # the MCP contract tells consumers is "unknown, not forged, do not treat as
        # an attack signal" -- detection suppressed by attacker choice.
        #
        # The distinction is whether the key set is current. Before a refetch a
        # stale document genuinely cannot distinguish "key rolled in since we
        # cached" from "forged", so unknown is the honest answer. After a
        # successful refetch we hold the publisher's current keys and none of them
        # verifies this signature. That is a rejection, not an absence.
        # The discriminator is whether a real key rejected these bytes, NOT
        # whether a network fetch happened to succeed.
        #
        # Gating INVALID on the refetch left the choice with the attacker: the
        # refetch budget is per domain per cache window, so spending it once --
        # with a single bogus kid, or by blackholing the JWKS host they already
        # control in this threat model -- made every later forgery report
        # NO_KEY, the status the MCP contract tells consumers is "unknown, not
        # forged, do not treat as an attack signal". Three forgeries produced
        # invalid, no_key, no_key. An attacker cannot make the publisher's
        # cached key set empty, so this discriminator has no lever on it.
        #
        # A publisher who retires a key without an overlap window (RFC 7671
        # Section 8.1 stages rollovers by publishing both) will see INVALID
        # rather than NO_KEY for records still cached under the old kid. That is
        # accurate: no key they serve verifies those records.
        if rejected_by_a_real_key:
            logger.warning(
                "signature was rejected by every key this publisher serves",
                domain=domain,
                kid=_short_kid(kid),
            )
            return False, None, SignatureStatus.INVALID
        logger.warning("no usable key in JWKS", domain=domain, kid=_short_kid(kid))
        return False, None, SignatureStatus.NO_KEY

    if result is None:
        return False, None, SignatureStatus.NO_KEY
    return result


def _verify_against(
    jwks: dict[str, Any],
    jws: str,
    kid: str | None,
    domain: str,
) -> tuple[bool, RecordPayload | None, SignatureStatus] | None:
    """Try the key set. ``None`` means no key was usable at all."""
    tried_any = False
    last_status = SignatureStatus.INVALID

    for jwk in _candidate_keys(jwks, kid):
        try:
            public_key = import_public_key_from_jwk(jwk)
        except Exception as e:
            logger.debug("Unusable JWK, trying next", kid=_short_kid(jwk.get("kid")), error=str(e))
            continue

        tried_any = True
        is_valid, payload, status = verify_signature_detailed(jws, public_key)
        if is_valid:
            logger.info(
                "Signature verified successfully", domain=domain, kid=_short_kid(jwk.get("kid"))
            )
            return True, payload, status
        # An expired signature is expired regardless of which key is tried;
        # keep that reason rather than reporting the last key's INVALID.
        if status is SignatureStatus.EXPIRED:
            return False, None, status
        last_status = status

    if not tried_any:
        return None
    return False, None, last_status


# ============================================================================
# Helper Functions
# ============================================================================


def _b64url_encode(s: str) -> str:
    """Base64url encode a string without padding."""
    return base64.urlsafe_b64encode(s.encode("utf-8")).rstrip(b"=").decode("ascii")


def _b64url_encode_bytes(b: bytes) -> str:
    """Base64url encode bytes without padding."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> str:
    """Base64url decode a string (add padding if needed)."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s).decode("utf-8")


def _b64url_decode_bytes(s: str) -> bytes:
    """Base64url decode to bytes (add padding if needed)."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _der_to_raw_signature(der_signature: bytes) -> bytes:
    """Convert DER-encoded ECDSA signature to raw r||s format."""
    # DER format: 0x30 [len] 0x02 [r_len] [r] 0x02 [s_len] [s]
    # We need to extract r and s and pad to 32 bytes each

    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    r, s = decode_dss_signature(der_signature)
    return r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")


def _raw_to_der_signature(raw_signature: bytes) -> bytes:
    """Convert raw r||s signature to DER format."""
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    r = int.from_bytes(raw_signature[:32], byteorder="big")
    s = int.from_bytes(raw_signature[32:], byteorder="big")
    return encode_dss_signature(r, s)


def load_private_key_from_pem(
    pem_path: str, password: bytes | None = None
) -> EllipticCurvePrivateKey:
    """
    Load a private key from a PEM file.

    Args:
        pem_path: Path to the PEM file
        password: Optional password for encrypted keys

    Returns:
        EC private key
    """
    with open(pem_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=password)  # type: ignore


def save_private_key_to_pem(
    private_key: EllipticCurvePrivateKey,
    pem_path: str,
    password: bytes | None = None,
) -> None:
    """
    Save a private key to a PEM file.

    Args:
        private_key: The key to save
        pem_path: Path to write to
        password: Optional password for encryption
    """
    encryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )

    pem_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )

    with open(pem_path, "wb") as f:
        f.write(pem_data)
