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

import base64
import json
import time
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

    VERIFIED = "verified"  # signature valid AND bound to this record
    INVALID = "invalid"  # a key was retrieved; the signature did not verify
    UNBOUND = "unbound"  # signature valid but describes a different record
    EXPIRED = "expired"  # signature lapsed; re-publish
    NO_KEY = "no_key"  # no JWKS reachable / no key matched -- unknown
    NOT_SIGNED = "not_signed"  # record carries no sig parameter
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

    def to_json(self) -> str:
        """Serialize to canonical JSON (sorted keys, no whitespace)."""
        return json.dumps(
            {
                "fqdn": self.fqdn,
                "target": self.target,
                "port": self.port,
                "alpn": self.alpn,
                "iat": self.iat,
                "exp": self.exp,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    @classmethod
    def from_agent_record(
        cls,
        fqdn: str,
        target: str,
        port: int,
        protocol: str,
        ttl_seconds: int = 86400,
    ) -> RecordPayload:
        """Create payload from agent record fields."""
        now = int(time.time())
        return cls(
            fqdn=fqdn,
            target=target,
            port=port,
            alpn=protocol,
            iat=now,
            exp=now + ttl_seconds,
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
    cached = _jwks_cache.get(domain)
    if cached is not None:
        jwks, expiry = cached
        if now < expiry:
            return jwks
        _jwks_cache.pop(domain, None)  # expired — drop it

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

        # Bound cache growth: evict oldest entries (FIFO) before insert.
        while len(_jwks_cache) >= _JWKS_CACHE_MAX:
            _jwks_cache.pop(next(iter(_jwks_cache)), None)
        _jwks_cache[domain] = (jwks, now + JWKS_CACHE_TTL)

        logger.info("JWKS fetched successfully", domain=domain, url=url)
        return jwks

    logger.warning("No JWKS available at any known location", domain=domain, tried=candidates)
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
    # Strict when a kid is named: an empty result is the signal that this key
    # is absent from the document we hold, which is what distinguishes "rolled
    # in since we cached" from "this signature is bad". Falling back to the
    # whole set here would hide that difference and defeat the refresh.
    return [k for k in keys if k.get("kid") == kid]


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
        logger.warning("No JWKS available", domain=domain, kid=kid)
        return False, None, SignatureStatus.NO_KEY

    result = _verify_against(jwks, jws, kid, domain)

    # A signature naming a key absent from the cached document is the
    # signature of a rollover that happened inside the cache window. Refetch
    # once rather than making the publisher wait out JWKS_CACHE_TTL.
    if result is None and kid is not None:
        logger.debug("kid not present in cached JWKS; refreshing once", domain=domain, kid=kid)
        _jwks_cache.pop(domain, None)
        refreshed = await fetch_jwks(domain)
        if refreshed and "keys" in refreshed:
            jwks = refreshed
            result = _verify_against(jwks, jws, kid, domain)

    if result is None:
        # Either the signature named no key, or it named one this publisher
        # does not list. Try the whole set: signatures published before kid was
        # emitted carry no identifier, and a publisher may serve a JWKS whose
        # entries omit kid entirely. Both must keep verifying.
        result = _verify_against(jwks, jws, None, domain)

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
            logger.debug("Unusable JWK, trying next", kid=jwk.get("kid"), error=str(e))
            continue

        tried_any = True
        is_valid, payload, status = verify_signature_detailed(jws, public_key)
        if is_valid:
            logger.info("Signature verified successfully", domain=domain, kid=jwk.get("kid"))
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
