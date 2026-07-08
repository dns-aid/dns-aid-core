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
) -> str:
    """
    Sign a record payload with the private key.

    Creates a compact JWS (header.payload.signature) suitable for
    inclusion in DNS SVCB `sig` parameter.

    Args:
        payload: The record payload to sign
        private_key: EC private key for signing

    Returns:
        Compact JWS string (base64url encoded)
    """
    # JWS Header
    header = {"alg": "ES256", "typ": "JWT"}
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
    try:
        parts = jws.split(".")
        if len(parts) != 3:
            return False, None

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
            return False, None

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
            logger.warning("Signature expired", exp=payload_dict.get("exp"))
            return False, None

        payload = RecordPayload(
            fqdn=payload_dict["fqdn"],
            target=payload_dict["target"],
            port=payload_dict["port"],
            alpn=payload_dict["alpn"],
            iat=payload_dict["iat"],
            exp=payload_dict["exp"],
        )

        return True, payload

    except Exception as e:
        logger.debug("Signature verification failed", error=str(e))
        return False, None


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

    # Fetch from well-known endpoint. This input stamps trust
    # (signature_verified), so it goes through the same SSRF guard and
    # streaming size cap as every other untrusted fetch — no raw httpx.get,
    # no unbounded .json(), and no cross-host redirects.
    url = f"https://{domain}{JWKS_WELL_KNOWN_PATH}"

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
        logger.warning("JWKS URL blocked by SSRF protection", domain=domain, error=str(e))
        return None

    try:
        body = await safe_fetch_bytes(
            url,
            max_bytes=_MAX_JWKS_RESPONSE_BYTES,
            timeout=10.0,
            follow_redirects=False,
        )
        if body is None:
            logger.warning("JWKS fetch failed (non-200)", domain=domain)
            return None

        jwks = json.loads(body)
        if not isinstance(jwks, dict):
            logger.warning("JWKS document is not a JSON object", domain=domain)
            return None

        # Bound cache growth: evict oldest entries (FIFO) before insert.
        while len(_jwks_cache) >= _JWKS_CACHE_MAX:
            _jwks_cache.pop(next(iter(_jwks_cache)), None)
        _jwks_cache[domain] = (jwks, now + JWKS_CACHE_TTL)

        logger.info("JWKS fetched successfully", domain=domain)
        return jwks

    except ResponseTooLargeError as e:
        logger.warning("JWKS document too large", domain=domain, error=str(e))
        return None
    except Exception as e:
        logger.warning("Failed to fetch JWKS", domain=domain, error=str(e))
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
    # Fetch JWKS
    jwks = await fetch_jwks(domain)
    if not jwks or "keys" not in jwks:
        logger.warning("No JWKS available", domain=domain)
        return False, None

    # Try each key in the JWKS
    for jwk in jwks["keys"]:
        try:
            public_key = import_public_key_from_jwk(jwk)
            is_valid, payload = verify_signature(jws, public_key)
            if is_valid:
                logger.info(
                    "Signature verified successfully",
                    domain=domain,
                    kid=jwk.get("kid"),
                )
                return True, payload
        except Exception as e:
            logger.debug(
                "Key verification failed, trying next",
                kid=jwk.get("kid"),
                error=str(e),
            )
            continue

    return False, None


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
