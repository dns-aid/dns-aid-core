# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for HTTP Message Signatures auth handler (Ed25519 + ML-DSA-65)."""

from __future__ import annotations

import base64

import httpx
import pytest

from dns_aid.sdk.auth.http_msg_sig import HttpMsgSigAuthHandler


def _generate_ed25519_keypair() -> tuple[str, bytes]:
    """Generate an Ed25519 keypair, return (PEM private key, public key bytes)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    private_key = Ed25519PrivateKey.generate()
    pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    public_bytes = private_key.public_key().public_bytes_raw()
    return pem.decode(), public_bytes


def _ml_dsa_keypair() -> tuple[bytes, bytes]:
    """(public key, secret key) for ML-DSA-65 on either pqcrypto API.

    pqcrypto 1.0 renamed generate_keypair() to keygen(); 1.0 is the first
    release with Python 3.15 wheels.
    """
    from pqcrypto.sign import ml_dsa_65  # guarded by requires_pqcrypto

    keygen = getattr(ml_dsa_65, "keygen", None) or ml_dsa_65.generate_keypair
    pk, sk = keygen()
    return bytes(pk), bytes(sk)


def _ml_dsa_verifies(pk: bytes, message: bytes, signature: bytes) -> bool:
    """pqcrypto < 1.0 returns a bool; 1.0 returns None and raises on a bad signature."""
    from pqcrypto.sign import ml_dsa_65

    try:
        result = ml_dsa_65.verify(pk, message, signature)
    except Exception:  # noqa: BLE001 — InvalidSignatureError on 1.0
        return False
    return result is None or bool(result)


def _generate_ml_dsa_keypair() -> tuple[str, bytes]:
    """Generate an ML-DSA-65 keypair, return (base64 secret key, public key bytes)."""
    pk, sk = _ml_dsa_keypair()
    return base64.b64encode(sk).decode(), pk


@pytest.fixture
def ed25519_handler() -> HttpMsgSigAuthHandler:
    pem, _ = _generate_ed25519_keypair()
    return HttpMsgSigAuthHandler(
        private_key_pem=pem,
        key_id="test-key-ed25519",
        algorithm="ed25519",
    )


@pytest.fixture
def ml_dsa_handler() -> HttpMsgSigAuthHandler:
    sk_b64, _ = _generate_ml_dsa_keypair()
    return HttpMsgSigAuthHandler(
        private_key_pem=sk_b64,
        key_id="test-key-ml-dsa",
        algorithm="ml-dsa-65",
    )


@pytest.fixture
def sample_request() -> httpx.Request:
    return httpx.Request(
        "POST",
        "https://agent.example.com/mcp",
        json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
        headers={"Content-Type": "application/json"},
    )


class TestEd25519Signing:
    @pytest.mark.asyncio
    async def test_produces_signature_headers(
        self, ed25519_handler: HttpMsgSigAuthHandler, sample_request: httpx.Request
    ) -> None:
        result = await ed25519_handler.apply(sample_request)

        assert "signature" in result.headers
        assert "signature-input" in result.headers
        assert "date" in result.headers
        assert "content-digest" in result.headers

    @pytest.mark.asyncio
    async def test_signature_input_contains_algorithm(
        self, ed25519_handler: HttpMsgSigAuthHandler, sample_request: httpx.Request
    ) -> None:
        result = await ed25519_handler.apply(sample_request)

        sig_input = result.headers["signature-input"]
        assert 'alg="ed25519"' in sig_input
        assert 'keyid="test-key-ed25519"' in sig_input

    @pytest.mark.asyncio
    async def test_signature_is_valid_base64(
        self, ed25519_handler: HttpMsgSigAuthHandler, sample_request: httpx.Request
    ) -> None:
        result = await ed25519_handler.apply(sample_request)

        sig_header = result.headers["signature"]
        # Format: sig1=:<base64>:
        assert sig_header.startswith("sig1=:")
        assert sig_header.endswith(":")
        b64_part = sig_header[6:-1]
        sig_bytes = base64.b64decode(b64_part)
        assert len(sig_bytes) == 64  # Ed25519 signature is always 64 bytes

    @pytest.mark.asyncio
    async def test_content_digest_sha256(
        self, ed25519_handler: HttpMsgSigAuthHandler, sample_request: httpx.Request
    ) -> None:
        result = await ed25519_handler.apply(sample_request)

        digest = result.headers["content-digest"]
        assert digest.startswith("sha-256=:")

    @pytest.mark.asyncio
    async def test_verify_ed25519_signature(self, sample_request: httpx.Request) -> None:
        """Round-trip: sign with Ed25519, then verify with public key."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
        )

        private_key = Ed25519PrivateKey.generate()
        pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
        public_key = private_key.public_key()

        handler = HttpMsgSigAuthHandler(private_key_pem=pem, key_id="verify-test")
        result = await handler.apply(sample_request)

        # Extract signature bytes
        sig_header = result.headers["signature"]
        sig_bytes = base64.b64decode(sig_header[6:-1])

        # Rebuild signature base (same as handler does internally)
        from dns_aid.sdk.auth.http_msg_sig import _build_signature_base

        sig_base = _build_signature_base(result, ("@method", "@target-uri", "content-digest"))

        # Verify — raises InvalidSignature if bad
        public_key.verify(sig_bytes, sig_base.encode())


class TestMlDsa65Signing:
    @pytest.mark.asyncio
    async def test_produces_signature_headers(
        self, ml_dsa_handler: HttpMsgSigAuthHandler, sample_request: httpx.Request
    ) -> None:
        result = await ml_dsa_handler.apply(sample_request)

        assert "signature" in result.headers
        assert "signature-input" in result.headers

    @pytest.mark.asyncio
    async def test_signature_input_contains_ml_dsa_algorithm(
        self, ml_dsa_handler: HttpMsgSigAuthHandler, sample_request: httpx.Request
    ) -> None:
        result = await ml_dsa_handler.apply(sample_request)

        sig_input = result.headers["signature-input"]
        assert 'alg="ml-dsa-65"' in sig_input
        assert 'keyid="test-key-ml-dsa"' in sig_input

    @pytest.mark.asyncio
    async def test_ml_dsa_signature_size(
        self, ml_dsa_handler: HttpMsgSigAuthHandler, sample_request: httpx.Request
    ) -> None:
        result = await ml_dsa_handler.apply(sample_request)

        sig_header = result.headers["signature"]
        b64_part = sig_header[6:-1]
        sig_bytes = base64.b64decode(b64_part)
        assert len(sig_bytes) == 3309  # ML-DSA-65 signature is 3309 bytes

    @pytest.mark.asyncio
    async def test_verify_ml_dsa_signature(self, sample_request: httpx.Request) -> None:
        """Round-trip: sign with ML-DSA-65, then verify with public key."""
        pk, sk = _ml_dsa_keypair()
        sk_b64 = base64.b64encode(sk).decode()

        handler = HttpMsgSigAuthHandler(
            private_key_pem=sk_b64,
            key_id="pqc-verify-test",
            algorithm="ml-dsa-65",
        )
        result = await handler.apply(sample_request)

        # Extract signature bytes
        sig_header = result.headers["signature"]
        sig_bytes = base64.b64decode(sig_header[6:-1])

        # Rebuild signature base
        from dns_aid.sdk.auth.http_msg_sig import _build_signature_base

        sig_base = _build_signature_base(result, ("@method", "@target-uri", "content-digest"))

        # Verify with pqcrypto, and check a tampered base does not verify
        assert _ml_dsa_verifies(pk, sig_base.encode(), sig_bytes)
        assert not _ml_dsa_verifies(pk, sig_base.encode() + b"x", sig_bytes)


class TestMissingCoveredComponent:
    @pytest.mark.asyncio
    async def test_raises_on_missing_header(self) -> None:
        """Signing a missing header must raise, not silently sign empty string."""
        pem, _ = _generate_ed25519_keypair()
        handler = HttpMsgSigAuthHandler(
            private_key_pem=pem,
            key_id="test",
            covered_components=("@method", "@target-uri", "authorization"),
        )
        request = httpx.Request("GET", "https://example.com/api")
        # "authorization" header is NOT on the request
        with pytest.raises(ValueError, match="Covered component 'authorization' is not present"):
            await handler.apply(request)

    @pytest.mark.asyncio
    async def test_derived_components_always_available(self) -> None:
        """@method, @target-uri, @authority, @path are always available."""
        pem, _ = _generate_ed25519_keypair()
        handler = HttpMsgSigAuthHandler(
            private_key_pem=pem,
            key_id="test",
            covered_components=("@method", "@target-uri", "@authority", "@path"),
        )
        request = httpx.Request("GET", "https://example.com/api")
        result = await handler.apply(request)
        assert "signature" in result.headers

    @pytest.mark.asyncio
    async def test_present_header_succeeds(self) -> None:
        """A header that IS present on the request should sign fine."""
        pem, _ = _generate_ed25519_keypair()
        handler = HttpMsgSigAuthHandler(
            private_key_pem=pem,
            key_id="test",
            covered_components=("@method", "x-custom-header"),
        )
        request = httpx.Request(
            "GET",
            "https://example.com/api",
            headers={"X-Custom-Header": "value"},
        )
        result = await handler.apply(request)
        assert "signature" in result.headers


class TestAlgorithmValidation:
    def test_rejects_unsupported_algorithm(self) -> None:
        with pytest.raises(ValueError, match="Unsupported algorithm"):
            HttpMsgSigAuthHandler(
                private_key_pem="fake",
                key_id="test",
                algorithm="rsa-sha256",
            )

    def test_rejects_invalid_ml_dsa_key_size(self) -> None:
        with pytest.raises(ValueError, match="ML-DSA-65 secret key must be"):
            HttpMsgSigAuthHandler(
                private_key_pem=base64.b64encode(b"too-short").decode(),
                key_id="test",
                algorithm="ml-dsa-65",
            )
