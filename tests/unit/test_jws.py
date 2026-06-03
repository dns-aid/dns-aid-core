# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for JWS signing and verification."""

import json
import time

import pytest

from dns_aid.core.jwks import (
    RecordPayload,
    export_jwks,
    generate_keypair,
    import_public_key_from_jwk,
    sign_record,
    verify_signature,
)


class TestKeyGeneration:
    """Tests for key generation."""

    def test_generate_keypair(self):
        """Test generating an EC P-256 keypair."""
        private_key, public_key = generate_keypair()

        assert private_key is not None
        assert public_key is not None

        # Verify it's EC P-256
        assert private_key.curve.name == "secp256r1"

    def test_generate_unique_keypairs(self):
        """Test that each generation produces unique keys."""
        key1, _ = generate_keypair()
        key2, _ = generate_keypair()

        # Private keys should be different
        assert key1.private_numbers().private_value != key2.private_numbers().private_value


class TestJWKSExport:
    """Tests for JWKS export."""

    def test_export_jwks_structure(self):
        """Test JWKS document has correct structure."""
        _, public_key = generate_keypair()
        jwks = export_jwks(public_key, kid="test-key")

        assert "keys" in jwks
        assert len(jwks["keys"]) == 1

        key = jwks["keys"][0]
        assert key["kty"] == "EC"
        assert key["crv"] == "P-256"
        assert key["kid"] == "test-key"
        assert key["use"] == "sig"
        assert key["alg"] == "ES256"
        assert "x" in key
        assert "y" in key

    def test_export_jwks_roundtrip(self):
        """Test exporting and importing a key preserves it."""
        _, original_public = generate_keypair()
        jwks = export_jwks(original_public)

        # Import back
        imported_public = import_public_key_from_jwk(jwks["keys"][0])

        # Compare public numbers
        orig_numbers = original_public.public_numbers()
        imported_numbers = imported_public.public_numbers()

        assert orig_numbers.x == imported_numbers.x
        assert orig_numbers.y == imported_numbers.y


class TestRecordPayload:
    """Tests for RecordPayload."""

    def test_payload_to_json(self):
        """Test payload serialization."""
        payload = RecordPayload(
            fqdn="_test._mcp._agents.example.com",
            target="mcp.example.com",
            port=443,
            alpn="mcp",
            iat=1704067200,
            exp=1704153600,
        )

        json_str = payload.to_json()
        parsed = json.loads(json_str)

        assert parsed["fqdn"] == "_test._mcp._agents.example.com"
        assert parsed["target"] == "mcp.example.com"
        assert parsed["port"] == 443
        assert parsed["alpn"] == "mcp"

    def test_payload_from_agent_record(self):
        """Test creating payload from agent record fields."""
        payload = RecordPayload.from_agent_record(
            fqdn="_payment._mcp._agents.example.com",
            target="payment.example.com",
            port=443,
            protocol="mcp",
            ttl_seconds=3600,
        )

        assert payload.fqdn == "_payment._mcp._agents.example.com"
        assert payload.target == "payment.example.com"
        assert payload.port == 443
        assert payload.alpn == "mcp"
        assert payload.exp > payload.iat
        assert payload.exp - payload.iat == 3600


class TestSigningAndVerification:
    """Tests for JWS signing and verification."""

    @pytest.fixture
    def keypair(self):
        """Generate a keypair for tests."""
        return generate_keypair()

    @pytest.fixture
    def sample_payload(self):
        """Create a sample payload."""
        now = int(time.time())
        return RecordPayload(
            fqdn="_test._mcp._agents.example.com",
            target="mcp.example.com",
            port=443,
            alpn="mcp",
            iat=now,
            exp=now + 86400,  # 24 hours
        )

    def test_sign_record(self, keypair, sample_payload):
        """Test signing a record."""
        private_key, _ = keypair
        jws = sign_record(sample_payload, private_key)

        # JWS should have 3 parts: header.payload.signature
        parts = jws.split(".")
        assert len(parts) == 3

        # All parts should be non-empty base64url strings
        for part in parts:
            assert len(part) > 0
            assert all(
                c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                for c in part
            )

    def test_verify_valid_signature(self, keypair, sample_payload):
        """Test verifying a valid signature."""
        private_key, public_key = keypair

        jws = sign_record(sample_payload, private_key)
        is_valid, payload = verify_signature(jws, public_key)

        assert is_valid is True
        assert payload is not None
        assert payload.fqdn == sample_payload.fqdn
        assert payload.target == sample_payload.target
        assert payload.port == sample_payload.port

    def test_verify_invalid_signature(self, keypair, sample_payload):
        """Test that tampered signatures fail verification."""
        private_key, public_key = keypair

        jws = sign_record(sample_payload, private_key)

        # Tamper with the signature
        parts = jws.split(".")
        tampered = parts[0] + "." + parts[1] + "." + parts[2][:-4] + "XXXX"

        is_valid, payload = verify_signature(tampered, public_key)

        assert is_valid is False
        assert payload is None

    def test_verify_wrong_key(self, sample_payload):
        """Test that verification fails with wrong key."""
        private_key1, _ = generate_keypair()
        _, public_key2 = generate_keypair()

        jws = sign_record(sample_payload, private_key1)
        is_valid, payload = verify_signature(jws, public_key2)

        assert is_valid is False
        assert payload is None

    def test_verify_expired_signature(self, keypair):
        """Test that expired signatures fail verification."""
        private_key, public_key = keypair

        # Create an already-expired payload
        now = int(time.time())
        expired_payload = RecordPayload(
            fqdn="_test._mcp._agents.example.com",
            target="mcp.example.com",
            port=443,
            alpn="mcp",
            iat=now - 7200,  # 2 hours ago
            exp=now - 3600,  # 1 hour ago (expired)
        )

        jws = sign_record(expired_payload, private_key)
        is_valid, payload = verify_signature(jws, public_key)

        assert is_valid is False
        assert payload is None

    def test_verify_malformed_jws(self, keypair):
        """Test that malformed JWS fails gracefully."""
        _, public_key = keypair

        # Test various malformed inputs
        malformed_cases = [
            "",
            "not-a-jws",
            "only.two",
            "too.many.parts.here",
            "....",
        ]

        for jws in malformed_cases:
            is_valid, payload = verify_signature(jws, public_key)
            assert is_valid is False
            assert payload is None


class TestPublisherIntegration:
    """Test JWS integration with publisher."""

    @pytest.mark.asyncio
    async def test_publish_with_signature(self, mock_backend, tmp_path):
        """Test publishing an agent with JWS signature."""
        from cryptography.hazmat.primitives import serialization

        from dns_aid.core.publisher import publish

        # Generate and save keypair
        private_key, _ = generate_keypair()
        key_path = tmp_path / "private.pem"
        key_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

        # Publish with signing
        result = await publish(
            name="payment",
            domain="example.com",
            protocol="mcp",
            endpoint="payment.example.com",
            backend=mock_backend,
            sign=True,
            private_key_path=str(key_path),
        )

        assert result.success is True
        assert result.agent.sig is not None

        # Verify the signature format
        parts = result.agent.sig.split(".")
        assert len(parts) == 3

    @pytest.mark.asyncio
    async def test_publish_without_signature(self, mock_backend):
        """Test that publishing without sign=True has no signature."""
        from dns_aid.core.publisher import publish

        result = await publish(
            name="chat",
            domain="example.com",
            protocol="mcp",
            endpoint="chat.example.com",
            backend=mock_backend,
            sign=False,
        )

        assert result.success is True
        assert result.agent.sig is None


class TestFetchJWKS:
    """Tests for JWKS fetching."""

    @pytest.mark.asyncio
    async def test_fetch_jwks_success(self):
        """Test successful JWKS fetch."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from dns_aid.core.jwks import _jwks_cache, fetch_jwks

        # Clear cache
        _jwks_cache.clear()

        mock_jwks = {
            "keys": [
                {
                    "kty": "EC",
                    "crv": "P-256",
                    "kid": "test-key",
                    "x": "test-x",
                    "y": "test-y",
                }
            ]
        }

        with patch("dns_aid.core.jwks.httpx.AsyncClient") as mock_client:
            mock_response = MagicMock()
            mock_response.json.return_value = mock_jwks
            mock_response.raise_for_status.return_value = None

            mock_instance = AsyncMock()
            mock_instance.get.return_value = mock_response
            mock_instance.__aenter__.return_value = mock_instance
            mock_instance.__aexit__.return_value = None

            mock_client.return_value = mock_instance

            result = await fetch_jwks("example.com")

        assert result is not None
        assert "keys" in result
        assert len(result["keys"]) == 1

    @pytest.mark.asyncio
    async def test_fetch_jwks_failure(self):
        """Test JWKS fetch failure returns None."""
        from unittest.mock import AsyncMock, patch

        from dns_aid.core.jwks import _jwks_cache, fetch_jwks

        # Clear cache
        _jwks_cache.clear()

        with patch("dns_aid.core.jwks.httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get.side_effect = Exception("Network error")
            mock_instance.__aenter__.return_value = mock_instance
            mock_instance.__aexit__.return_value = None

            mock_client.return_value = mock_instance

            result = await fetch_jwks("example.com")

        assert result is None

    @pytest.mark.asyncio
    async def test_fetch_jwks_uses_cache(self):
        """Test that JWKS fetch uses cache."""
        import time
        from unittest.mock import patch

        from dns_aid.core.jwks import JWKS_CACHE_TTL, _jwks_cache, fetch_jwks

        # Pre-populate cache
        cached_jwks = {"keys": [{"cached": True}]}
        _jwks_cache["cached-domain.com"] = (cached_jwks, time.time() + JWKS_CACHE_TTL)

        with patch("dns_aid.core.jwks.httpx.AsyncClient") as mock_client:
            result = await fetch_jwks("cached-domain.com")

            # Should not have made any HTTP calls
            mock_client.assert_not_called()

        assert result == cached_jwks


class TestVerifyRecordSignature:
    """Tests for verify_record_signature."""

    @pytest.mark.asyncio
    async def test_verify_record_signature_success(self):
        """Test successful signature verification."""
        from unittest.mock import AsyncMock, patch

        from dns_aid.core.jwks import (
            RecordPayload,
            export_jwks,
            generate_keypair,
            sign_record,
            verify_record_signature,
        )

        # Generate keypair and sign a payload
        private_key, public_key = generate_keypair()
        jwks = export_jwks(public_key, kid="test-key")

        payload = RecordPayload.from_agent_record(
            fqdn="_test._mcp._agents.example.com",
            target="mcp.example.com",
            port=443,
            protocol="mcp",
        )
        jws = sign_record(payload, private_key)

        # Mock fetch_jwks to return our JWKS
        with patch("dns_aid.core.jwks.fetch_jwks", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = jwks

            is_valid, result_payload = await verify_record_signature("example.com", jws)

        assert is_valid is True
        assert result_payload is not None
        assert result_payload.fqdn == payload.fqdn

    @pytest.mark.asyncio
    async def test_verify_record_signature_no_jwks(self):
        """Test verification fails when JWKS not available."""
        from unittest.mock import AsyncMock, patch

        from dns_aid.core.jwks import verify_record_signature

        with patch("dns_aid.core.jwks.fetch_jwks", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = None

            is_valid, payload = await verify_record_signature("example.com", "some.jws.token")

        assert is_valid is False
        assert payload is None

    @pytest.mark.asyncio
    async def test_verify_record_signature_wrong_key(self):
        """Test verification fails with wrong key."""
        from unittest.mock import AsyncMock, patch

        from dns_aid.core.jwks import (
            RecordPayload,
            export_jwks,
            generate_keypair,
            sign_record,
            verify_record_signature,
        )

        # Generate two different keypairs
        private_key1, _ = generate_keypair()
        _, public_key2 = generate_keypair()

        # Sign with key1, but JWKS contains key2
        jwks = export_jwks(public_key2, kid="wrong-key")

        payload = RecordPayload.from_agent_record(
            fqdn="_test._mcp._agents.example.com",
            target="mcp.example.com",
            port=443,
            protocol="mcp",
        )
        jws = sign_record(payload, private_key1)

        with patch("dns_aid.core.jwks.fetch_jwks", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = jwks

            is_valid, result_payload = await verify_record_signature("example.com", jws)

        assert is_valid is False
        assert result_payload is None


class TestModelIntegration:
    """Test JWS integration with models."""

    def test_agent_record_sig_in_svcb_params(self):
        """Test that sig is included in SVCB params when present."""
        from dns_aid.core.models import AgentRecord, Protocol

        agent = AgentRecord(
            name="test",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="mcp.example.com",
            sig="eyJhbGciOiJFUzI1NiJ9.eyJmcWRuIjoiX3Rlc3QuX21jcC5fYWdlbnRzLmV4YW1wbGUuY29tIn0.signature",
        )

        params = agent.to_svcb_params()
        # Default: keyNNNNN format (key65405 = sig)
        assert "key65405" in params
        assert params["key65405"].startswith("eyJ")

    def test_agent_record_no_sig_when_none(self):
        """Test that sig is not in SVCB params when None."""
        from dns_aid.core.models import AgentRecord, Protocol

        agent = AgentRecord(
            name="test",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="mcp.example.com",
        )

        params = agent.to_svcb_params()
        assert "sig" not in params


class TestSignatureBindsToRecord:
    """Regression tests: a valid signature MUST bind to the record it travels with.

    Before this binding was enforced, an attacker could lift a legitimately
    signed `sig` value from one agent's SVCB record and paste it onto a
    spoofed SVCB pointing at their own host. The signature would still
    verify (it's cryptographically valid) and the discoverer would stamp
    ``signature_verified=True`` — turning the JWS into a forgeable
    rubber-stamp instead of a record-binding proof.

    Publisher-side: ``core/publisher.py`` signs a ``RecordPayload`` whose
    fields are ``(fqdn, target, port, alpn)``. Verifier-side: the
    discoverer must re-derive the same tuple from the AgentRecord it's
    about to trust and refuse if any field disagrees.
    """

    @pytest.mark.asyncio
    async def test_valid_sig_with_mismatched_target_is_rejected(self):
        """Sig is cryptographically valid but signed payload.target != agent.target_host."""
        from unittest.mock import AsyncMock, patch

        from dns_aid.core.discoverer import _verify_agent_signatures
        from dns_aid.core.jwks import (
            RecordPayload,
            export_jwks,
            generate_keypair,
            sign_record,
        )
        from dns_aid.core.models import AgentRecord, Protocol

        private_key, public_key = generate_keypair()
        jwks = export_jwks(public_key, kid="binding-test")

        # Sign a payload that says target=legit.example.com.
        payload = RecordPayload.from_agent_record(
            fqdn="chat.example.com",
            target="legit.example.com",
            port=443,
            protocol="mcp",
        )
        legit_sig = sign_record(payload, private_key)

        # Attacker pastes the legit sig onto a spoofed record pointing
        # at attacker.example.com.
        spoofed = AgentRecord(
            name="chat",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="attacker.example.com",
            port=443,
            sig=legit_sig,
        )

        with patch("dns_aid.core.jwks.fetch_jwks", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = jwks
            await _verify_agent_signatures([spoofed], "example.com", dnssec_validated=False)

        assert spoofed.signature_verified is False
        assert spoofed.signature_algorithm is None

    @pytest.mark.asyncio
    async def test_valid_sig_with_mismatched_port_is_rejected(self):
        """Sig is valid; port disagrees; binding must reject."""
        from unittest.mock import AsyncMock, patch

        from dns_aid.core.discoverer import _verify_agent_signatures
        from dns_aid.core.jwks import (
            RecordPayload,
            export_jwks,
            generate_keypair,
            sign_record,
        )
        from dns_aid.core.models import AgentRecord, Protocol

        private_key, public_key = generate_keypair()
        jwks = export_jwks(public_key, kid="binding-test")

        payload = RecordPayload.from_agent_record(
            fqdn="chat.example.com",
            target="chat.example.com",
            port=443,
            protocol="mcp",
        )
        sig = sign_record(payload, private_key)

        agent = AgentRecord(
            name="chat",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="chat.example.com",
            port=8443,  # disagrees with signed payload.port
            sig=sig,
        )

        with patch("dns_aid.core.jwks.fetch_jwks", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = jwks
            await _verify_agent_signatures([agent], "example.com", dnssec_validated=False)

        assert agent.signature_verified is False

    @pytest.mark.asyncio
    async def test_valid_sig_with_mismatched_alpn_is_rejected(self):
        """Sig is valid for protocol=mcp; record claims a2a; binding must reject."""
        from unittest.mock import AsyncMock, patch

        from dns_aid.core.discoverer import _verify_agent_signatures
        from dns_aid.core.jwks import (
            RecordPayload,
            export_jwks,
            generate_keypair,
            sign_record,
        )
        from dns_aid.core.models import AgentRecord, Protocol

        private_key, public_key = generate_keypair()
        jwks = export_jwks(public_key, kid="binding-test")

        payload = RecordPayload.from_agent_record(
            fqdn="chat.example.com",
            target="chat.example.com",
            port=443,
            protocol="mcp",
        )
        sig = sign_record(payload, private_key)

        agent = AgentRecord(
            name="chat",
            domain="example.com",
            protocol=Protocol.A2A,  # disagrees with signed payload.alpn
            target_host="chat.example.com",
            port=443,
            sig=sig,
        )

        with patch("dns_aid.core.jwks.fetch_jwks", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = jwks
            await _verify_agent_signatures([agent], "example.com", dnssec_validated=False)

        assert agent.signature_verified is False

    @pytest.mark.asyncio
    async def test_valid_sig_matching_record_is_accepted(self):
        """Happy path: every field of the signed payload binds to the record."""
        from unittest.mock import AsyncMock, patch

        from dns_aid.core.discoverer import _verify_agent_signatures
        from dns_aid.core.jwks import (
            RecordPayload,
            export_jwks,
            generate_keypair,
            sign_record,
        )
        from dns_aid.core.models import AgentRecord, Protocol

        private_key, public_key = generate_keypair()
        jwks = export_jwks(public_key, kid="binding-test")

        payload = RecordPayload.from_agent_record(
            fqdn="chat.example.com",
            target="chat.example.com",
            port=443,
            protocol="mcp",
        )
        sig = sign_record(payload, private_key)

        agent = AgentRecord(
            name="chat",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="chat.example.com",
            port=443,
            sig=sig,
        )

        with patch("dns_aid.core.jwks.fetch_jwks", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = jwks
            await _verify_agent_signatures([agent], "example.com", dnssec_validated=False)

        assert agent.signature_verified is True
        assert agent.signature_algorithm is not None
