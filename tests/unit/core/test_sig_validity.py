# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""JWS signature validity is independent of the DNS record TTL.

The publisher previously passed the DNS TTL straight into the JWS ``exp``, so a
signature expired at the resolver cache-refresh interval: with the default TTL a
signed record verified for one hour and failed for the rest of its life in DNS,
and at the 30s TTL floor it was dead almost immediately. The relationship was
also inverted from intent -- the shorter the TTL an operator chose for fast
propagation, the faster their signatures broke.

TTL governs caching. ``exp`` governs how long the assertion holds. They are
unrelated and are now configured separately.
"""

import json
import time
from unittest.mock import patch

import pytest

from dns_aid.core.jwks import (
    RecordPayload,
    generate_keypair,
    save_private_key_to_pem,
    verify_signature,
)
from dns_aid.core.publisher import (
    DEFAULT_SIG_VALIDITY_SECONDS,
    MAX_SIG_VALIDITY_SECONDS,
    MIN_SIG_VALIDITY_SECONDS,
    publish,
)


def _decode_exp(jws: str) -> int:
    """Pull the exp claim straight out of the signed payload."""
    import base64

    payload_b64 = jws.split(".")[1]
    payload_b64 += "=" * (-len(payload_b64) % 4)
    return json.loads(base64.urlsafe_b64decode(payload_b64))["exp"]


@pytest.fixture
def key_pem(tmp_path):
    private_key, _ = generate_keypair()
    path = tmp_path / "signing.pem"
    save_private_key_to_pem(private_key, str(path))
    return str(path), private_key


async def _publish_signed(backend, key_path: str, **kwargs) -> str:
    """Publish with signing; return the JWS written onto the record."""
    result = await publish(
        name="booking",
        domain="example.com",
        protocol="mcp",
        endpoint="mcp.example.com",
        backend=backend,
        sign=True,
        private_key_path=key_path,
        **kwargs,
    )
    assert result.success is True
    assert result.agent.sig is not None
    return result.agent.sig


class TestSignatureValidityIsIndependentOfTTL:
    @pytest.mark.asyncio
    async def test_short_ttl_does_not_shorten_the_signature(self, mock_backend, key_pem):
        """A 30s TTL must not produce a 30s signature.

        This is the defect: at the TTL floor the signature expired almost
        immediately while the DNS record lived on indefinitely.
        """
        key_path, _ = key_pem
        before = int(time.time())
        sig = await _publish_signed(mock_backend, key_path, ttl=30)
        exp = _decode_exp(sig)

        assert exp - before >= MIN_SIG_VALIDITY_SECONDS
        assert exp - before > 30 * 100, "signature validity is still tracking the DNS TTL"

    @pytest.mark.asyncio
    async def test_default_validity_is_ninety_days(self, mock_backend, key_pem):
        key_path, _ = key_pem
        before = int(time.time())
        sig = await _publish_signed(mock_backend, key_path, ttl=3600)
        exp = _decode_exp(sig)

        assert abs((exp - before) - DEFAULT_SIG_VALIDITY_SECONDS) <= 5

    @pytest.mark.asyncio
    async def test_validity_is_explicitly_configurable(self, mock_backend, key_pem):
        key_path, _ = key_pem
        before = int(time.time())
        sig = await _publish_signed(
            mock_backend, key_path, ttl=3600, sig_validity_seconds=7 * 86400
        )
        exp = _decode_exp(sig)

        assert abs((exp - before) - 7 * 86400) <= 5

    @pytest.mark.asyncio
    async def test_signature_still_verifies_after_the_ttl_elapses(self, mock_backend, key_pem):
        """The end-to-end symptom: publish with a short TTL, verify later.

        Simulated by checking the signature against a clock advanced well past
        the TTL but inside the validity window.
        """
        key_path, private_key = key_pem
        sig = await _publish_signed(mock_backend, key_path, ttl=30)

        public_key = private_key.public_key()
        later = time.time() + 3600  # an hour on: far past the TTL
        with patch("dns_aid.core.jwks.time.time", return_value=later):
            is_valid, payload = verify_signature(sig, public_key)

        assert is_valid is True
        assert payload is not None

    @pytest.mark.asyncio
    async def test_rejects_out_of_range_validity(self, mock_backend, key_pem):
        key_path, _ = key_pem
        with pytest.raises(ValueError, match="sig_validity_seconds"):
            await _publish_signed(mock_backend, key_path, sig_validity_seconds=60)
        with pytest.raises(ValueError, match="sig_validity_seconds"):
            await _publish_signed(
                mock_backend, key_path, sig_validity_seconds=MAX_SIG_VALIDITY_SECONDS + 1
            )

    def test_an_expired_signature_is_still_rejected(self):
        """Guard against over-correcting: expiry must still be enforced."""
        private_key, public_key = generate_keypair()
        from dns_aid.core.jwks import sign_record

        payload = RecordPayload.from_agent_record(
            fqdn="booking.example.com",
            target="mcp.example.com",
            port=443,
            protocol="mcp",
            validity_seconds=MIN_SIG_VALIDITY_SECONDS,
        )
        sig = sign_record(payload, private_key)

        way_later = time.time() + MIN_SIG_VALIDITY_SECONDS + 60
        with patch("dns_aid.core.jwks.time.time", return_value=way_later):
            is_valid, _ = verify_signature(sig, public_key)

        assert is_valid is False
