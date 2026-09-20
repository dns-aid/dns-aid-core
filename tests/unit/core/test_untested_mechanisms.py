# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for three mechanisms that mutation testing proved were uncovered.

Each of these could be deleted outright and the whole suite stayed green:

1. The unmatched-kid forced refetch, which is what lets a key rolled in
   mid-cache-window be picked up. The existing tests clear the JWKS cache in an
   autouse fixture, so the stale-document precondition never held and the first
   ordinary fetch already returned the new key.
2. The teardown in _fetch_peer_cert, where a peer sending RST could otherwise
   discard a certificate already in hand and suppress its own DANE verdict.
3. The CLI private-key existence and readability check.

A test that passes whether or not the code exists is not a test. Each case here
was confirmed to fail with its mechanism disabled.
"""

import asyncio
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dns_aid.core.jwks import (
    RecordPayload,
    SignatureStatus,
    _cache_jwks,
    _jwks_cache,
    _jwks_forced_refresh,
    _jwks_negative,
    export_jwks,
    generate_keypair,
    sign_record,
    verify_record_signature_detailed,
)


@pytest.fixture(autouse=True)
def _allow_test_hosts():
    """_fetch_peer_cert SSRF-guards the dial, which resolves the host for real.

    These tests use reserved example.com names and mock the socket, so the guard
    would reject before any mocked behaviour is reached. Neutralised here rather
    than per test: the guard has its own coverage, and what is under test is what
    happens after the dial is permitted.
    """
    with patch("dns_aid.utils.url_safety.validate_fetch_url_async", new=AsyncMock(return_value="")):
        yield


ZONE = "agents.example.com"


@pytest.fixture(autouse=True)
def _clean():
    _jwks_cache.clear()
    _jwks_forced_refresh.clear()
    _jwks_negative.clear()
    yield
    _jwks_cache.clear()
    _jwks_forced_refresh.clear()
    _jwks_negative.clear()


def _sig(priv, kid=None):
    return sign_record(
        RecordPayload.from_agent_record("a." + ZONE, "t." + ZONE, 443, "mcp"), priv, kid=kid
    )


class TestForcedRefetchActuallyRuns:
    """The cache must already hold a stale document, or nothing is being tested."""

    @pytest.mark.asyncio
    async def test_a_key_rolled_in_after_caching_is_picked_up(self):
        new_priv, new_pub = generate_keypair()
        _, old_pub = generate_keypair()

        # The precondition the previous tests never established.
        _cache_jwks(ZONE, export_jwks(old_pub, kid="old-key"))
        current = export_jwks(new_pub, kid="rolled-in")

        with (
            patch("dns_aid.core.jwks.fetch_jwks", new=AsyncMock(return_value=_jwks_cache[ZONE][0])),
            patch("dns_aid.core.jwks._fetch_jwks_uncached", new=AsyncMock(return_value=current)),
        ):
            ok, _, status = await verify_record_signature_detailed(
                ZONE, _sig(new_priv, kid="rolled-in")
            )

        assert ok is True, "the refetch is the only thing that could have found this key"
        assert status is SignatureStatus.VERIFIED

    @pytest.mark.asyncio
    async def test_the_refetch_happens_exactly_once_per_domain(self):
        priv, _ = generate_keypair()
        _, other = generate_keypair()
        stale = export_jwks(other, kid="old-key")
        _cache_jwks(ZONE, stale)

        calls = []

        async def uncached(domain):
            calls.append(domain)
            return stale

        with (
            patch("dns_aid.core.jwks.fetch_jwks", new=AsyncMock(return_value=stale)),
            patch("dns_aid.core.jwks._fetch_jwks_uncached", new=uncached),
        ):
            for i in range(10):
                await verify_record_signature_detailed(ZONE, _sig(priv, kid=f"rotating-{i}"))

        assert len(calls) == 1, f"{len(calls)} refetches for 10 rotating kids"


class TestPeerCertTeardown:
    """A hostile peer must not be able to discard its own DANE verdict."""

    @staticmethod
    def _writer(*, wait_closed):
        writer = MagicMock()
        ssl_obj = MagicMock()
        ssl_obj.getpeercert.return_value = b"peer-der"
        writer.get_extra_info.return_value = ssl_obj
        writer.wait_closed = wait_closed
        writer.close = MagicMock()
        return writer

    @pytest.mark.asyncio
    async def test_a_reset_during_teardown_does_not_lose_the_certificate(self):
        from dns_aid.core import validator as v

        writer = self._writer(wait_closed=AsyncMock(side_effect=ConnectionResetError))
        with patch.object(
            v.asyncio, "open_connection", new=AsyncMock(return_value=(MagicMock(), writer))
        ):
            der = await v._fetch_peer_cert("h.example.com", 443, pkix=False)

        assert der == b"peer-der", "the peer suppressed its own verdict by resetting"

    @pytest.mark.asyncio
    async def test_a_hung_teardown_does_not_hang_the_call(self):
        from dns_aid.core import validator as v

        async def never_closes():
            await asyncio.sleep(3600)

        writer = self._writer(wait_closed=never_closes)
        with (
            patch.object(
                v.asyncio, "open_connection", new=AsyncMock(return_value=(MagicMock(), writer))
            ),
            patch.object(v, "DANE_SHUTDOWN_TIMEOUT", 0.01),
        ):
            der = await asyncio.wait_for(
                v._fetch_peer_cert("h.example.com", 443, pkix=False), timeout=5
            )

        assert der == b"peer-der"


class TestCliPrivateKeyCheck:
    """A missing or unreadable key must be an error, not a traceback."""

    @staticmethod
    def _publish(*args):
        from typer.testing import CliRunner

        from dns_aid.cli.main import app

        return CliRunner().invoke(
            app,
            [
                "publish",
                "--name",
                "x",
                "--domain",
                "example.com",
                "--protocol",
                "mcp",
                "--endpoint",
                "e.example.com",
                *args,
            ],
            env={"DNS_AID_BACKEND": "mock"},
        )

    def test_a_missing_key_is_reported_not_raised(self):
        result = self._publish("--sign", "--private-key", "/nonexistent/key.pem")

        assert result.exit_code == 1
        assert "not found" in result.output
        assert "Traceback" not in result.output

    @pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
    def test_an_unreadable_key_is_reported(self, tmp_path):
        import os

        if os.geteuid() == 0:
            pytest.skip("root reads everything")
        key = tmp_path / "k.pem"
        key.write_text("x")
        key.chmod(0o000)

        result = self._publish("--sign", "--private-key", str(key))

        assert result.exit_code == 1
        assert "not readable" in result.output

    def test_publishing_is_not_announced_before_the_input_is_accepted(self):
        result = self._publish("--sign", "--private-key", "/nonexistent/key.pem")

        assert "Publishing agent to DNS" not in result.output
