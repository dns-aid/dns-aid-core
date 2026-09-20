# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Coverage for mechanisms that mutation testing showed could be deleted silently.

Each of these was removable with the whole suite still green. A test that passes
whether or not the code exists is not a test, so each case here was confirmed to
fail with its mechanism disabled.
"""

import asyncio
import sys
import warnings
from unittest.mock import AsyncMock, patch

import pytest
import structlog

from dns_aid.core.jwks import (
    DEFAULT_SIG_VALIDITY_SECONDS,
    RecordPayload,
    SignatureStatus,
    _jwks_cache,
    _jwks_forced_refresh,
    _jwks_negative,
    export_jwks,
    generate_keypair,
    sign_record,
    verify_record_signature_detailed,
)

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


def _sig(priv, kid=None, validity=DEFAULT_SIG_VALIDITY_SECONDS):
    return sign_record(
        RecordPayload.from_agent_record(
            "a." + ZONE, "t." + ZONE, 443, "mcp", validity_seconds=validity
        ),
        priv,
        kid=kid,
    )


class TestExpiredSurvivesAStaleKidHint:
    """EXPIRED must reach the caller even when the kid is a stale hint.

    A key verified the bytes and only the exp claim had lapsed. Collapsing that
    into INVALID sends an operator hunting for an attacker when the fix is to
    re-publish, which is the exact status inversion this module exists to remove.
    """

    @pytest.mark.asyncio
    async def test_a_lapsed_signature_under_a_stale_kid_reports_expired(self):
        priv, pub = generate_keypair()
        served = export_jwks(pub, kid="actual-kid")

        with patch("dns_aid.core.jwks._fetch_jwks_from", new=AsyncMock(return_value=served)):
            ok, _, status = await verify_record_signature_detailed(
                ZONE, _sig(priv, kid="stale-hint", validity=-10)
            )

        assert ok is False
        assert status is SignatureStatus.EXPIRED, "a lapsed signature is not a forgery"


class TestKidIsAHintNotABinding:
    """A stale kid must recover from the CACHED document, without a refetch.

    Otherwise every unmatched-but-valid kid costs a round trip and spends the
    domain's once-per-window refetch budget, delaying a genuine rollover.
    """

    @pytest.mark.asyncio
    async def test_recovery_needs_no_refetch(self):
        priv, pub = generate_keypair()
        served = export_jwks(pub, kid="actual-kid")

        async def must_not_run(domain):  # noqa: ARG001
            raise AssertionError("a stale kid must recover from the cached document")

        with (
            patch("dns_aid.core.jwks._fetch_jwks_from", new=AsyncMock(return_value=served)),
            patch("dns_aid.core.jwks._fetch_jwks_uncached", new=must_not_run),
        ):
            ok, _, status = await verify_record_signature_detailed(
                ZONE, _sig(priv, kid="stale-hint")
            )

        assert ok is True
        assert status is SignatureStatus.VERIFIED


class TestForgeryIsInvalidWithoutNeedingARefetch:
    """The anti-laundering control must not depend on a network round trip.

    kid is attacker-chosen, so if an absent kid meant NO_KEY the attacker would
    pick the status their forgery reports -- and NO_KEY is documented to
    consumers as "unknown, not forged, do not treat as an attack signal".
    """

    @pytest.mark.asyncio
    async def test_the_cached_rejection_stands_when_the_refetch_fails(self):
        """The refetch is a legitimate rollover attempt, so it still runs.

        What must not happen is the verdict depending on whether it succeeded.
        Here it fails -- which an attacker who forges answers for the zone can
        always arrange, since they control the JWKS host's address -- and the
        rejection recorded from the cached key set must still stand.
        """
        _, victim_pub = generate_keypair()
        attacker_priv, _ = generate_keypair()
        served = export_jwks(victim_pub, kid="publisher-2026")

        with (
            patch("dns_aid.core.jwks._fetch_jwks_from", new=AsyncMock(return_value=served)),
            patch("dns_aid.core.jwks._fetch_jwks_uncached", new=AsyncMock(return_value=None)),
        ):
            ok, _, status = await verify_record_signature_detailed(
                ZONE, _sig(attacker_priv, kid="attacker-chosen")
            )

        assert ok is False
        assert status is SignatureStatus.INVALID, (
            "blackholing the JWKS host must not launder a forgery into NO_KEY"
        )


class TestDaneCancellationIsDriven:
    """asyncio.wait does not cancel its awaitables when the caller is cancelled."""

    @pytest.mark.asyncio
    async def test_an_outside_cancellation_leaves_no_task_alive(self):
        from dns_aid.core.discoverer import _verify_agents_dane
        from dns_aid.core.models import AgentRecord, Protocol

        agents = [
            AgentRecord(
                name=f"a{i}",
                domain="example.com",
                protocol=Protocol.MCP,
                target_host=f"e{i}.example.com",
                port=443,
            )
            for i in range(6)
        ]
        # The DANE gate now short-circuits an unauthenticated record before the
        # dial, so an unvalidated agent never creates a task to cancel.
        for a in agents:
            a.dnssec_validated = True
        created = []
        real_create = asyncio.create_task

        def tracking(coro, **kw):
            task = real_create(coro, **kw)
            created.append(task)
            return task

        async def hangs(host, port, *, verify_cert=True):  # noqa: ARG001
            await asyncio.sleep(3600)

        with (
            patch("dns_aid.core.validator._check_dane", hangs),
            patch("dns_aid.core.discoverer.asyncio.create_task", tracking),
        ):
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(_verify_agents_dane(agents), timeout=0.05)

        await asyncio.sleep(0)
        assert created, "no tasks were created, the test proves nothing"
        assert all(t.cancelled() or t.done() for t in created), (
            "tasks outlived the cancelled call: sockets stay open and discarded "
            "records keep being mutated"
        )


class TestTtlSecondsShim:
    def test_the_deprecated_name_still_works_and_warns(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            payload = RecordPayload.from_agent_record(
                "a.e.com", "t.e.com", 443, "mcp", ttl_seconds=3600
            )

        assert payload.exp - payload.iat == 3600
        assert any(issubclass(w.category, DeprecationWarning) for w in caught)

    def test_passing_both_is_an_error_not_a_silent_win(self):
        """The deprecated name used to override the new one with no signal."""
        with pytest.raises(TypeError, match="not both"):
            RecordPayload.from_agent_record(
                "a.e.com", "t.e.com", 443, "mcp", validity_seconds=100, ttl_seconds=7200
            )


class TestValidityDefault:
    def test_the_payload_and_the_publisher_share_one_default(self):
        from dns_aid.core import publisher

        assert publisher.DEFAULT_SIG_VALIDITY_SECONDS is DEFAULT_SIG_VALIDITY_SECONDS

    def test_the_default_is_ninety_days_and_inside_the_bounds(self):
        from dns_aid.core.publisher import (
            MAX_SIG_VALIDITY_SECONDS,
            MIN_SIG_VALIDITY_SECONDS,
        )

        assert DEFAULT_SIG_VALIDITY_SECONDS == 90 * 86400
        assert MIN_SIG_VALIDITY_SECONDS <= DEFAULT_SIG_VALIDITY_SECONDS <= MAX_SIG_VALIDITY_SECONDS


class TestLogStreamEscapeHatch:
    """The only migration path for embedders whose stdout logging this breaks."""

    @pytest.fixture(autouse=True)
    def _restore_structlog(self):
        """configure_logging mutates process-global state.

        Leaving it applied broke log capture in unrelated suites, which is the
        kind of cross-test coupling that makes a failure look like a code bug.
        """
        saved = structlog.get_config().copy()
        yield
        structlog.configure(**saved)

    def test_the_env_override_puts_diagnostics_back_on_stdout(self, monkeypatch):
        from dns_aid.utils.logging import configure_logging

        monkeypatch.setenv("DNS_AID_LOG_STREAM", "stdout")
        configure_logging(level="INFO")

        assert structlog.get_config()["logger_factory"]()._file is sys.stdout

    def test_without_it_the_default_is_stderr(self, monkeypatch):
        from dns_aid.utils.logging import configure_logging

        monkeypatch.delenv("DNS_AID_LOG_STREAM", raising=False)
        configure_logging(level="INFO")

        assert structlog.get_config()["logger_factory"]()._file is sys.stderr
