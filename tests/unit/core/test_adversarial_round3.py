# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Regressions from the third adversarial round. Each was live before the fix."""

import asyncio
import time
from unittest.mock import AsyncMock, patch

import pytest

from dns_aid.core.discoverer import _verify_agent_signatures
from dns_aid.core.jwks import (
    JWKS_NEGATIVE_TTL,
    RecordPayload,
    SignatureStatus,
    _jwks_cache,
    _jwks_forced_refresh,
    _jwks_negative,
    export_jwks,
    fetch_jwks,
    generate_keypair,
    sign_record,
)
from dns_aid.core.models import CATALOG_ENDPOINT_SOURCES, AgentRecord, Protocol

PARAMS = {"cap": "https://real.example.com/cap.json", "cap-sha256": "a" * 64, "realm": "prod"}


@pytest.fixture(autouse=True)
def _clean():
    for d in (_jwks_cache, _jwks_forced_refresh, _jwks_negative):
        d.clear()
    yield
    for d in (_jwks_cache, _jwks_forced_refresh, _jwks_negative):
        d.clear()


def _record(source, cap=PARAMS["cap"], sha=PARAMS["cap-sha256"], sig=None):
    return AgentRecord(
        name="a",
        domain="example.com",
        protocol=Protocol.MCP,
        target_host="t.example.com",
        port=443,
        sig=sig,
        cap_uri=cap,
        cap_sha256=sha,
        realm="prod",
        endpoint_source=source,
    )


async def _verify(agent, pub):
    with patch("dns_aid.core.jwks.fetch_jwks", new=AsyncMock(return_value=export_jwks(pub))):
        await _verify_agent_signatures([agent], "example.com", dnssec_validated={})
    return agent


class TestCatalogRecordsAreNotExemptFromTheParamBinding:
    """The exemption switched the binding off where JWS is the SOLE trust anchor.

    An off-domain catalog could republish a publisher's signature verbatim with
    cap and cap-sha256 swapped for its own, keep the endpoint tuple identical,
    and be reported verified -- while _drop_unverified_off_domain keeps exactly
    those records BECAUSE the signature verified.
    """

    @pytest.mark.asyncio
    @pytest.mark.parametrize("source", sorted(CATALOG_ENDPOINT_SOURCES))
    async def test_a_swapped_capability_pointer_is_refused_on_every_source(self, source):
        priv, pub = generate_keypair()
        genuine = sign_record(
            RecordPayload.from_agent_record(
                "a.example.com", "t.example.com", 443, "mcp", params=PARAMS
            ),
            priv,
        )
        agent = await _verify(
            _record(source, cap="https://attacker.example/evil.json", sha="b" * 64, sig=genuine),
            pub,
        )

        assert agent.signature_verified is False, f"{source} accepted a swapped cap pointer"
        assert agent.signature_status == SignatureStatus.UNBOUND

    @pytest.mark.asyncio
    @pytest.mark.parametrize("source", sorted(CATALOG_ENDPOINT_SOURCES))
    async def test_a_matching_catalog_record_still_verifies_with_coverage(self, source):
        """require_signed_params must not delete every catalog result."""
        priv, pub = generate_keypair()
        genuine = sign_record(
            RecordPayload.from_agent_record(
                "a.example.com", "t.example.com", 443, "mcp", params=PARAMS
            ),
            priv,
        )
        agent = await _verify(_record(source, sig=genuine), pub)

        assert agent.signature_verified is True
        assert agent.signature_covers_params is True


class TestCoverageFlagIsReset:
    @pytest.mark.asyncio
    async def test_a_stale_true_does_not_survive_a_failed_verification(self):
        """Its only write direction was 'more trusted'."""
        _, pub = generate_keypair()
        agent = _record("dns_svcb", sig="not.a.jws")
        agent.signature_covers_params = True

        await _verify(agent, pub)

        assert agent.signature_verified is not True
        assert agent.signature_covers_params is False


class TestExpiryIsNotAttackerSelectable:
    @pytest.mark.asyncio
    async def test_an_unbound_record_carries_no_expiry(self):
        """A lifted signature must not stamp the publisher's exp on the forgery."""
        priv, pub = generate_keypair()
        lifted = sign_record(
            RecordPayload.from_agent_record(
                "a.example.com", "t.example.com", 443, "mcp", params=PARAMS
            ),
            priv,
        )
        agent = _record("dns_svcb", sig=lifted)
        agent.target_host = "attacker.example"

        await _verify(agent, pub)

        assert agent.signature_status == SignatureStatus.UNBOUND
        assert agent.signature_expires_at is None


class TestJwksCacheKeysAreNormalised:
    @pytest.mark.asyncio
    async def test_case_and_trailing_dot_share_one_entry(self):
        """DNS labels are case-insensitive, and MCP takes `domain` from model output."""
        seen = []

        async def dead(url, domain):  # noqa: ARG001
            seen.append(url)
            return None

        with patch("dns_aid.core.jwks._fetch_jwks_from", new=dead):
            for spelling in ("victim.test", "Victim.test", "VICTIM.TEST", "victim.test."):
                await fetch_jwks(spelling)

        assert len(seen) == 2, f"{len(seen)} fetches for one zone spelled four ways"
        assert len(_jwks_negative) == 1


class TestNegativeCacheOutlivesTheFetch:
    @pytest.mark.asyncio
    async def test_a_slow_failure_still_leaves_a_usable_window(self):
        """The stamp used a clock read from BEFORE the fetch, so it expired on arrival."""

        async def slow_dead(url, domain):  # noqa: ARG001
            await asyncio.sleep(0.05)
            return None

        with (
            patch("dns_aid.core.jwks._fetch_jwks_from", new=slow_dead),
            patch("dns_aid.core.jwks.JWKS_NEGATIVE_TTL", 0.5),
        ):
            await fetch_jwks("dead.example.com")

        remaining = next(iter(_jwks_negative.values())) - time.time()
        assert remaining > 0, f"negative entry was born expired ({remaining:+.2f}s)"

    def test_the_window_is_short_enough_to_recover(self):
        assert JWKS_NEGATIVE_TTL <= 60
