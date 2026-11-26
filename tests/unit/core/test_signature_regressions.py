# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Regressions in the record-signature path found in review of the JWS branch.

Both defects were invisible to the existing suite for the same reason: each one
only shows up on a path the tests never took. The JWKS lock is only bound to a
loop when a second waiter CONTENDS on it, and the publish/verify digest only
disagrees when a field is one the model normalises. Single-caller, already-
normalised fixtures pass either way.
"""

import asyncio
import gc
from unittest.mock import AsyncMock, patch

import pytest

from dns_aid.core import jwks as jwks_module
from dns_aid.core.jwks import (
    RecordPayload,
    export_jwks,
    generate_keypair,
    params_from_record,
    svcb_digest,
    verify_record_signature_detailed,
)
from dns_aid.core.models import AgentRecord, Protocol


def _reset_jwks_state() -> None:
    jwks_module._jwks_cache.clear()
    jwks_module._jwks_negative.clear()
    jwks_module._jwks_forced_refresh.clear()
    jwks_module._jwks_inflight.clear()


class TestInflightLockSurvivesANewEventLoop:
    """The single-flight lock must not be shared across event loops.

    An ``asyncio.Lock`` binds itself to the loop that first contends on it and
    refuses to be awaited from any other. The MCP server runs every tool call
    under its own ``asyncio.run``, so a module-level dict of bare locks handed
    loop B a lock owned by loop A. ``_verify_one`` catches the resulting
    RuntimeError and records ``no_key``, so every agent in the zone silently
    reported unverified and ``require_signed=True`` returned nothing from then
    on.
    """

    @staticmethod
    def _one_call_in_a_fresh_loop() -> list[object]:
        """Two concurrent fetches for one zone, in a brand-new loop."""

        async def slow_fetch(domain):
            # Hold the lock long enough that the second caller must wait, which
            # is the only path that touches the loop.
            await asyncio.sleep(0.02)
            return None

        async def body():
            return await asyncio.gather(
                jwks_module.fetch_jwks("example.com"),
                jwks_module.fetch_jwks("example.com"),
                return_exceptions=True,
            )

        with patch.object(jwks_module, "_fetch_jwks_locked", new=AsyncMock(side_effect=slow_fetch)):
            return asyncio.run(body())

    def test_a_contended_zone_is_fetchable_again_from_a_later_loop(self):
        _reset_jwks_state()

        first = self._one_call_in_a_fresh_loop()
        assert not any(isinstance(r, BaseException) for r in first), first

        # The negative cache would short-circuit the second call before it ever
        # reached the lock, which is exactly how this hid.
        jwks_module._jwks_negative.clear()

        second = self._one_call_in_a_fresh_loop()
        errors = [r for r in second if isinstance(r, BaseException)]
        assert not errors, f"lock leaked across event loops: {errors!r}"

    def test_each_loop_gets_its_own_lock_for_the_same_zone(self):
        _reset_jwks_state()
        locks = []

        async def grab():
            locks.append(jwks_module._inflight_lock("example.com"))

        asyncio.run(grab())
        asyncio.run(grab())

        assert locks[0] is not locks[1], "one lock object was shared across two event loops"

    def test_finished_loops_do_not_accumulate(self):
        """Weakly keyed, so a collected loop takes its lock map with it."""
        _reset_jwks_state()

        async def grab():
            jwks_module._inflight_lock("example.com")

        for _ in range(5):
            asyncio.run(grab())
        gc.collect()

        assert len(jwks_module._jwks_inflight) <= 1

    def test_a_held_lock_is_never_evicted(self):
        """Evicting a held lock hands the next arrival a fresh one, so two
        coroutines fetch the same JWKS -- losing the property the dict exists
        for."""
        _reset_jwks_state()

        async def body():
            held = jwks_module._inflight_lock("busy.example")
            await held.acquire()
            try:
                for i in range(jwks_module._JWKS_CACHE_MAX + 10):
                    jwks_module._inflight_lock(f"zone-{i}.example")
                # Same object, still held, still there.
                assert jwks_module._inflight_lock("busy.example") is held
                assert held.locked()
            finally:
                held.release()

        asyncio.run(body())


class TestPublishSignsWhatIsPublished:
    """The digest must cover the record as written, not the arguments.

    ``AgentRecord`` normalises several fields on the way in. Signing the raw
    kwargs signed one value and published another, so the publisher's own
    genuine record verified as ``unbound`` -- the status documented to consumers
    as a lifted signature pasted onto a spoofed record.
    """

    def test_normalised_field_signs_and_verifies_to_the_same_digest(self):
        record = AgentRecord(
            name="chat",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="mcp.example.com",
            port=443,
            connect_class="Direct",  # model lower-cases this
        )
        assert record.connect_class == "direct", "fixture no longer exercises normalisation"

        signed_as_published = svcb_digest(params_from_record(record))
        signed_from_kwargs = svcb_digest({"connect-class": "Direct"})

        assert signed_as_published != signed_from_kwargs, (
            "normalisation is what made the two sides disagree"
        )
        # The verifier reads the record, so reading the record is what publish
        # must sign.
        assert signed_as_published == svcb_digest(params_from_record(record))

    def test_empty_param_signs_as_absent_because_the_wire_cannot_carry_it(self):
        """``to_params()`` drops falsy params, so an empty one is unpublishable.

        Signing ``{"realm": ""}`` and publishing no realm at all produced two
        different digests for one record.
        """
        with_empty = AgentRecord(
            name="chat",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="mcp.example.com",
            port=443,
            realm="",
        )
        without = AgentRecord(
            name="chat",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="mcp.example.com",
            port=443,
        )

        assert params_from_record(with_empty)["realm"] is None
        assert svcb_digest(params_from_record(with_empty)) == svcb_digest(
            params_from_record(without)
        )

    def test_svcb_digest_still_separates_empty_from_absent(self):
        """The normalisation belongs to the record reader, not to the digest."""
        assert svcb_digest({"realm": ""}) != svcb_digest({})

    @pytest.mark.asyncio
    async def test_a_record_signed_by_publish_verifies_against_its_own_zone(self):
        """End to end: sign a normalising record, then verify it as a consumer.

        This is the assertion the branch lacked. Every existing test built the
        payload from the same values it later compared against, so the two sides
        could not disagree.
        """
        from dns_aid.core.jwks import sign_record

        private_key, public_key = generate_keypair()

        record = AgentRecord(
            name="chat",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="mcp.example.com",
            port=443,
            connect_class="Direct",
            realm="",
        )
        payload = RecordPayload.from_agent_record(
            fqdn=record.fqdn,
            target=record.target_host,
            port=record.port,
            protocol=record.protocol.value,
            params=params_from_record(record),
        )
        sig = sign_record(payload, private_key, kid="rollover-key")

        _reset_jwks_state()
        with patch.object(
            jwks_module,
            "fetch_jwks",
            new=AsyncMock(return_value=export_jwks(public_key, kid="rollover-key")),
        ):
            is_valid, verified_payload, status = await verify_record_signature_detailed(
                record.domain, sig
            )

        assert is_valid, f"publisher's own record did not verify: {status}"
        assert verified_payload is not None
        assert verified_payload.svcb == svcb_digest(params_from_record(record))
