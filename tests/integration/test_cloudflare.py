# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Integration tests for the Cloudflare backend against a live zone.

These tests require a Cloudflare API token with DNS edit permissions and a
real zone. Set environment variables:
  - CLOUDFLARE_API_TOKEN   API token with Zone.DNS Edit + Read
  - DNS_AID_TEST_ZONE      e.g. "testing.example.com"
  - CLOUDFLARE_ZONE_ID     optional; otherwise looked up by zone name

Read-only tests run with just the above. Tests that create or delete records
are additionally gated behind:
  - CLOUDFLARE_MUTATION_TESTS=1

Run with: pytest tests/integration/test_cloudflare.py -m live -v
"""

import contextlib
import os
import uuid

import pytest


async def _safe_delete(backend, zone: str, name: str, record_type: str) -> None:
    """Best-effort cleanup: never let one delete failure mask another.

    delete_record can raise (its underlying API call uses raise_for_status),
    so sequential cleanups in a finally block must be individually guarded or
    a single failure leaks the remaining live test records.
    """
    with contextlib.suppress(Exception):
        await backend.delete_record(zone, name, record_type)


# Live backend tests — run with: pytest -m live
pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        not os.environ.get("DNS_AID_TEST_ZONE"),
        reason="DNS_AID_TEST_ZONE not set",
    ),
    pytest.mark.skipif(
        not os.environ.get("CLOUDFLARE_API_TOKEN"),
        reason="CLOUDFLARE_API_TOKEN not set",
    ),
]

_MUTATION = pytest.mark.skipif(
    not os.environ.get("CLOUDFLARE_MUTATION_TESTS"),
    reason="CLOUDFLARE_MUTATION_TESTS not set (set to 1 to enable writes)",
)


@pytest.fixture
def test_zone() -> str:
    """Get test zone from environment."""
    return os.environ["DNS_AID_TEST_ZONE"]


@pytest.fixture
async def cloudflare_backend():
    """Create a Cloudflare backend, closing its client afterwards."""
    from dns_aid.backends.cloudflare import CloudflareBackend

    backend = CloudflareBackend()
    try:
        yield backend
    finally:
        await backend.close()


class TestCloudflareBackendReadOnly:
    """Non-mutating live checks."""

    @pytest.mark.asyncio
    async def test_zone_exists(self, cloudflare_backend, test_zone):
        assert await cloudflare_backend.zone_exists(test_zone) is True

    @pytest.mark.asyncio
    @pytest.mark.skipif(
        bool(os.environ.get("CLOUDFLARE_ZONE_ID")),
        reason="zone_exists short-circuits to True when a zone ID is pinned; "
        "this negative test requires name-based lookup",
    )
    async def test_zone_not_exists(self, cloudflare_backend):
        assert await cloudflare_backend.zone_exists("nonexistent-zone-12345.example") is False

    @pytest.mark.asyncio
    async def test_backend_declares_native_svcb_support(self, cloudflare_backend):
        # The whole point of this backend revision: no TXT demotion needed.
        assert cloudflare_backend.supports_private_svcb_keys is True


@_MUTATION
class TestCloudflareBackendNativeSvcb:
    """Live create/read/delete proving native private-use SVCB keys."""

    @pytest.mark.asyncio
    async def test_svcb_private_use_keys_roundtrip(self, cloudflare_backend, test_zone):
        """Private-use keys (key65400..key65404) are stored on the SVCB record
        verbatim — NOT demoted to TXT."""
        suffix = uuid.uuid4().hex[:8]
        name = f"_it-svcb-{suffix}._mcp._agents"
        params = {
            "alpn": "mcp",
            "port": "443",
            "key65400": "https://example.com/cap.json",  # cap
            "key65401": "cGxhY2Vob2xkZXI",  # cap-sha256
            "key65402": "mcp=1.0",  # bap
            "key65403": "https://example.com/policy",  # policy
            "key65404": "production",  # realm
        }
        try:
            fqdn = await cloudflare_backend.create_svcb_record(
                zone=test_zone,
                name=name,
                priority=1,
                target=".",
                params=params,
                ttl=300,
            )
            assert fqdn == f"{name}.{test_zone}"

            record = await cloudflare_backend.get_record(test_zone, name, "SVCB")
            assert record is not None, "SVCB record not found after creation"

            value = record["values"][0]
            # Every private-use key must survive on the SVCB record.
            for key in ("key65400", "key65401", "key65402", "key65403", "key65404"):
                assert f'{key}="' in value, f"{key} missing from SVCB rdata: {value!r}"
        finally:
            await _safe_delete(cloudflare_backend, test_zone, name, "SVCB")

    @pytest.mark.asyncio
    async def test_publish_agent_writes_native_svcb(self, cloudflare_backend, test_zone):
        """Full publish path: custom params land on SVCB, TXT has no dnsaid_ demotion."""
        from dns_aid.core.models import AgentRecord, Protocol

        suffix = uuid.uuid4().hex[:8]
        agent = AgentRecord(
            name=f"it-agent-{suffix}",
            domain=test_zone,
            protocol=Protocol.MCP,
            target_host=f"mcp.{test_zone}",
            port=443,
            capabilities=["test", "integration"],
            cap_uri="https://example.com/cap.json",
            policy_uri="https://example.com/policy",
            realm="production",
            ttl=300,
        )
        record_name = agent.name  # draft-02 flat primary owner
        walkable_name = f"{agent.name}._agents"
        try:
            records = await cloudflare_backend.publish_agent(agent)
            assert any(r.startswith("SVCB") for r in records)

            svcb = await cloudflare_backend.get_record(test_zone, record_name, "SVCB")
            assert svcb is not None
            value = svcb["values"][0]
            assert 'key65400="' in value  # cap
            assert 'key65403="' in value  # policy
            assert 'key65404="' in value  # realm

            txt = await cloudflare_backend.get_record(test_zone, record_name, "TXT")
            if txt is not None:
                assert not any(v.startswith("dnsaid_") for v in txt["values"])
        finally:
            await _safe_delete(cloudflare_backend, test_zone, record_name, "SVCB")
            await _safe_delete(cloudflare_backend, test_zone, record_name, "TXT")
            await _safe_delete(cloudflare_backend, test_zone, walkable_name, "SVCB")

    @pytest.mark.asyncio
    async def test_txt_multistring_roundtrip(self, cloudflare_backend, test_zone):
        """Multiple TXT values round-trip as distinct character-strings."""
        suffix = uuid.uuid4().hex[:8]
        name = f"_it-txt-{suffix}._mcp._agents"
        values = ["capabilities=chat,code", "version=1.0.0", "description=has spaces here"]
        try:
            await cloudflare_backend.create_txt_record(
                zone=test_zone, name=name, values=values, ttl=300
            )
            record = await cloudflare_backend.get_record(test_zone, name, "TXT")
            assert record is not None
            # Each value must come back as its own string, spaces preserved.
            for v in values:
                assert v in record["values"], f"{v!r} not in {record['values']!r}"
        finally:
            await _safe_delete(cloudflare_backend, test_zone, name, "TXT")
