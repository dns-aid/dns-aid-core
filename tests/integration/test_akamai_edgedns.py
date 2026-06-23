# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Integration tests for Akamai Edge DNS backend.

These tests require Akamai EdgeGrid credentials and a real zone you control.
Credentials can be supplied via environment variables or ~/.edgerc.

Environment variables:
  AKAMAI_HOST            — EdgeGrid API hostname
  AKAMAI_CLIENT_TOKEN    — EdgeGrid client token
  AKAMAI_CLIENT_SECRET   — EdgeGrid client secret
  AKAMAI_ACCESS_TOKEN    — EdgeGrid access token
  AKAMAI_TEST_ZONE       — Zone to run tests against (e.g. "example.com")

Run with: uv run pytest tests/integration/test_akamai_edgedns.py -v

Mutation tests (create/delete) additionally require:
  AKAMAI_MUTATION_TESTS=1
"""

import os
import uuid

import pytest


def _edgegrid_available() -> bool:
    try:
        import akamai.edgegrid  # noqa: F401

        return True
    except ImportError:
        return False


pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        not os.environ.get("AKAMAI_TEST_ZONE"),
        reason="AKAMAI_TEST_ZONE not set",
    ),
    pytest.mark.skipif(
        not _edgegrid_available(),
        reason="edgegrid-python not installed — run: uv pip install edgegrid-python",
    ),
]


@pytest.fixture
def test_zone() -> str:
    """Get test zone from environment."""
    return os.environ["AKAMAI_TEST_ZONE"]


@pytest.fixture
async def backend():
    """Create Akamai Edge DNS backend from environment variables / ~/.edgerc."""
    from dns_aid.backends.akamai_edgedns import AkamaiEdgeDNSBackend

    b = AkamaiEdgeDNSBackend()
    yield b
    await b.close()


@pytest.fixture
def unique_name() -> str:
    """Generate unique record name to avoid conflicts."""
    short_id = str(uuid.uuid4())[:8]
    return f"_inttest-{short_id}._mcp._agents"


class TestAkamaiEdgeDNSReadOnly:
    """Read-only integration tests for Akamai Edge DNS backend."""

    async def test_zone_exists(self, backend, test_zone):
        """Test zone existence check."""
        assert await backend.zone_exists(test_zone) is True

    async def test_zone_exists_trailing_dot(self, backend, test_zone):
        """Test zone existence with trailing dot."""
        assert await backend.zone_exists(f"{test_zone}.") is True

    async def test_zone_not_exists(self, backend):
        """Test zone non-existence."""
        assert await backend.zone_exists("nonexistent-zone-xyz123.invalid") is False


class TestAkamaiEdgeDNSMutation:
    """Mutation integration tests (create/delete) for Akamai Edge DNS backend."""

    pytestmark = pytest.mark.skipif(
        not os.environ.get("AKAMAI_MUTATION_TESTS"),
        reason="AKAMAI_MUTATION_TESTS not set (set to 1 to enable)",
    )

    async def test_create_verify_delete_svcb(self, backend, test_zone, unique_name):
        """SVCB record lifecycle with private-use key65400."""
        try:
            fqdn = await backend.create_svcb_record(
                zone=test_zone,
                name=unique_name,
                priority=1,
                target=f"fake.{test_zone}",
                params={
                    "mandatory": "alpn,port",
                    "alpn": "mcp",
                    "port": "443",
                    "key65400": "https://fake.example.com/.well-known/agent-cap.json",
                },
                ttl=120,
            )

            assert unique_name in fqdn

            # Verify key65400 is preserved verbatim in rdata
            record = await backend.get_record(test_zone, unique_name, "SVCB")
            assert record is not None
            assert record["type"] == "SVCB"
            assert any("key65400" in v for v in record["values"])

        finally:
            await backend.delete_record(test_zone, unique_name, "SVCB")

    async def test_create_verify_delete_txt(self, backend, test_zone, unique_name):
        """TXT record lifecycle."""
        try:
            fqdn = await backend.create_txt_record(
                zone=test_zone,
                name=unique_name,
                values=["capabilities=integration,test", "version=0.0.1"],
                ttl=120,
            )

            assert unique_name in fqdn

            record = await backend.get_record(test_zone, unique_name, "TXT")
            assert record is not None
            assert record["type"] == "TXT"

        finally:
            await backend.delete_record(test_zone, unique_name, "TXT")

    async def test_upsert_svcb(self, backend, test_zone, unique_name):
        """Re-publishing an existing SVCB record updates it without error."""
        try:
            await backend.create_svcb_record(
                zone=test_zone,
                name=unique_name,
                priority=1,
                target=f"fake.{test_zone}",
                params={"alpn": "mcp", "port": "443"},
                ttl=120,
            )
            # Second call — should PUT, not fail
            fqdn = await backend.create_svcb_record(
                zone=test_zone,
                name=unique_name,
                priority=1,
                target=f"fake.{test_zone}",
                params={"alpn": "mcp", "port": "443", "key65404": "production"},
                ttl=120,
            )
            assert unique_name in fqdn

        finally:
            await backend.delete_record(test_zone, unique_name, "SVCB")

    async def test_list_records_contains_created(self, backend, test_zone, unique_name):
        """list_records yields the created SVCB record."""
        try:
            await backend.create_svcb_record(
                zone=test_zone,
                name=unique_name,
                priority=1,
                target=f"fake.{test_zone}",
                params={"alpn": "mcp", "port": "443"},
                ttl=120,
            )

            found = False
            async for record in backend.list_records(test_zone, name_pattern=unique_name):
                if record["type"] == "SVCB":
                    found = True
                    break

            assert found, "Created SVCB record not found in list_records"

        finally:
            await backend.delete_record(test_zone, unique_name, "SVCB")

    async def test_delete_nonexistent_returns_false(self, backend, test_zone):
        """Deleting a record that doesn't exist returns False, never raises."""
        result = await backend.delete_record(
            zone=test_zone,
            name="_nonexistent-inttest-xyz._mcp._agents",
            record_type="SVCB",
        )
        assert result is False

    async def test_full_publish_agent_workflow(self, backend, test_zone):
        """Full DNS-AID publish: SVCB + TXT via publish_agent()."""
        from dns_aid.core.models import AgentRecord, Protocol

        agent = AgentRecord(
            name=f"inttest-{str(uuid.uuid4())[:8]}",
            domain=test_zone,
            protocol=Protocol.MCP,
            target_host=f"fake.{test_zone}",
            port=443,
            capabilities=["integration", "test"],
            realm="test",
            ttl=120,
        )

        record_name = agent.name

        try:
            records_created = await backend.publish_agent(agent)

            assert any("SVCB" in r for r in records_created)
            assert any("TXT" in r for r in records_created)

            # Verify private-use keys are in SVCB (realm → key65404)
            record = await backend.get_record(test_zone, record_name, "SVCB")
            assert record is not None
            assert any("key65404" in v for v in record["values"])

            # Verify no dnsaid_ demotion in TXT
            txt = await backend.get_record(test_zone, record_name, "TXT")
            assert txt is not None
            assert not any("dnsaid_" in v for v in txt["values"])

        finally:
            await backend.delete_record(test_zone, record_name, "SVCB")
            await backend.delete_record(test_zone, record_name, "TXT")
