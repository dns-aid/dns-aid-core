# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Live tests for the DNSimple backend.

These tests use the real DNSimple API and a real zone. They make sure that:

- the zone lookup works.
- the private-use SVCB keys (key65400 to key65409) stay on the SVCB record.
- the publish path writes a native SVCB record and the TXT values.
- a second publish replaces the records in place.
- TXT values, list_records and delete_record work.

Each test uses a new record name and removes its records at the end.

Gated behind DNS_AID_LIVE_TESTS=1 so CI stays hermetic:

    DNS_AID_LIVE_TESTS=1 \\
    DNSIMPLE_TOKEN=... DNSIMPLE_ACCOUNT_ID=... DNSIMPLE_TEST_ZONE=example.com \\
    uv run pytest tests/integration/test_dnsimple.py -v
"""

from __future__ import annotations

import os
import uuid

import pytest

from dns_aid.backends.dnsimple import DNSimpleBackend
from dns_aid.core.models import AgentRecord, Protocol

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("DNS_AID_LIVE_TESTS") != "1"
        or not os.environ.get("DNSIMPLE_TOKEN")
        or not os.environ.get("DNSIMPLE_TEST_ZONE"),
        reason="Set DNS_AID_LIVE_TESTS=1, DNSIMPLE_TOKEN and DNSIMPLE_TEST_ZONE",
    ),
]

ZONE = os.environ.get("DNSIMPLE_TEST_ZONE", "")
TTL = 300


@pytest.fixture
async def backend():
    """DNSimple backend for the live API."""
    b = DNSimpleBackend()
    yield b
    await b.close()


@pytest.fixture
async def cleanup(backend):
    """Collect (name, type) pairs. Delete their records at the end.

    Try all deletes. Then fail the test if a delete failed, so that a record
    that the test did not remove is not ignored.
    """
    pairs: list[tuple[str, str]] = []
    yield pairs
    errors: list[str] = []
    for name, record_type in pairs:
        try:
            await backend.delete_record(ZONE, name, record_type)
        except Exception as exc:
            errors.append(f"{record_type} {name}: {exc}")
    if errors:
        pytest.fail("Cleanup failed: " + "; ".join(errors))


def _name(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _agent(name: str, capabilities: list[str], cap_uri: str) -> AgentRecord:
    return AgentRecord(
        name=name,
        domain=ZONE,
        protocol=Protocol.MCP,
        target_host=f"mcp.{ZONE}",
        port=443,
        capabilities=capabilities,
        cap_uri=cap_uri,
        policy_uri="https://example.com/policy",
        realm="production",
        ttl=TTL,
    )


class TestDNSimpleBackendReadOnly:
    """Live checks that do not change the zone."""

    async def test_zone_exists(self, backend):
        assert await backend.zone_exists(ZONE) is True

    async def test_zone_not_exists(self, backend):
        assert await backend.zone_exists("nonexistent-zone-12345.example") is False

    async def test_backend_declares_native_svcb_support(self, backend):
        assert backend.supports_private_svcb_keys is True


class TestDNSimpleBackendRecords:
    """Live create, read, replace and delete."""

    async def test_svcb_private_use_keys_roundtrip(self, backend, cleanup):
        """The private-use keys stay on the SVCB record. They are not demoted to TXT."""
        name = f"{_name('it-svcb')}._mcp._agents"
        cleanup.append((name, "SVCB"))
        params = {
            "alpn": "mcp",
            "port": "443",
            "key65400": "https://example.com/cap.json",  # cap
            "key65401": "cGxhY2Vob2xkZXI",  # cap-sha256
            "key65402": "mcp=1.0",  # bap
            "key65403": "https://example.com/policy",  # policy
            "key65404": "production",  # realm
        }

        fqdn = await backend.create_svcb_record(
            zone=ZONE, name=name, priority=1, target=".", params=params, ttl=TTL
        )

        assert fqdn == f"{name}.{ZONE}"
        record = await backend.get_record(ZONE, name, "SVCB")
        assert record is not None, "SVCB record not found after creation"
        assert len(record["values"]) == 1
        value = record["values"][0]
        # The API sorts the keys and quotes all values.
        for key, expected in params.items():
            assert f'{key}="{expected}"' in value, f"{key} missing from SVCB: {value!r}"

    async def test_publish_agent_writes_native_svcb(self, backend, cleanup):
        """The publish path puts the custom params on SVCB and has no dnsaid_ TXT values."""
        agent = _agent(_name("it-agent"), ["test", "integration"], "https://example.com/cap.json")
        cleanup.extend([(agent.name, "SVCB"), (agent.name, "TXT")])

        records = await backend.publish_agent(agent)

        assert any(r.startswith("SVCB") for r in records)
        svcb = await backend.get_record(ZONE, agent.name, "SVCB")
        assert svcb is not None
        value = svcb["values"][0]
        assert value.startswith(f"1 mcp.{ZONE} ")  # no trailing dot on the target
        assert 'key65400="https://example.com/cap.json"' in value
        assert 'key65403="https://example.com/policy"' in value
        assert 'key65404="production"' in value

        txt = await backend.get_record(ZONE, agent.name, "TXT")
        assert txt is not None
        assert sorted(txt["values"]) == ["capabilities=test,integration", "version=1.0.0"]

    async def test_publish_twice_replaces_records_in_place(self, backend, cleanup):
        """A second publish changes the records. It does not add records."""
        name = _name("it-agent")
        cleanup.extend([(name, "SVCB"), (name, "TXT")])
        await backend.publish_agent(_agent(name, ["search", "chat"], "https://example.com/v1.json"))
        svcb_before = await backend._find_records(ZONE, name, "SVCB")

        await backend.publish_agent(_agent(name, ["code"], "https://example.com/v2.json"))

        svcb_after = await backend._find_records(ZONE, name, "SVCB")
        assert len(svcb_after) == 1
        assert svcb_after[0]["id"] == svcb_before[0]["id"], "SVCB was not updated in place"
        assert 'key65400="https://example.com/v2.json"' in svcb_after[0]["content"]

        txt = await backend.get_record(ZONE, name, "TXT")
        assert txt is not None
        assert sorted(txt["values"]) == ["capabilities=code", "version=1.0.0"]

    async def test_txt_multistring_roundtrip(self, backend, cleanup):
        """Each TXT value comes back as a separate value. Spaces and quotes stay."""
        name = f"{_name('it-txt')}._mcp._agents"
        cleanup.append((name, "TXT"))
        values = ["capabilities=chat,code", "version=1.0.0", 'description=Say "hi" to me']

        await backend.create_txt_record(zone=ZONE, name=name, values=values, ttl=TTL)

        record = await backend.get_record(ZONE, name, "TXT")
        assert record is not None
        assert sorted(record["values"]) == sorted(values)

    async def test_list_records_and_delete_record(self, backend, cleanup):
        """list_records finds a record. delete_record removes it."""
        name = _name("it-list")
        cleanup.append((name, "TXT"))
        await backend.create_txt_record(zone=ZONE, name=name, values=["a=1"], ttl=TTL)

        found = [r async for r in backend.list_records(ZONE, name_pattern=name, record_type="TXT")]
        assert [(r["name"], r["fqdn"], r["values"]) for r in found] == [
            (name, f"{name}.{ZONE}", ["a=1"])
        ]

        assert await backend.delete_record(ZONE, name, "TXT") is True
        assert await backend.get_record(ZONE, name, "TXT") is None
        assert await backend.delete_record(ZONE, name, "TXT") is False
