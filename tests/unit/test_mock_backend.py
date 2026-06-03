# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for mock DNS backend."""

import pytest

from dns_aid.backends.mock import MockBackend


class TestMockBackend:
    """Tests for MockBackend."""

    @pytest.mark.asyncio
    async def test_create_svcb_record(self, mock_backend: MockBackend):
        """Test creating SVCB record."""
        fqdn = await mock_backend.create_svcb_record(
            zone="example.com",
            name="_chat._a2a._agents",
            priority=1,
            target="chat.example.com.",
            params={"alpn": "a2a", "port": "443"},
            ttl=3600,
        )

        assert fqdn == "_chat._a2a._agents.example.com"

        # Verify record stored
        record = mock_backend.get_svcb_record("example.com", "_chat._a2a._agents")
        assert record is not None
        assert record["priority"] == 1
        assert record["target"] == "chat.example.com."
        assert record["params"]["alpn"] == "a2a"

    @pytest.mark.asyncio
    async def test_create_txt_record(self, mock_backend: MockBackend):
        """Test creating TXT record."""
        fqdn = await mock_backend.create_txt_record(
            zone="example.com",
            name="_chat._a2a._agents",
            values=["capabilities=chat,assistant", "version=1.0.0"],
            ttl=3600,
        )

        assert fqdn == "_chat._a2a._agents.example.com"

        values = mock_backend.get_txt_record("example.com", "_chat._a2a._agents")
        assert values is not None
        assert "capabilities=chat,assistant" in values
        assert "version=1.0.0" in values

    @pytest.mark.asyncio
    async def test_delete_record(self, mock_backend: MockBackend):
        """Test deleting record."""
        await mock_backend.create_svcb_record(
            zone="example.com",
            name="_chat._a2a._agents",
            priority=1,
            target="chat.example.com.",
            params={},
        )

        # Delete
        result = await mock_backend.delete_record(
            zone="example.com",
            name="_chat._a2a._agents",
            record_type="SVCB",
        )

        assert result is True
        assert mock_backend.get_svcb_record("example.com", "_chat._a2a._agents") is None

    @pytest.mark.asyncio
    async def test_delete_nonexistent(self, mock_backend: MockBackend):
        """Test deleting non-existent record."""
        result = await mock_backend.delete_record(
            zone="example.com",
            name="_nonexistent._a2a._agents",
            record_type="SVCB",
        )

        assert result is False

    @pytest.mark.asyncio
    async def test_list_records(self, mock_backend: MockBackend):
        """Test listing records."""
        # Create some records
        await mock_backend.create_svcb_record(
            zone="example.com",
            name="_chat._a2a._agents",
            priority=1,
            target="chat.example.com.",
            params={"alpn": "a2a"},
        )
        await mock_backend.create_svcb_record(
            zone="example.com",
            name="_network._mcp._agents",
            priority=1,
            target="mcp.example.com.",
            params={"alpn": "mcp"},
        )

        # List all
        records = []
        async for record in mock_backend.list_records("example.com"):
            records.append(record)

        assert len(records) == 2

    @pytest.mark.asyncio
    async def test_list_records_with_filter(self, mock_backend: MockBackend):
        """Test listing records with type filter."""
        await mock_backend.create_svcb_record(
            zone="example.com",
            name="_chat._a2a._agents",
            priority=1,
            target="chat.example.com.",
            params={},
        )
        await mock_backend.create_txt_record(
            zone="example.com",
            name="_chat._a2a._agents",
            values=["test=value"],
        )

        # List only SVCB
        records = []
        async for record in mock_backend.list_records("example.com", record_type="SVCB"):
            records.append(record)

        assert len(records) == 1
        assert records[0]["type"] == "SVCB"

    @pytest.mark.asyncio
    async def test_zone_exists_all_valid(self, mock_backend: MockBackend):
        """Test zone_exists when no restrictions."""
        # Default: all zones valid
        assert await mock_backend.zone_exists("any.com") is True
        assert await mock_backend.zone_exists("another.org") is True

    @pytest.mark.asyncio
    async def test_zone_exists_restricted(self):
        """Test zone_exists with restrictions."""
        backend = MockBackend(zones=["allowed.com", "also-allowed.org"])

        assert await backend.zone_exists("allowed.com") is True
        assert await backend.zone_exists("also-allowed.org") is True
        assert await backend.zone_exists("not-allowed.com") is False

    def test_clear(self, mock_backend: MockBackend):
        """Test clearing all records."""
        mock_backend.records["example.com"]["test"]["SVCB"] = [{"test": True}]

        mock_backend.clear()

        assert len(mock_backend.records) == 0

    @pytest.mark.asyncio
    async def test_get_record_svcb(self, mock_backend: MockBackend):
        """Test get_record() for SVCB records."""
        await mock_backend.create_svcb_record(
            zone="example.com",
            name="_chat._a2a._agents",
            priority=1,
            target="chat.example.com.",
            params={"alpn": "a2a", "port": "443"},
            ttl=3600,
        )

        result = await mock_backend.get_record("example.com", "_chat._a2a._agents", "SVCB")

        assert result is not None
        assert result["name"] == "_chat._a2a._agents"
        assert result["fqdn"] == "_chat._a2a._agents.example.com"
        assert result["type"] == "SVCB"
        assert result["ttl"] == 3600
        # SVCB values formatted as "priority target params..."
        assert len(result["values"]) == 1
        assert "chat.example.com." in result["values"][0]

    @pytest.mark.asyncio
    async def test_get_record_txt(self, mock_backend: MockBackend):
        """Test get_record() for TXT records."""
        await mock_backend.create_txt_record(
            zone="example.com",
            name="_chat._a2a._agents",
            values=["capabilities=chat,assistant", "version=1.0.0"],
        )

        result = await mock_backend.get_record("example.com", "_chat._a2a._agents", "TXT")

        assert result is not None
        assert result["type"] == "TXT"
        assert "capabilities=chat,assistant" in result["values"]

    @pytest.mark.asyncio
    async def test_get_record_not_found(self, mock_backend: MockBackend):
        """Test get_record() returns None for missing records."""
        result = await mock_backend.get_record("example.com", "_nope._mcp._agents", "SVCB")
        assert result is None

    @pytest.mark.asyncio
    async def test_publish_agent_helper(self, mock_backend: MockBackend, sample_agent):
        """Test publish_agent convenience method.

        Default walkable=False under -02 (avoids enumeration handle).
        Opt into walkable explicitly to verify the AliasMode write.
        """
        sample_agent.publish_walkable_alias = True
        records = await mock_backend.publish_agent(sample_agent)

        # SVCB primary + TXT companion + walkable AliasMode (opted in).
        assert len(records) == 3
        assert any("SVCB" in r for r in records)
        assert any("TXT" in r for r in records)
        assert any("AliasMode" in r for r in records)

        # Verify records created — flat primary owner under draft-02
        svcb = mock_backend.get_svcb_record(sample_agent.domain, sample_agent.name)
        assert svcb is not None
