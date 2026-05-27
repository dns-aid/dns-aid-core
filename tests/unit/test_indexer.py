# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for DNS-AID indexer."""

import pytest

from dns_aid.backends.mock import MockBackend
from dns_aid.core.indexer import (
    INDEX_RECORD_NAME,
    IndexEntry,
    IndexResult,
    delete_index,
    format_index_txt,
    parse_index_txt,
    read_index,
    sync_index,
    update_index,
)
from dns_aid.core.publisher import publish


class TestIndexEntry:
    """Tests for IndexEntry dataclass."""

    def test_str_representation(self):
        """Test string representation."""
        entry = IndexEntry(name="chat", protocol="mcp")
        assert str(entry) == "chat:mcp"

    def test_equality(self):
        """Test equality comparison."""
        entry1 = IndexEntry(name="chat", protocol="mcp")
        entry2 = IndexEntry(name="chat", protocol="mcp")
        entry3 = IndexEntry(name="chat", protocol="a2a")

        assert entry1 == entry2
        assert entry1 != entry3

    def test_hash(self):
        """Test hash for use in sets."""
        entry1 = IndexEntry(name="chat", protocol="mcp")
        entry2 = IndexEntry(name="chat", protocol="mcp")

        # Should be able to use in sets
        entries = {entry1, entry2}
        assert len(entries) == 1

    def test_hash_different_entries(self):
        """Test hash uniqueness for different entries."""
        entry1 = IndexEntry(name="chat", protocol="mcp")
        entry2 = IndexEntry(name="chat", protocol="a2a")
        entry3 = IndexEntry(name="billing", protocol="mcp")

        entries = {entry1, entry2, entry3}
        assert len(entries) == 3


class TestParseIndexTxt:
    """Tests for parse_index_txt function."""

    def test_parse_single_entry(self):
        """Test parsing a single entry."""
        txt = "agents=chat:mcp"
        entries = parse_index_txt(txt)

        assert len(entries) == 1
        assert entries[0].name == "chat"
        assert entries[0].protocol == "mcp"

    def test_parse_multiple_entries(self):
        """Test parsing multiple entries."""
        txt = "agents=chat:mcp,billing:a2a,support:https"
        entries = parse_index_txt(txt)

        assert len(entries) == 3
        assert IndexEntry(name="chat", protocol="mcp") in entries
        assert IndexEntry(name="billing", protocol="a2a") in entries
        assert IndexEntry(name="support", protocol="https") in entries

    def test_parse_with_spaces(self):
        """Test parsing with extra spaces."""
        txt = "agents=chat:mcp, billing:a2a , support:https"
        entries = parse_index_txt(txt)

        assert len(entries) == 3
        assert entries[0].name == "chat"
        assert entries[1].name == "billing"
        assert entries[2].name == "support"

    def test_parse_empty_agents(self):
        """Test parsing empty agents list."""
        txt = "agents="
        entries = parse_index_txt(txt)

        assert len(entries) == 0

    def test_parse_invalid_format(self):
        """Test parsing invalid format returns empty list."""
        txt = "not-agents-format"
        entries = parse_index_txt(txt)

        assert len(entries) == 0

    def test_parse_malformed_entries(self):
        """Test parsing skips malformed entries."""
        txt = "agents=chat:mcp,malformed,billing:a2a"
        entries = parse_index_txt(txt)

        # Should only parse valid entries
        assert len(entries) == 2
        assert IndexEntry(name="chat", protocol="mcp") in entries
        assert IndexEntry(name="billing", protocol="a2a") in entries

    def test_parse_protocol_lowercase(self):
        """Test protocol is normalized to lowercase."""
        txt = "agents=chat:MCP,billing:A2A"
        entries = parse_index_txt(txt)

        assert len(entries) == 2
        assert entries[0].protocol == "mcp"
        assert entries[1].protocol == "a2a"


class TestFormatIndexTxt:
    """Tests for format_index_txt function."""

    def test_format_single_entry(self):
        """Test formatting a single entry."""
        entries = [IndexEntry(name="chat", protocol="mcp")]
        txt = format_index_txt(entries)

        assert txt == "agents=chat:mcp"

    def test_format_multiple_entries(self):
        """Test formatting multiple entries (sorted)."""
        entries = [
            IndexEntry(name="chat", protocol="mcp"),
            IndexEntry(name="billing", protocol="a2a"),
        ]
        txt = format_index_txt(entries)

        # Should be sorted by name then protocol
        assert txt == "agents=billing:a2a,chat:mcp"

    def test_format_empty_list(self):
        """Test formatting empty list."""
        entries = []
        txt = format_index_txt(entries)

        assert txt == "agents="

    def test_format_roundtrip(self):
        """Test that format and parse are inverses."""
        original = [
            IndexEntry(name="chat", protocol="mcp"),
            IndexEntry(name="billing", protocol="a2a"),
            IndexEntry(name="support", protocol="https"),
        ]
        txt = format_index_txt(original)
        parsed = parse_index_txt(txt)

        assert set(parsed) == set(original)


class TestReadIndex:
    """Tests for read_index function."""

    @pytest.mark.asyncio
    async def test_read_empty_index(self, mock_backend: MockBackend):
        """Test reading from domain with no index."""
        entries = await read_index("example.com", mock_backend)

        assert len(entries) == 0

    @pytest.mark.asyncio
    async def test_read_existing_index(self, mock_backend: MockBackend):
        """Test reading an existing index record."""
        # Create an index record manually
        await mock_backend.create_txt_record(
            zone="example.com",
            name=INDEX_RECORD_NAME,
            values=["agents=chat:mcp,billing:a2a"],
            ttl=3600,
        )

        entries = await read_index("example.com", mock_backend)

        assert len(entries) == 2
        assert IndexEntry(name="chat", protocol="mcp") in entries
        assert IndexEntry(name="billing", protocol="a2a") in entries

    @pytest.mark.asyncio
    async def test_read_index_with_quotes(self, mock_backend: MockBackend):
        """Test reading index record with quoted values."""
        await mock_backend.create_txt_record(
            zone="example.com",
            name=INDEX_RECORD_NAME,
            values=['"agents=chat:mcp"'],
            ttl=3600,
        )

        entries = await read_index("example.com", mock_backend)

        assert len(entries) == 1
        assert entries[0].name == "chat"


class TestUpdateIndex:
    """Tests for update_index function."""

    @pytest.mark.asyncio
    async def test_update_add_first_entry(self, mock_backend: MockBackend):
        """Test adding the first entry to an empty index."""
        result = await update_index(
            domain="example.com",
            backend=mock_backend,
            add=[IndexEntry(name="chat", protocol="mcp")],
        )

        assert result.success is True
        assert result.created is True
        assert len(result.entries) == 1
        assert result.entries[0].name == "chat"

    @pytest.mark.asyncio
    async def test_update_add_to_existing(self, mock_backend: MockBackend):
        """Test adding an entry to an existing index."""
        # Create initial index
        await mock_backend.create_txt_record(
            zone="example.com",
            name=INDEX_RECORD_NAME,
            values=["agents=chat:mcp"],
            ttl=3600,
        )

        result = await update_index(
            domain="example.com",
            backend=mock_backend,
            add=[IndexEntry(name="billing", protocol="a2a")],
        )

        assert result.success is True
        assert result.created is False
        assert len(result.entries) == 2

    @pytest.mark.asyncio
    async def test_update_remove_entry(self, mock_backend: MockBackend):
        """Test removing an entry from the index."""
        # Create initial index
        await mock_backend.create_txt_record(
            zone="example.com",
            name=INDEX_RECORD_NAME,
            values=["agents=chat:mcp,billing:a2a"],
            ttl=3600,
        )

        result = await update_index(
            domain="example.com",
            backend=mock_backend,
            remove=[IndexEntry(name="chat", protocol="mcp")],
        )

        assert result.success is True
        assert len(result.entries) == 1
        assert result.entries[0].name == "billing"

    @pytest.mark.asyncio
    async def test_update_add_and_remove(self, mock_backend: MockBackend):
        """Test adding and removing entries simultaneously."""
        # Create initial index
        await mock_backend.create_txt_record(
            zone="example.com",
            name=INDEX_RECORD_NAME,
            values=["agents=chat:mcp,billing:a2a"],
            ttl=3600,
        )

        result = await update_index(
            domain="example.com",
            backend=mock_backend,
            add=[IndexEntry(name="support", protocol="https")],
            remove=[IndexEntry(name="chat", protocol="mcp")],
        )

        assert result.success is True
        assert len(result.entries) == 2
        assert IndexEntry(name="billing", protocol="a2a") in result.entries
        assert IndexEntry(name="support", protocol="https") in result.entries
        assert IndexEntry(name="chat", protocol="mcp") not in result.entries

    @pytest.mark.asyncio
    async def test_update_nonexistent_zone(self, mock_backend: MockBackend):
        """Test updating index for non-existent zone fails."""
        mock_backend._zones = {"allowed.com"}

        result = await update_index(
            domain="notallowed.com",
            backend=mock_backend,
            add=[IndexEntry(name="chat", protocol="mcp")],
        )

        assert result.success is False
        assert "does not exist" in result.message

    @pytest.mark.asyncio
    async def test_update_duplicate_entry(self, mock_backend: MockBackend):
        """Test adding duplicate entry is idempotent."""
        # Create initial index
        await mock_backend.create_txt_record(
            zone="example.com",
            name=INDEX_RECORD_NAME,
            values=["agents=chat:mcp"],
            ttl=3600,
        )

        result = await update_index(
            domain="example.com",
            backend=mock_backend,
            add=[IndexEntry(name="chat", protocol="mcp")],  # Already exists
        )

        assert result.success is True
        assert len(result.entries) == 1  # No duplicate

    @pytest.mark.asyncio
    async def test_update_custom_ttl(self, mock_backend: MockBackend):
        """Test updating index with custom TTL."""
        result = await update_index(
            domain="example.com",
            backend=mock_backend,
            add=[IndexEntry(name="chat", protocol="mcp")],
            ttl=300,
        )

        assert result.success is True

        # Verify TTL was set (check mock backend)
        txt = mock_backend.get_txt_record("example.com", INDEX_RECORD_NAME)
        assert txt is not None


class TestUpdateIndexSvcbPrimary:
    """Tests for draft-02 SVCB-primary org index (opt-in via index_target)."""

    @pytest.mark.asyncio
    async def test_index_target_writes_svcb_and_txt(self, mock_backend: MockBackend):
        """When index_target is provided, both SVCB and TXT records are written."""
        result = await update_index(
            domain="example.com",
            backend=mock_backend,
            add=[IndexEntry(name="chat", protocol="mcp")],
            index_target="agent-index.example.com",
        )

        assert result.success is True

        # SVCB primary at _index._agents pointing at the (non-underscored) target
        svcb = mock_backend.get_svcb_record("example.com", INDEX_RECORD_NAME)
        assert svcb is not None
        assert svcb["priority"] == 1  # ServiceMode
        assert svcb["target"] == "agent-index.example.com."

        # TXT inline-listing still written as the §TXT-fallback form
        txt = mock_backend.get_txt_record("example.com", INDEX_RECORD_NAME)
        assert txt is not None
        assert any("chat:mcp" in v for v in txt)

    @pytest.mark.asyncio
    async def test_index_target_underscored_rejected(self, mock_backend: MockBackend):
        """Underscored TargetName fails the validator (no public x.509 cert)."""
        from dns_aid.utils.validation import ValidationError

        with pytest.raises(ValidationError) as exc:
            await update_index(
                domain="example.com",
                backend=mock_backend,
                add=[IndexEntry(name="chat", protocol="mcp")],
                index_target="_internal.example.com",
            )
        assert exc.value.field == "target"

    @pytest.mark.asyncio
    async def test_no_index_target_keeps_txt_only(self, mock_backend: MockBackend):
        """Without index_target the behavior matches pre-draft-02 (TXT only)."""
        result = await update_index(
            domain="example.com",
            backend=mock_backend,
            add=[IndexEntry(name="chat", protocol="mcp")],
        )

        assert result.success is True
        assert mock_backend.get_svcb_record("example.com", INDEX_RECORD_NAME) is None
        assert mock_backend.get_txt_record("example.com", INDEX_RECORD_NAME) is not None


class TestDeleteIndex:
    """Tests for delete_index function."""

    @pytest.mark.asyncio
    async def test_delete_existing_index(self, mock_backend: MockBackend):
        """Test deleting an existing index."""
        # Create index first
        await mock_backend.create_txt_record(
            zone="example.com",
            name=INDEX_RECORD_NAME,
            values=["agents=chat:mcp"],
            ttl=3600,
        )

        result = await delete_index("example.com", mock_backend)

        assert result is True

        # Verify deleted
        entries = await read_index("example.com", mock_backend)
        assert len(entries) == 0

    @pytest.mark.asyncio
    async def test_delete_nonexistent_index(self, mock_backend: MockBackend):
        """Test deleting non-existent index returns False."""
        result = await delete_index("example.com", mock_backend)

        assert result is False


class TestSyncIndex:
    """Tests for sync_index function."""

    @pytest.mark.asyncio
    async def test_sync_empty_zone(self, mock_backend: MockBackend):
        """Test syncing an empty zone."""
        result = await sync_index("example.com", mock_backend)

        assert result.success is True
        assert len(result.entries) == 0

    @pytest.mark.asyncio
    async def test_sync_discovers_agents(self, mock_backend: MockBackend):
        """Test that sync discovers published agents."""
        # Publish some agents
        await publish(
            name="chat",
            domain="example.com",
            protocol="mcp",
            endpoint="mcp.example.com",
            backend=mock_backend,
        )
        await publish(
            name="billing",
            domain="example.com",
            protocol="a2a",
            endpoint="a2a.example.com",
            backend=mock_backend,
        )

        result = await sync_index("example.com", mock_backend)

        assert result.success is True
        assert len(result.entries) == 2
        assert IndexEntry(name="chat", protocol="mcp") in result.entries
        assert IndexEntry(name="billing", protocol="a2a") in result.entries

    @pytest.mark.asyncio
    async def test_sync_creates_index(self, mock_backend: MockBackend):
        """Test that sync creates index if it doesn't exist."""
        # Publish an agent (without updating index)
        await publish(
            name="chat",
            domain="example.com",
            protocol="mcp",
            endpoint="mcp.example.com",
            backend=mock_backend,
        )

        result = await sync_index("example.com", mock_backend)

        assert result.success is True
        assert result.created is True
        assert len(result.entries) == 1

    @pytest.mark.asyncio
    async def test_sync_updates_stale_index(self, mock_backend: MockBackend):
        """Test that sync updates an outdated index."""
        # Create stale index
        await mock_backend.create_txt_record(
            zone="example.com",
            name=INDEX_RECORD_NAME,
            values=["agents=oldagent:mcp"],
            ttl=3600,
        )

        # Publish new agent
        await publish(
            name="chat",
            domain="example.com",
            protocol="mcp",
            endpoint="mcp.example.com",
            backend=mock_backend,
        )

        result = await sync_index("example.com", mock_backend)

        assert result.success is True
        # Index should only contain discovered agents, not stale ones
        assert len(result.entries) == 1
        assert result.entries[0].name == "chat"

    @pytest.mark.asyncio
    async def test_sync_custom_ttl(self, mock_backend: MockBackend):
        """Test syncing with custom TTL."""
        await publish(
            name="chat",
            domain="example.com",
            protocol="mcp",
            endpoint="mcp.example.com",
            backend=mock_backend,
        )

        result = await sync_index("example.com", mock_backend, ttl=300)

        assert result.success is True


class TestIndexResult:
    """Tests for IndexResult dataclass."""

    def test_result_fields(self):
        """Test IndexResult has expected fields."""
        result = IndexResult(
            domain="example.com",
            entries=[IndexEntry(name="chat", protocol="mcp")],
            success=True,
            message="Updated",
            created=True,
        )

        assert result.domain == "example.com"
        assert len(result.entries) == 1
        assert result.success is True
        assert result.message == "Updated"
        assert result.created is True

    def test_result_created_default(self):
        """Test created defaults to False."""
        result = IndexResult(
            domain="example.com",
            entries=[],
            success=True,
            message="OK",
        )

        assert result.created is False


# =============================================================================
# Additional coverage tests
# =============================================================================


class TestIndexEntryEq:
    """Tests for IndexEntry.__eq__ with non-IndexEntry objects."""

    def test_eq_non_indexentry(self):
        """Comparing IndexEntry to non-IndexEntry returns NotImplemented."""
        entry = IndexEntry(name="chat", protocol="mcp")
        result = entry.__eq__("not-an-entry")
        assert result is NotImplemented

    def test_eq_none(self):
        """Comparing IndexEntry to None returns NotImplemented."""
        entry = IndexEntry(name="chat", protocol="mcp")
        result = entry.__eq__(None)
        assert result is NotImplemented


class TestReadIndexViaDns:
    """Tests for read_index_via_dns function."""

    @pytest.mark.asyncio
    async def test_read_index_via_dns_success(self):
        """Successful DNS TXT query returns parsed entries."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from dns_aid.core.indexer import read_index_via_dns

        mock_rdata = MagicMock()
        mock_rdata.strings = [b"agents=chat:mcp,billing:a2a"]

        mock_answers = MagicMock()
        mock_answers.__iter__ = MagicMock(return_value=iter([mock_rdata]))

        with patch("dns_aid.core.indexer.dns.asyncresolver.Resolver") as mock_resolver:
            resolver_instance = MagicMock()
            resolver_instance.resolve = AsyncMock(return_value=mock_answers)
            mock_resolver.return_value = resolver_instance

            entries = await read_index_via_dns("example.com")

        assert len(entries) == 2
        assert IndexEntry(name="chat", protocol="mcp") in entries
        assert IndexEntry(name="billing", protocol="a2a") in entries

    @pytest.mark.asyncio
    async def test_read_index_via_dns_nxdomain(self):
        """NXDOMAIN returns empty list."""
        from unittest.mock import AsyncMock, MagicMock, patch

        import dns.resolver

        from dns_aid.core.indexer import read_index_via_dns

        with patch("dns_aid.core.indexer.dns.asyncresolver.Resolver") as mock_resolver:
            resolver_instance = MagicMock()
            resolver_instance.resolve = AsyncMock(side_effect=dns.resolver.NXDOMAIN())
            mock_resolver.return_value = resolver_instance

            entries = await read_index_via_dns("nonexistent.com")

        assert entries == []

    @pytest.mark.asyncio
    async def test_read_index_via_dns_generic_error(self):
        """Generic exception returns empty list."""
        from unittest.mock import AsyncMock, MagicMock, patch

        from dns_aid.core.indexer import read_index_via_dns

        with patch("dns_aid.core.indexer.dns.asyncresolver.Resolver") as mock_resolver:
            resolver_instance = MagicMock()
            resolver_instance.resolve = AsyncMock(side_effect=Exception("DNS failure"))
            mock_resolver.return_value = resolver_instance

            entries = await read_index_via_dns("example.com")

        assert entries == []


class TestDeleteIndexException:
    """Tests for delete_index exception path."""

    @pytest.mark.asyncio
    async def test_delete_index_exception(self):
        """Backend raises during delete → returns False."""
        from unittest.mock import AsyncMock, MagicMock

        from dns_aid.core.indexer import delete_index

        mock_backend = MagicMock()
        mock_backend.delete_record = AsyncMock(side_effect=RuntimeError("boom"))

        result = await delete_index("example.com", mock_backend)
        assert result is False


class TestSyncIndexScanException:
    """Tests for sync_index when list_records raises."""

    @pytest.mark.asyncio
    async def test_sync_index_scan_exception(self):
        """list_records raises during scan → returns failure."""
        from unittest.mock import AsyncMock, MagicMock

        from dns_aid.core.indexer import sync_index

        async def _failing_list(*args, **kwargs):
            raise RuntimeError("scan boom")
            # Make it an async generator that raises
            yield  # pragma: no cover

        mock_backend = MagicMock()
        mock_backend.zone_exists = AsyncMock(return_value=True)
        mock_backend.list_records = _failing_list

        result = await sync_index("example.com", mock_backend)
        assert result.success is False
        assert "scan boom" in result.message
