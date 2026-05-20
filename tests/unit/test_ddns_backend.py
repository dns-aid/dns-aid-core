# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for dns_aid.backends.ddns module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import dns.rcode
import dns.rdatatype
import pytest

from dns_aid.backends.ddns import DDNSBackend


class TestDDNSBackendInit:
    """Tests for DDNSBackend initialization."""

    def test_init_with_all_params(self):
        """Test initialization with all parameters provided."""
        backend = DDNSBackend(
            server="ns1.example.com",
            key_name="test-key",
            key_secret="dGVzdHNlY3JldA==",  # base64 encoded "testsecret"
            key_algorithm="hmac-sha256",
            port=53,
            timeout=10.0,
        )
        assert backend.server == "ns1.example.com"
        assert backend.key_name == "test-key"
        assert backend.key_algorithm == "hmac-sha256"
        assert backend.port == 53
        assert backend.timeout == 10.0

    def test_init_with_env_vars(self):
        """Test initialization from environment variables."""
        with patch.dict(
            "os.environ",
            {
                "DDNS_SERVER": "ns2.example.com",
                "DDNS_KEY_NAME": "env-key",
                "DDNS_KEY_SECRET": "ZW52c2VjcmV0",
                "DDNS_KEY_ALGORITHM": "hmac-sha512",
                "DDNS_PORT": "5353",
                "DDNS_TIMEOUT": "30",
            },
        ):
            backend = DDNSBackend()
            assert backend.server == "ns2.example.com"
            assert backend.key_name == "env-key"
            assert backend.key_algorithm == "hmac-sha512"
            assert backend.port == 5353
            assert backend.timeout == 30.0

    def test_init_missing_server_raises(self):
        """Test that missing server raises ValueError."""
        with pytest.raises(ValueError, match="DDNS server not configured"):
            DDNSBackend(key_name="test", key_secret="c2VjcmV0")

    def test_init_missing_key_raises(self):
        """Test that missing TSIG key raises ValueError."""
        with pytest.raises(ValueError, match="TSIG key not configured"):
            DDNSBackend(server="ns1.example.com")

    def test_init_invalid_algorithm_raises(self):
        """Test that invalid algorithm raises ValueError."""
        with pytest.raises(ValueError, match="Unsupported TSIG algorithm"):
            DDNSBackend(
                server="ns1.example.com",
                key_name="test",
                key_secret="c2VjcmV0",
                key_algorithm="invalid-algo",
            )

    def test_supported_algorithms(self):
        """Test all supported algorithms."""
        for algo in DDNSBackend.SUPPORTED_ALGORITHMS:
            backend = DDNSBackend(
                server="ns1.example.com",
                key_name="test",
                key_secret="c2VjcmV0",
                key_algorithm=algo,
            )
            assert backend.key_algorithm == algo


class TestDDNSBackendKeyFile:
    """Tests for TSIG key file loading."""

    def test_load_key_file(self, tmp_path):
        """Test loading TSIG key from file."""
        key_file = tmp_path / "test.key"
        key_file.write_text("""
key "dns-aid-key" {
    algorithm hmac-sha256;
    secret "c2VjcmV0c2VjcmV0";
};
""")
        backend = DDNSBackend(server="ns1.example.com", key_file=key_file)
        assert backend.key_name == "dns-aid-key"
        assert backend.key_algorithm == "hmac-sha256"
        assert backend.key_secret == "c2VjcmV0c2VjcmV0"

    def test_load_key_file_not_found(self, tmp_path):
        """Test that missing key file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            DDNSBackend(server="ns1.example.com", key_file=tmp_path / "nonexistent.key")

    def test_load_invalid_key_file(self, tmp_path):
        """Test that invalid key file format raises ValueError."""
        key_file = tmp_path / "invalid.key"
        key_file.write_text("invalid content")
        with pytest.raises(ValueError, match="Invalid TSIG key file format"):
            DDNSBackend(server="ns1.example.com", key_file=key_file)


class TestDDNSBackendProperties:
    """Tests for DDNSBackend properties."""

    @pytest.fixture
    def backend(self):
        """Create a test backend."""
        return DDNSBackend(
            server="ns1.example.com",
            key_name="test-key",
            key_secret="c2VjcmV0",
        )

    def test_name_property(self, backend):
        """Test name property returns 'ddns'."""
        assert backend.name == "ddns"


class TestDDNSBackendSvcbRecord:
    """Tests for SVCB record creation."""

    @pytest.fixture
    def backend(self):
        """Create a test backend."""
        return DDNSBackend(
            server="ns1.example.com",
            key_name="test-key",
            key_secret="c2VjcmV0",
        )

    def test_format_svcb_rdata(self, backend):
        """Test SVCB rdata formatting."""
        rdata = backend._format_svcb_rdata(
            priority=1,
            target="chat.example.com",
            params={"alpn": "a2a", "port": "443"},
        )
        assert "1 chat.example.com." in rdata
        assert 'alpn="a2a"' in rdata
        assert 'port="443"' in rdata

    def test_format_svcb_rdata_adds_trailing_dot(self, backend):
        """Test that target gets trailing dot added."""
        rdata = backend._format_svcb_rdata(
            priority=1,
            target="chat.example.com",
            params={},
        )
        assert "chat.example.com." in rdata

    @pytest.mark.asyncio
    async def test_create_svcb_record_success(self, backend):
        """Test successful SVCB record creation."""
        mock_response = MagicMock()
        mock_response.rcode.return_value = dns.rcode.NOERROR

        with patch("dns.query.tcp", return_value=mock_response):
            result = await backend.create_svcb_record(
                zone="example.com",
                name="_chat._a2a._agents",
                priority=1,
                target="chat.example.com",
                params={"alpn": "a2a", "port": "443"},
                ttl=3600,
            )
            assert result == "_chat._a2a._agents.example.com"

    @pytest.mark.asyncio
    async def test_create_svcb_record_failure(self, backend):
        """Test SVCB record creation failure."""
        mock_response = MagicMock()
        mock_response.rcode.return_value = dns.rcode.REFUSED

        with (
            patch("dns.query.tcp", return_value=mock_response),
            pytest.raises(RuntimeError, match="DDNS update failed"),
        ):
            await backend.create_svcb_record(
                zone="example.com",
                name="_chat._a2a._agents",
                priority=1,
                target="chat.example.com",
                params={"alpn": "a2a"},
            )

    @pytest.mark.asyncio
    async def test_create_svcb_record_bad_response(self, backend):
        """Test SVCB record creation with bad response."""
        with (
            patch("dns.query.tcp", side_effect=dns.query.BadResponse("Bad response")),
            pytest.raises(RuntimeError, match="DDNS update failed"),
        ):
            await backend.create_svcb_record(
                zone="example.com",
                name="_chat._a2a._agents",
                priority=1,
                target="chat.example.com",
                params={},
            )


class TestDDNSBackendTxtRecord:
    """Tests for TXT record creation."""

    @pytest.fixture
    def backend(self):
        """Create a test backend."""
        return DDNSBackend(
            server="ns1.example.com",
            key_name="test-key",
            key_secret="c2VjcmV0",
        )

    @pytest.mark.asyncio
    async def test_create_txt_record_success(self, backend):
        """Test successful TXT record creation."""
        mock_response = MagicMock()
        mock_response.rcode.return_value = dns.rcode.NOERROR

        with patch("dns.query.tcp", return_value=mock_response):
            result = await backend.create_txt_record(
                zone="example.com",
                name="_chat._a2a._agents",
                values=["capabilities=chat,code", "version=1.0.0"],
                ttl=3600,
            )
            assert result == "_chat._a2a._agents.example.com"

    @pytest.mark.asyncio
    async def test_create_txt_record_failure(self, backend):
        """Test TXT record creation failure."""
        mock_response = MagicMock()
        mock_response.rcode.return_value = dns.rcode.SERVFAIL

        with (
            patch("dns.query.tcp", return_value=mock_response),
            pytest.raises(RuntimeError, match="DDNS update failed"),
        ):
            await backend.create_txt_record(
                zone="example.com",
                name="_chat._a2a._agents",
                values=["test=value"],
            )


class TestDDNSBackendDeleteRecord:
    """Tests for record deletion."""

    @pytest.fixture
    def backend(self):
        """Create a test backend."""
        return DDNSBackend(
            server="ns1.example.com",
            key_name="test-key",
            key_secret="c2VjcmV0",
        )

    @pytest.mark.asyncio
    async def test_delete_record_success(self, backend):
        """Test successful record deletion."""
        mock_response = MagicMock()
        mock_response.rcode.return_value = dns.rcode.NOERROR

        with patch("dns.query.tcp", return_value=mock_response):
            result = await backend.delete_record(
                zone="example.com",
                name="_chat._a2a._agents",
                record_type="SVCB",
            )
            assert result is True

    @pytest.mark.asyncio
    async def test_delete_record_non_noerror(self, backend):
        """Test record deletion with non-NOERROR response."""
        mock_response = MagicMock()
        mock_response.rcode.return_value = dns.rcode.NXDOMAIN

        with patch("dns.query.tcp", return_value=mock_response):
            result = await backend.delete_record(
                zone="example.com",
                name="_chat._a2a._agents",
                record_type="SVCB",
            )
            assert result is False

    @pytest.mark.asyncio
    async def test_delete_record_bad_response(self, backend):
        """Test record deletion with bad response."""
        with patch("dns.query.tcp", side_effect=dns.query.BadResponse("Bad")):
            result = await backend.delete_record(
                zone="example.com",
                name="_chat._a2a._agents",
                record_type="SVCB",
            )
            assert result is False


class TestDDNSBackendListRecords:
    """Tests for record listing."""

    @pytest.fixture
    def backend(self):
        """Create a test backend."""
        return DDNSBackend(
            server="ns1.example.com",
            key_name="test-key",
            key_secret="c2VjcmV0",
        )

    @pytest.mark.asyncio
    async def test_list_records_specific_name(self, backend):
        """Test listing records with specific name."""
        mock_answer = MagicMock()
        mock_answer.rrset.ttl = 3600
        mock_rdata = MagicMock()
        mock_rdata.__str__ = lambda self: "1 chat.example.com. alpn=a2a"
        mock_answer.__iter__ = lambda self: iter([mock_rdata])

        with patch("dns.resolver.resolve", return_value=mock_answer):
            records = []
            async for record in backend.list_records(
                zone="example.com",
                name_pattern="_chat._a2a._agents",
                record_type="SVCB",
            ):
                records.append(record)
            assert len(records) == 1
            assert records[0]["name"] == "_chat._a2a._agents"

    @pytest.mark.asyncio
    async def test_list_records_nxdomain(self, backend):
        """Test listing records when name doesn't exist."""
        with patch("dns.resolver.resolve", side_effect=dns.resolver.NXDOMAIN()):
            records = []
            async for record in backend.list_records(
                zone="example.com",
                name_pattern="_nonexistent._agents",
            ):
                records.append(record)
            assert len(records) == 0

    @pytest.mark.asyncio
    async def test_list_records_wildcard_returns_empty(self, backend):
        """Test that wildcard pattern returns empty (DDNS can't enumerate)."""
        records = []
        async for record in backend.list_records(
            zone="example.com",
            name_pattern="*._agents",
        ):
            records.append(record)
        # DDNS can't list without specific name pattern
        assert len(records) == 0

    @pytest.mark.asyncio
    async def test_list_records_yields_values_list_not_data_string(self, backend):
        """Regression for #137: ``list_records`` MUST yield ``values`` as a
        list (matching every other backend's documented contract), NOT a
        singular ``data`` string. ``read_index()`` reads ``values`` per the
        contract; the previous shape made it invisible to DDNS records,
        causing the index to be overwritten on multi-agent publish."""
        mock_answer = MagicMock()
        mock_answer.rrset.ttl = 3600
        mock_rdata = MagicMock()
        mock_rdata.__str__ = lambda self: '"agents=alpha:mcp,beta:a2a"'
        mock_answer.__iter__ = lambda self: iter([mock_rdata])

        with patch("dns.resolver.resolve", return_value=mock_answer):
            records = []
            async for record in backend.list_records(
                zone="example.com",
                name_pattern="_index._agents",
                record_type="TXT",
            ):
                records.append(record)

        assert len(records) == 1
        record = records[0]
        # The contract: ``values`` is a list of strings.
        assert "values" in record, (
            f"DDNS must yield 'values' key per the documented contract; got {record!r}"
        )
        assert isinstance(record["values"], list), (
            f"'values' must be a list, got {type(record['values']).__name__}"
        )
        assert record["values"] == ['"agents=alpha:mcp,beta:a2a"']
        # And NOT the legacy ``data`` singular string key.
        assert "data" not in record, (
            f"'data' key from the broken pre-fix shape must not appear; got {record!r}"
        )

    @pytest.mark.asyncio
    async def test_list_records_groups_multiple_rdata_into_one_dict(self, backend):
        """Multiple rdata at the same (name, type) MUST be grouped into one
        yielded dict with a multi-element ``values`` list — NOT yielded as
        separate dicts. Matches Route53/Cloudflare/NS1 grouping behavior."""
        mock_answer = MagicMock()
        mock_answer.rrset.ttl = 3600
        r1 = MagicMock()
        r1.__str__ = lambda self: "value-one"
        r2 = MagicMock()
        r2.__str__ = lambda self: "value-two"
        r3 = MagicMock()
        r3.__str__ = lambda self: "value-three"
        mock_answer.__iter__ = lambda self: iter([r1, r2, r3])

        with patch("dns.resolver.resolve", return_value=mock_answer):
            records = []
            async for record in backend.list_records(
                zone="example.com",
                name_pattern="_some._agents",
                record_type="TXT",
            ):
                records.append(record)

        # One dict, three values — NOT three dicts.
        assert len(records) == 1, (
            f"3 rdata must group into 1 dict, got {len(records)} dicts: {records!r}"
        )
        assert records[0]["values"] == ["value-one", "value-two", "value-three"]


class TestDDNSBackendZoneExists:
    """Tests for zone existence check."""

    @pytest.fixture
    def backend(self):
        """Create a test backend."""
        return DDNSBackend(
            server="ns1.example.com",
            key_name="test-key",
            key_secret="c2VjcmV0",
        )

    @pytest.mark.asyncio
    async def test_zone_exists_true(self, backend):
        """Test zone exists returns True."""
        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()
            mock_resolver_class.return_value = mock_resolver
            mock_resolver.resolve.return_value = MagicMock()

            result = await backend.zone_exists("example.com")
            assert result is True

    @pytest.mark.asyncio
    async def test_zone_exists_nxdomain(self, backend):
        """Test zone exists returns False for NXDOMAIN."""
        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()
            mock_resolver_class.return_value = mock_resolver
            mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()

            result = await backend.zone_exists("nonexistent.com")
            assert result is False

    @pytest.mark.asyncio
    async def test_zone_exists_exception(self, backend):
        """Test zone exists returns False on exception."""
        with patch("dns.resolver.Resolver") as mock_resolver_class:
            mock_resolver = MagicMock()
            mock_resolver_class.return_value = mock_resolver
            mock_resolver.resolve.side_effect = Exception("Network error")

            result = await backend.zone_exists("example.com")
            assert result is False


class TestDDNSBackendContextManager:
    """Tests for async context manager."""

    @pytest.fixture
    def backend(self):
        """Create a test backend."""
        return DDNSBackend(
            server="ns1.example.com",
            key_name="test-key",
            key_secret="c2VjcmV0",
        )

    @pytest.mark.asyncio
    async def test_async_context_manager(self, backend):
        """Test async context manager protocol."""
        async with backend as b:
            assert b is backend
