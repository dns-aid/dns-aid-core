# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for dns_aid.backends.akamai_edgedns module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from dns_aid.backends.akamai_edgedns import AkamaiEdgeDNSBackend

# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestAkamaiEdgeDNSBackendInit:
    """Tests for AkamaiEdgeDNSBackend initialization."""

    def test_init_with_explicit_credentials(self):
        backend = AkamaiEdgeDNSBackend(
            host="akab-test.luna.akamaiapis.net",
            client_token="ct-xxx",
            client_secret="cs-xxx",
            access_token="at-xxx",
        )
        assert backend._host == "akab-test.luna.akamaiapis.net"
        assert backend._client_token == "ct-xxx"
        assert backend._client_secret == "cs-xxx"
        assert backend._access_token == "at-xxx"

    def test_init_from_env_vars(self):
        env = {
            "AKAMAI_HOST": "akab-env.luna.akamaiapis.net",
            "AKAMAI_CLIENT_TOKEN": "ct-env",
            "AKAMAI_CLIENT_SECRET": "cs-env",
            "AKAMAI_ACCESS_TOKEN": "at-env",
        }
        with patch.dict("os.environ", env):
            backend = AkamaiEdgeDNSBackend()
            assert backend._host == "akab-env.luna.akamaiapis.net"
            assert backend._client_token == "ct-env"

    def test_init_defaults(self):
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )
        assert backend._client is None
        assert backend._zone_cache == {}
        assert backend._auth is None
        assert backend._edgerc_path == "~/.edgerc"
        assert backend._edgerc_section == "default"

    def test_init_custom_edgerc(self):
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
            edgerc_path="/custom/.edgerc",
            edgerc_section="dns",
        )
        assert backend._edgerc_path == "/custom/.edgerc"
        assert backend._edgerc_section == "dns"


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------


class TestAkamaiEdgeDNSBackendProperties:
    """Tests for backend properties."""

    def test_name_property(self):
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )
        assert backend.name == "akamai-edgedns"

    def test_supports_private_svcb_keys(self):
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )
        assert backend.supports_private_svcb_keys is True


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


class TestAkamaiEdgeDNSBackendAuth:
    """Tests for EdgeGrid authentication initialization."""

    def test_ensure_auth_with_env_credentials(self):
        backend = AkamaiEdgeDNSBackend(
            host="akab-test.luna.akamaiapis.net",
            client_token="ct-xxx",
            client_secret="cs-xxx",
            access_token="at-xxx",
        )
        MockAuth = MagicMock()
        with patch("dns_aid.backends.akamai_edgedns.AkamaiEdgeDNSBackend._ensure_auth") as m:
            m.side_effect = lambda: setattr(backend, "_auth", MockAuth)
            backend._ensure_auth()
            assert backend._auth is not None

    def test_ensure_auth_raises_without_credentials(self):
        backend = AkamaiEdgeDNSBackend()
        backend._edgerc_path = "/nonexistent/.edgerc"
        with pytest.raises(ValueError, match="credentials not configured"):
            backend._ensure_auth()


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class TestAkamaiEdgeDNSBackendClient:
    """Tests for httpx client creation."""

    @pytest.mark.asyncio
    async def test_get_client_creates_client(self):
        backend = AkamaiEdgeDNSBackend(
            host="akab-test.luna.akamaiapis.net",
            client_token="ct-xxx",
            client_secret="cs-xxx",
            access_token="at-xxx",
        )
        mock_auth = MagicMock()
        with patch.object(
            backend, "_ensure_auth", side_effect=lambda: setattr(backend, "_auth", mock_auth)
        ):
            client = await backend._get_client()
            assert isinstance(client, httpx.AsyncClient)
            await backend.close()

    @pytest.mark.asyncio
    async def test_get_client_caches_client(self):
        backend = AkamaiEdgeDNSBackend(
            host="akab-test.luna.akamaiapis.net",
            client_token="ct-xxx",
            client_secret="cs-xxx",
            access_token="at-xxx",
        )
        mock_auth = MagicMock()
        with patch.object(
            backend, "_ensure_auth", side_effect=lambda: setattr(backend, "_auth", mock_auth)
        ):
            client1 = await backend._get_client()
            client2 = await backend._get_client()
            assert client1 is client2
            await backend.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TestAkamaiEdgeDNSHelpers:
    """Tests for helper methods."""

    def test_to_fqdn(self):
        assert (
            AkamaiEdgeDNSBackend._to_fqdn("_chat._a2a._agents", "example.com")
            == "_chat._a2a._agents.example.com"
        )

    def test_to_fqdn_already_qualified(self):
        assert (
            AkamaiEdgeDNSBackend._to_fqdn("_chat._agents.example.com", "example.com")
            == "_chat._agents.example.com"
        )

    def test_to_fqdn_strips_trailing_dot(self):
        assert AkamaiEdgeDNSBackend._to_fqdn("_chat", "example.com.") == "_chat.example.com"

    def test_extract_name_from_fqdn(self):
        assert (
            AkamaiEdgeDNSBackend._extract_name_from_fqdn("_chat._agents.example.com", "example.com")
            == "_chat._agents"
        )

    def test_extract_name_from_fqdn_no_match(self):
        assert (
            AkamaiEdgeDNSBackend._extract_name_from_fqdn("other.net", "example.com") == "other.net"
        )

    def test_to_numeric_key_custom(self):
        assert AkamaiEdgeDNSBackend._to_numeric_key("cap") == "key65400"
        assert AkamaiEdgeDNSBackend._to_numeric_key("bap") == "key65402"
        assert AkamaiEdgeDNSBackend._to_numeric_key("realm") == "key65404"

    def test_to_numeric_key_standard(self):
        assert AkamaiEdgeDNSBackend._to_numeric_key("alpn") == "alpn"
        assert AkamaiEdgeDNSBackend._to_numeric_key("port") == "port"

    def test_to_numeric_key_already_numeric(self):
        assert AkamaiEdgeDNSBackend._to_numeric_key("key65500") == "key65500"

    def test_from_numeric_key(self):
        assert AkamaiEdgeDNSBackend._from_numeric_key("key65400") == "cap"
        assert AkamaiEdgeDNSBackend._from_numeric_key("key65402") == "bap"

    def test_from_numeric_key_unknown(self):
        assert AkamaiEdgeDNSBackend._from_numeric_key("alpn") == "alpn"

    def test_build_url(self):
        backend = AkamaiEdgeDNSBackend(
            host="akab-test.luna.akamaiapis.net",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )
        assert (
            backend._build_url("/config-dns/v2/zones")
            == "https://akab-test.luna.akamaiapis.net/config-dns/v2/zones"
        )

    def test_build_url_with_https_prefix(self):
        backend = AkamaiEdgeDNSBackend(
            host="https://akab-test.luna.akamaiapis.net",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )
        assert (
            backend._build_url("/config-dns/v2/zones")
            == "https://akab-test.luna.akamaiapis.net/config-dns/v2/zones"
        )


# ---------------------------------------------------------------------------
# SVCB rdata formatting
# ---------------------------------------------------------------------------


class TestAkamaiEdgeDNSSvcbFormat:
    """Tests for SVCB rdata formatting."""

    def test_format_svcb_rdata_basic(self):
        rdata = AkamaiEdgeDNSBackend._format_svcb_rdata(
            priority=1,
            target="chat.example.com",
            params={"alpn": "a2a", "port": "443"},
        )
        assert rdata.startswith("1 chat.example.com.")
        assert 'alpn="a2a"' in rdata
        assert 'port="443"' in rdata

    def test_format_svcb_rdata_trailing_dot_preserved(self):
        rdata = AkamaiEdgeDNSBackend._format_svcb_rdata(
            priority=1,
            target="chat.example.com.",
            params={},
        )
        assert rdata == "1 chat.example.com."

    def test_format_svcb_rdata_custom_params_mapped(self):
        rdata = AkamaiEdgeDNSBackend._format_svcb_rdata(
            priority=1,
            target="chat.example.com",
            params={"alpn": "mcp", "cap": "https://cap.example.com"},
        )
        assert 'key65400="https://cap.example.com"' in rdata
        assert 'alpn="mcp"' in rdata

    def test_format_svcb_rdata_no_params(self):
        rdata = AkamaiEdgeDNSBackend._format_svcb_rdata(
            priority=0,
            target="alias.example.com.",
            params={},
        )
        assert rdata == "0 alias.example.com."

    def test_format_svcb_rdata_all_custom_params(self):
        rdata = AkamaiEdgeDNSBackend._format_svcb_rdata(
            priority=1,
            target="t.example.com",
            params={
                "cap": "https://cap.example.com",
                "bap": "mcp=1.0",
                "realm": "prod",
            },
        )
        assert 'key65400="https://cap.example.com"' in rdata
        assert 'key65402="mcp=1.0"' in rdata
        assert 'key65404="prod"' in rdata


# ---------------------------------------------------------------------------
# Create SVCB record
# ---------------------------------------------------------------------------


class TestAkamaiEdgeDNSCreateSvcb:
    """Tests for SVCB record creation."""

    @pytest.mark.asyncio
    async def test_create_svcb_record_new(self):
        backend = AkamaiEdgeDNSBackend(
            host="akab-test.luna.akamaiapis.net",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        call_log: list[tuple[str, str]] = []

        async def mock_request(method, path, **kwargs):
            call_log.append((method, path))
            if method == "GET":
                return None  # record doesn't exist
            return {}

        with patch.object(backend, "_request", side_effect=mock_request):
            result = await backend.create_svcb_record(
                zone="example.com",
                name="_chat._a2a._agents",
                priority=1,
                target="chat.example.com",
                params={"alpn": "a2a", "port": "443"},
                ttl=3600,
            )

        assert result == "_chat._a2a._agents.example.com"
        assert call_log[0] == (
            "GET",
            "/config-dns/v2/zones/example.com/names/_chat._a2a._agents.example.com/types/SVCB",
        )
        assert call_log[1][0] == "POST"

    @pytest.mark.asyncio
    async def test_create_svcb_record_update_existing(self):
        backend = AkamaiEdgeDNSBackend(
            host="akab-test.luna.akamaiapis.net",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        call_log: list[tuple[str, str]] = []

        async def mock_request(method, path, **kwargs):
            call_log.append((method, path))
            if method == "GET":
                return {"name": "fqdn", "type": "SVCB", "ttl": 3600, "rdata": ["1 old."]}
            return {}

        with patch.object(backend, "_request", side_effect=mock_request):
            result = await backend.create_svcb_record(
                zone="example.com",
                name="_chat._a2a._agents",
                priority=1,
                target="chat.example.com",
                params={"alpn": "a2a"},
                ttl=3600,
            )

        assert result == "_chat._a2a._agents.example.com"
        assert call_log[1][0] == "PUT"

    @pytest.mark.asyncio
    async def test_create_svcb_passes_custom_params_natively(self):
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        captured_payload: list[dict] = []

        async def mock_request(method, path, *, json_data=None, **kwargs):
            if method == "GET":
                return None
            if json_data:
                captured_payload.append(json_data)
            return {}

        with patch.object(backend, "_request", side_effect=mock_request):
            await backend.create_svcb_record(
                zone="example.com",
                name="agent",
                priority=1,
                target="agent.example.com",
                params={"alpn": "mcp", "port": "443", "cap": "https://c.example.com"},
            )

        rdata = captured_payload[0]["rdata"][0]
        assert 'key65400="https://c.example.com"' in rdata
        assert 'alpn="mcp"' in rdata


# ---------------------------------------------------------------------------
# Create TXT record
# ---------------------------------------------------------------------------


class TestAkamaiEdgeDNSCreateTxt:
    """Tests for TXT record creation."""

    @pytest.mark.asyncio
    async def test_create_txt_record_new(self):
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        captured_payload: list[dict] = []

        async def mock_request(method, path, *, json_data=None, **kwargs):
            if method == "GET":
                return None
            if json_data:
                captured_payload.append(json_data)
            return {}

        with patch.object(backend, "_request", side_effect=mock_request):
            result = await backend.create_txt_record(
                zone="example.com",
                name="_chat._agents",
                values=["capabilities=chat,code", "version=1.0.0"],
                ttl=3600,
            )

        assert result == "_chat._agents.example.com"
        assert captured_payload[0]["type"] == "TXT"
        assert "capabilities=chat,code version=1.0.0" in captured_payload[0]["rdata"][0]


# ---------------------------------------------------------------------------
# Delete record
# ---------------------------------------------------------------------------


class TestAkamaiEdgeDNSDeleteRecord:
    """Tests for record deletion."""

    @pytest.mark.asyncio
    async def test_delete_record_success(self):
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        async def mock_request(method, path, **kwargs):
            return {}

        with patch.object(backend, "_request", side_effect=mock_request):
            result = await backend.delete_record(
                zone="example.com",
                name="_chat._agents",
                record_type="SVCB",
            )

        assert result is True

    @pytest.mark.asyncio
    async def test_delete_record_not_found(self):
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        async def mock_request(method, path, **kwargs):
            return None

        with patch.object(backend, "_request", side_effect=mock_request):
            result = await backend.delete_record(
                zone="example.com",
                name="_nonexistent._agents",
                record_type="SVCB",
            )

        assert result is False


# ---------------------------------------------------------------------------
# List records
# ---------------------------------------------------------------------------


class TestAkamaiEdgeDNSListRecords:
    """Tests for record listing."""

    @pytest.mark.asyncio
    async def test_list_records_all(self):
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        async def mock_request(method, path, *, params=None, **kwargs):
            return {
                "recordsets": [
                    {
                        "name": "_chat._agents.example.com",
                        "type": "SVCB",
                        "ttl": 3600,
                        "rdata": ['1 chat.example.com. alpn="mcp"'],
                    },
                    {
                        "name": "_chat._agents.example.com",
                        "type": "TXT",
                        "ttl": 3600,
                        "rdata": ["capabilities=chat"],
                    },
                ],
                "metadata": {"totalElements": 2, "pageSize": 100},
            }

        with patch.object(backend, "_request", side_effect=mock_request):
            records = []
            async for record in backend.list_records(zone="example.com"):
                records.append(record)

        assert len(records) == 2
        assert records[0]["type"] == "SVCB"
        assert records[1]["type"] == "TXT"

    @pytest.mark.asyncio
    async def test_list_records_filter_by_name(self):
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        async def mock_request(method, path, *, params=None, **kwargs):
            return {
                "recordsets": [
                    {"name": "_chat._agents.example.com", "type": "SVCB", "ttl": 3600, "rdata": []},
                    {"name": "www.example.com", "type": "A", "ttl": 300, "rdata": []},
                ],
                "metadata": {"totalElements": 2, "pageSize": 100},
            }

        with patch.object(backend, "_request", side_effect=mock_request):
            records = []
            async for record in backend.list_records(zone="example.com", name_pattern="_agents"):
                records.append(record)

        assert len(records) == 1
        assert "_agents" in records[0]["fqdn"]

    @pytest.mark.asyncio
    async def test_list_records_pagination(self):
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        call_count = 0

        async def mock_request(method, path, *, params=None, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {
                    "recordsets": [
                        {"name": "a.example.com", "type": "TXT", "ttl": 300, "rdata": ["v1"]},
                    ],
                    "metadata": {"totalElements": 2, "pageSize": 1},
                }
            return {
                "recordsets": [
                    {"name": "b.example.com", "type": "TXT", "ttl": 300, "rdata": ["v2"]},
                ],
                "metadata": {"totalElements": 2, "pageSize": 1},
            }

        with patch.object(backend, "_request", side_effect=mock_request):
            records = []
            async for record in backend.list_records(zone="example.com"):
                records.append(record)

        assert len(records) == 2


# ---------------------------------------------------------------------------
# Get record
# ---------------------------------------------------------------------------


class TestAkamaiEdgeDNSGetRecord:
    """Tests for get_record method."""

    @pytest.mark.asyncio
    async def test_get_record_found(self):
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        async def mock_request(method, path, **kwargs):
            return {
                "name": "_chat._agents.example.com",
                "type": "SVCB",
                "ttl": 3600,
                "rdata": ['1 chat.example.com. alpn="a2a"'],
            }

        with patch.object(backend, "_request", side_effect=mock_request):
            record = await backend.get_record("example.com", "_chat._agents", "SVCB")

        assert record is not None
        assert record["type"] == "SVCB"
        assert record["fqdn"] == "_chat._agents.example.com"
        assert '1 chat.example.com. alpn="a2a"' in record["values"]

    @pytest.mark.asyncio
    async def test_get_record_not_found(self):
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        async def mock_request(method, path, **kwargs):
            return None

        with patch.object(backend, "_request", side_effect=mock_request):
            record = await backend.get_record("example.com", "_missing._agents", "SVCB")

        assert record is None


# ---------------------------------------------------------------------------
# Zone exists
# ---------------------------------------------------------------------------


class TestAkamaiEdgeDNSZoneExists:
    """Tests for zone existence check."""

    @pytest.mark.asyncio
    async def test_zone_exists_true(self):
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        async def mock_request(method, path, **kwargs):
            return {"zone": "example.com", "type": "primary"}

        with patch.object(backend, "_request", side_effect=mock_request):
            result = await backend.zone_exists("example.com")

        assert result is True
        assert backend._zone_cache["example.com"] is True

    @pytest.mark.asyncio
    async def test_zone_exists_false(self):
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        async def mock_request(method, path, **kwargs):
            return None

        with patch.object(backend, "_request", side_effect=mock_request):
            result = await backend.zone_exists("notfound.com")

        assert result is False

    @pytest.mark.asyncio
    async def test_zone_exists_cached(self):
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )
        backend._zone_cache["cached.com"] = True

        result = await backend.zone_exists("cached.com")
        assert result is True

    @pytest.mark.asyncio
    async def test_zone_exists_error_returns_false(self):
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        async def mock_request(method, path, **kwargs):
            raise RuntimeError("API error")

        with patch.object(backend, "_request", side_effect=mock_request):
            result = await backend.zone_exists("error.com")

        assert result is False


# ---------------------------------------------------------------------------
# List zones
# ---------------------------------------------------------------------------


class TestAkamaiEdgeDNSListZones:
    """Tests for listing zones."""

    @pytest.mark.asyncio
    async def test_list_zones(self):
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        async def mock_request(method, path, *, params=None, **kwargs):
            return {
                "zones": [
                    {"zone": "example.com", "type": "primary", "contractId": "ctr-123"},
                    {"zone": "other.com", "type": "secondary", "contractId": "ctr-456"},
                ],
                "metadata": {"totalElements": 2, "pageSize": 100},
            }

        with patch.object(backend, "_request", side_effect=mock_request):
            zones = await backend.list_zones()

        assert len(zones) == 2
        assert zones[0]["name"] == "example.com"
        assert zones[0]["type"] == "primary"
        assert zones[1]["name"] == "other.com"


# ---------------------------------------------------------------------------
# Close
# ---------------------------------------------------------------------------


class TestAkamaiEdgeDNSClose:
    """Tests for client cleanup."""

    @pytest.mark.asyncio
    async def test_close(self):
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        mock_auth = MagicMock()
        with patch.object(
            backend, "_ensure_auth", side_effect=lambda: setattr(backend, "_auth", mock_auth)
        ):
            await backend._get_client()
            assert backend._client is not None

            await backend.close()
            assert backend._client is None


# ---------------------------------------------------------------------------
# Param demotion (should NOT demote — supports_private_svcb_keys = True)
# ---------------------------------------------------------------------------


class TestAkamaiEdgeDNSPublishAgentNoDemotion:
    """Akamai Edge DNS passes ALL SVCB params natively — no demotion to TXT."""

    @pytest.mark.asyncio
    async def test_publish_passes_all_params_to_svcb(self):
        from dns_aid.core.models import AgentRecord, Protocol

        agent = AgentRecord(
            name="lf-test",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="lf-test.example.com",
            port=443,
            capabilities=["testing"],
            realm="demo",
            publish_walkable_alias=True,
        )

        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        svcb_calls: list[dict] = []
        txt_calls: list[dict] = []

        async def _mock_create_svcb(**kwargs):
            svcb_calls.append(kwargs)
            return f"SVCB {kwargs.get('name', '')}.{kwargs.get('zone', '')}"

        async def _mock_create_txt(**kwargs):
            txt_calls.append(kwargs)
            return f"TXT {kwargs.get('name', '')}.{kwargs.get('zone', '')}"

        with (
            patch.object(backend, "create_svcb_record", side_effect=_mock_create_svcb),
            patch.object(backend, "create_txt_record", side_effect=_mock_create_txt),
        ):
            records = await backend.publish_agent(agent)

        # SVCB primary + TXT + walkable AliasMode
        assert any(r.startswith("SVCB") for r in records)

        # SVCB params SHOULD contain custom keys (no demotion)
        svcb_params = svcb_calls[0]["params"]
        custom_keys = [
            k
            for k in svcb_params
            if k
            not in {
                "mandatory",
                "alpn",
                "no-default-alpn",
                "port",
                "ipv4hint",
                "ipv6hint",
                "ech",
            }
        ]
        assert len(custom_keys) > 0, "Custom params should be in SVCB, not demoted"

        # TXT should NOT contain dnsaid_ demoted params
        if txt_calls:
            txt_values = txt_calls[0]["values"]
            dnsaid_txt = [v for v in txt_values if v.startswith("dnsaid_")]
            assert len(dnsaid_txt) == 0, "No dnsaid_ params should appear in TXT"
