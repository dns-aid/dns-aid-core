# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for dns_aid.backends.ns1 module."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from dns_aid.backends.ns1 import NS1Backend


class TestNS1BackendInit:
    """Tests for NS1Backend initialization."""

    def test_init_with_api_key(self):
        """Test initialization with API key."""
        backend = NS1Backend(api_key="test-key-123")
        assert backend._api_key == "test-key-123"

    def test_init_with_base_url(self):
        """Test initialization with custom base URL."""
        backend = NS1Backend(api_key="key", base_url="https://custom.ns1.net/v2")
        assert backend._base_url == "https://custom.ns1.net/v2"

    def test_init_from_env_key(self):
        """Test API key from environment variable."""
        with patch.dict("os.environ", {"NS1_API_KEY": "env-key"}):
            backend = NS1Backend()
            assert backend._api_key == "env-key"

    def test_init_from_env_base_url(self):
        """Test base URL from environment variable."""
        with patch.dict(
            "os.environ",
            {"NS1_API_KEY": "key", "NS1_BASE_URL": "https://env.ns1.net/v2"},
        ):
            backend = NS1Backend()
            assert backend._base_url == "https://env.ns1.net/v2"

    def test_init_defaults(self):
        """Test default values."""
        backend = NS1Backend(api_key="key")
        assert backend._client is None
        assert backend._zone_cache == {}
        assert backend._base_url == "https://api.nsone.net/v1"


class TestNS1BackendProperties:
    """Tests for NS1Backend properties."""

    def test_name_property(self):
        """Test name property returns 'ns1'."""
        backend = NS1Backend(api_key="key")
        assert backend.name == "ns1"


class TestNS1BackendHelpers:
    """Tests for _normalize and _extract_values helpers."""

    def test_normalize_with_name(self):
        """Test _normalize returns (domain, fqdn)."""
        backend = NS1Backend(api_key="key")
        domain, fqdn = backend._normalize("example.com", "_chat._mcp._agents")
        assert domain == "example.com"
        assert fqdn == "_chat._mcp._agents.example.com"

    def test_normalize_without_name(self):
        """Test _normalize with no name returns domain as fqdn."""
        backend = NS1Backend(api_key="key")
        domain, fqdn = backend._normalize("example.com")
        assert domain == "example.com"
        assert fqdn == "example.com"

    def test_normalize_strips_trailing_dot(self):
        """Test _normalize strips trailing dot from zone."""
        backend = NS1Backend(api_key="key")
        domain, fqdn = backend._normalize("example.com.", "_chat")
        assert domain == "example.com"
        assert fqdn == "_chat.example.com"

    def test_normalize_lowercases(self):
        """Test _normalize lowercases the domain."""
        backend = NS1Backend(api_key="key")
        domain, fqdn = backend._normalize("Example.COM", "_chat")
        assert domain == "example.com"
        assert fqdn == "_chat.example.com"

    def test_extract_values_single_answer(self):
        """Test _extract_values with a single answer."""
        answers = [{"answer": ['1 chat.example.com. alpn="mcp" port="443"']}]
        values = NS1Backend._extract_values(answers)
        assert values == ['1 chat.example.com. alpn="mcp" port="443"']

    def test_extract_values_multiple_answers(self):
        """Test _extract_values with multiple answers."""
        answers = [
            {"answer": ["version=1.0.0"]},
            {"answer": ["capabilities=chat,search"]},
        ]
        values = NS1Backend._extract_values(answers)
        assert values == ["version=1.0.0", "capabilities=chat,search"]

    def test_extract_values_empty(self):
        """Test _extract_values with no answers."""
        assert NS1Backend._extract_values([]) == []

    def test_extract_values_missing_answer_key(self):
        """Test _extract_values with missing answer key in dict."""
        answers = [{"meta": {}}]
        values = NS1Backend._extract_values(answers)
        assert values == [""]


class TestNS1BackendClient:
    """Tests for httpx client creation."""

    @pytest.mark.asyncio
    async def test_get_client_creates_client(self):
        """Test that _get_client creates httpx client."""
        backend = NS1Backend(api_key="test-key")

        client = await backend._get_client()

        assert isinstance(client, httpx.AsyncClient)
        assert client.headers["X-NSONE-Key"] == "test-key"
        assert client.headers["Content-Type"] == "application/json"

        await backend.close()

    @pytest.mark.asyncio
    async def test_get_client_caches_client(self):
        """Test that client is cached."""
        backend = NS1Backend(api_key="test-key")

        client1 = await backend._get_client()
        client2 = await backend._get_client()

        assert client1 is client2

        await backend.close()

    @pytest.mark.asyncio
    async def test_get_client_raises_without_key(self):
        """Test that missing API key raises ValueError."""
        backend = NS1Backend()
        backend._api_key = None

        with pytest.raises(ValueError, match="API key not configured"):
            await backend._get_client()


class TestNS1BackendZone:
    """Tests for zone resolution."""

    @pytest.mark.asyncio
    async def test_get_zone_from_cache(self):
        """Test that cached zone is returned."""
        backend = NS1Backend(api_key="key")
        backend._zone_cache["example.com"] = {"zone": "example.com"}

        zone = await backend._get_zone("example.com")
        assert zone == {"zone": "example.com"}

    @pytest.mark.asyncio
    async def test_get_zone_from_api(self):
        """Test zone lookup from API."""
        backend = NS1Backend(api_key="key")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "zone": "example.com",
            "records": [],
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch.object(backend, "_get_client", return_value=mock_client):
            zone = await backend._get_zone("example.com")
            assert zone["zone"] == "example.com"
            assert "example.com" in backend._zone_cache

    @pytest.mark.asyncio
    async def test_get_zone_not_found(self):
        """Test zone lookup when zone doesn't exist."""
        backend = NS1Backend(api_key="key")

        mock_response = MagicMock()
        mock_response.status_code = 404

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with (
            patch.object(backend, "_get_client", return_value=mock_client),
            pytest.raises(ValueError, match="No zone found"),
        ):
            await backend._get_zone("notfound.com")

    @pytest.mark.asyncio
    async def test_get_zone_strips_trailing_dot(self):
        """Test that trailing dots are stripped from zone names."""
        backend = NS1Backend(api_key="key")
        backend._zone_cache["example.com"] = {"zone": "example.com"}

        zone = await backend._get_zone("example.com.")
        assert zone == {"zone": "example.com"}


class TestNS1BackendFormatSvcb:
    """Tests for SVCB data formatting."""

    def test_format_svcb_rdata_basic(self):
        """Test basic SVCB rdata formatting."""
        backend = NS1Backend(api_key="key")
        rdata = backend._format_svcb_rdata(
            priority=1,
            target="chat.example.com",
            params={"alpn": "a2a", "port": "443"},
        )
        assert "1 chat.example.com." in rdata
        assert 'alpn="a2a"' in rdata
        assert 'port="443"' in rdata

    def test_format_svcb_rdata_adds_trailing_dot(self):
        """Test that trailing dot is added to target."""
        backend = NS1Backend(api_key="key")
        rdata = backend._format_svcb_rdata(
            priority=1,
            target="chat.example.com",
            params={},
        )
        assert rdata == "1 chat.example.com."

    def test_format_svcb_rdata_preserves_trailing_dot(self):
        """Test that existing trailing dot is preserved."""
        backend = NS1Backend(api_key="key")
        rdata = backend._format_svcb_rdata(
            priority=1,
            target="chat.example.com.",
            params={},
        )
        assert rdata == "1 chat.example.com."

    def test_format_svcb_rdata_no_params(self):
        """Test SVCB rdata with no params."""
        backend = NS1Backend(api_key="key")
        rdata = backend._format_svcb_rdata(
            priority=0,
            target="alias.example.com.",
            params={},
        )
        assert rdata == "0 alias.example.com."


class TestNS1BackendUpsert:
    """Tests for the _upsert_record method (PUT create, POST update on 400)."""

    @pytest.mark.asyncio
    async def test_upsert_put_creates(self):
        """Test upsert when PUT succeeds (new record created)."""
        backend = NS1Backend(api_key="key")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.put = AsyncMock(return_value=mock_response)

        with patch.object(backend, "_get_client", return_value=mock_client):
            resp = await backend._upsert_record(
                "example.com",
                "_chat.example.com",
                "SVCB",
                {"type": "SVCB", "answers": [{"answer": ["1 t."]}], "ttl": 300},
            )
            assert resp.status_code == 200
            mock_client.put.assert_called_once()
            mock_client.post.assert_not_called()

    @pytest.mark.asyncio
    async def test_upsert_falls_back_to_post_on_400(self):
        """Test upsert falls back to POST when PUT returns 400 (record exists)."""
        backend = NS1Backend(api_key="key")

        mock_400 = MagicMock()
        mock_400.status_code = 400

        mock_200 = MagicMock()
        mock_200.status_code = 200
        mock_200.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.put = AsyncMock(return_value=mock_400)
        mock_client.post = AsyncMock(return_value=mock_200)

        with patch.object(backend, "_get_client", return_value=mock_client):
            resp = await backend._upsert_record(
                "example.com",
                "_chat.example.com",
                "SVCB",
                {"type": "SVCB", "answers": [{"answer": ["1 t."]}], "ttl": 300},
            )
            assert resp.status_code == 200
            mock_client.put.assert_called_once()
            mock_client.post.assert_called_once()
            # POST should only send answers + ttl, not zone/domain
            post_data = mock_client.post.call_args[1]["json"]
            assert "answers" in post_data
            assert "zone" not in post_data
            assert "domain" not in post_data

    @pytest.mark.asyncio
    async def test_upsert_propagates_server_errors(self):
        """Test upsert propagates server errors from PUT."""
        backend = NS1Backend(api_key="key")

        mock_500 = MagicMock()
        mock_500.status_code = 500
        mock_500.raise_for_status = MagicMock(
            side_effect=httpx.HTTPStatusError(
                "Server Error", request=MagicMock(), response=mock_500
            )
        )

        mock_client = AsyncMock()
        mock_client.put = AsyncMock(return_value=mock_500)

        with (
            patch.object(backend, "_get_client", return_value=mock_client),
            pytest.raises(httpx.HTTPStatusError),
        ):
            await backend._upsert_record(
                "example.com",
                "_chat.example.com",
                "SVCB",
                {"type": "SVCB", "answers": [{"answer": ["1 t."]}]},
            )


class TestNS1BackendCreateSvcb:
    """Tests for SVCB record creation."""

    @pytest.mark.asyncio
    async def test_create_svcb_record_success(self):
        """Test successful SVCB record creation via PUT."""
        backend = NS1Backend(api_key="key")
        backend._zone_cache["example.com"] = {"zone": "example.com"}

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"domain": "_chat._a2a._agents.example.com"}
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.put = AsyncMock(return_value=mock_response)

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend.create_svcb_record(
                zone="example.com",
                name="_chat._a2a._agents",
                priority=1,
                target="chat.example.com",
                params={"alpn": "a2a", "port": "443"},
                ttl=3600,
            )

            assert result == "_chat._a2a._agents.example.com"
            mock_client.put.assert_called_once()

            # Verify the request payload
            call_kwargs = mock_client.put.call_args
            json_data = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
            assert json_data["type"] == "SVCB"
            assert json_data["ttl"] == 3600
            assert len(json_data["answers"]) == 1

    @pytest.mark.asyncio
    async def test_create_svcb_record_update_fallback(self):
        """Test SVCB update via POST when PUT returns 400 (record exists)."""
        backend = NS1Backend(api_key="key")
        backend._zone_cache["example.com"] = {"zone": "example.com"}

        mock_400 = MagicMock()
        mock_400.status_code = 400

        mock_200 = MagicMock()
        mock_200.status_code = 200
        mock_200.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.put = AsyncMock(return_value=mock_400)
        mock_client.post = AsyncMock(return_value=mock_200)

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend.create_svcb_record(
                zone="example.com",
                name="_chat._a2a._agents",
                priority=1,
                target="chat.example.com",
                params={"alpn": "a2a", "port": "443"},
            )

            assert result == "_chat._a2a._agents.example.com"
            mock_client.put.assert_called_once()
            mock_client.post.assert_called_once()


class TestNS1BackendCreateTxt:
    """Tests for TXT record creation."""

    @pytest.mark.asyncio
    async def test_create_txt_record_success(self):
        """Test successful TXT record creation."""
        backend = NS1Backend(api_key="key")
        backend._zone_cache["example.com"] = {"zone": "example.com"}

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"domain": "_chat._a2a._agents.example.com"}
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.put = AsyncMock(return_value=mock_response)

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend.create_txt_record(
                zone="example.com",
                name="_chat._a2a._agents",
                values=["version=1.0.0", "capabilities=chat,search"],
                ttl=3600,
            )

            assert result == "_chat._a2a._agents.example.com"
            mock_client.put.assert_called_once()

            # Verify multiple TXT values become separate answers
            call_kwargs = mock_client.put.call_args
            json_data = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
            assert json_data["type"] == "TXT"
            assert len(json_data["answers"]) == 2

    @pytest.mark.asyncio
    async def test_create_txt_record_update_fallback(self):
        """Test TXT update via POST when PUT returns 400 (record exists)."""
        backend = NS1Backend(api_key="key")
        backend._zone_cache["example.com"] = {"zone": "example.com"}

        mock_400 = MagicMock()
        mock_400.status_code = 400

        mock_200 = MagicMock()
        mock_200.status_code = 200
        mock_200.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.put = AsyncMock(return_value=mock_400)
        mock_client.post = AsyncMock(return_value=mock_200)

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend.create_txt_record(
                zone="example.com",
                name="_chat._a2a._agents",
                values=["version=1.0.0"],
            )

            assert result == "_chat._a2a._agents.example.com"
            mock_client.put.assert_called_once()
            mock_client.post.assert_called_once()


class TestNS1BackendDeleteRecord:
    """Tests for record deletion."""

    @pytest.mark.asyncio
    async def test_delete_record_success(self):
        """Test successful record deletion."""
        backend = NS1Backend(api_key="key")
        backend._zone_cache["example.com"] = {"zone": "example.com"}

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.delete = AsyncMock(return_value=mock_response)

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend.delete_record(
                zone="example.com",
                name="_chat._a2a._agents",
                record_type="SVCB",
            )

            assert result is True
            mock_client.delete.assert_called_once_with(
                "/zones/example.com/_chat._a2a._agents.example.com/SVCB"
            )

    @pytest.mark.asyncio
    async def test_delete_record_not_found(self):
        """Test deletion of non-existent record."""
        backend = NS1Backend(api_key="key")
        backend._zone_cache["example.com"] = {"zone": "example.com"}

        mock_response = MagicMock()
        mock_response.status_code = 404

        mock_client = AsyncMock()
        mock_client.delete = AsyncMock(return_value=mock_response)

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend.delete_record(
                zone="example.com",
                name="_chat._a2a._agents",
                record_type="SVCB",
            )

            assert result is False


class TestNS1BackendZoneExists:
    """Tests for zone existence check."""

    @pytest.mark.asyncio
    async def test_zone_exists_true(self):
        """Test zone_exists returns True for existing zone."""
        backend = NS1Backend(api_key="key")
        backend._zone_cache["example.com"] = {"zone": "example.com"}

        result = await backend.zone_exists("example.com")
        assert result is True

    @pytest.mark.asyncio
    async def test_zone_exists_false(self):
        """Test zone_exists returns False for missing zone."""
        backend = NS1Backend(api_key="key")

        mock_response = MagicMock()
        mock_response.status_code = 404

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend.zone_exists("notfound.com")
            assert result is False

    @pytest.mark.asyncio
    async def test_zone_exists_false_on_error(self):
        """Test zone_exists returns False on network error."""
        backend = NS1Backend(api_key="key")

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend.zone_exists("example.com")
            assert result is False


class TestNS1BackendGetRecord:
    """Tests for single record lookup."""

    @pytest.mark.asyncio
    async def test_get_record_found(self):
        """Test get_record returns record when found."""
        backend = NS1Backend(api_key="key")
        backend._zone_cache["example.com"] = {"zone": "example.com"}

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "domain": "_chat._a2a._agents.example.com",
            "type": "SVCB",
            "ttl": 3600,
            "answers": [{"answer": ['1 chat.example.com. alpn="a2a" port="443"']}],
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend.get_record(
                zone="example.com",
                name="_chat._a2a._agents",
                record_type="SVCB",
            )

            assert result is not None
            assert result["fqdn"] == "_chat._a2a._agents.example.com"
            assert result["type"] == "SVCB"
            assert result["ttl"] == 3600
            assert len(result["values"]) == 1

    @pytest.mark.asyncio
    async def test_get_record_not_found(self):
        """Test get_record returns None when not found."""
        backend = NS1Backend(api_key="key")
        backend._zone_cache["example.com"] = {"zone": "example.com"}

        mock_response = MagicMock()
        mock_response.status_code = 404

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend.get_record(
                zone="example.com",
                name="_chat._a2a._agents",
                record_type="SVCB",
            )

            assert result is None

    @pytest.mark.asyncio
    async def test_get_record_propagates_network_error(self):
        """A network error must propagate, NOT be masked as 'record absent'.

        Only a 404 means the record is missing. Swallowing a ConnectError to
        None makes a transient failure indistinguishable from absence, which
        lets callers such as publisher._unpublish disarm their masked-failure
        guard and de-index a still-live agent. Guard the raising contract so a
        future refactor can't silently re-introduce the swallow.
        """
        backend = NS1Backend(api_key="key")
        backend._zone_cache["example.com"] = {"zone": "example.com"}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("Connection refused"))

        with patch.object(backend, "_get_client", return_value=mock_client):
            with pytest.raises(httpx.ConnectError):
                await backend.get_record(
                    zone="example.com",
                    name="_chat._a2a._agents",
                    record_type="SVCB",
                )

    @pytest.mark.asyncio
    async def test_get_record_propagates_server_error(self):
        """A 5xx must propagate rather than be masked as 'record absent'."""
        backend = NS1Backend(api_key="key")
        backend._zone_cache["example.com"] = {"zone": "example.com"}

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.raise_for_status = MagicMock(
            side_effect=httpx.HTTPStatusError(
                "500 Internal Server Error",
                request=httpx.Request("GET", "https://api.nsone.net"),
                response=httpx.Response(500),
            )
        )
        # json() must never be consulted once raise_for_status has fired.
        mock_response.json = MagicMock(
            side_effect=AssertionError("json() should not be called on an error response")
        )

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch.object(backend, "_get_client", return_value=mock_client):
            with pytest.raises(httpx.HTTPStatusError):
                await backend.get_record(
                    zone="example.com",
                    name="_chat._a2a._agents",
                    record_type="SVCB",
                )


class TestNS1BackendListRecords:
    """Tests for listing records."""

    @pytest.mark.asyncio
    async def test_list_records_fetches_fresh_zone_data(self):
        """Test that list_records does a fresh GET, not using stale cache."""
        backend = NS1Backend(api_key="key")
        # Seed cache with stale data (no records)
        backend._zone_cache["example.com"] = {"zone": "example.com", "records": []}

        # Fresh zone response has a record
        mock_zone_resp = MagicMock()
        mock_zone_resp.status_code = 200
        mock_zone_resp.json.return_value = {
            "zone": "example.com",
            "records": [
                {"domain": "_chat._mcp._agents.example.com", "type": "SVCB"},
            ],
        }
        mock_zone_resp.raise_for_status = MagicMock()

        mock_detail_resp = MagicMock()
        mock_detail_resp.status_code = 200
        mock_detail_resp.json.return_value = {
            "domain": "_chat._mcp._agents.example.com",
            "type": "SVCB",
            "ttl": 3600,
            "answers": [{"answer": ['1 chat.example.com. alpn="mcp" port="443"']}],
        }

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[mock_zone_resp, mock_detail_resp])

        with patch.object(backend, "_get_client", return_value=mock_client):
            records = []
            async for record in backend.list_records(zone="example.com"):
                records.append(record)

            # Should find the record from the fresh fetch, not the empty cache
            assert len(records) == 1
            assert records[0]["fqdn"] == "_chat._mcp._agents.example.com"

    @pytest.mark.asyncio
    async def test_list_records_with_type_filter(self):
        """Test listing records with type filter."""
        backend = NS1Backend(api_key="key")

        mock_zone_resp = MagicMock()
        mock_zone_resp.status_code = 200
        mock_zone_resp.json.return_value = {
            "zone": "example.com",
            "records": [
                {"domain": "_chat._mcp._agents.example.com", "type": "SVCB"},
                {"domain": "_chat._mcp._agents.example.com", "type": "TXT"},
                {"domain": "www.example.com", "type": "A"},
            ],
        }
        mock_zone_resp.raise_for_status = MagicMock()

        mock_detail_resp = MagicMock()
        mock_detail_resp.status_code = 200
        mock_detail_resp.json.return_value = {
            "domain": "_chat._mcp._agents.example.com",
            "type": "SVCB",
            "ttl": 3600,
            "answers": [{"answer": ['1 chat.example.com. alpn="mcp" port="443"']}],
        }

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[mock_zone_resp, mock_detail_resp])

        with patch.object(backend, "_get_client", return_value=mock_client):
            records = []
            async for record in backend.list_records(
                zone="example.com",
                record_type="SVCB",
            ):
                records.append(record)

            assert len(records) == 1
            assert records[0]["type"] == "SVCB"

    @pytest.mark.asyncio
    async def test_list_records_with_name_filter(self):
        """Test listing records with name pattern filter."""
        backend = NS1Backend(api_key="key")

        mock_zone_resp = MagicMock()
        mock_zone_resp.status_code = 200
        mock_zone_resp.json.return_value = {
            "zone": "example.com",
            "records": [
                {"domain": "_chat._mcp._agents.example.com", "type": "SVCB"},
                {"domain": "_search._mcp._agents.example.com", "type": "SVCB"},
            ],
        }
        mock_zone_resp.raise_for_status = MagicMock()

        mock_detail_resp = MagicMock()
        mock_detail_resp.status_code = 200
        mock_detail_resp.json.return_value = {
            "domain": "_chat._mcp._agents.example.com",
            "type": "SVCB",
            "ttl": 3600,
            "answers": [{"answer": ['1 chat.example.com. alpn="mcp" port="443"']}],
        }

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[mock_zone_resp, mock_detail_resp])

        with patch.object(backend, "_get_client", return_value=mock_client):
            records = []
            async for record in backend.list_records(
                zone="example.com",
                name_pattern="_chat",
            ):
                records.append(record)

            assert len(records) == 1
            assert "_chat" in records[0]["fqdn"]

    @pytest.mark.asyncio
    async def test_list_records_empty_zone(self):
        """Test listing records in zone with no records."""
        backend = NS1Backend(api_key="key")

        mock_zone_resp = MagicMock()
        mock_zone_resp.status_code = 200
        mock_zone_resp.json.return_value = {
            "zone": "example.com",
            "records": [],
        }
        mock_zone_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_zone_resp)

        with patch.object(backend, "_get_client", return_value=mock_client):
            records = []
            async for record in backend.list_records(zone="example.com"):
                records.append(record)

            assert records == []

    @pytest.mark.asyncio
    async def test_list_records_zone_not_found(self):
        """Test listing records when zone doesn't exist returns empty."""
        backend = NS1Backend(api_key="key")

        mock_404 = MagicMock()
        mock_404.status_code = 404

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_404)

        with patch.object(backend, "_get_client", return_value=mock_client):
            records = []
            async for record in backend.list_records(zone="notfound.com"):
                records.append(record)

            assert records == []

    @pytest.mark.asyncio
    async def test_list_records_skips_on_detail_http_error(self):
        """Test that HTTP errors on detail fetch skip the record, not crash."""
        backend = NS1Backend(api_key="key")

        mock_zone_resp = MagicMock()
        mock_zone_resp.status_code = 200
        mock_zone_resp.json.return_value = {
            "zone": "example.com",
            "records": [
                {"domain": "_broken.example.com", "type": "SVCB"},
            ],
        }
        mock_zone_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(
            side_effect=[
                mock_zone_resp,
                httpx.ConnectError("Connection refused"),
            ]
        )

        with patch.object(backend, "_get_client", return_value=mock_client):
            records = []
            async for record in backend.list_records(zone="example.com"):
                records.append(record)

            assert records == []


class TestNS1BackendClose:
    """Tests for client cleanup."""

    @pytest.mark.asyncio
    async def test_close_with_client(self):
        """Test closing an active client."""
        backend = NS1Backend(api_key="key")
        await backend._get_client()

        assert backend._client is not None
        assert backend._client_loop_id is not None
        await backend.close()
        assert backend._client is None
        assert backend._client_loop_id is None

    @pytest.mark.asyncio
    async def test_close_without_client(self):
        """Test closing when no client exists."""
        backend = NS1Backend(api_key="key")
        await backend.close()  # Should not raise
