# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for dns_aid.backends.cloudflare module."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from dns_aid.backends.cloudflare import (
    CloudflareBackend,
    _escape_dns_char_string,
    _parse_txt_content,
    _quote_txt_value,
)


class TestCloudflareBackendInit:
    """Tests for CloudflareBackend initialization."""

    def test_init_with_api_token(self):
        """Test initialization with API token."""
        backend = CloudflareBackend(api_token="test-token-123")
        assert backend._api_token == "test-token-123"

    def test_init_with_zone_id(self):
        """Test initialization with zone ID."""
        backend = CloudflareBackend(api_token="token", zone_id="zone123")
        assert backend._zone_id == "zone123"

    def test_init_from_env_token(self):
        """Test API token from environment variable."""
        with patch.dict("os.environ", {"CLOUDFLARE_API_TOKEN": "env-token"}):
            backend = CloudflareBackend()
            assert backend._api_token == "env-token"

    def test_init_from_env_zone_id(self):
        """Test zone ID from environment variable."""
        with patch.dict(
            "os.environ",
            {"CLOUDFLARE_API_TOKEN": "token", "CLOUDFLARE_ZONE_ID": "env-zone"},
        ):
            backend = CloudflareBackend()
            assert backend._zone_id == "env-zone"

    def test_init_defaults(self):
        """Test default values."""
        backend = CloudflareBackend(api_token="token")
        assert backend._client is None
        assert backend._zone_cache == {}
        assert backend._base_url == "https://api.cloudflare.com/client/v4"


class TestCloudflareBackendProperties:
    """Tests for CloudflareBackend properties."""

    def test_name_property(self):
        """Test name property returns 'cloudflare'."""
        backend = CloudflareBackend(api_token="token")
        assert backend.name == "cloudflare"


class TestCloudflareBackendClient:
    """Tests for httpx client creation."""

    @pytest.mark.asyncio
    async def test_get_client_creates_client(self):
        """Test that _get_client creates httpx client."""
        backend = CloudflareBackend(api_token="test-token")

        client = await backend._get_client()

        assert isinstance(client, httpx.AsyncClient)
        assert client.headers["Authorization"] == "Bearer test-token"
        assert client.headers["Content-Type"] == "application/json"

        await backend.close()

    @pytest.mark.asyncio
    async def test_get_client_caches_client(self):
        """Test that client is cached."""
        backend = CloudflareBackend(api_token="test-token")

        client1 = await backend._get_client()
        client2 = await backend._get_client()

        assert client1 is client2

        await backend.close()

    @pytest.mark.asyncio
    async def test_get_client_raises_without_token(self):
        """Test that missing token raises ValueError."""
        backend = CloudflareBackend()
        backend._api_token = None

        with pytest.raises(ValueError, match="API token not configured"):
            await backend._get_client()


class TestCloudflareBackendZoneId:
    """Tests for zone ID resolution."""

    @pytest.mark.asyncio
    async def test_get_zone_id_returns_configured(self):
        """Test that configured zone ID is returned."""
        backend = CloudflareBackend(api_token="token", zone_id="ZCONFIGURED")
        zone_id = await backend._get_zone_id("example.com")
        assert zone_id == "ZCONFIGURED"

    @pytest.mark.asyncio
    async def test_get_zone_id_from_cache(self):
        """Test that cached zone ID is returned."""
        backend = CloudflareBackend(api_token="token")
        backend._zone_cache["example.com"] = "ZCACHED"

        zone_id = await backend._get_zone_id("example.com")
        assert zone_id == "ZCACHED"

    @pytest.mark.asyncio
    async def test_get_zone_id_from_api(self):
        """Test zone ID lookup from API."""
        backend = CloudflareBackend(api_token="token")

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "success": True,
            "result": [{"id": "ZFOUND", "name": "example.com"}],
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch.object(backend, "_get_client", return_value=mock_client):
            zone_id = await backend._get_zone_id("example.com")
            assert zone_id == "ZFOUND"
            assert backend._zone_cache["example.com"] == "ZFOUND"

    @pytest.mark.asyncio
    async def test_get_zone_id_not_found(self):
        """Test zone ID lookup when zone doesn't exist."""
        backend = CloudflareBackend(api_token="token")

        mock_response = MagicMock()
        mock_response.json.return_value = {"success": True, "result": []}
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with (
            patch.object(backend, "_get_client", return_value=mock_client),
            pytest.raises(ValueError, match="No zone found"),
        ):
            await backend._get_zone_id("notfound.com")

    @pytest.mark.asyncio
    async def test_get_zone_id_api_error(self):
        """Test zone ID lookup with API error."""
        backend = CloudflareBackend(api_token="token")

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "success": False,
            "errors": [{"message": "Invalid token"}],
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with (
            patch.object(backend, "_get_client", return_value=mock_client),
            pytest.raises(ValueError, match="Cloudflare API error"),
        ):
            await backend._get_zone_id("example.com")


class TestCloudflareBackendFormatSvcb:
    """Tests for SVCB data formatting."""

    def test_format_svcb_data_basic(self):
        """Test basic SVCB data formatting."""
        backend = CloudflareBackend(api_token="token")
        data = backend._format_svcb_data(
            priority=1,
            target="chat.example.com",
            params={"alpn": "a2a", "port": "443"},
        )
        assert data["priority"] == 1
        assert data["target"] == "chat.example.com."
        assert 'alpn="a2a"' in data["value"]
        assert 'port="443"' in data["value"]

    def test_format_svcb_data_adds_trailing_dot(self):
        """Test that trailing dot is added to target."""
        backend = CloudflareBackend(api_token="token")
        data = backend._format_svcb_data(
            priority=1,
            target="chat.example.com",
            params={},
        )
        assert data["target"] == "chat.example.com."

    def test_format_svcb_data_preserves_trailing_dot(self):
        """Test that existing trailing dot is preserved."""
        backend = CloudflareBackend(api_token="token")
        data = backend._format_svcb_data(
            priority=1,
            target="chat.example.com.",
            params={},
        )
        assert data["target"] == "chat.example.com."

    def test_format_svcb_data_no_params(self):
        """Test SVCB data with no params."""
        backend = CloudflareBackend(api_token="token")
        data = backend._format_svcb_data(
            priority=0,
            target="alias.example.com.",
            params={},
        )
        assert data["priority"] == 0
        assert data["value"] == ""


class TestCloudflareBackendCreateSvcb:
    """Tests for SVCB record creation."""

    @pytest.mark.asyncio
    async def test_create_svcb_record_success(self):
        """Test successful SVCB record creation."""
        backend = CloudflareBackend(api_token="token", zone_id="Z123")

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "success": True,
            "result": {"id": "rec123"},
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(
            return_value=MagicMock(
                json=MagicMock(return_value={"success": True, "result": []}),
                raise_for_status=MagicMock(),
            )
        )
        mock_client.post = AsyncMock(return_value=mock_response)

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
            mock_client.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_svcb_record_update_existing(self):
        """Test updating existing SVCB record."""
        backend = CloudflareBackend(api_token="token", zone_id="Z123")

        # Mock finding existing record
        mock_get_response = MagicMock()
        mock_get_response.json.return_value = {
            "success": True,
            "result": [{"id": "existing123"}],
        }
        mock_get_response.raise_for_status = MagicMock()

        # Mock update response
        mock_put_response = MagicMock()
        mock_put_response.json.return_value = {
            "success": True,
            "result": {"id": "existing123"},
        }
        mock_put_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_get_response)
        mock_client.put = AsyncMock(return_value=mock_put_response)

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend.create_svcb_record(
                zone="example.com",
                name="_chat._a2a._agents",
                priority=1,
                target="chat.example.com",
                params={"alpn": "a2a"},
                ttl=3600,
            )

            assert result == "_chat._a2a._agents.example.com"
            mock_client.put.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_svcb_record_api_error(self):
        """Test SVCB creation with API error."""
        backend = CloudflareBackend(api_token="token", zone_id="Z123")

        mock_get_response = MagicMock()
        mock_get_response.json.return_value = {"success": True, "result": []}
        mock_get_response.raise_for_status = MagicMock()

        mock_post_response = MagicMock()
        mock_post_response.status_code = 400
        mock_post_response.json.return_value = {
            "success": False,
            "errors": [{"code": 1004, "message": "Invalid record"}],
        }
        mock_post_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_get_response)
        mock_client.post = AsyncMock(return_value=mock_post_response)

        with (
            patch.object(backend, "_get_client", return_value=mock_client),
            pytest.raises(ValueError, match="Failed to write SVCB record"),
        ):
            await backend.create_svcb_record(
                zone="example.com",
                name="_chat._a2a._agents",
                priority=1,
                target="chat.example.com",
                params={},
            )

    @pytest.mark.asyncio
    async def test_create_svcb_record_idempotent_on_duplicate(self):
        """A concurrent duplicate (CF error 81058) is treated as success."""
        backend = CloudflareBackend(api_token="token", zone_id="Z123")

        # No existing record found on the pre-check...
        mock_get_response = MagicMock()
        mock_get_response.json.return_value = {"success": True, "result": []}
        mock_get_response.raise_for_status = MagicMock()

        # ...but the POST races a concurrent publisher and hits 81058.
        mock_post_response = MagicMock()
        mock_post_response.status_code = 400
        mock_post_response.json.return_value = {
            "success": False,
            "errors": [{"code": 81058, "message": "An identical record already exists."}],
        }
        mock_post_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_get_response)
        mock_client.post = AsyncMock(return_value=mock_post_response)

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend.create_svcb_record(
                zone="example.com",
                name="_chat._a2a._agents",
                priority=1,
                target="chat.example.com",
                params={"alpn": "a2a"},
            )

        # Idempotent: returns the fqdn instead of raising.
        assert result == "_chat._a2a._agents.example.com"

    @pytest.mark.asyncio
    async def test_create_svcb_record_recreates_on_put_404(self):
        """Delete race: the record is removed between lookup and PUT.

        _get_record_id finds an id, but a concurrent publisher deletes the
        record before our PUT, which 404s. We must recover by POSTing a fresh
        record rather than failing the publish.
        """
        backend = CloudflareBackend(api_token="token", zone_id="Z123")

        # Pre-check finds an existing record...
        mock_get_response = MagicMock()
        mock_get_response.json.return_value = {"success": True, "result": [{"id": "gone123"}]}
        mock_get_response.raise_for_status = MagicMock()

        # ...the PUT 404s (record was deleted out from under us)...
        mock_put_response = MagicMock()
        mock_put_response.status_code = 404
        mock_put_response.json.return_value = {
            "success": False,
            "errors": [{"code": 81044, "message": "record does not exist"}],
        }

        # ...and the fallback POST succeeds.
        mock_post_response = MagicMock()
        mock_post_response.status_code = 200
        mock_post_response.json.return_value = {"success": True, "result": {"id": "new456"}}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_get_response)
        mock_client.put = AsyncMock(return_value=mock_put_response)
        mock_client.post = AsyncMock(return_value=mock_post_response)

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend.create_svcb_record(
                zone="example.com",
                name="_chat._a2a._agents",
                priority=1,
                target="chat.example.com",
                params={"alpn": "a2a"},
            )

        assert result == "_chat._a2a._agents.example.com"
        mock_client.put.assert_called_once()
        mock_client.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_put_81058_raises_not_silent_success(self):
        """A PUT hitting 81058 must RAISE, not report success.

        Cloudflare allows multiple records at one name and ``_get_record_id``
        returns the first. If our PUT would make the targeted record identical
        to a *different* record at the same name, Cloudflare answers 400/81058
        and the update does NOT apply — the record still resolves to its old
        value. Treating that as idempotent success (as a POST race legitimately
        is) would tell the caller we wrote when we did not, so it must raise.
        """
        backend = CloudflareBackend(api_token="token", zone_id="Z123")

        # Pre-check finds an existing record, so we PUT.
        mock_get_response = MagicMock()
        mock_get_response.json.return_value = {"success": True, "result": [{"id": "alpha1"}]}
        mock_get_response.raise_for_status = MagicMock()

        # The PUT collides with a different record at the same name -> 81058.
        mock_put_response = MagicMock()
        mock_put_response.status_code = 400
        mock_put_response.json.return_value = {
            "success": False,
            "errors": [{"code": 81058, "message": "An identical record already exists."}],
        }

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_get_response)
        mock_client.put = AsyncMock(return_value=mock_put_response)
        mock_client.post = AsyncMock()

        with patch.object(backend, "_get_client", return_value=mock_client):
            with pytest.raises(ValueError, match="81058"):
                await backend.create_svcb_record(
                    zone="example.com",
                    name="_chat._a2a._agents",
                    priority=1,
                    target="chat.example.com",
                    params={"alpn": "a2a"},
                )

        # We must NOT have fallen back to a POST on a 400 (only a 404 recreates).
        mock_client.post.assert_not_called()

    @pytest.mark.asyncio
    async def test_fallback_post_after_put_404_still_idempotent_on_81058(self):
        """Delete-race fallback POST that itself loses a create race converges.

        A PUT 404s (record deleted), we fall back to POST, and that POST races a
        concurrent publisher into 81058. Because the write we interpret is a
        POST, 81058 is still idempotent success — the record exists as intended.
        """
        backend = CloudflareBackend(api_token="token", zone_id="Z123")

        mock_get_response = MagicMock()
        mock_get_response.json.return_value = {"success": True, "result": [{"id": "gone123"}]}
        mock_get_response.raise_for_status = MagicMock()

        mock_put_response = MagicMock()
        mock_put_response.status_code = 404
        mock_put_response.json.return_value = {
            "success": False,
            "errors": [{"code": 81044, "message": "record does not exist"}],
        }

        mock_post_response = MagicMock()
        mock_post_response.status_code = 400
        mock_post_response.json.return_value = {
            "success": False,
            "errors": [{"code": 81058, "message": "An identical record already exists."}],
        }

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_get_response)
        mock_client.put = AsyncMock(return_value=mock_put_response)
        mock_client.post = AsyncMock(return_value=mock_post_response)

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend.create_svcb_record(
                zone="example.com",
                name="_chat._a2a._agents",
                priority=1,
                target="chat.example.com",
                params={"alpn": "a2a"},
            )

        assert result == "_chat._a2a._agents.example.com"
        mock_client.put.assert_called_once()
        mock_client.post.assert_called_once()


class TestCloudflareBackendCreateTxt:
    """Tests for TXT record creation."""

    @pytest.mark.asyncio
    async def test_create_txt_record_success(self):
        """Test successful TXT record creation."""
        backend = CloudflareBackend(api_token="token", zone_id="Z123")

        mock_get_response = MagicMock()
        mock_get_response.json.return_value = {"success": True, "result": []}
        mock_get_response.raise_for_status = MagicMock()

        mock_post_response = MagicMock()
        mock_post_response.json.return_value = {
            "success": True,
            "result": {"id": "txt123"},
        }
        mock_post_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_get_response)
        mock_client.post = AsyncMock(return_value=mock_post_response)

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend.create_txt_record(
                zone="example.com",
                name="_chat._a2a._agents",
                values=["capabilities=chat,code", "version=1.0.0"],
                ttl=3600,
            )

            assert result == "_chat._a2a._agents.example.com"
            mock_client.post.assert_called_once()

            # Verify content format: each value is its own quoted
            # RFC 1035 <character-string> (not space-joined into one).
            call_args = mock_client.post.call_args
            json_data = call_args.kwargs["json"]
            assert json_data["type"] == "TXT"
            assert json_data["content"] == '"capabilities=chat,code" "version=1.0.0"'


class TestCloudflareBackendDeleteRecord:
    """Tests for record deletion."""

    @pytest.mark.asyncio
    async def test_delete_record_success(self):
        """Test successful record deletion."""
        backend = CloudflareBackend(api_token="token", zone_id="Z123")

        # Mock finding record
        mock_get_response = MagicMock()
        mock_get_response.json.return_value = {
            "success": True,
            "result": [{"id": "rec123"}],
        }
        mock_get_response.raise_for_status = MagicMock()

        # Mock delete
        mock_delete_response = MagicMock()
        mock_delete_response.json.return_value = {"success": True}
        mock_delete_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_get_response)
        mock_client.delete = AsyncMock(return_value=mock_delete_response)

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend.delete_record(
                zone="example.com",
                name="_chat._a2a._agents",
                record_type="SVCB",
            )

            assert result is True
            mock_client.delete.assert_called_once()

    @pytest.mark.asyncio
    async def test_delete_record_not_found(self):
        """Test deletion when record doesn't exist."""
        backend = CloudflareBackend(api_token="token", zone_id="Z123")

        mock_response = MagicMock()
        mock_response.json.return_value = {"success": True, "result": []}
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend.delete_record(
                zone="example.com",
                name="_nonexistent._agents",
                record_type="SVCB",
            )

            assert result is False

    @pytest.mark.asyncio
    async def test_delete_record_api_error(self):
        """Test deletion with API error."""
        backend = CloudflareBackend(api_token="token", zone_id="Z123")

        mock_get_response = MagicMock()
        mock_get_response.json.return_value = {
            "success": True,
            "result": [{"id": "rec123"}],
        }
        mock_get_response.raise_for_status = MagicMock()

        mock_delete_response = MagicMock()
        mock_delete_response.json.return_value = {
            "success": False,
            "errors": [{"message": "Delete failed"}],
        }
        mock_delete_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_get_response)
        mock_client.delete = AsyncMock(return_value=mock_delete_response)

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend.delete_record(
                zone="example.com",
                name="_chat._agents",
                record_type="SVCB",
            )

            assert result is False


class TestCloudflareBackendListRecords:
    """Tests for record listing."""

    @pytest.mark.asyncio
    async def test_list_records_all(self):
        """Test listing all records."""
        backend = CloudflareBackend(api_token="token", zone_id="Z123")

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "success": True,
            "result": [
                {
                    "id": "rec1",
                    "name": "_chat._agents.example.com",
                    "type": "SVCB",
                    "ttl": 3600,
                    "data": {"priority": 1, "target": "chat.example.com.", "value": ""},
                },
                {
                    "id": "rec2",
                    "name": "_chat._agents.example.com",
                    "type": "TXT",
                    "ttl": 3600,
                    "content": '"capabilities=chat"',
                },
            ],
            "result_info": {"total_pages": 1},
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch.object(backend, "_get_client", return_value=mock_client):
            records = []
            async for record in backend.list_records(zone="example.com"):
                records.append(record)

            assert len(records) == 2

    @pytest.mark.asyncio
    async def test_list_records_filter_by_name(self):
        """Test listing records filtered by name."""
        backend = CloudflareBackend(api_token="token", zone_id="Z123")

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "success": True,
            "result": [
                {
                    "id": "rec1",
                    "name": "_chat._agents.example.com",
                    "type": "SVCB",
                    "ttl": 3600,
                    "data": {},
                },
                {
                    "id": "rec2",
                    "name": "www.example.com",
                    "type": "A",
                    "ttl": 300,
                    "content": "1.2.3.4",
                },
            ],
            "result_info": {"total_pages": 1},
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch.object(backend, "_get_client", return_value=mock_client):
            records = []
            async for record in backend.list_records(zone="example.com", name_pattern="_agents"):
                records.append(record)

            assert len(records) == 1
            assert "_agents" in records[0]["fqdn"]

    @pytest.mark.asyncio
    async def test_list_records_pagination(self):
        """Test listing records with pagination."""
        backend = CloudflareBackend(api_token="token", zone_id="Z123")

        # Page 1
        page1_response = MagicMock()
        page1_response.json.return_value = {
            "success": True,
            "result": [{"id": "rec1", "name": "a.example.com", "type": "A", "content": "1.1.1.1"}],
            "result_info": {"total_pages": 2},
        }
        page1_response.raise_for_status = MagicMock()

        # Page 2
        page2_response = MagicMock()
        page2_response.json.return_value = {
            "success": True,
            "result": [{"id": "rec2", "name": "b.example.com", "type": "A", "content": "2.2.2.2"}],
            "result_info": {"total_pages": 2},
        }
        page2_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[page1_response, page2_response])

        with patch.object(backend, "_get_client", return_value=mock_client):
            records = []
            async for record in backend.list_records(zone="example.com"):
                records.append(record)

            assert len(records) == 2


class TestCloudflareBackendZoneExists:
    """Tests for zone existence check."""

    @pytest.mark.asyncio
    async def test_zone_exists_true(self):
        """Test zone exists returns True."""
        backend = CloudflareBackend(api_token="token", zone_id="Z123")
        result = await backend.zone_exists("example.com")
        assert result is True

    @pytest.mark.asyncio
    async def test_zone_exists_false(self):
        """Test zone exists returns False when not found."""
        backend = CloudflareBackend(api_token="token")

        mock_response = MagicMock()
        mock_response.json.return_value = {"success": True, "result": []}
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend.zone_exists("notfound.com")
            assert result is False


class TestCloudflareBackendListZones:
    """Tests for listing zones."""

    @pytest.mark.asyncio
    async def test_list_zones(self):
        """Test listing all zones."""
        backend = CloudflareBackend(api_token="token")

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "success": True,
            "result": [
                {
                    "id": "zone1",
                    "name": "example.com",
                    "status": "active",
                    "name_servers": ["ns1.cloudflare.com", "ns2.cloudflare.com"],
                },
                {
                    "id": "zone2",
                    "name": "other.com",
                    "status": "pending",
                    "name_servers": [],
                },
            ],
            "result_info": {"total_pages": 1},
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch.object(backend, "_get_client", return_value=mock_client):
            zones = await backend.list_zones()

            assert len(zones) == 2
            assert zones[0]["id"] == "zone1"
            assert zones[0]["name"] == "example.com"
            assert zones[0]["status"] == "active"


class TestCloudflareBackendClose:
    """Tests for client cleanup."""

    @pytest.mark.asyncio
    async def test_close(self):
        """Test closing the client."""
        backend = CloudflareBackend(api_token="token")

        # Create a client first
        await backend._get_client()
        assert backend._client is not None

        # Close it
        await backend.close()
        assert backend._client is None


# =============================================================================
# Native private-use SVCB key emission & get_record coverage
# =============================================================================


class TestCloudflarePublishAgentNativeSvcb:
    """Cloudflare writes DNS-AID private-use SVCB keys natively (no TXT demotion).

    Cloudflare's SVCB data.value accepts RFC 9460 generic private-use keys
    (key65280-key65534), verified against the live API, so
    supports_private_svcb_keys is True and the base class passes custom
    params straight to the SVCB record.
    """

    @pytest.mark.asyncio
    async def test_backend_declares_native_support(self):
        """The backend must advertise native private-use SVCB key support."""
        backend = CloudflareBackend(api_token="token", zone_id="Z123")
        assert backend.supports_private_svcb_keys is True

    @pytest.mark.asyncio
    async def test_publish_writes_custom_svcb_params_natively(self):
        """Custom DNS-AID params (key65400+) go into SVCB, not TXT."""
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

        backend = CloudflareBackend(api_token="token", zone_id="Z123")

        svcb_calls: list[dict] = []
        txt_calls: list[dict] = []

        async def _mock_create_svcb(**kwargs):
            svcb_calls.append(kwargs)
            return "SVCB _lf-test._mcp._agents.example.com"

        async def _mock_create_txt(**kwargs):
            txt_calls.append(kwargs)
            return "TXT _lf-test._mcp._agents.example.com"

        with (
            patch.object(backend, "create_svcb_record", side_effect=_mock_create_svcb),
            patch.object(backend, "create_txt_record", side_effect=_mock_create_txt),
        ):
            records = await backend.publish_agent(agent)

        # SVCB primary + TXT companion + walkable AliasMode (default-on per draft-02)
        assert len(records) == 3
        assert records[0].startswith("SVCB")
        assert records[1].startswith("TXT")
        assert records[2].startswith("SVCB(AliasMode)")

        # The primary SVCB record must carry the private-use realm key (key65404),
        # NOT have it demoted to TXT.
        svcb_params = svcb_calls[0]["params"]
        assert "key65404" in svcb_params
        assert svcb_params["key65404"] == "demo"

        # TXT must NOT contain any demoted dnsaid_ entries.
        txt_values = txt_calls[0]["values"]
        dnsaid_txt = [v for v in txt_values if v.startswith("dnsaid_")]
        assert dnsaid_txt == []

    @pytest.mark.asyncio
    async def test_publish_no_custom_params_unchanged(self):
        """No demotion when agent has no custom params."""
        from dns_aid.core.models import AgentRecord, Protocol

        agent = AgentRecord(
            name="basic",
            domain="example.com",
            protocol=Protocol.A2A,
            target_host="basic.example.com",
            port=443,
            capabilities=["chat"],
        )

        backend = CloudflareBackend(api_token="token", zone_id="Z123")

        svcb_calls: list[dict] = []
        txt_calls: list[dict] = []

        async def _mock_create_svcb(**kwargs):
            svcb_calls.append(kwargs)
            return "SVCB fqdn"

        async def _mock_create_txt(**kwargs):
            txt_calls.append(kwargs)
            return "TXT fqdn"

        with (
            patch.object(backend, "create_svcb_record", side_effect=_mock_create_svcb),
            patch.object(backend, "create_txt_record", side_effect=_mock_create_txt),
        ):
            await backend.publish_agent(agent)

        # No dnsaid_ entries in TXT
        if txt_calls:
            txt_values = txt_calls[0]["values"]
            dnsaid_txt = [v for v in txt_values if v.startswith("dnsaid_")]
            assert len(dnsaid_txt) == 0

    @pytest.mark.asyncio
    async def test_publish_writes_multiple_params_natively(self):
        """Multiple custom params all go into the SVCB record, not TXT."""
        from dns_aid.core.models import AgentRecord, Protocol

        agent = AgentRecord(
            name="multi",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="multi.example.com",
            port=443,
            capabilities=["all"],
            cap_uri="https://multi.example.com/cap.json",
            cap_sha256="abc123",
            bap="mcp=2.1",
            policy_uri="https://example.com/policy",
            realm="production",
        )

        backend = CloudflareBackend(api_token="token", zone_id="Z123")

        svcb_calls: list[dict] = []
        txt_calls: list[dict] = []

        async def _mock_create_svcb(**kwargs):
            svcb_calls.append(kwargs)
            return "SVCB fqdn"

        async def _mock_create_txt(**kwargs):
            txt_calls.append(kwargs)
            return "TXT fqdn"

        with (
            patch.object(backend, "create_svcb_record", side_effect=_mock_create_svcb),
            patch.object(backend, "create_txt_record", side_effect=_mock_create_txt),
        ):
            await backend.publish_agent(agent)

        # cap, cap-sha256, bap, policy, realm -> key65400..key65404, all in SVCB.
        svcb_params = svcb_calls[0]["params"]
        private_keys = [k for k in svcb_params if k.startswith("key654")]
        assert len(private_keys) >= 5
        for k in ("key65400", "key65401", "key65402", "key65403", "key65404"):
            assert k in svcb_params

        # Nothing demoted to TXT.
        if txt_calls:
            txt_values = txt_calls[0]["values"]
            assert [v for v in txt_values if v.startswith("dnsaid_")] == []


class TestCloudflareGetRecord:
    """Tests for get_record method."""

    @pytest.mark.asyncio
    async def test_get_record_svcb(self):
        """get_record returns SVCB record data."""
        backend = CloudflareBackend(api_token="token", zone_id="Z123")

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "success": True,
            "result": [
                {
                    "id": "rec1",
                    "name": "_chat._a2a._agents.example.com",
                    "type": "SVCB",
                    "ttl": 3600,
                    "data": {"priority": 1, "target": "chat.example.com.", "value": 'alpn="a2a"'},
                }
            ],
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch.object(backend, "_get_client", return_value=mock_client):
            record = await backend.get_record("example.com", "_chat._a2a._agents", "SVCB")

        assert record is not None
        assert record["type"] == "SVCB"
        assert "1 chat.example.com." in record["values"][0]

    @pytest.mark.asyncio
    async def test_get_record_txt(self):
        """get_record returns TXT record data."""
        backend = CloudflareBackend(api_token="token", zone_id="Z123")

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "success": True,
            "result": [
                {
                    "id": "rec2",
                    "name": "_chat._a2a._agents.example.com",
                    "type": "TXT",
                    "ttl": 3600,
                    "content": "capabilities=chat",
                }
            ],
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch.object(backend, "_get_client", return_value=mock_client):
            record = await backend.get_record("example.com", "_chat._a2a._agents", "TXT")

        assert record is not None
        assert record["type"] == "TXT"
        assert record["values"] == ["capabilities=chat"]

    @pytest.mark.asyncio
    async def test_get_record_not_found(self):
        """get_record returns None when no record exists."""
        backend = CloudflareBackend(api_token="token", zone_id="Z123")

        mock_response = MagicMock()
        mock_response.json.return_value = {"success": True, "result": []}
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch.object(backend, "_get_client", return_value=mock_client):
            record = await backend.get_record("example.com", "_missing._agents", "SVCB")

        assert record is None

    @pytest.mark.asyncio
    async def test_get_record_propagates_server_error(self):
        """get_record must NOT mask errors as 'not found'.

        Only an empty result set means the record is absent. A 5xx (or any
        other non-success response) has to raise, otherwise a transient
        auth/network/server error would look identical to a missing record and
        let reconciliation silently recreate or overwrite an existing record.
        Guard the raising contract so a future "align the backends" refactor
        can't quietly revert it to swallowing errors.
        """
        backend = CloudflareBackend(api_token="token", zone_id="Z123")

        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock(
            side_effect=httpx.HTTPStatusError(
                "500 Internal Server Error",
                request=httpx.Request("GET", "https://api.cloudflare.com"),
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
                await backend.get_record("example.com", "_chat._a2a._agents", "SVCB")


class TestCloudflareTxtCharacterStringHelpers:
    """Round-trip and edge-case coverage for the TXT presentation-format helpers.

    These are the security-relevant boundary (escaping) and the read-path
    parser; the live integration test exercises them end-to-end, but these
    mocked unit tests lock the behavior so CI catches a regression.
    """

    def test_escape_backslash_and_quote(self):
        assert _escape_dns_char_string('a"b\\c') == 'a\\"b\\\\c'

    def test_escape_noop_when_clean(self):
        assert _escape_dns_char_string("cap=chat,code") == "cap=chat,code"

    def test_quote_wraps_and_escapes(self):
        assert _quote_txt_value('say "hi"') == '"say \\"hi\\""'

    def test_roundtrip_plain_values(self):
        values = ["capabilities=chat,code", "version=1.0.0"]
        content = " ".join(_quote_txt_value(v) for v in values)
        assert _parse_txt_content(content) == values

    def test_roundtrip_value_with_spaces(self):
        # The whole motivation: a value containing spaces must survive as ONE
        # character-string, not fragment into several.
        values = ["description=A helpful chat agent", "version=1.0.0"]
        content = " ".join(_quote_txt_value(v) for v in values)
        assert _parse_txt_content(content) == values

    def test_roundtrip_embedded_quotes_and_backslashes(self):
        values = ['note=he said "hi"', "path=C:\\tmp\\x"]
        content = " ".join(_quote_txt_value(v) for v in values)
        assert _parse_txt_content(content) == values

    def test_parse_empty_content_returns_empty_list(self):
        # Behavior change from the old backend: empty content is [] not [""].
        assert _parse_txt_content("") == []

    def test_parse_single_bare_value(self):
        assert _parse_txt_content("capabilities=chat") == ["capabilities=chat"]

    def test_parse_unterminated_quote_recovers_gracefully(self):
        # The DNS tokenizer never raises on malformed input (shouldn't happen
        # from Cloudflare). An unterminated quote simply ends the final token,
        # recovering the content instead of dumping the raw blob back.
        assert _parse_txt_content('"unterminated') == ["unterminated"]

    def test_parse_bare_apostrophe(self):
        # Regression: shlex raised ValueError on a bare apostrophe and the
        # fallback returned the whole blob as one value. The DNS tokenizer
        # splits it into character-strings normally.
        assert _parse_txt_content("it's fine") == ["it's", "fine"]

    def test_parse_decimal_octet_escapes_utf8(self):
        # Cloudflare returns non-ASCII as \DDD decimal octet escapes; a
        # multi-byte character split across escapes must UTF-8 decode back.
        # "café" -> é is U+00E9 = UTF-8 0xC3 0xA9 = \195\169.
        assert _parse_txt_content('"caf\\195\\169"') == ["café"]

    def test_parse_single_char_escape(self):
        # \X (non-digit) emits the literal X, inverting _escape_dns_char_string.
        assert _parse_txt_content(r'"a\"b\\c"') == ['a"b\\c']

    def test_roundtrip_unicode_value(self):
        # Escaping does not touch non-ASCII (it stays literal in content), but a
        # value survives the round-trip intact regardless.
        values = ["description=café ☕", "version=1.0.0"]
        content = " ".join(_quote_txt_value(v) for v in values)
        assert _parse_txt_content(content) == values

    def test_parse_out_of_range_octet_not_treated_as_escape(self):
        # \999 exceeds a single octet (0–255), so it is not a valid \DDD escape.
        # The backslash-digit is treated as a literal \X escape (emitting "9"),
        # yielding "999" rather than raising or corrupting the value.
        assert _parse_txt_content(r"\999") == ["999"]

    def test_parse_superscript_digits_do_not_crash(self):
        # Regression: '²'.isdigit() is True but int('²') raises. The tokenizer
        # must NOT treat \²²² as a \DDD escape (isascii()+isdecimal() guard),
        # and must honour its "never raises" contract.
        assert _parse_txt_content("\\\u00b2\u00b2\u00b2") == ["\u00b2\u00b2\u00b2"]

    def test_parse_quoted_empty_string(self):
        # A quoted empty string is one (empty) character-string, not zero.
        assert _parse_txt_content('""') == [""]

    def test_roundtrip_value_with_literal_backslash_digits(self):
        # The interesting round-trip: a value containing a literal backslash
        # followed by digits (which the parser must not misread as a \DDD octet
        # after _quote_txt_value doubles the backslash).
        values = ["path=x\\123y", "version=1.0.0"]
        content = " ".join(_quote_txt_value(v) for v in values)
        assert _parse_txt_content(content) == values

    @pytest.mark.asyncio
    async def test_get_record_parses_multistring_txt_back_to_list(self):
        """get_record read path splits presentation-format content into values."""
        backend = CloudflareBackend(api_token="token", zone_id="Z123")

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "success": True,
            "result": [
                {
                    "id": "rec1",
                    "name": "_chat._a2a._agents.example.com",
                    "type": "TXT",
                    "ttl": 3600,
                    "content": '"capabilities=chat,code" "description=A helpful agent"',
                }
            ],
        }
        mock_response.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch.object(backend, "_get_client", return_value=mock_client):
            record = await backend.get_record("example.com", "_chat._a2a._agents", "TXT")

        assert record is not None
        assert record["values"] == ["capabilities=chat,code", "description=A helpful agent"]


class TestCloudflareRateLimitHandling:
    """The shared _request helper retries uniformly on Cloudflare 429s."""

    def _resp(self, status_code, *, headers=None, json_body=None):
        r = MagicMock()
        r.status_code = status_code
        r.headers = headers or {}
        r.json.return_value = json_body if json_body is not None else {}
        r.raise_for_status = MagicMock()
        return r

    @pytest.mark.asyncio
    async def test_request_retries_on_429_then_succeeds(self):
        """A 429 followed by a 200 is retried transparently; caller sees 200."""
        backend = CloudflareBackend(api_token="token", zone_id="Z123")

        limited = self._resp(429, headers={"Retry-After": "0"})
        ok = self._resp(200, json_body={"success": True, "result": []})

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[limited, ok])

        sleeps: list[float] = []

        async def fake_sleep(secs):
            sleeps.append(secs)

        with patch.object(backend, "_get_client", return_value=mock_client):
            with patch("dns_aid.backends.cloudflare.asyncio.sleep", fake_sleep):
                response = await backend._request("GET", "/zones")

        assert response is ok
        assert mock_client.get.await_count == 2
        # Honoured the Retry-After header (0s) rather than the backoff default.
        assert sleeps == [0.0]

    @pytest.mark.asyncio
    async def test_request_honours_retry_after_header(self):
        """Retry-After takes precedence over exponential backoff."""
        backend = CloudflareBackend(api_token="token", zone_id="Z123")

        limited = self._resp(429, headers={"Retry-After": "7"})
        ok = self._resp(200, json_body={"success": True})

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[limited, ok])

        sleeps: list[float] = []

        async def fake_sleep(secs):
            sleeps.append(secs)

        with patch.object(backend, "_get_client", return_value=mock_client):
            with patch("dns_aid.backends.cloudflare.asyncio.sleep", fake_sleep):
                await backend._request("GET", "/zones")

        assert sleeps == [7.0]

    @pytest.mark.asyncio
    async def test_request_backs_off_when_no_retry_after(self):
        """Without Retry-After, sleep uses the exponential backoff schedule."""
        backend = CloudflareBackend(api_token="token", zone_id="Z123")

        r1 = self._resp(429)
        r2 = self._resp(429)
        ok = self._resp(200, json_body={"success": True})

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[r1, r2, ok])

        sleeps: list[float] = []

        async def fake_sleep(secs):
            sleeps.append(secs)

        with patch.object(backend, "_get_client", return_value=mock_client):
            with patch("dns_aid.backends.cloudflare.asyncio.sleep", fake_sleep):
                await backend._request("GET", "/zones")

        # Base delay then doubled.
        assert sleeps == [1.0, 2.0]

    @pytest.mark.asyncio
    async def test_request_raises_when_rate_limit_never_clears(self):
        """A persistent 429 raises after _CF_MAX_RETRIES rather than returning it.

        Returning a throttled body would let a persistent 200 success:false
        rate-limit response be misread downstream as "not found"/empty.
        """
        backend = CloudflareBackend(api_token="token", zone_id="Z123")

        # Distinct objects per send so we prove the loop exhausts, not that it
        # trivially returns the same mock.
        responses = [self._resp(429) for _ in range(4)]
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=responses)

        async def fake_sleep(secs):
            return None

        with patch.object(backend, "_get_client", return_value=mock_client):
            with patch("dns_aid.backends.cloudflare.asyncio.sleep", fake_sleep):
                with pytest.raises(ValueError, match="rate limit not cleared"):
                    await backend._request("GET", "/zones")

        # Initial attempt + _CF_MAX_RETRIES retries.
        assert mock_client.get.await_count == 4

    @pytest.mark.asyncio
    async def test_request_caps_absurd_retry_after(self):
        """A huge Retry-After is clamped to _CF_MAX_RETRY_DELAY, not obeyed."""
        backend = CloudflareBackend(api_token="token", zone_id="Z123")

        limited = self._resp(429, headers={"Retry-After": "86400"})
        ok = self._resp(200, json_body={"success": True})

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[limited, ok])

        sleeps: list[float] = []

        async def fake_sleep(secs):
            sleeps.append(secs)

        with patch.object(backend, "_get_client", return_value=mock_client):
            with patch("dns_aid.backends.cloudflare.asyncio.sleep", fake_sleep):
                await backend._request("GET", "/zones")

        assert sleeps == [30.0]  # _CF_MAX_RETRY_DELAY

    @pytest.mark.asyncio
    async def test_request_unparseable_retry_after_falls_back_to_backoff(self):
        """A non-numeric Retry-After (e.g. an HTTP-date) uses exponential backoff."""
        backend = CloudflareBackend(api_token="token", zone_id="Z123")

        limited = self._resp(429, headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"})
        ok = self._resp(200, json_body={"success": True})

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[limited, ok])

        sleeps: list[float] = []

        async def fake_sleep(secs):
            sleeps.append(secs)

        with patch.object(backend, "_get_client", return_value=mock_client):
            with patch("dns_aid.backends.cloudflare.asyncio.sleep", fake_sleep):
                await backend._request("GET", "/zones")

        assert sleeps == [1.0]  # base backoff, header ignored

    @pytest.mark.asyncio
    async def test_get_record_raises_on_persistent_rate_limit_body(self):
        """A persistent 200 success:false rate-limit body must not read as None."""
        backend = CloudflareBackend(api_token="token", zone_id="Z123")

        limited = MagicMock()
        limited.status_code = 200
        limited.headers = {}
        limited.json.return_value = {
            "success": False,
            "errors": [{"code": 10000, "message": "Rate limit exceeded"}],
        }
        limited.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=limited)

        async def fake_sleep(secs):
            return None

        with patch.object(backend, "_get_client", return_value=mock_client):
            with patch("dns_aid.backends.cloudflare.asyncio.sleep", fake_sleep):
                with pytest.raises(ValueError, match="rate limit not cleared"):
                    await backend.get_record("example.com", "_chat._a2a._agents", "TXT")

    @pytest.mark.asyncio
    async def test_request_detects_rate_limit_in_200_body(self):
        """A throttle surfacing as HTTP 200 success:false is still retried."""
        backend = CloudflareBackend(api_token="token", zone_id="Z123")

        limited = self._resp(
            200,
            json_body={
                "success": False,
                "errors": [{"code": 10000, "message": "Rate limit exceeded"}],
            },
        )
        ok = self._resp(200, json_body={"success": True})

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=[limited, ok])

        async def fake_sleep(secs):
            return None

        with patch.object(backend, "_get_client", return_value=mock_client):
            with patch("dns_aid.backends.cloudflare.asyncio.sleep", fake_sleep):
                response = await backend._request("GET", "/zones")

        assert response is ok
        assert mock_client.get.await_count == 2
