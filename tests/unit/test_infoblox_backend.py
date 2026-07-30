# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for Infoblox BloxOne backend.

These tests mock the HTTP API to test the backend logic without
requiring real Infoblox credentials.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from dns_aid.backends.infoblox.bloxone import InfobloxBloxOneBackend


class TestInfobloxBloxOneBackend:
    """Tests for InfobloxBloxOneBackend."""

    def test_init_with_api_key(self):
        """Test initialization with explicit API key."""
        backend = InfobloxBloxOneBackend(api_key="test-key")
        assert backend._api_key == "test-key"
        assert backend._base_url == "https://csp.infoblox.com"
        assert backend.name == "bloxone"

    def test_init_with_custom_base_url(self):
        """Test initialization with custom base URL."""
        backend = InfobloxBloxOneBackend(api_key="test-key", base_url="https://custom.infoblox.com")
        assert backend._base_url == "https://custom.infoblox.com"

    def test_init_without_api_key_raises(self):
        """Test that missing API key raises ValueError."""
        with (
            patch.dict("os.environ", {}, clear=True),
            pytest.raises(ValueError, match="API key required"),
        ):
            InfobloxBloxOneBackend()

    def test_init_from_env_var(self):
        """Test initialization from environment variable."""
        with patch.dict("os.environ", {"INFOBLOX_API_KEY": "env-key"}):
            backend = InfobloxBloxOneBackend()
            assert backend._api_key == "env-key"

    def test_name_property(self):
        """Test name property returns 'bloxone'."""
        backend = InfobloxBloxOneBackend(api_key="test-key")
        assert backend.name == "bloxone"

    def test_format_svcb_rdata_service_mode(self):
        """ServiceMode SVCB rdata carries priority + svc_params as {key,value} objects."""
        backend = InfobloxBloxOneBackend(api_key="test-key")

        rdata = backend._format_svcb_rdata(
            priority=1,
            target="target.example.com",
            params={"alpn": "mcp", "port": "443", "key65400": "https://x/cap.json"},
        )

        assert rdata["target_name"] == "target.example.com."
        assert rdata["priority"] == 1
        # svc_params is a list of {"key","value"} (UDDI DNS Data schema), and
        # DNS-AID private-use keys (key65400-key65405) are carried natively.
        assert {"key": "alpn", "value": "mcp"} in rdata["svc_params"]
        assert {"key": "port", "value": "443"} in rdata["svc_params"]
        assert {"key": "key65400", "value": "https://x/cap.json"} in rdata["svc_params"]

    def test_format_svcb_rdata_alias_mode(self):
        """AliasMode (priority 0) carries no svc_params (used for walkable aliases)."""
        backend = InfobloxBloxOneBackend(api_key="test-key")

        rdata = backend._format_svcb_rdata(priority=0, target="flat.example.com.", params={})

        assert rdata == {"priority": 0, "target_name": "flat.example.com."}

    def test_supports_private_svcb_keys(self):
        """UDDI declares private-key support, so customs are not demoted to TXT."""
        backend = InfobloxBloxOneBackend(api_key="test-key")
        assert backend.supports_private_svcb_keys is True

    def test_svcb_presentation_service_mode(self):
        """SVCB readback renders real priority + params (not a hardcoded 0)."""
        value = InfobloxBloxOneBackend._svcb_presentation(
            {
                "priority": 1,
                "target_name": "mcp.example.com.",
                "svc_params": [
                    {"key": "alpn", "value": "mcp"},
                    {"key": "no-default-alpn", "value": ""},
                ],
            }
        )
        assert value == "1 mcp.example.com. alpn=mcp no-default-alpn"

    def test_format_svcb_rdata_with_trailing_dot(self):
        """Test SVCB rdata doesn't double trailing dot."""
        backend = InfobloxBloxOneBackend(api_key="test-key")

        rdata = backend._format_svcb_rdata(
            priority=1,
            target="target.example.com.",  # Already has dot
            params={},
        )

        assert rdata["target_name"] == "target.example.com."
        assert rdata["target_name"].count(".") == 3  # Not doubled


class TestInfobloxBloxOneBackendAsync:
    """Async tests for InfobloxBloxOneBackend."""

    @pytest.fixture
    def backend(self):
        """Create backend with test API key."""
        return InfobloxBloxOneBackend(api_key="test-key")

    @pytest.fixture
    def mock_view_response(self):
        """Mock view lookup response."""
        return {
            "results": [
                {
                    "id": "dns/view/view123",
                    "name": "default",
                }
            ]
        }

    @pytest.fixture
    def mock_zone_response(self):
        """Mock zone lookup response."""
        return {
            "results": [
                {
                    "id": "dns/auth_zone/abc123",
                    "fqdn": "example.com.",
                    "comment": "Test zone",
                }
            ]
        }

    @pytest.fixture
    def mock_record_response(self):
        """Mock record creation response."""
        return {
            "result": {
                "id": "dns/record/xyz789",
                "name_in_zone": "_test._mcp._agents",
                "type": "SVCB",
            }
        }

    async def test_zone_exists_true(self, backend, mock_view_response, mock_zone_response):
        """Test zone_exists returns True for existing zone."""
        with patch.object(backend, "_request", new_callable=AsyncMock) as mock_req:
            # First call: view lookup, second call: zone lookup
            mock_req.side_effect = [mock_view_response, mock_zone_response]

            result = await backend.zone_exists("example.com")

            assert result is True
            assert mock_req.call_count == 2

    async def test_zone_exists_false(self, backend, mock_view_response):
        """Test zone_exists returns False for non-existing zone."""
        with patch.object(backend, "_request", new_callable=AsyncMock) as mock_req:
            # First call: view lookup, second call: zone lookup (empty)
            mock_req.side_effect = [mock_view_response, {"results": []}]

            result = await backend.zone_exists("nonexistent.com")

            assert result is False

    async def test_create_svcb_record(
        self, backend, mock_view_response, mock_zone_response, mock_record_response
    ):
        """Test SVCB record creation."""
        with patch.object(backend, "_request", new_callable=AsyncMock) as mock_req:
            # Calls: view lookup, zone lookup, upsert-existing lookup (none
            # present), record creation.
            mock_req.side_effect = [
                mock_view_response,
                mock_zone_response,
                {"results": []},  # no existing SVCB at this name
                mock_record_response,
            ]

            result = await backend.create_svcb_record(
                zone="example.com",
                name="_test._mcp._agents",
                priority=1,
                target="mcp.example.com",
                params={"alpn": "mcp", "port": "443"},
                ttl=300,
            )

            assert result == "_test._mcp._agents.example.com"
            assert mock_req.call_count == 4

            # Verify the POST call payload
            post_call = mock_req.call_args_list[3]
            assert post_call[0][0] == "POST"
            assert post_call[0][1] == "/dns/record"
            payload = post_call[1]["json"]
            assert payload["type"] == "SVCB"
            assert payload["name_in_zone"] == "_test._mcp._agents"
            assert payload["ttl"] == 300

    async def test_create_txt_record(self, backend, mock_view_response, mock_zone_response):
        """Test TXT record creation."""
        mock_txt_response = {
            "result": {
                "id": "dns/record/txt123",
                "name_in_zone": "_test._mcp._agents",
                "type": "TXT",
            }
        }

        with patch.object(backend, "_request", new_callable=AsyncMock) as mock_req:
            # Calls: view lookup, zone lookup, upsert-existing lookup (none
            # present), record creation.
            mock_req.side_effect = [
                mock_view_response,
                mock_zone_response,
                {"results": []},  # no existing TXT at this name
                mock_txt_response,
            ]

            result = await backend.create_txt_record(
                zone="example.com",
                name="_test._mcp._agents",
                values=["capabilities=chat,code", "version=1.0.0"],
                ttl=600,
            )

            assert result == "_test._mcp._agents.example.com"

            # Verify payload
            post_call = mock_req.call_args_list[3]
            payload = post_call[1]["json"]
            assert payload["type"] == "TXT"
            assert "capabilities" in payload["rdata"]["text"]

    async def test_create_is_idempotent_patches_existing_in_place(
        self, backend, mock_view_response, mock_zone_response
    ):
        """A create with an existing record at the same (name, type) updates it
        in place with PATCH — an upsert that never deletes the live record
        before the replacement is committed, so a failed write can't drop it
        (regression for the BloxOne _index._agents duplication bug, hardened so
        a rejected re-publish keeps the previous record)."""
        existing = {"results": [{"id": "dns/record/old-index-1"}]}
        patch_resp = {"result": {"id": "dns/record/old-index-1", "type": "TXT"}}

        with patch.object(backend, "_request", new_callable=AsyncMock) as mock_req:
            # view, zone, upsert-existing lookup (one present), PATCH
            mock_req.side_effect = [
                mock_view_response,
                mock_zone_response,
                existing,
                patch_resp,
            ]

            await backend.create_txt_record(
                zone="example.com",
                name="_index._agents",
                values=["agents=chat:mcp"],
                ttl=3600,
            )

            methods_paths = [(c[0][0], c[0][1]) for c in mock_req.call_args_list]
            # The live record is updated in place — no delete, no create.
            assert ("PATCH", "/dns/record/old-index-1") in methods_paths
            assert not any(m == "DELETE" for m, _ in methods_paths), (
                "in-place upsert must not delete the live record"
            )
            assert not any(m == "POST" and p == "/dns/record" for m, p in methods_paths), (
                "an existing record is patched, not re-created"
            )
            # PATCH carries the new rdata.
            patch_call = next(c for c in mock_req.call_args_list if c[0][0] == "PATCH")
            assert "agents=chat:mcp" in patch_call[1]["json"]["rdata"]["text"]

    async def test_upsert_heals_duplicates(self, backend, mock_view_response, mock_zone_response):
        """When earlier non-idempotent writes left duplicates, the upsert patches
        the first and removes the extras so the name converges on one record."""
        existing = {"results": [{"id": "dns/record/dup-1"}, {"id": "dns/record/dup-2"}]}
        patch_resp = {"result": {"id": "dns/record/dup-1", "type": "TXT"}}

        with patch.object(backend, "_request", new_callable=AsyncMock) as mock_req:
            # view, zone, existing lookup (two present), PATCH first, DELETE extra
            mock_req.side_effect = [
                mock_view_response,
                mock_zone_response,
                existing,
                patch_resp,
                {},  # DELETE of the duplicate
            ]

            await backend.create_txt_record(
                zone="example.com",
                name="_index._agents",
                values=["agents=chat:mcp"],
                ttl=3600,
            )

            methods_paths = [(c[0][0], c[0][1]) for c in mock_req.call_args_list]
            assert ("PATCH", "/dns/record/dup-1") in methods_paths
            assert ("DELETE", "/dns/record/dup-2") in methods_paths
            patch_idx = methods_paths.index(("PATCH", "/dns/record/dup-1"))
            delete_idx = methods_paths.index(("DELETE", "/dns/record/dup-2"))
            assert patch_idx < delete_idx, "patch the survivor before pruning duplicates"

    async def test_upsert_failed_patch_preserves_record(
        self, backend, mock_view_response, mock_zone_response
    ):
        """A failed in-place update must not have deleted the live record first —
        the previous record keeps serving (no silent agent disappearance)."""
        existing = {"results": [{"id": "dns/record/live-1"}]}

        with patch.object(backend, "_request", new_callable=AsyncMock) as mock_req:
            mock_req.side_effect = [
                mock_view_response,
                mock_zone_response,
                existing,
                httpx.HTTPStatusError(
                    "boom", request=MagicMock(), response=MagicMock(status_code=400)
                ),
            ]

            with pytest.raises(httpx.HTTPStatusError):
                await backend.create_svcb_record(
                    zone="example.com",
                    name="_test._mcp._agents",
                    priority=1,
                    target="mcp.example.com",
                    params={"alpn": "mcp", "port": "443"},
                )

            methods = [c[0][0] for c in mock_req.call_args_list]
            # Critical: no DELETE was issued, so the existing record still exists.
            assert "DELETE" not in methods, "a failed upsert must never delete the live record"

    async def test_delete_record_success(self, backend, mock_view_response, mock_zone_response):
        """Test successful record deletion."""
        mock_list_response = {
            "results": [
                {
                    "id": "dns/record/del123",
                    "absolute_name_spec": "_test._mcp._agents.example.com.",
                    "type": "SVCB",
                }
            ]
        }

        with patch.object(backend, "_request", new_callable=AsyncMock) as mock_req:
            # Calls: view lookup, zone lookup, list records, delete
            mock_req.side_effect = [mock_view_response, mock_zone_response, mock_list_response, {}]

            result = await backend.delete_record(
                zone="example.com", name="_test._mcp._agents", record_type="SVCB"
            )

            assert result is True
            # Should have called: view lookup, zone lookup, list records, delete
            assert mock_req.call_count == 4

    async def test_delete_record_not_found(self, backend, mock_view_response, mock_zone_response):
        """Test delete when record doesn't exist."""
        with patch.object(backend, "_request", new_callable=AsyncMock) as mock_req:
            # Calls: view lookup, zone lookup, list records (empty)
            mock_req.side_effect = [mock_view_response, mock_zone_response, {"results": []}]

            result = await backend.delete_record(
                zone="example.com", name="_nonexistent._mcp._agents", record_type="SVCB"
            )

            assert result is False

    async def test_list_zones(self, backend):
        """Test listing zones."""
        mock_response = {
            "results": [
                {
                    "id": "zone1",
                    "fqdn": "example.com.",
                    "comment": "Test 1",
                    "dnssec_enabled": True,
                },
                {
                    "id": "zone2",
                    "fqdn": "example.org.",
                    "comment": "Test 2",
                    "dnssec_enabled": False,
                },
            ]
        }

        with patch.object(backend, "_request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = mock_response

            zones = await backend.list_zones()

            assert len(zones) == 2
            assert zones[0]["name"] == "example.com"
            assert zones[0]["dnssec_enabled"] is True
            assert zones[1]["name"] == "example.org"

    async def test_list_records(self, backend, mock_view_response, mock_zone_response):
        """Test listing records."""
        mock_records_response = {
            "results": [
                {
                    "id": "rec1",
                    "name_in_zone": "_agent1._mcp._agents",
                    "absolute_name_spec": "_agent1._mcp._agents.example.com.",
                    "type": "SVCB",
                    "ttl": 300,
                    "rdata": {"target_name": "mcp.example.com.", "svc_params": ""},
                },
                {
                    "id": "rec2",
                    "name_in_zone": "_agent1._mcp._agents",
                    "absolute_name_spec": "_agent1._mcp._agents.example.com.",
                    "type": "TXT",
                    "ttl": 300,
                    "rdata": {"text": "capabilities=chat"},
                },
            ]
        }

        with patch.object(backend, "_request", new_callable=AsyncMock) as mock_req:
            # Calls: view lookup, zone lookup, list records, list records (empty to end pagination)
            mock_req.side_effect = [
                mock_view_response,
                mock_zone_response,
                mock_records_response,
                {"results": []},
            ]

            records = []
            async for record in backend.list_records(zone="example.com"):
                records.append(record)

            assert len(records) == 2
            assert records[0]["type"] == "SVCB"
            assert records[1]["type"] == "TXT"

    async def test_context_manager(self, backend):
        """Test async context manager."""
        async with backend as b:
            assert b is backend

    async def test_close(self, backend):
        """Test close method."""
        # Create a mock client
        mock_client = MagicMock()
        mock_client.is_closed = False
        mock_client.aclose = AsyncMock()
        backend._client = mock_client

        await backend.close()

        mock_client.aclose.assert_called_once()
        assert backend._client is None  # Client should be cleared after close


class TestInfobloxNIOSBackendImport:
    """Verify NIOS backend is importable via the infoblox package."""

    def test_nios_import(self):
        """Test that InfobloxNIOSBackend can be imported from infoblox package."""
        from dns_aid.backends.infoblox import InfobloxNIOSBackend

        backend = InfobloxNIOSBackend(host="nios.example.com", username="admin", password="secret")
        assert backend.name == "nios"


def _mock_response(
    json_data=None,
    status_code=200,
    raise_error: Exception | None = None,
):
    """Build a MagicMock httpx response."""
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = json_data if json_data is not None else {}
    if raise_error is not None:
        response.raise_for_status = MagicMock(side_effect=raise_error)
    else:
        response.raise_for_status = MagicMock()
    return response


class TestBloxOneClientAndRequest:
    """Tests for HTTP client lifecycle and the low-level _request helper."""

    @pytest.fixture
    def backend(self):
        return InfobloxBloxOneBackend(api_key="test-key")

    def test_dns_view_property(self, backend):
        assert backend.dns_view == "default"

    async def test_get_client_creates_and_caches(self, backend):
        client = await backend._get_client()
        assert isinstance(client, httpx.AsyncClient)
        assert client.headers["Authorization"] == "Token test-key"
        assert client.headers["Content-Type"] == "application/json"

        # Second call within the same loop returns the same client.
        assert await backend._get_client() is client

        await backend.close()
        assert backend._client is None

    async def test_get_client_recreates_on_loop_change(self, backend):
        old_client = MagicMock()
        old_client.is_closed = False
        old_client.aclose = AsyncMock()
        backend._client = old_client
        backend._client_loop_id = -1  # Never a real loop id

        client = await backend._get_client()

        old_client.aclose.assert_awaited_once()
        assert client is not old_client
        assert isinstance(client, httpx.AsyncClient)
        await backend.close()

    async def test_close_noop_without_client(self, backend):
        assert backend._client is None
        await backend.close()  # Must not raise

    async def test_request_returns_json(self, backend):
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=_mock_response({"results": [{"id": "x"}]}))

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend._request("GET", "/dns/view", params={"_filter": "x"})

        assert result == {"results": [{"id": "x"}]}
        call = mock_client.request.call_args
        assert call[1]["url"] == "/api/ddi/v1/dns/view"
        assert call[1]["method"] == "GET"

    async def test_request_204_returns_empty_dict(self, backend):
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=_mock_response(status_code=204))

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend._request("DELETE", "/dns/record/abc")

        assert result == {}

    async def test_request_raises_on_http_error(self, backend):
        error = httpx.HTTPStatusError(
            "401", request=MagicMock(), response=MagicMock(status_code=401)
        )
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(
            return_value=_mock_response(status_code=401, raise_error=error)
        )

        with (
            patch.object(backend, "_get_client", return_value=mock_client),
            pytest.raises(httpx.HTTPStatusError),
        ):
            await backend._request("GET", "/dns/auth_zone")

    async def test_td_request_returns_json(self, backend):
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=_mock_response({"results": []}))

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend._td_request("GET", "/named_lists")

        assert result == {"results": []}
        call = mock_client.request.call_args
        assert call[1]["url"] == "/api/atcfw/v1/named_lists"

    async def test_td_request_204_returns_empty_dict(self, backend):
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=_mock_response(status_code=204))

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend._td_request("DELETE", "/named_lists/1")

        assert result == {}

    async def test_td_request_raises_on_http_error(self, backend):
        error = httpx.HTTPStatusError(
            "403", request=MagicMock(), response=MagicMock(status_code=403)
        )
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(
            return_value=_mock_response(status_code=403, raise_error=error)
        )

        with (
            patch.object(backend, "_get_client", return_value=mock_client),
            pytest.raises(httpx.HTTPStatusError),
        ):
            await backend._td_request("GET", "/security_policies")


class TestBloxOneViewAndZoneLookup:
    """Tests for view/zone resolution helpers and their caches."""

    @pytest.fixture
    def backend(self):
        return InfobloxBloxOneBackend(api_key="test-key")

    async def test_get_view_id_cache_hit(self, backend):
        backend._view_cache["default"] = "dns/view/cached"

        with patch.object(backend, "_request", new_callable=AsyncMock) as mock_req:
            view_id = await backend._get_view_id("default")

        assert view_id == "dns/view/cached"
        mock_req.assert_not_called()

    async def test_get_view_id_not_found_returns_none(self, backend):
        with patch.object(backend, "_request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {"results": []}
            view_id = await backend._get_view_id("missing-view")

        assert view_id is None
        assert "missing-view" not in backend._view_cache

    async def test_get_zone_info_cache_hit(self, backend):
        cached = {"id": "dns/auth_zone/cached", "fqdn": "example.com."}
        backend._zone_cache["example.com:default"] = cached

        with patch.object(backend, "_request", new_callable=AsyncMock) as mock_req:
            zone_info = await backend._get_zone_info("Example.COM.")

        assert zone_info is cached
        mock_req.assert_not_called()

    async def test_get_zone_info_without_view_skips_view_filter(self, backend):
        backend._dns_view = ""  # No view configured

        with patch.object(backend, "_request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {"results": [{"id": "dns/auth_zone/z1"}]}
            zone_info = await backend._get_zone_info("example.com")

        assert zone_info["id"] == "dns/auth_zone/z1"
        # Only the zone lookup happened (no view resolution call).
        assert mock_req.call_count == 1
        assert mock_req.call_args[1]["params"]["_filter"] == 'fqdn=="example.com."'

    async def test_get_zone_info_view_unresolved_omits_view_filter(self, backend):
        with patch.object(backend, "_request", new_callable=AsyncMock) as mock_req:
            mock_req.side_effect = [
                {"results": []},  # view lookup: not found
                {"results": [{"id": "dns/auth_zone/z1"}]},
            ]
            zone_info = await backend._get_zone_info("example.com")

        assert zone_info["id"] == "dns/auth_zone/z1"
        zone_call = mock_req.call_args_list[1]
        assert zone_call[1]["params"]["_filter"] == 'fqdn=="example.com."'

    async def test_zone_exists_false_on_api_error(self, backend):
        with patch.object(backend, "_request", new_callable=AsyncMock) as mock_req:
            mock_req.side_effect = httpx.ConnectError("network down")
            assert await backend.zone_exists("example.com") is False


class TestBloxOneRecordReadPaths:
    """Tests for get_record, delete edge cases, and list_records filters."""

    @pytest.fixture
    def backend(self):
        return InfobloxBloxOneBackend(api_key="test-key")

    @pytest.fixture
    def mock_view_response(self):
        return {"results": [{"id": "dns/view/view123", "name": "default"}]}

    @pytest.fixture
    def mock_zone_response(self):
        return {"results": [{"id": "dns/auth_zone/abc123", "fqdn": "example.com."}]}

    async def test_get_record_txt(self, backend):
        record = {
            "id": "dns/record/txt1",
            "name_in_zone": "_index._agents",
            "absolute_name_spec": "_index._agents.example.com.",
            "type": "TXT",
            "ttl": 300,
            "rdata": {"text": '"agents=chat:mcp"'},
        }
        with patch.object(backend, "_request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {"results": [record]}
            result = await backend.get_record("example.com", "_index._agents", "TXT")

        assert result is not None
        assert result["name"] == "_index._agents"
        assert result["fqdn"] == "_index._agents.example.com"
        assert result["values"] == ['"agents=chat:mcp"']
        assert result["ttl"] == 300
        # The lookup uses the trailing-dot FQDN filter.
        filt = mock_req.call_args[1]["params"]["_filter"]
        assert 'absolute_name_spec=="_index._agents.example.com."' in filt

    async def test_get_record_svcb_presentation(self, backend):
        record = {
            "id": "dns/record/svcb1",
            "name_in_zone": "_chat._mcp._agents",
            "absolute_name_spec": "_chat._mcp._agents.example.com.",
            "type": "SVCB",
            "ttl": 600,
            "rdata": {
                "priority": 1,
                "target_name": "mcp.example.com.",
                "svc_params": [{"key": "alpn", "value": "mcp"}],
            },
        }
        with patch.object(backend, "_request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {"results": [record]}
            result = await backend.get_record("example.com", "_chat._mcp._agents", "SVCB")

        assert result is not None
        assert result["values"] == ["1 mcp.example.com. alpn=mcp"]

    async def test_get_record_generic_type_with_trailing_dot_zone(self, backend):
        record = {
            "id": "dns/record/a1",
            "name_in_zone": "www",
            "absolute_name_spec": "www.example.com.",
            "type": "A",
            "ttl": 60,
            "rdata": {"address": "192.0.2.1"},
        }
        with patch.object(backend, "_request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {"results": [record]}
            # Zone with trailing dot exercises the no-extra-dot branch.
            result = await backend.get_record("example.com.", "www", "A")

        assert result is not None
        assert result["values"] == [str({"address": "192.0.2.1"})]

    async def test_get_record_not_found_returns_none(self, backend):
        with patch.object(backend, "_request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = {"results": []}
            result = await backend.get_record("example.com", "_missing._agents", "TXT")

        assert result is None

    async def test_get_record_error_returns_none(self, backend):
        with patch.object(backend, "_request", new_callable=AsyncMock) as mock_req:
            mock_req.side_effect = httpx.ConnectError("boom")
            result = await backend.get_record("example.com", "_chat._mcp._agents", "SVCB")

        assert result is None

    async def test_delete_record_zone_with_trailing_dot(
        self, backend, mock_view_response, mock_zone_response
    ):
        """A zone given with a trailing dot must not get a second dot appended."""
        found = {"results": [{"id": "dns/record/del1"}]}
        with patch.object(backend, "_request", new_callable=AsyncMock) as mock_req:
            mock_req.side_effect = [mock_view_response, mock_zone_response, found, {}]
            result = await backend.delete_record("example.com.", "_x._mcp._agents", "SVCB")

        assert result is True
        list_call = mock_req.call_args_list[2]
        filt = list_call[1]["params"]["_filter"]
        assert '=="_x._mcp._agents.example.com."' in filt  # single trailing dot

    async def test_delete_record_error_returns_false(self, backend):
        with patch.object(backend, "_request", new_callable=AsyncMock) as mock_req:
            mock_req.side_effect = httpx.ConnectError("boom")
            result = await backend.delete_record("example.com", "_x._mcp._agents", "SVCB")

        assert result is False

    async def test_list_records_type_and_name_filters(
        self, backend, mock_view_response, mock_zone_response
    ):
        with patch.object(backend, "_request", new_callable=AsyncMock) as mock_req:
            mock_req.side_effect = [
                mock_view_response,
                mock_zone_response,
                {"results": []},
            ]
            records = [
                r
                async for r in backend.list_records(
                    "example.com", name_pattern="_agent", record_type="SVCB"
                )
            ]

        assert records == []
        filt = mock_req.call_args_list[2][1]["params"]["_filter"]
        assert 'type=="SVCB"' in filt
        assert 'name_in_zone~"_agent"' in filt

    async def test_list_records_generic_rdata(
        self, backend, mock_view_response, mock_zone_response
    ):
        record = {
            "id": "rec-a",
            "name_in_zone": "www",
            "absolute_name_spec": "www.example.com.",
            "type": "A",
            "ttl": 60,
            "rdata": {"address": "192.0.2.1"},
        }
        with patch.object(backend, "_request", new_callable=AsyncMock) as mock_req:
            mock_req.side_effect = [
                mock_view_response,
                mock_zone_response,
                {"results": [record]},
                {"results": []},
            ]
            records = [r async for r in backend.list_records("example.com")]

        assert len(records) == 1
        assert records[0]["values"] == [str({"address": "192.0.2.1"})]

    def test_svcb_presentation_non_list_params(self):
        value = InfobloxBloxOneBackend._svcb_presentation(
            {"priority": 1, "target_name": "x.example.com.", "svc_params": "alpn=mcp"}
        )
        assert value == "1 x.example.com. alpn=mcp"


class TestBloxOneThreatDefenseNamedLists:
    """Tests for TD named list operations."""

    @pytest.fixture
    def backend(self):
        return InfobloxBloxOneBackend(api_key="test-key")

    async def test_create_named_list_new(self, backend):
        with patch.object(backend, "_td_request", new_callable=AsyncMock) as mock_td:
            mock_td.side_effect = [
                {"results": []},  # no existing lists
                {"results": {"id": "nl-new", "name": "dns-aid-rpz"}},  # POST
            ]
            result = await backend.create_or_update_named_list(
                name="dns-aid-rpz",
                items=["evil.com", "worse.com"],
                description="blocked",
            )

        assert result == {"id": "nl-new", "name": "dns-aid-rpz", "updated": False}
        post_call = mock_td.call_args_list[1]
        assert post_call[0][0] == "POST"
        assert post_call[0][1] == "/named_lists"
        payload = post_call[1]["json"]
        assert payload["type"] == "custom_list"
        assert payload["confidence_level"] == "HIGH"
        assert {"item": "evil.com", "description": "blocked"} in payload["items_described"]

    async def test_create_named_list_update_existing(self, backend):
        with patch.object(backend, "_td_request", new_callable=AsyncMock) as mock_td:
            mock_td.side_effect = [
                {
                    "results": [
                        {"id": "nl-0", "name": "unrelated-list"},
                        {"id": "nl-1", "name": "dns-aid-rpz"},
                    ]
                },
                {},  # PUT
            ]
            result = await backend.create_or_update_named_list(
                name="dns-aid-rpz",
                items=["evil.com"],
            )

        assert result == {"id": "nl-1", "name": "dns-aid-rpz", "updated": True}
        put_call = mock_td.call_args_list[1]
        assert put_call[0][0] == "PUT"
        assert put_call[0][1] == "/named_lists/nl-1"
        # Default per-item description is applied when none was given.
        assert put_call[1]["json"]["items_described"][0]["description"] == "DNS-AID policy"

    async def test_create_named_list_new_flat_response(self, backend):
        """A POST response without a 'results' wrapper is used directly."""
        with patch.object(backend, "_td_request", new_callable=AsyncMock) as mock_td:
            mock_td.side_effect = [
                {"results": []},
                {"id": "nl-flat"},
            ]
            result = await backend.create_or_update_named_list(name="x", items=[])

        assert result["id"] == "nl-flat"
        assert result["updated"] is False

    async def test_list_named_lists(self, backend):
        lists = [
            {
                "id": "nl-1",
                "name": "dns-aid-rpz",
                "type": "custom_list",
                "item_count": 2,
                "description": "d",
                "confidence_level": "HIGH",
            },
            {"id": "nl-2", "name": "other", "type": "custom_list"},
        ]
        with patch.object(backend, "_td_request", new_callable=AsyncMock) as mock_td:
            mock_td.return_value = {"results": lists}
            all_lists = await backend.list_named_lists()
            filtered = await backend.list_named_lists(name_filter="dns-aid-rpz")

        assert len(all_lists) == 2
        assert all_lists[1]["item_count"] == 0  # default fill-in
        assert len(filtered) == 1
        assert filtered[0]["id"] == "nl-1"

    async def test_delete_named_list(self, backend):
        with patch.object(backend, "_td_request", new_callable=AsyncMock) as mock_td:
            mock_td.return_value = {}
            assert await backend.delete_named_list("nl-1") is True

        mock_td.assert_awaited_once_with("DELETE", "/named_lists/nl-1")


class TestBloxOneThreatDefensePolicies:
    """Tests for TD security policy operations."""

    @pytest.fixture
    def backend(self):
        return InfobloxBloxOneBackend(api_key="test-key")

    async def test_list_security_policies(self, backend):
        with patch.object(backend, "_td_request", new_callable=AsyncMock) as mock_td:
            mock_td.return_value = {
                "results": [
                    {
                        "id": 5,
                        "name": "Default Global Policy",
                        "description": "d",
                        "rules": [{"data": "x"}],
                        "is_default": True,
                    },
                    {"id": 6, "name": "Custom"},
                ]
            }
            policies = await backend.list_security_policies()

        assert policies[0] == {
            "id": 5,
            "name": "Default Global Policy",
            "description": "d",
            "rule_count": 1,
            "is_default": True,
        }
        assert policies[1]["rule_count"] == 0
        assert policies[1]["is_default"] is False

    async def test_get_security_policy_unwraps_results(self, backend):
        with patch.object(backend, "_td_request", new_callable=AsyncMock) as mock_td:
            mock_td.return_value = {"results": {"id": 5, "name": "Default"}}
            policy = await backend.get_security_policy(5)

        assert policy == {"id": 5, "name": "Default"}
        mock_td.assert_awaited_once_with("GET", "/security_policies/5")

    async def test_get_security_policy_flat_response(self, backend):
        with patch.object(backend, "_td_request", new_callable=AsyncMock) as mock_td:
            mock_td.return_value = {"id": 5, "name": "Default"}
            policy = await backend.get_security_policy(5)

        assert policy == {"id": 5, "name": "Default"}

    async def test_bind_named_list_uses_default_policy(self, backend):
        with patch.object(backend, "_td_request", new_callable=AsyncMock) as mock_td:
            mock_td.side_effect = [
                # list_security_policies
                {
                    "results": [
                        {"id": 9, "name": "Custom", "is_default": False},
                        {"id": 5, "name": "Default", "is_default": True, "rules": []},
                    ]
                },
                # get_security_policy(5)
                {
                    "results": {
                        "id": 5,
                        "name": "Default",
                        "rules": [{"action": "action_allow", "data": "other-list"}],
                        "default_action": "action_allow",
                    }
                },
                {},  # PUT
            ]
            result = await backend.bind_named_list_to_policy("dns-aid-rpz")

        assert result["policy_id"] == 5
        assert result["action"] == "bound"
        assert result["rule_count"] == 2
        put_call = mock_td.call_args_list[2]
        assert put_call[0][0] == "PUT"
        assert put_call[0][1] == "/security_policies/5"
        rules = put_call[1]["json"]["rules"]
        # Our rule is prepended and evaluated first.
        assert rules[0] == {
            "action": "action_block",
            "data": "dns-aid-rpz",
            "type": "custom_list",
        }

    async def test_bind_named_list_no_default_policy_raises(self, backend):
        with patch.object(backend, "_td_request", new_callable=AsyncMock) as mock_td:
            mock_td.return_value = {"results": [{"id": 9, "name": "Custom", "is_default": False}]}
            with pytest.raises(ValueError, match="No default security policy"):
                await backend.bind_named_list_to_policy("dns-aid-rpz")

    async def test_bind_named_list_already_bound(self, backend):
        with patch.object(backend, "_td_request", new_callable=AsyncMock) as mock_td:
            mock_td.return_value = {
                "results": {
                    "id": 5,
                    "name": "Default",
                    "rules": [{"action": "action_block", "data": "dns-aid-rpz"}],
                }
            }
            result = await backend.bind_named_list_to_policy("dns-aid-rpz", policy_id=5)

        assert result["action"] == "already_bound"
        assert result["rule_count"] == 1
        # Only the GET happened — no PUT for an already-bound rule.
        assert mock_td.await_count == 1

    async def test_bind_named_list_replaces_rule_with_new_action(self, backend):
        with patch.object(backend, "_td_request", new_callable=AsyncMock) as mock_td:
            mock_td.side_effect = [
                {
                    "results": {
                        "id": 5,
                        "name": "Default",
                        "rules": [
                            {"action": "action_log", "data": "dns-aid-rpz"},
                            {"action": "action_allow", "data": "other"},
                        ],
                        "default_action": "action_allow",
                    }
                },
                {},  # PUT
            ]
            result = await backend.bind_named_list_to_policy(
                "dns-aid-rpz", policy_id=5, action="action_block"
            )

        assert result["action"] == "bound"
        assert result["rule_count"] == 2  # old rule replaced, not duplicated
        rules = mock_td.call_args_list[1][1]["json"]["rules"]
        assert rules[0]["action"] == "action_block"
        assert sum(1 for r in rules if r["data"] == "dns-aid-rpz") == 1

    async def test_unbind_named_list(self, backend):
        with patch.object(backend, "_td_request", new_callable=AsyncMock) as mock_td:
            mock_td.side_effect = [
                {
                    "results": {
                        "id": 5,
                        "name": "Default",
                        "rules": [
                            {"action": "action_block", "data": "dns-aid-rpz"},
                            {"action": "action_allow", "data": "other"},
                        ],
                        "default_action": "action_allow",
                    }
                },
                {},  # PUT
            ]
            result = await backend.unbind_named_list_from_policy("dns-aid-rpz", policy_id=5)

        assert result["action"] == "unbound"
        assert result["rule_count"] == 1
        rules = mock_td.call_args_list[1][1]["json"]["rules"]
        assert rules == [{"action": "action_allow", "data": "other"}]

    async def test_unbind_named_list_not_found(self, backend):
        with patch.object(backend, "_td_request", new_callable=AsyncMock) as mock_td:
            mock_td.return_value = {
                "results": {
                    "id": 5,
                    "name": "Default",
                    "rules": [{"action": "action_allow", "data": "other"}],
                }
            }
            result = await backend.unbind_named_list_from_policy("dns-aid-rpz", policy_id=5)

        assert result["action"] == "not_found"
        assert mock_td.await_count == 1  # no PUT issued

    async def test_unbind_named_list_uses_default_policy(self, backend):
        with patch.object(backend, "_td_request", new_callable=AsyncMock) as mock_td:
            mock_td.side_effect = [
                {"results": [{"id": 5, "name": "Default", "is_default": True}]},
                {
                    "results": {
                        "id": 5,
                        "name": "Default",
                        "rules": [{"action": "action_block", "data": "dns-aid-rpz"}],
                        "default_action": "action_allow",
                    }
                },
                {},  # PUT
            ]
            result = await backend.unbind_named_list_from_policy("dns-aid-rpz")

        assert result["policy_id"] == 5
        assert result["action"] == "unbound"

    async def test_unbind_named_list_no_default_policy_raises(self, backend):
        with patch.object(backend, "_td_request", new_callable=AsyncMock) as mock_td:
            mock_td.return_value = {"results": []}
            with pytest.raises(ValueError, match="No default security policy"):
                await backend.unbind_named_list_from_policy("dns-aid-rpz")
