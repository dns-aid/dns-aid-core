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
