# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for Infoblox NIOS (on-premises) backend.

These tests mock the HTTP API to test the backend logic without
requiring real NIOS credentials.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from dns_aid.backends.infoblox.nios import InfobloxNIOSBackend


class TestInfobloxNIOSInit:
    """Tests for InfobloxNIOSBackend initialization."""

    @pytest.mark.parametrize(
        ("kwargs", "error_match"),
        [
            (
                {"host": "", "username": "admin", "password": "secret"},
                "NIOS host required",
            ),
            (
                {"host": "nios.local", "username": "", "password": "secret"},
                "NIOS username required",
            ),
            (
                {"host": "nios.local", "username": "admin", "password": ""},
                "NIOS password required",
            ),
        ],
    )
    def test_constructor_validation_errors(self, kwargs: dict[str, str], error_match: str) -> None:
        with pytest.raises(ValueError, match=error_match):
            InfobloxNIOSBackend(**kwargs)

    def test_init_with_explicit_params(self) -> None:
        backend = InfobloxNIOSBackend(host="nios.local", username="admin", password="secret")
        assert backend.name == "nios"
        assert backend.dns_view == "default"
        assert backend._host == "nios.local"

    def test_init_custom_wapi_version(self) -> None:
        backend = InfobloxNIOSBackend(
            host="nios.local",
            username="admin",
            password="secret",
            wapi_version="2.12",
        )
        assert backend._wapi_version == "2.12"
        assert "v2.12" in backend._base_url

    def test_init_custom_dns_view(self) -> None:
        backend = InfobloxNIOSBackend(
            host="nios.local",
            username="admin",
            password="secret",
            dns_view="internal",
        )
        assert backend.dns_view == "internal"

    def test_init_from_env_vars(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NIOS_HOST", "env-nios.local")
        monkeypatch.setenv("NIOS_USERNAME", "env-admin")
        monkeypatch.setenv("NIOS_PASSWORD", "env-secret")
        monkeypatch.setenv("NIOS_WAPI_VERSION", "2.11")
        monkeypatch.setenv("NIOS_DNS_VIEW", "custom")
        monkeypatch.setenv("NIOS_TIMEOUT", "60")

        backend = InfobloxNIOSBackend()
        assert backend._host == "env-nios.local"
        assert backend._username == "env-admin"
        assert backend._wapi_version == "2.11"
        assert backend.dns_view == "custom"
        assert backend._timeout == 60.0


class TestInfobloxNIOSHelpers:
    """Tests for NIOS backend helper methods."""

    def test_parse_bool_env_true_values(self) -> None:
        for val in ("1", "true", "True", "YES", "on"):
            assert InfobloxNIOSBackend._parse_bool_env(val, default=False) is True

    def test_parse_bool_env_false_values(self) -> None:
        for val in ("0", "false", "False", "NO", "off"):
            assert InfobloxNIOSBackend._parse_bool_env(val, default=True) is False

    def test_parse_bool_env_none_returns_default(self) -> None:
        assert InfobloxNIOSBackend._parse_bool_env(None, default=True) is True
        assert InfobloxNIOSBackend._parse_bool_env(None, default=False) is False

    def test_parse_bool_env_invalid_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid boolean value"):
            InfobloxNIOSBackend._parse_bool_env("maybe", default=True)

    def test_to_fqdn_simple(self) -> None:
        assert (
            InfobloxNIOSBackend._to_fqdn("_agent._mcp._agents", "example.com")
            == "_agent._mcp._agents.example.com"
        )

    def test_to_fqdn_already_qualified(self) -> None:
        assert (
            InfobloxNIOSBackend._to_fqdn("_agent._mcp._agents.example.com", "example.com")
            == "_agent._mcp._agents.example.com"
        )

    def test_to_fqdn_strips_trailing_dots(self) -> None:
        assert (
            InfobloxNIOSBackend._to_fqdn("_agent._mcp._agents.", "example.com.")
            == "_agent._mcp._agents.example.com"
        )

    def test_normalize_target(self) -> None:
        assert InfobloxNIOSBackend._normalize_target("mcp.example.com.") == "mcp.example.com"
        assert InfobloxNIOSBackend._normalize_target("  host.com  ") == "host.com"

    def test_extract_name_from_fqdn(self) -> None:
        assert (
            InfobloxNIOSBackend._extract_name_from_fqdn(
                "_agent._mcp._agents.example.com", "example.com"
            )
            == "_agent._mcp._agents"
        )

    def test_extract_name_from_fqdn_no_match(self) -> None:
        # When zone doesn't match, return FQDN unchanged
        assert (
            InfobloxNIOSBackend._extract_name_from_fqdn(
                "_agent._mcp._agents.other.com", "example.com"
            )
            == "_agent._mcp._agents.other.com"
        )

    def test_extract_name_from_fqdn_trailing_dots(self) -> None:
        assert (
            InfobloxNIOSBackend._extract_name_from_fqdn(
                "_agent._mcp._agents.example.com.", "example.com."
            )
            == "_agent._mcp._agents"
        )


class TestInfobloxNIOSSvcParameters:
    """Tests for SVC parameter conversion."""

    def test_svc_parameters_conversion(self) -> None:
        params = {
            "mandatory": "alpn,port,cap,connect-class",
            "alpn": "h2,h3",
            "port": "443",
            "bap": "mcp=1.0",
            "cap": "https://example.com/.well-known/agent-cap.json",
            "sig": "abc123",
            "connect-class": "lattice",
        }

        converted = InfobloxNIOSBackend._svc_parameters_from_params(params)

        as_map = {item["svc_key"]: item for item in converted}
        assert as_map["alpn"]["svc_value"] == ["h2", "h3"]
        assert as_map["alpn"]["mandatory"] is True
        # bap is no longer in _SPLIT_VALUE_KEYS (draft-02 §5.1 makes it
        # a single scalar) — NIOS wraps non-split values in a 1-element
        # list for the API shape regardless.
        assert as_map["key65402"]["svc_value"] == ["mcp=1.0"]
        assert as_map["port"]["svc_value"] == ["443"]
        assert as_map["key65400"]["mandatory"] is True
        assert as_map["key65405"]["svc_value"] == ["abc123"]
        assert as_map["key65406"]["mandatory"] is True
        assert as_map["key65406"]["svc_value"] == ["lattice"]

    def test_svc_parameters_preserves_numeric_keys(self) -> None:
        converted = InfobloxNIOSBackend._svc_parameters_from_params(
            {"mandatory": "key65402,port", "key65402": "mcp=1.0", "port": "443"}
        )
        as_map = {item["svc_key"]: item for item in converted}

        assert as_map["key65402"]["mandatory"] is True
        assert as_map["key65402"]["svc_value"] == ["mcp=1.0"]
        assert as_map["port"]["mandatory"] is True

    def test_format_svc_parameters_for_value(self) -> None:
        svc_params = [
            {"svc_key": "alpn", "svc_value": ["mcp"], "mandatory": True},
            {"svc_key": "port", "svc_value": ["443"], "mandatory": True},
            {"svc_key": "key65404", "svc_value": ["prod"], "mandatory": False},
        ]
        result = InfobloxNIOSBackend._format_svc_parameters_for_value(svc_params)
        assert 'mandatory="alpn,port"' in result
        assert 'alpn="mcp"' in result
        assert 'port="443"' in result
        assert 'realm="prod"' in result

    def test_format_svc_parameters_non_list_returns_empty(self) -> None:
        assert InfobloxNIOSBackend._format_svc_parameters_for_value(None) == ""
        assert InfobloxNIOSBackend._format_svc_parameters_for_value("invalid") == ""


class TestInfobloxNIOSAsync:
    """Async tests for InfobloxNIOSBackend."""

    @pytest.fixture
    def backend(self) -> InfobloxNIOSBackend:
        return InfobloxNIOSBackend(host="nios.local", username="admin", password="secret")

    async def test_create_svcb_record_new(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[tuple[str, str, dict | None]] = []

        async def fake_find_record_ref(zone: str, name: str, record_type: str) -> None:
            return None

        async def fake_request(
            method: str,
            endpoint: str,
            *,
            params: dict[str, str] | None = None,
            json: dict | None = None,
        ) -> dict:
            calls.append((method, endpoint, json))
            return {}

        monkeypatch.setattr(backend, "_find_record_ref", fake_find_record_ref)
        monkeypatch.setattr(backend, "_request", fake_request)

        await backend.create_svcb_record(
            zone="example.com",
            name="_agent._mcp._agents",
            priority=1,
            target="mcp.example.com",
            params={
                "mandatory": "alpn,port",
                "alpn": "mcp",
                "port": "443",
                "realm": "prod",
            },
            ttl=900,
        )

        assert calls
        method, endpoint, payload = calls[0]
        assert method == "POST"
        assert endpoint == "record:svcb"
        assert payload is not None
        assert payload["priority"] == 1
        assert payload["target_name"] == "mcp.example.com"
        assert payload["ttl"] == 900
        assert payload["use_ttl"] is True
        assert payload["view"] == "default"
        assert any(param["svc_key"] == "key65404" for param in payload["svc_parameters"])

    async def test_create_svcb_record_update(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[tuple[str, str, dict | None]] = []

        async def fake_find_record_ref(zone: str, name: str, record_type: str) -> str:
            return "record:svcb/ZG5z..."

        async def fake_request(
            method: str,
            endpoint: str,
            *,
            params: dict[str, str] | None = None,
            json: dict | None = None,
        ) -> dict:
            calls.append((method, endpoint, json))
            return {}

        monkeypatch.setattr(backend, "_find_record_ref", fake_find_record_ref)
        monkeypatch.setattr(backend, "_request", fake_request)

        await backend.create_svcb_record(
            zone="example.com",
            name="_agent._mcp._agents",
            priority=1,
            target="mcp.example.com",
            params={"alpn": "mcp", "port": "443"},
        )

        assert calls[0][0] == "PUT"
        assert calls[0][1] == "record:svcb/ZG5z..."
        # NIOS WAPI rejects immutable fields (name, view) in PUT requests
        put_payload = calls[0][2]
        assert "name" not in put_payload
        assert "view" not in put_payload

    async def test_find_record_ref(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_request(
            method: str,
            endpoint: str,
            *,
            params: dict[str, str] | None = None,
            json: dict | None = None,
        ) -> list[dict[str, str]]:
            assert method == "GET"
            assert endpoint == "record:svcb"
            return [{"_ref": "record:svcb/ZG5z..."}]

        monkeypatch.setattr(backend, "_request", fake_request)

        ref = await backend._find_record_ref("example.com", "_agent._mcp._agents", "SVCB")
        assert ref == "record:svcb/ZG5z..."

    async def test_strict_fail_on_svcb_validation_error(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_find_record_ref(zone: str, name: str, record_type: str) -> None:
            return None

        async def fake_request(
            method: str,
            endpoint: str,
            *,
            params: dict[str, str] | None = None,
            json: dict | None = None,
        ) -> dict:
            raise RuntimeError("NIOS validation failed: invalid svc_key cap")

        monkeypatch.setattr(backend, "_find_record_ref", fake_find_record_ref)
        monkeypatch.setattr(backend, "_request", fake_request)

        with pytest.raises(RuntimeError, match="validation failed"):
            await backend.create_svcb_record(
                zone="example.com",
                name="_agent._mcp._agents",
                priority=1,
                target="mcp.example.com",
                params={"alpn": "mcp", "port": "443", "cap": "https://x"},
            )

    async def test_txt_create_and_update_upsert(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[tuple[str, str, dict | None]] = []

        async def fake_request(
            method: str,
            endpoint: str,
            *,
            params: dict[str, str] | None = None,
            json: dict | None = None,
        ) -> dict:
            calls.append((method, endpoint, json))
            return {}

        monkeypatch.setattr(backend, "_request", fake_request)

        async def missing_ref(zone: str, name: str, record_type: str) -> None:
            return None

        monkeypatch.setattr(backend, "_find_record_ref", missing_ref)
        await backend.create_txt_record(
            "example.com", "_agent._mcp._agents", ["capabilities=chat"], ttl=1200
        )
        assert calls[-1][0] == "POST"
        assert calls[-1][1] == "record:txt"

        async def existing_ref(zone: str, name: str, record_type: str) -> str:
            return "record:txt/ZG5z..."

        monkeypatch.setattr(backend, "_find_record_ref", existing_ref)
        await backend.create_txt_record(
            "example.com", "_agent._mcp._agents", ["version=1.0.0"], ttl=1200
        )
        assert calls[-1][0] == "PUT"
        assert calls[-1][1] == "record:txt/ZG5z..."

    async def test_delete_record_found_and_not_found(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[tuple[str, str]] = []

        async def fake_request(
            method: str,
            endpoint: str,
            *,
            params: dict[str, str] | None = None,
            json: dict | None = None,
        ) -> dict:
            calls.append((method, endpoint))
            return {}

        monkeypatch.setattr(backend, "_request", fake_request)

        async def found_ref(zone: str, name: str, record_type: str) -> str:
            return "record:svcb/ZG5z..."

        monkeypatch.setattr(backend, "_find_record_ref", found_ref)
        deleted = await backend.delete_record("example.com", "_agent._mcp._agents", "SVCB")
        assert deleted is True
        assert calls[-1] == ("DELETE", "record:svcb/ZG5z...")

        async def missing_ref(zone: str, name: str, record_type: str) -> None:
            return None

        monkeypatch.setattr(backend, "_find_record_ref", missing_ref)
        deleted = await backend.delete_record("example.com", "_agent._mcp._agents", "SVCB")
        assert deleted is False

    async def test_zone_exists_true_false(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def request_found(
            method: str,
            endpoint: str,
            *,
            params: dict[str, str] | None = None,
            json: dict | None = None,
        ) -> list[dict[str, str]]:
            return [{"_ref": "zone_auth/ZG5z..."}]

        monkeypatch.setattr(backend, "_request", request_found)
        assert await backend.zone_exists("example.com") is True

        # Second call should hit the cache
        assert await backend.zone_exists("example.com") is True

    async def test_zone_exists_false(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def request_missing(
            method: str,
            endpoint: str,
            *,
            params: dict[str, str] | None = None,
            json: dict | None = None,
        ) -> list[dict[str, str]]:
            return []

        monkeypatch.setattr(backend, "_request", request_missing)
        assert await backend.zone_exists("nonexistent.com") is False

    async def test_zone_exists_caching(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Verify zone_exists uses cache on second call."""
        call_count = 0

        async def counting_request(
            method: str,
            endpoint: str,
            *,
            params: dict[str, str] | None = None,
            json: dict | None = None,
        ) -> list[dict[str, str]]:
            nonlocal call_count
            call_count += 1
            return [{"_ref": "zone_auth/ZG5z..."}]

        monkeypatch.setattr(backend, "_request", counting_request)

        assert await backend.zone_exists("cached.com") is True
        first_count = call_count
        assert await backend.zone_exists("cached.com") is True
        # Second call should NOT make any HTTP requests (cached)
        assert call_count == first_count

    async def test_list_zones(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_request(
            method: str,
            endpoint: str,
            *,
            params: dict[str, str] | None = None,
            json: dict | None = None,
        ) -> list[dict[str, object]]:
            assert method == "GET"
            assert endpoint == "zone_auth"
            return [
                {
                    "_ref": "zone_auth/ZG5z...:example.com/default",
                    "fqdn": "example.com.",
                    "view": "default",
                    "comment": "Primary zone",
                    "disable": False,
                    "zone_format": "FORWARD",
                }
            ]

        monkeypatch.setattr(backend, "_request", fake_request)
        zones = await backend.list_zones()

        assert len(zones) == 1
        assert zones[0]["name"] == "example.com"
        assert zones[0]["fqdn"] == "example.com."
        assert zones[0]["view"] == "default"
        assert zones[0]["comment"] == "Primary zone"
        assert zones[0]["zone_format"] == "FORWARD"

    async def test_list_records_normalization(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_request(
            method: str,
            endpoint: str,
            *,
            params: dict[str, str] | None = None,
            json: dict | None = None,
        ) -> list[dict[str, object]]:
            if endpoint == "record:svcb":
                return [
                    {
                        "_ref": "record:svcb/abc",
                        "name": "_agent._mcp._agents.example.com",
                        "ttl": 3600,
                        "priority": 1,
                        "target_name": "mcp.example.com",
                        "svc_parameters": [
                            {"svc_key": "alpn", "svc_value": ["mcp"], "mandatory": True},
                            {"svc_key": "port", "svc_value": ["443"], "mandatory": True},
                            {
                                "svc_key": "key65404",
                                "svc_value": ["prod"],
                                "mandatory": False,
                            },
                        ],
                    }
                ]

            return [
                {
                    "_ref": "record:txt/def",
                    "name": "_agent._mcp._agents.example.com",
                    "ttl": 3600,
                    "text": '"capabilities=chat" "version=1.0.0"',
                }
            ]

        monkeypatch.setattr(backend, "_request", fake_request)

        records = [record async for record in backend.list_records("example.com")]

        assert len(records) == 2
        assert records[0]["type"] == "SVCB"
        assert records[1]["type"] == "TXT"
        assert records[0]["fqdn"] == "_agent._mcp._agents.example.com"
        assert records[0]["name"] == "_agent._mcp._agents"
        assert 'port="443"' in records[0]["values"][0]
        assert 'realm="prod"' in records[0]["values"][0]

    async def test_list_records_unsupported_type_warns(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """list_records should yield nothing for unsupported record types."""
        records = [
            record async for record in backend.list_records("example.com", record_type="AAAA")
        ]
        assert records == []

    async def test_get_record_found(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_request(
            method: str,
            endpoint: str,
            *,
            params: dict[str, str] | None = None,
            json: dict | None = None,
        ) -> list[dict[str, object]]:
            return [
                {
                    "_ref": "record:svcb/abc",
                    "name": "_agent._mcp._agents.example.com",
                    "ttl": 3600,
                    "priority": 1,
                    "target_name": "mcp.example.com",
                    "svc_parameters": [],
                }
            ]

        monkeypatch.setattr(backend, "_request", fake_request)

        result = await backend.get_record("example.com", "_agent._mcp._agents", "SVCB")
        assert result is not None
        assert result["name"] == "_agent._mcp._agents"
        assert result["type"] == "SVCB"

    async def test_get_record_not_found(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_request(
            method: str,
            endpoint: str,
            *,
            params: dict[str, str] | None = None,
            json: dict | None = None,
        ) -> list:
            return []

        monkeypatch.setattr(backend, "_request", fake_request)

        result = await backend.get_record("example.com", "_nonexistent._mcp._agents", "SVCB")
        assert result is None

    async def test_context_manager(self, backend: InfobloxNIOSBackend) -> None:
        async with backend as b:
            assert b is backend

    async def test_close(self, backend: InfobloxNIOSBackend) -> None:
        mock_client = MagicMock()
        mock_client.is_closed = False
        mock_client.aclose = AsyncMock()
        backend._client = mock_client

        await backend.close()

        mock_client.aclose.assert_called_once()
        assert backend._client is None

    async def test_zone_exists_bad_view_returns_false(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """zone_exists returns False when DNS view doesn't exist (not raise)."""
        backend._dns_view = "nonexistent-view"

        async def raise_view_not_found(
            method: str,
            endpoint: str,
            *,
            params: dict[str, str] | None = None,
            json: dict | None = None,
        ) -> dict:
            raise RuntimeError(
                "NIOS WAPI request failed (GET /zone_auth): "
                "status=404 body=View nonexistent-view not found"
            )

        monkeypatch.setattr(backend, "_request", raise_view_not_found)

        result = await backend.zone_exists("example.com")
        assert result is False
        # Should also be cached as False
        assert backend._zone_cache.get("example.com:nonexistent-view") is False

    async def test_zone_exists_transport_error_returns_false(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """zone_exists returns False on transport errors (network unreachable)."""

        async def raise_transport_error(
            method: str,
            endpoint: str,
            *,
            params: dict[str, str] | None = None,
            json: dict | None = None,
        ) -> dict:
            raise RuntimeError("NIOS WAPI transport error (GET /zone_auth): Connection refused")

        monkeypatch.setattr(backend, "_request", raise_transport_error)

        result = await backend.zone_exists("example.com")
        assert result is False

    async def test_txt_update_excludes_immutable_fields(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """PUT for TXT update must NOT include name or view fields."""
        calls: list[tuple[str, str, dict | None]] = []

        async def fake_find_existing(zone: str, name: str, record_type: str) -> str:
            return "record:txt/ZG5z..."

        async def fake_request(
            method: str,
            endpoint: str,
            *,
            params: dict[str, str] | None = None,
            json: dict | None = None,
        ) -> dict:
            calls.append((method, endpoint, json))
            return {}

        monkeypatch.setattr(backend, "_find_record_ref", fake_find_existing)
        monkeypatch.setattr(backend, "_request", fake_request)

        await backend.create_txt_record("example.com", "_agent._mcp._agents", ["updated=true"])

        assert calls[0][0] == "PUT"
        put_payload = calls[0][2]
        assert "name" not in put_payload
        assert "view" not in put_payload
        assert "text" in put_payload

    async def test_list_records_name_pattern_filter(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """list_records with name_pattern filters results correctly."""

        async def fake_request(
            method: str,
            endpoint: str,
            *,
            params: dict[str, str] | None = None,
            json: dict | None = None,
        ) -> list[dict[str, object]]:
            return [
                {
                    "_ref": "record:txt/a",
                    "name": "_agent1._mcp._agents.example.com",
                    "ttl": 300,
                    "text": '"capabilities=a"',
                },
                {
                    "_ref": "record:txt/b",
                    "name": "_agent2._a2a._agents.example.com",
                    "ttl": 300,
                    "text": '"capabilities=b"',
                },
            ]

        monkeypatch.setattr(backend, "_request", fake_request)

        # Filter by name_pattern — only _agent1 should match
        records = [
            r
            async for r in backend.list_records(
                "example.com", name_pattern="_agent1", record_type="TXT"
            )
        ]
        assert len(records) == 1
        assert "_agent1" in records[0]["fqdn"]


class TestPublisherNIOSBackendSelection:
    """Tests for publisher backend selection with NIOS."""

    def setup_method(self) -> None:
        from dns_aid.core.publisher import reset_default_backend

        reset_default_backend()

    def teardown_method(self) -> None:
        from dns_aid.core.publisher import reset_default_backend

        reset_default_backend()

    def test_get_default_backend_nios(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DNS_AID_BACKEND", "nios")
        monkeypatch.setenv("NIOS_HOST", "nios.local")
        monkeypatch.setenv("NIOS_USERNAME", "admin")
        monkeypatch.setenv("NIOS_PASSWORD", "secret")

        from dns_aid.core.publisher import get_default_backend

        backend = get_default_backend()

        assert isinstance(backend, InfobloxNIOSBackend)
        assert backend.name == "nios"

    def test_get_default_backend_infoblox_stays_bloxone(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Ensure DNS_AID_BACKEND=infoblox still resolves to BloxOne."""
        monkeypatch.setenv("DNS_AID_BACKEND", "infoblox")
        monkeypatch.setenv("INFOBLOX_API_KEY", "token")

        from dns_aid.backends.infoblox import InfobloxBloxOneBackend
        from dns_aid.core.publisher import get_default_backend

        backend = get_default_backend()

        assert isinstance(backend, InfobloxBloxOneBackend)

    async def test_publish_to_nonexistent_zone_returns_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """publish() returns success=False when zone doesn't exist."""
        monkeypatch.setenv("DNS_AID_BACKEND", "nios")
        monkeypatch.setenv("NIOS_HOST", "nios.local")
        monkeypatch.setenv("NIOS_USERNAME", "admin")
        monkeypatch.setenv("NIOS_PASSWORD", "secret")

        from dns_aid.core.publisher import publish, reset_default_backend

        reset_default_backend()

        backend = InfobloxNIOSBackend(host="nios.local", username="admin", password="secret")

        # Mock zone_exists to return False
        async def fake_zone_not_exists(zone: str) -> bool:
            return False

        monkeypatch.setattr(backend, "zone_exists", fake_zone_not_exists)

        result = await publish(
            name="test-agent",
            domain="nonexistent.com",
            protocol="mcp",
            endpoint="mcp.nonexistent.com",
            backend=backend,
        )

        assert result.success is False
        assert "does not exist" in result.message

    async def test_publish_to_bad_view_returns_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """publish() returns success=False when DNS view is misconfigured."""
        backend = InfobloxNIOSBackend(
            host="nios.local",
            username="admin",
            password="secret",
            dns_view="nonexistent-view",
        )

        # Simulate WAPI 404 for bad view
        async def raise_view_not_found(
            method: str,
            endpoint: str,
            *,
            params: dict[str, str] | None = None,
            json: dict | None = None,
        ) -> dict:
            raise RuntimeError("NIOS WAPI request failed: View nonexistent-view not found")

        monkeypatch.setattr(backend, "_request", raise_view_not_found)

        from dns_aid.core.publisher import publish

        result = await publish(
            name="test-agent",
            domain="example.com",
            protocol="mcp",
            endpoint="mcp.example.com",
            backend=backend,
        )

        assert result.success is False
        assert "does not exist" in result.message


def _nios_backend(**kwargs) -> InfobloxNIOSBackend:
    defaults = {"host": "nios.local", "username": "admin", "password": "secret"}
    defaults.update(kwargs)
    return InfobloxNIOSBackend(**defaults)


def _mock_response(
    *,
    json_data=None,
    status_code: int = 200,
    content: bytes = b"{}",
    content_type: str = "application/json",
    text: str = "",
):
    """Build a MagicMock httpx response for NIOS _request tests."""
    response = MagicMock()
    response.status_code = status_code
    response.content = content
    response.text = text
    response.headers = {"content-type": content_type}
    response.json.return_value = json_data
    response.raise_for_status = MagicMock()
    return response


class TestNIOSInitBranches:
    """Constructor branches not covered by the main init tests."""

    def test_explicit_verify_ssl_param(self) -> None:
        backend = _nios_backend(verify_ssl=False)
        assert backend._verify_ssl is False

    def test_verify_ssl_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NIOS_VERIFY_SSL", "false")
        backend = _nios_backend()
        assert backend._verify_ssl is False

    def test_explicit_timeout_param(self) -> None:
        backend = _nios_backend(timeout=12.5)
        assert backend._timeout == 12.5

    def test_supports_private_svcb_keys(self) -> None:
        assert _nios_backend().supports_private_svcb_keys is True


class TestNIOSClient:
    """HTTP client lifecycle."""

    async def test_get_client_creates_and_caches(self) -> None:
        backend = _nios_backend(verify_ssl=False)
        client = await backend._get_client()
        assert isinstance(client, httpx.AsyncClient)
        assert client.headers["Content-Type"] == "application/json"

        assert await backend._get_client() is client
        await backend.close()
        assert backend._client is None

    async def test_get_client_recreates_on_loop_change(self) -> None:
        backend = _nios_backend(verify_ssl=False)
        old_client = MagicMock()
        old_client.is_closed = False
        old_client.aclose = AsyncMock()
        backend._client = old_client
        backend._client_loop_id = -1  # never a real loop id

        client = await backend._get_client()

        old_client.aclose.assert_awaited_once()
        assert client is not old_client
        assert isinstance(client, httpx.AsyncClient)
        await backend.close()

    async def test_close_noop_without_client(self) -> None:
        backend = _nios_backend()
        await backend.close()  # must not raise


class TestNIOSRequest:
    """Low-level _request error handling and response parsing."""

    @pytest.fixture
    def backend(self) -> InfobloxNIOSBackend:
        return _nios_backend()

    def _patch_client(self, backend: InfobloxNIOSBackend, response=None, side_effect=None):
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=response, side_effect=side_effect)
        return patch.object(backend, "_get_client", return_value=mock_client), mock_client

    async def test_request_returns_json_list(self, backend: InfobloxNIOSBackend) -> None:
        response = _mock_response(json_data=[{"_ref": "zone_auth/x"}], content=b"[...]")
        ctx, mock_client = self._patch_client(backend, response=response)
        with ctx:
            result = await backend._request("GET", "zone_auth", params={"fqdn": "example.com"})

        assert result == [{"_ref": "zone_auth/x"}]
        # Endpoint without a leading slash gets one prepended.
        assert mock_client.request.call_args[1]["url"] == "/zone_auth"

    async def test_request_http_status_error_raises_runtime_error(
        self, backend: InfobloxNIOSBackend
    ) -> None:
        error_response = MagicMock()
        error_response.status_code = 400
        error_response.text = "Bad svc_key"
        response = _mock_response()
        response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "400", request=MagicMock(), response=error_response
        )
        ctx, _ = self._patch_client(backend, response=response)
        with ctx, pytest.raises(RuntimeError, match="status=400 body=Bad svc_key"):
            await backend._request("POST", "/record:svcb", json={})

    async def test_request_transport_error_raises_runtime_error(
        self, backend: InfobloxNIOSBackend
    ) -> None:
        ctx, _ = self._patch_client(backend, side_effect=httpx.ConnectError("refused"))
        with ctx, pytest.raises(RuntimeError, match="transport error"):
            await backend._request("GET", "zone_auth")

    async def test_request_empty_body_returns_empty_dict(
        self, backend: InfobloxNIOSBackend
    ) -> None:
        response = _mock_response(content=b"")
        ctx, _ = self._patch_client(backend, response=response)
        with ctx:
            assert await backend._request("DELETE", "record:txt/ZG5z") == {}

    async def test_request_non_json_content_type_returns_raw(
        self, backend: InfobloxNIOSBackend
    ) -> None:
        response = _mock_response(content=b"plain", content_type="text/plain", text="plain")
        ctx, _ = self._patch_client(backend, response=response)
        with ctx:
            assert await backend._request("GET", "grid") == {"raw": "plain"}

    async def test_request_scalar_json_returns_raw(self, backend: InfobloxNIOSBackend) -> None:
        response = _mock_response(json_data="record:txt/ZG5z", content=b'"record:txt/ZG5z"')
        ctx, _ = self._patch_client(backend, response=response)
        with ctx:
            assert await backend._request("POST", "record:txt", json={}) == {
                "raw": "record:txt/ZG5z"
            }


class TestNIOSFormatSvcParametersEdgeCases:
    """Edge cases of _format_svc_parameters_for_value."""

    def test_skips_non_dict_and_empty_key_items(self) -> None:
        result = InfobloxNIOSBackend._format_svc_parameters_for_value(
            [
                "junk",
                {"svc_value": ["orphan"]},
                {"svc_key": "  ", "svc_value": ["blank-key"]},
                {"svc_key": "port", "svc_value": ["443"]},
            ]
        )
        assert result == 'port="443"'

    def test_scalar_and_none_svc_values(self) -> None:
        result = InfobloxNIOSBackend._format_svc_parameters_for_value(
            [
                {"svc_key": "port", "svc_value": "443"},  # scalar → single value
                {"svc_key": "alpn", "svc_value": None, "mandatory": True},  # value-less
                {"svc_key": "key65404", "svc_value": "   "},  # blank scalar dropped
            ]
        )
        # alpn is mandatory but value-less: listed in mandatory, no alpn=... token.
        assert result == 'mandatory="alpn" port="443"'
        assert "alpn=" not in result

    def test_mandatory_deduplicated(self) -> None:
        result = InfobloxNIOSBackend._format_svc_parameters_for_value(
            [
                {"svc_key": "alpn", "svc_value": ["mcp"], "mandatory": True},
                {"svc_key": "alpn", "svc_value": ["h2"], "mandatory": True},
            ]
        )
        assert result.startswith('mandatory="alpn" ')
        assert result.count("mandatory=") == 1


class TestNIOSFindRecordRef:
    """_find_record_ref result handling."""

    @pytest.fixture
    def backend(self) -> InfobloxNIOSBackend:
        return _nios_backend()

    async def test_empty_results_returns_none(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(backend, "_request", AsyncMock(return_value=[]))
        assert await backend._find_record_ref("example.com", "_a._mcp._agents", "SVCB") is None

    async def test_non_list_results_returns_none(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(backend, "_request", AsyncMock(return_value={"error": "x"}))
        assert await backend._find_record_ref("example.com", "_a._mcp._agents", "TXT") is None

    async def test_non_string_ref_returns_none(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(backend, "_request", AsyncMock(return_value=[{"_ref": 123}]))
        assert await backend._find_record_ref("example.com", "_a._mcp._agents", "TXT") is None


class TestNIOSListAndGetRecordEdgeCases:
    """list_records / list_zones / get_record edge branches."""

    @pytest.fixture
    def backend(self) -> InfobloxNIOSBackend:
        return _nios_backend()

    async def test_list_records_non_list_response_skipped(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(backend, "_request", AsyncMock(return_value={"error": "boom"}))
        records = [r async for r in backend.list_records("example.com")]
        assert records == []

    async def test_list_records_skips_records_without_name(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def fake_request(method, endpoint, *, params=None, json=None):
            if endpoint == "record:txt":
                return [
                    {"_ref": "record:txt/a", "text": '"orphan"'},  # no name → skipped
                    {
                        "_ref": "record:txt/b",
                        "name": "_agent._mcp._agents.example.com",
                        "ttl": 300,
                        "text": '"kept"',
                    },
                ]
            return []

        monkeypatch.setattr(backend, "_request", fake_request)
        records = [r async for r in backend.list_records("example.com", record_type="TXT")]
        assert len(records) == 1
        assert records[0]["values"] == ['"kept"']

    async def test_get_record_txt(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            backend,
            "_request",
            AsyncMock(
                return_value=[
                    {
                        "_ref": "record:txt/abc",
                        "name": "_index._agents.example.com",
                        "ttl": 600,
                        "text": '"agents=chat:mcp"',
                    }
                ]
            ),
        )
        result = await backend.get_record("example.com", "_index._agents", "TXT")
        assert result is not None
        assert result["type"] == "TXT"
        assert result["values"] == ['"agents=chat:mcp"']
        assert result["name"] == "_index._agents"
        assert result["ttl"] == 600

    async def test_list_zones_non_list_response(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(backend, "_request", AsyncMock(return_value={"error": "x"}))
        assert await backend.list_zones() == []

    async def test_list_zones_skips_non_dict_entries(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            backend,
            "_request",
            AsyncMock(
                return_value=[
                    "junk",
                    {"_ref": "zone_auth/x", "fqdn": "example.com", "view": "default"},
                ]
            ),
        )
        zones = await backend.list_zones()
        assert len(zones) == 1
        assert zones[0]["name"] == "example.com"


class TestNIOSRPZ:
    """RPZ (Response Policy Zone) operations."""

    @pytest.fixture
    def backend(self) -> InfobloxNIOSBackend:
        return _nios_backend()

    async def test_create_rpz_cname_nxdomain_new(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[tuple[str, str, dict | None]] = []

        async def fake_request(method, endpoint, *, params=None, json=None):
            calls.append((method, endpoint, json))
            return [] if method == "GET" else {}

        monkeypatch.setattr(backend, "_request", fake_request)
        fqdn = await backend.create_rpz_cname_record(
            "rpz.example.com", "evil.com", "nxdomain", comment="block it"
        )

        assert fqdn == "evil.com.rpz.example.com"
        method, endpoint, payload = calls[-1]
        assert (method, endpoint) == ("POST", "record:rpz:cname")
        assert payload == {
            "name": "evil.com.rpz.example.com",
            "rp_zone": "rpz.example.com",
            "canonical": "",
            "comment": "block it",
        }

    async def test_create_rpz_cname_passthru_uses_identity_cname(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[tuple[str, str, dict | None]] = []

        async def fake_request(method, endpoint, *, params=None, json=None):
            calls.append((method, endpoint, json))
            return [] if method == "GET" else {}

        monkeypatch.setattr(backend, "_request", fake_request)
        await backend.create_rpz_cname_record("rpz.example.com", "good.com", "PASSTHRU")

        payload = calls[-1][2]
        assert payload["canonical"] == "good.com"
        assert payload["comment"] == "DNS-AID RPZ: PASSTHRU good.com"

    async def test_create_rpz_cname_updates_existing(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[tuple[str, str, dict | None]] = []

        async def fake_request(method, endpoint, *, params=None, json=None):
            calls.append((method, endpoint, json))
            if method == "GET":
                return [{"_ref": "record:rpz:cname/abc"}]
            return {}

        monkeypatch.setattr(backend, "_request", fake_request)
        # Owner already carries the RPZ zone suffix — no double append.
        fqdn = await backend.create_rpz_cname_record(
            "rpz.example.com", "evil.com.rpz.example.com", "NXDOMAIN"
        )

        assert fqdn == "evil.com.rpz.example.com"
        method, endpoint, payload = calls[-1]
        assert (method, endpoint) == ("PUT", "record:rpz:cname/abc")
        assert payload == {
            "canonical": "",
            "comment": "DNS-AID RPZ: NXDOMAIN evil.com.rpz.example.com",
        }

    async def test_create_rpz_cname_existing_without_ref_creates(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[tuple[str, str]] = []

        async def fake_request(method, endpoint, *, params=None, json=None):
            calls.append((method, endpoint))
            if method == "GET":
                return [{"name": "evil.com.rpz.example.com"}]  # no _ref
            return {}

        monkeypatch.setattr(backend, "_request", fake_request)
        await backend.create_rpz_cname_record("rpz.example.com", "evil.com", "NXDOMAIN")

        assert calls[-1] == ("POST", "record:rpz:cname")

    async def test_delete_rpz_cname_found(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[tuple[str, str]] = []

        async def fake_request(method, endpoint, *, params=None, json=None):
            calls.append((method, endpoint))
            if method == "GET":
                return [{"_ref": "record:rpz:cname/abc"}]
            return {}

        monkeypatch.setattr(backend, "_request", fake_request)
        assert await backend.delete_rpz_cname_record("rpz.example.com", "evil.com") is True
        assert calls[-1] == ("DELETE", "record:rpz:cname/abc")

    async def test_delete_rpz_cname_not_found(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(backend, "_request", AsyncMock(return_value=[]))
        assert await backend.delete_rpz_cname_record("rpz.example.com", "evil.com") is False

    async def test_delete_rpz_cname_non_list_response(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(backend, "_request", AsyncMock(return_value={"error": "x"}))
        assert await backend.delete_rpz_cname_record("rpz.example.com", "evil.com") is False

    async def test_delete_rpz_cname_missing_ref(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(backend, "_request", AsyncMock(return_value=[{"name": "x"}]))
        assert await backend.delete_rpz_cname_record("rpz.example.com", "evil.com") is False

    async def test_list_rpz_cname_records_actions(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            backend,
            "_request",
            AsyncMock(
                return_value=[
                    "junk",  # non-dict skipped
                    {
                        "name": "evil.com.rpz.example.com",
                        "canonical": "",
                        "comment": "blocked",
                        "disable": False,
                    },
                    {
                        "name": "good.com.rpz.example.com",
                        "canonical": "good.com",
                    },
                    {
                        "name": "odd.com.rpz.example.com",
                        "canonical": "somewhere.else",
                        "disable": True,
                    },
                ]
            ),
        )
        records = await backend.list_rpz_cname_records("rpz.example.com")

        assert len(records) == 3
        assert records[0]["owner"] == "evil.com"
        assert records[0]["action"] == "NXDOMAIN"
        assert records[1]["action"] == "PASSTHRU"
        assert records[2]["action"] == "NXDOMAIN"  # fallback
        assert records[2]["disabled"] is True

    async def test_list_rpz_cname_records_non_list_response(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(backend, "_request", AsyncMock(return_value={"error": "x"}))
        assert await backend.list_rpz_cname_records("rpz.example.com") == []

    async def test_ensure_rpz_zone_exists(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        mock_request = AsyncMock(return_value=[{"_ref": "zone_rp/abc"}])
        monkeypatch.setattr(backend, "_request", mock_request)

        assert await backend.ensure_rpz_zone("rpz.example.com") is True
        mock_request.assert_awaited_once()  # no POST when zone exists

    async def test_ensure_rpz_zone_creates(
        self, backend: InfobloxNIOSBackend, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[tuple[str, str, dict | None]] = []

        async def fake_request(method, endpoint, *, params=None, json=None):
            calls.append((method, endpoint, json))
            return [] if method == "GET" else {}

        monkeypatch.setattr(backend, "_request", fake_request)
        assert await backend.ensure_rpz_zone("rpz.example.com") is True

        method, endpoint, payload = calls[-1]
        assert (method, endpoint) == ("POST", "zone_rp")
        assert payload["fqdn"] == "rpz.example.com"
        assert payload["rpz_policy"] == "GIVEN"
