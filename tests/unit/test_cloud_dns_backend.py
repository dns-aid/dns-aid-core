# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for dns_aid.backends.cloud_dns."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from dns_aid.backends.cloud_dns import CloudDNSBackend

_GOOGLE_PROJECT_ENV_VARS = ("GOOGLE_CLOUD_PROJECT", "GCP_PROJECT", "CLOUD_DNS_PROJECT")


def _backend() -> CloudDNSBackend:
    return CloudDNSBackend(
        project_id="test-project",
        managed_zone="agents-zone",
        token_provider=lambda: ("test-token", None),
    )


def _clear_project_env(monkeypatch) -> None:
    for var in (*_GOOGLE_PROJECT_ENV_VARS, "CLOUD_DNS_MANAGED_ZONE"):
        monkeypatch.delenv(var, raising=False)


def _attach_transport(
    backend: CloudDNSBackend, handler: Callable[[httpx.Request], httpx.Response]
) -> None:
    """Wire the backend to an httpx.MockTransport bound to the running loop."""
    backend._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url=backend._base_url
    )
    backend._client_loop_id = id(asyncio.get_running_loop())


class TestCloudDNSBackend:
    """Unit coverage for Cloud DNS request shaping."""

    def test_name_property(self):
        backend = _backend()
        assert backend.name == "cloud-dns"

    @pytest.mark.asyncio
    async def test_create_svcb_record_builds_change_payload(self):
        backend = _backend()

        with (
            patch.object(backend, "get_record", AsyncMock(return_value=None)),
            patch.object(backend, "_request", AsyncMock(return_value={})) as mock_request,
        ):
            result = await backend.create_svcb_record(
                zone="example.com",
                name="_chat._mcp._agents",
                priority=1,
                target="service.example.internal",
                params={"alpn": "mcp", "port": "443", "key65406": "lattice"},
                ttl=30,
            )

        assert result == "_chat._mcp._agents.example.com"
        assert mock_request.await_count == 1
        call = mock_request.await_args
        assert call.args == (
            "POST",
            "/projects/test-project/managedZones/agents-zone/changes",
        )
        payload = call.kwargs["json"]
        assert payload["additions"] == [
            {
                "name": "_chat._mcp._agents.example.com.",
                "type": "SVCB",
                "ttl": 30,
                "rrdatas": ['1 service.example.internal. alpn="mcp" port="443" key65406="lattice"'],
            }
        ]

    @pytest.mark.asyncio
    async def test_create_txt_record_quotes_values(self):
        backend = _backend()

        with (
            patch.object(backend, "get_record", AsyncMock(return_value=None)),
            patch.object(backend, "_request", AsyncMock(return_value={})) as mock_request,
        ):
            await backend.create_txt_record(
                zone="example.com",
                name="_chat._mcp._agents",
                values=["capabilities=chat,search", '"version=1.0.0"'],
                ttl=300,
            )

        payload = mock_request.await_args.kwargs["json"]
        assert payload["additions"] == [
            {
                "name": "_chat._mcp._agents.example.com.",
                "type": "TXT",
                "ttl": 300,
                "rrdatas": ['"capabilities=chat,search"', '"version=1.0.0"'],
            }
        ]

    @pytest.mark.asyncio
    async def test_list_records_filters_and_normalizes_rrsets(self):
        backend = _backend()

        responses = [
            {
                "rrsets": [
                    {
                        "name": "_chat._mcp._agents.example.com.",
                        "type": "SVCB",
                        "ttl": 30,
                        "rrdatas": ['1 service.example.internal. alpn="mcp"'],
                    },
                    {
                        "name": "_chat._mcp._agents.example.com.",
                        "type": "TXT",
                        "ttl": 30,
                        "rrdatas": ['"version=1.0.0"'],
                    },
                ]
            }
        ]

        with patch.object(backend, "_request", AsyncMock(side_effect=responses)):
            records = [
                record
                async for record in backend.list_records(
                    "example.com",
                    name_pattern="_chat._mcp._agents",
                    record_type="SVCB",
                )
            ]

        assert records == [
            {
                "name": "_chat._mcp._agents",
                "fqdn": "_chat._mcp._agents.example.com",
                "type": "SVCB",
                "ttl": 30,
                "values": ['1 service.example.internal. alpn="mcp"'],
            }
        ]

    @pytest.mark.asyncio
    async def test_get_record_returns_none_for_mismatched_rrset(self):
        backend = _backend()

        with patch.object(
            backend,
            "_request",
            AsyncMock(
                return_value={
                    "rrsets": [
                        {
                            "name": "_other._mcp._agents.example.com.",
                            "type": "TXT",
                            "ttl": 30,
                            "rrdatas": ['"version=1.0.0"'],
                        }
                    ]
                }
            ),
        ):
            record = await backend.get_record("example.com", "_chat._mcp._agents", "TXT")

        assert record is None

    @pytest.mark.asyncio
    async def test_zone_exists_returns_false_on_lookup_failure(self):
        backend = _backend()

        with patch.object(
            backend,
            "_get_managed_zone_name",
            AsyncMock(side_effect=ValueError("zone missing")),
        ):
            assert await backend.zone_exists("example.com") is False

    @pytest.mark.asyncio
    async def test_zone_exists_returns_true_when_zone_found(self):
        backend = _backend()

        with patch.object(
            backend,
            "_get_managed_zone_name",
            AsyncMock(return_value="agents-zone"),
        ):
            assert await backend.zone_exists("example.com") is True


class TestCloudDNSBackendInit:
    """Tests for constructor configuration sources."""

    def test_init_reads_project_and_zone_from_env(self, monkeypatch):
        _clear_project_env(monkeypatch)
        monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "env-project")
        monkeypatch.setenv("CLOUD_DNS_MANAGED_ZONE", "env-zone")

        backend = CloudDNSBackend(token_provider=lambda: ("token", None))

        assert backend._project_id == "env-project"
        assert backend._managed_zone == "env-zone"

    def test_init_defaults_without_configuration(self, monkeypatch):
        _clear_project_env(monkeypatch)

        backend = CloudDNSBackend(token_provider=lambda: ("token", None))

        assert backend._project_id is None
        assert backend._managed_zone is None
        assert backend._base_url == "https://dns.googleapis.com/dns/v1"

    def test_init_strips_trailing_slash_from_base_url(self):
        backend = CloudDNSBackend(
            project_id="p",
            managed_zone="z",
            token_provider=lambda: ("token", None),
            base_url="https://dns.example.test/dns/v1/",
        )
        assert backend._base_url == "https://dns.example.test/dns/v1"


class TestCloudDNSBackendClient:
    """Tests for the loop-aware httpx client lifecycle."""

    @pytest.mark.asyncio
    async def test_get_client_creates_and_caches_client(self):
        backend = _backend()

        client1 = await backend._get_client()
        client2 = await backend._get_client()

        assert isinstance(client1, httpx.AsyncClient)
        assert client1 is client2
        assert backend._client_loop_id == id(asyncio.get_running_loop())

        await backend.close()

    @pytest.mark.asyncio
    async def test_get_client_recreates_client_on_loop_change(self):
        backend = _backend()
        stale_client = httpx.AsyncClient(
            transport=httpx.MockTransport(lambda request: httpx.Response(200))
        )
        backend._client = stale_client
        backend._client_loop_id = -1  # simulate a client bound to another loop

        client = await backend._get_client()

        assert client is not stale_client
        assert stale_client.is_closed
        assert backend._client_loop_id == id(asyncio.get_running_loop())

        await backend.close()

    @pytest.mark.asyncio
    async def test_close_resets_client_state(self):
        backend = _backend()
        client = await backend._get_client()

        await backend.close()

        assert client.is_closed
        assert backend._client is None
        assert backend._client_loop_id is None

    @pytest.mark.asyncio
    async def test_close_is_noop_without_client(self):
        backend = _backend()
        await backend.close()
        assert backend._client is None


class TestCloudDNSBackendProjectResolution:
    """Tests for project id discovery and validation."""

    def test_resolve_project_id_prefers_configured_project(self):
        backend = _backend()
        assert backend._resolve_project_id("discovered-project") == "test-project"

    def test_resolve_project_id_uses_discovered_project(self, monkeypatch):
        _clear_project_env(monkeypatch)
        backend = CloudDNSBackend(token_provider=lambda: ("token", None))

        assert backend._resolve_project_id("discovered-project") == "discovered-project"
        assert backend._project_id == "discovered-project"

    def test_resolve_project_id_raises_without_any_project(self, monkeypatch):
        _clear_project_env(monkeypatch)
        backend = CloudDNSBackend(token_provider=lambda: ("token", None))

        with pytest.raises(ValueError, match="project id not configured"):
            backend._resolve_project_id(None)

    def test_ensure_project_id_returns_configured_project(self):
        backend = _backend()
        assert backend._ensure_project_id() == "test-project"

    def test_ensure_project_id_discovers_project_via_token_provider(self, monkeypatch):
        _clear_project_env(monkeypatch)
        backend = CloudDNSBackend(token_provider=lambda: ("token", "adc-project"))

        assert backend._ensure_project_id() == "adc-project"
        assert backend._project_id == "adc-project"


class TestCloudDNSBackendRequest:
    """Tests for the authenticated request helper."""

    @pytest.mark.asyncio
    async def test_request_sends_bearer_token_and_parses_json(self, monkeypatch):
        _clear_project_env(monkeypatch)
        backend = CloudDNSBackend(
            managed_zone="agents-zone",
            token_provider=lambda: ("bearer-token", "adc-project"),
        )
        captured: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["authorization"] = request.headers["Authorization"]
            captured["url"] = str(request.url)
            return httpx.Response(200, json={"rrsets": []})

        _attach_transport(backend, handler)

        result = await backend._request(
            "GET",
            "/projects/adc-project/managedZones/agents-zone/rrsets",
            params={"maxResults": "1"},
        )

        assert result == {"rrsets": []}
        assert captured["authorization"] == "Bearer bearer-token"
        assert "maxResults=1" in captured["url"]
        assert backend._project_id == "adc-project"

        await backend.close()

    @pytest.mark.asyncio
    async def test_request_returns_empty_dict_for_empty_body(self):
        backend = _backend()
        _attach_transport(backend, lambda request: httpx.Response(200))

        result = await backend._request("POST", "/projects/test-project/managedZones/z/changes")

        assert result == {}
        await backend.close()

    @pytest.mark.asyncio
    async def test_request_raises_on_http_error(self):
        backend = _backend()
        _attach_transport(
            backend,
            lambda request: httpx.Response(403, json={"error": {"message": "forbidden"}}),
        )

        with pytest.raises(httpx.HTTPStatusError):
            await backend._request("GET", "/projects/test-project/managedZones")

        await backend.close()


class TestCloudDNSBackendManagedZone:
    """Tests for managed zone discovery."""

    @pytest.mark.asyncio
    async def test_get_managed_zone_name_discovers_and_caches_zone(self):
        backend = CloudDNSBackend(
            project_id="test-project",
            token_provider=lambda: ("token", None),
        )
        zones = [
            {"name": "other-zone", "dns_name": "other.com", "visibility": "public"},
            {"name": "agents-zone", "dns_name": "example.com", "visibility": "public"},
        ]

        with patch.object(backend, "list_zones", AsyncMock(return_value=zones)) as mock_zones:
            assert await backend._get_managed_zone_name("example.com.") == "agents-zone"
            # Second lookup must be served from the cache.
            assert await backend._get_managed_zone_name("example.com") == "agents-zone"

        assert mock_zones.await_count == 1

    @pytest.mark.asyncio
    async def test_get_managed_zone_name_raises_when_zone_missing(self):
        backend = CloudDNSBackend(
            project_id="test-project",
            token_provider=lambda: ("token", None),
        )

        with (
            patch.object(backend, "list_zones", AsyncMock(return_value=[])),
            pytest.raises(ValueError, match="No Cloud DNS managed zone found"),
        ):
            await backend._get_managed_zone_name("example.com")

    @pytest.mark.asyncio
    async def test_get_managed_zone_name_prefers_configured_zone(self):
        backend = _backend()
        assert await backend._get_managed_zone_name("example.com") == "agents-zone"


class TestCloudDNSBackendChanges:
    """Tests for record mutation payloads."""

    @pytest.mark.asyncio
    async def test_change_record_set_deletes_existing_record(self):
        backend = _backend()
        existing = {
            "name": "_chat._mcp._agents",
            "fqdn": "_chat._mcp._agents.example.com",
            "type": "TXT",
            "ttl": 60,
            "values": ['"version=0.9.0"'],
        }

        with (
            patch.object(backend, "get_record", AsyncMock(return_value=existing)),
            patch.object(backend, "_request", AsyncMock(return_value={})) as mock_request,
        ):
            await backend.create_txt_record(
                zone="example.com",
                name="_chat._mcp._agents",
                values=["version=1.0.0"],
                ttl=300,
            )

        payload = mock_request.await_args.kwargs["json"]
        assert payload["deletions"] == [
            {
                "name": "_chat._mcp._agents.example.com.",
                "type": "TXT",
                "ttl": 60,
                "rrdatas": ['"version=0.9.0"'],
            }
        ]

    @pytest.mark.asyncio
    async def test_delete_record_returns_false_when_record_missing(self):
        backend = _backend()

        with (
            patch.object(backend, "get_record", AsyncMock(return_value=None)),
            patch.object(backend, "_request", AsyncMock(return_value={})) as mock_request,
        ):
            deleted = await backend.delete_record("example.com", "_chat._mcp._agents", "SVCB")

        assert deleted is False
        mock_request.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_delete_record_posts_deletion_change(self):
        backend = _backend()
        existing = {
            "name": "_chat._mcp._agents",
            "fqdn": "_chat._mcp._agents.example.com",
            "type": "SVCB",
            "ttl": 30,
            "values": ['1 service.example.internal. alpn="mcp"'],
        }

        with (
            patch.object(backend, "get_record", AsyncMock(return_value=existing)),
            patch.object(backend, "_request", AsyncMock(return_value={})) as mock_request,
        ):
            deleted = await backend.delete_record("example.com", "_chat._mcp._agents", "SVCB")

        assert deleted is True
        call = mock_request.await_args
        assert call.args == (
            "POST",
            "/projects/test-project/managedZones/agents-zone/changes",
        )
        assert call.kwargs["json"] == {
            "deletions": [
                {
                    "name": "_chat._mcp._agents.example.com.",
                    "type": "SVCB",
                    "ttl": 30,
                    "rrdatas": ['1 service.example.internal. alpn="mcp"'],
                }
            ]
        }


class TestCloudDNSBackendListing:
    """Tests for record and zone listing."""

    @pytest.mark.asyncio
    async def test_list_records_paginates_and_skips_malformed_rrsets(self):
        backend = _backend()
        responses = [
            {
                "rrsets": [
                    {"name": "", "type": "SVCB", "ttl": 30, "rrdatas": []},
                    {
                        "name": "_chat._mcp._agents.example.com.",
                        "type": "SVCB",
                        "ttl": 30,
                        "rrdatas": ['1 svc. alpn="mcp"'],
                    },
                ],
                "nextPageToken": "page-2",
            },
            {
                "rrsets": [
                    {
                        "name": "_search._a2a._agents.example.com.",
                        "type": "SVCB",
                        "ttl": 60,
                        "rrdatas": ['1 svc2. alpn="a2a"'],
                    },
                ]
            },
        ]

        with patch.object(backend, "_request", AsyncMock(side_effect=responses)) as mock_request:
            records = [record async for record in backend.list_records("example.com")]

        assert [record["name"] for record in records] == [
            "_chat._mcp._agents",
            "_search._a2a._agents",
        ]
        assert mock_request.await_count == 2
        second_params = mock_request.await_args_list[1].kwargs["params"]
        assert second_params == {"maxResults": "1000", "pageToken": "page-2"}

    @pytest.mark.asyncio
    async def test_list_records_applies_name_pattern_filter(self):
        backend = _backend()
        response = {
            "rrsets": [
                {
                    "name": "_chat._mcp._agents.example.com.",
                    "type": "SVCB",
                    "ttl": 30,
                    "rrdatas": ['1 svc. alpn="mcp"'],
                },
                {
                    "name": "_other._mcp._agents.example.com.",
                    "type": "SVCB",
                    "ttl": 30,
                    "rrdatas": ['1 svc. alpn="mcp"'],
                },
            ]
        }

        with patch.object(backend, "_request", AsyncMock(return_value=response)):
            records = [
                record async for record in backend.list_records("example.com", name_pattern="_chat")
            ]

        assert [record["fqdn"] for record in records] == ["_chat._mcp._agents.example.com"]

    @pytest.mark.asyncio
    async def test_list_zones_paginates_and_normalizes(self):
        backend = _backend()
        responses = [
            {
                "managedZones": [
                    {"name": "zone-a", "dnsName": "example.com.", "visibility": "public"},
                ],
                "nextPageToken": "page-2",
            },
            {
                "managedZones": [
                    {"name": "zone-b", "dnsName": "internal.example.", "visibility": "private"},
                    {"name": "zone-c"},
                ]
            },
        ]

        with patch.object(backend, "_request", AsyncMock(side_effect=responses)) as mock_request:
            zones = await backend.list_zones()

        assert zones == [
            {"name": "zone-a", "dns_name": "example.com", "visibility": "public"},
            {"name": "zone-b", "dns_name": "internal.example", "visibility": "private"},
            {"name": "zone-c", "dns_name": "", "visibility": ""},
        ]
        first_call = mock_request.await_args_list[0]
        assert first_call.args == ("GET", "/projects/test-project/managedZones")
        assert first_call.kwargs["params"] == {"maxResults": "1000"}
        second_params = mock_request.await_args_list[1].kwargs["params"]
        assert second_params == {"maxResults": "1000", "pageToken": "page-2"}


class TestCloudDNSBackendGetRecord:
    """Tests for single-record lookup."""

    @pytest.mark.asyncio
    async def test_get_record_returns_none_when_no_rrsets(self):
        backend = _backend()

        with patch.object(backend, "_request", AsyncMock(return_value={})):
            record = await backend.get_record("example.com", "_chat._mcp._agents", "SVCB")

        assert record is None

    @pytest.mark.asyncio
    async def test_get_record_returns_normalized_record(self):
        backend = _backend()
        response = {
            "rrsets": [
                {
                    "name": "_chat._mcp._agents.example.com.",
                    "type": "SVCB",
                    "ttl": 30,
                    "rrdatas": ['1 service.example.internal. alpn="mcp"'],
                }
            ]
        }

        with patch.object(backend, "_request", AsyncMock(return_value=response)) as mock_request:
            record = await backend.get_record("example.com", "_chat._mcp._agents", "SVCB")

        assert record == {
            "name": "_chat._mcp._agents",
            "fqdn": "_chat._mcp._agents.example.com",
            "type": "SVCB",
            "ttl": 30,
            "values": ['1 service.example.internal. alpn="mcp"'],
        }
        call = mock_request.await_args
        assert call.args == (
            "GET",
            "/projects/test-project/managedZones/agents-zone/rrsets",
        )
        assert call.kwargs["params"] == {
            "name": "_chat._mcp._agents.example.com.",
            "type": "SVCB",
            "maxResults": "1",
        }
