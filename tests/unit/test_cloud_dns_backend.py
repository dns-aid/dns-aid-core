# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for dns_aid.backends.cloud_dns."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from dns_aid.backends.cloud_dns import CloudDNSBackend


def _backend() -> CloudDNSBackend:
    return CloudDNSBackend(
        project_id="test-project",
        managed_zone="agents-zone",
        token_provider=lambda: ("test-token", None),
    )


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
