# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for dns_aid.backends.route53 module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from dns_aid.backends.route53 import Route53Backend


class TestRoute53BackendInit:
    """Tests for Route53Backend initialization."""

    def test_init_with_zone_id(self):
        """Test initialization with zone ID."""
        backend = Route53Backend(zone_id="ZEXAMPLEZONEID")
        assert backend._zone_id == "ZEXAMPLEZONEID"

    def test_init_with_credentials(self):
        """Test initialization with AWS credentials."""
        # Using clearly fake test credentials (not real AWS format)
        test_key_id = "TEST_ACCESS_KEY_FOR_UNIT_TESTS"
        test_secret = "test_secret_key_for_unit_tests_only"
        backend = Route53Backend(
            zone_id="Z123",
            region="us-west-2",
            aws_access_key_id=test_key_id,
            aws_secret_access_key=test_secret,
        )
        assert backend._region == "us-west-2"
        assert backend._aws_access_key_id == test_key_id

    def test_init_default_region(self):
        """Test default region is us-east-1."""
        backend = Route53Backend()
        assert backend._region == "us-east-1"

    def test_init_region_from_env(self):
        """Test region from environment variable."""
        with patch.dict("os.environ", {"AWS_REGION": "eu-west-1"}):
            backend = Route53Backend()
            assert backend._region == "eu-west-1"

    # -----------------------------------------------------------------
    # ROUTE53_ZONE_ID env var (regression — bug fix v0.21.2)
    # -----------------------------------------------------------------
    # Prior to v0.21.2 the constructor read AWS_REGION but ignored
    # ROUTE53_ZONE_ID even though `cli/backends.py` advertised it as
    # "auto-detected if omitted". The CLI and MCP server both flow
    # through `create_backend("route53")` which calls `cls()` with no
    # kwargs, so a caller with only ROUTE53_ZONE_ID set always fell
    # through to ListHostedZones — requiring broader IAM than necessary
    # and adding an avoidable API call to every publish. Pin the fix.

    def test_init_no_zone_id_no_env(self, monkeypatch):
        """Bare construction with no env var leaves zone_id unset."""
        monkeypatch.delenv("ROUTE53_ZONE_ID", raising=False)
        backend = Route53Backend()
        assert backend._zone_id is None

    def test_init_zone_id_from_env(self, monkeypatch):
        """ROUTE53_ZONE_ID env var is honoured when no kwarg is supplied."""
        monkeypatch.setenv("ROUTE53_ZONE_ID", "ZFROMENVVAR")
        backend = Route53Backend()
        assert backend._zone_id == "ZFROMENVVAR"

    def test_init_kwarg_wins_over_env(self, monkeypatch):
        """Explicit zone_id kwarg takes precedence over ROUTE53_ZONE_ID env."""
        monkeypatch.setenv("ROUTE53_ZONE_ID", "ZFROMENVVAR")
        backend = Route53Backend(zone_id="ZEXPLICITKWARG")
        assert backend._zone_id == "ZEXPLICITKWARG"


class TestRoute53BackendProperties:
    """Tests for Route53Backend properties."""

    def test_name_property(self):
        """Test name property returns 'route53'."""
        backend = Route53Backend()
        assert backend.name == "route53"


class TestRoute53BackendClient:
    """Tests for boto3 client creation."""

    def test_get_client_creates_client(self):
        """Test that _get_client creates boto3 client."""
        backend = Route53Backend(zone_id="Z123")

        with patch("boto3.client") as mock_boto:
            mock_client = MagicMock()
            mock_boto.return_value = mock_client

            client = backend._get_client()

            mock_boto.assert_called_once_with("route53", region_name="us-east-1")
            assert client == mock_client

    def test_get_client_caches_client(self):
        """Test that client is cached."""
        backend = Route53Backend(zone_id="Z123")

        with patch("boto3.client") as mock_boto:
            mock_client = MagicMock()
            mock_boto.return_value = mock_client

            client1 = backend._get_client()
            client2 = backend._get_client()

            # Should only create once
            mock_boto.assert_called_once()
            assert client1 is client2

    def test_get_client_with_credentials(self):
        """Test client creation with explicit credentials."""
        backend = Route53Backend(
            zone_id="Z123",
            aws_access_key_id="AKIATEST",
            aws_secret_access_key="secretkey",
        )

        with patch("boto3.client") as mock_boto:
            mock_client = MagicMock()
            mock_boto.return_value = mock_client

            backend._get_client()

            mock_boto.assert_called_once_with(
                "route53",
                region_name="us-east-1",
                aws_access_key_id="AKIATEST",
                aws_secret_access_key="secretkey",
            )


class TestRoute53BackendZoneId:
    """Tests for zone ID resolution."""

    @pytest.mark.asyncio
    async def test_get_zone_id_returns_configured(self):
        """Test that configured zone ID is returned."""
        backend = Route53Backend(zone_id="Z123CONFIGURED")
        zone_id = await backend._get_zone_id("example.com")
        assert zone_id == "Z123CONFIGURED"

    @pytest.mark.asyncio
    async def test_get_zone_id_from_cache(self):
        """Test that cached zone ID is returned."""
        backend = Route53Backend()
        backend._zone_cache["example.com"] = "ZCACHED"

        zone_id = await backend._get_zone_id("example.com")
        assert zone_id == "ZCACHED"

    @pytest.mark.asyncio
    async def test_get_zone_id_from_api(self):
        """Test zone ID lookup from API."""
        backend = Route53Backend()

        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "HostedZones": [
                    {"Id": "/hostedzone/Z123", "Name": "other.com."},
                    {"Id": "/hostedzone/ZFOUND", "Name": "example.com."},
                ]
            }
        ]

        with patch.object(backend, "_get_client", return_value=mock_client):
            zone_id = await backend._get_zone_id("example.com")
            assert zone_id == "ZFOUND"

    @pytest.mark.asyncio
    async def test_get_zone_id_not_found(self):
        """Test zone ID lookup when zone doesn't exist."""
        backend = Route53Backend()

        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {"HostedZones": [{"Id": "/hostedzone/Z123", "Name": "other.com."}]}
        ]

        with (
            patch.object(backend, "_get_client", return_value=mock_client),
            pytest.raises(ValueError, match="No hosted zone found"),
        ):
            await backend._get_zone_id("notfound.com")


class TestRoute53BackendFormatSvcb:
    """Tests for SVCB value formatting."""

    def test_format_svcb_value_basic(self):
        """Test basic SVCB value formatting."""
        backend = Route53Backend()
        value = backend._format_svcb_value(
            priority=1,
            target="chat.example.com",
            params={"alpn": "a2a", "port": "443"},
        )
        assert value.startswith("1 chat.example.com.")
        assert 'alpn="a2a"' in value
        assert 'port="443"' in value

    def test_format_svcb_value_adds_trailing_dot(self):
        """Test that trailing dot is added to target."""
        backend = Route53Backend()
        value = backend._format_svcb_value(
            priority=1,
            target="chat.example.com",
            params={},
        )
        assert "chat.example.com." in value

    def test_format_svcb_value_no_params(self):
        """Test SVCB value with no params."""
        backend = Route53Backend()
        value = backend._format_svcb_value(
            priority=0,
            target="alias.example.com.",
            params={},
        )
        assert value == "0 alias.example.com."


class TestRoute53BackendCreateSvcb:
    """Tests for SVCB record creation."""

    @pytest.mark.asyncio
    async def test_create_svcb_record_success(self):
        """Test successful SVCB record creation."""
        backend = Route53Backend(zone_id="Z123")

        mock_client = MagicMock()
        mock_client.change_resource_record_sets.return_value = {
            "ChangeInfo": {"Id": "/change/CHANGE123"}
        }

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
            mock_client.change_resource_record_sets.assert_called_once()


class TestRoute53BackendCreateTxt:
    """Tests for TXT record creation."""

    @pytest.mark.asyncio
    async def test_create_txt_record_success(self):
        """Test successful TXT record creation."""
        backend = Route53Backend(zone_id="Z123")

        mock_client = MagicMock()
        mock_client.change_resource_record_sets.return_value = {
            "ChangeInfo": {"Id": "/change/CHANGE456"}
        }

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend.create_txt_record(
                zone="example.com",
                name="_chat._a2a._agents",
                values=["capabilities=chat,code", "version=1.0.0"],
                ttl=3600,
            )

            assert result == "_chat._a2a._agents.example.com"


class TestRoute53BackendDeleteRecord:
    """Tests for record deletion."""

    @pytest.mark.asyncio
    async def test_delete_record_success(self):
        """Test successful record deletion."""
        backend = Route53Backend(zone_id="Z123")

        mock_client = MagicMock()
        mock_client.list_resource_record_sets.return_value = {
            "ResourceRecordSets": [
                {
                    "Name": "_chat._a2a._agents.example.com.",
                    "Type": "SVCB",
                    "TTL": 3600,
                    "ResourceRecords": [{"Value": "1 chat.example.com."}],
                }
            ]
        }
        mock_client.change_resource_record_sets.return_value = {
            "ChangeInfo": {"Id": "/change/DEL123"}
        }

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend.delete_record(
                zone="example.com",
                name="_chat._a2a._agents",
                record_type="SVCB",
            )

            assert result is True

    @pytest.mark.asyncio
    async def test_delete_record_not_found(self):
        """Test deletion when record doesn't exist."""
        backend = Route53Backend(zone_id="Z123")

        mock_client = MagicMock()
        mock_client.list_resource_record_sets.return_value = {"ResourceRecordSets": []}

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend.delete_record(
                zone="example.com",
                name="_nonexistent._agents",
                record_type="SVCB",
            )

            assert result is False

    @pytest.mark.asyncio
    async def test_delete_record_mismatch(self):
        """Test deletion when record name/type doesn't match."""
        backend = Route53Backend(zone_id="Z123")

        mock_client = MagicMock()
        mock_client.list_resource_record_sets.return_value = {
            "ResourceRecordSets": [
                {
                    "Name": "_other._agents.example.com.",
                    "Type": "TXT",
                    "TTL": 3600,
                    "ResourceRecords": [],
                }
            ]
        }

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend.delete_record(
                zone="example.com",
                name="_chat._agents",
                record_type="SVCB",
            )

            assert result is False

    @pytest.mark.asyncio
    async def test_delete_record_exception(self):
        """Test deletion with exception."""
        backend = Route53Backend(zone_id="Z123")

        mock_client = MagicMock()
        mock_client.list_resource_record_sets.side_effect = Exception("AWS Error")

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend.delete_record(
                zone="example.com",
                name="_chat._agents",
                record_type="SVCB",
            )

            assert result is False


class TestRoute53BackendListRecords:
    """Tests for record listing."""

    @pytest.mark.asyncio
    async def test_list_records_all(self):
        """Test listing all records."""
        backend = Route53Backend(zone_id="Z123")

        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "ResourceRecordSets": [
                    {
                        "Name": "_chat._agents.example.com.",
                        "Type": "SVCB",
                        "TTL": 3600,
                        "ResourceRecords": [{"Value": "1 chat.example.com."}],
                    },
                    {
                        "Name": "_chat._agents.example.com.",
                        "Type": "TXT",
                        "TTL": 3600,
                        "ResourceRecords": [{"Value": '"capabilities=chat"'}],
                    },
                ]
            }
        ]

        with patch.object(backend, "_get_client", return_value=mock_client):
            records = []
            async for record in backend.list_records(zone="example.com"):
                records.append(record)

            assert len(records) == 2

    @pytest.mark.asyncio
    async def test_list_records_filter_by_name(self):
        """Test listing records filtered by name."""
        backend = Route53Backend(zone_id="Z123")

        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "ResourceRecordSets": [
                    {
                        "Name": "_chat._agents.example.com.",
                        "Type": "SVCB",
                        "TTL": 3600,
                        "ResourceRecords": [],
                    },
                    {
                        "Name": "_other.example.com.",
                        "Type": "A",
                        "TTL": 300,
                        "ResourceRecords": [],
                    },
                ]
            }
        ]

        with patch.object(backend, "_get_client", return_value=mock_client):
            records = []
            async for record in backend.list_records(zone="example.com", name_pattern="_agents"):
                records.append(record)

            assert len(records) == 1
            assert "_agents" in records[0]["fqdn"]

    @pytest.mark.asyncio
    async def test_list_records_filter_by_type(self):
        """Test listing records filtered by type."""
        backend = Route53Backend(zone_id="Z123")

        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "ResourceRecordSets": [
                    {
                        "Name": "_chat._agents.example.com.",
                        "Type": "SVCB",
                        "TTL": 3600,
                        "ResourceRecords": [],
                    },
                    {
                        "Name": "_chat._agents.example.com.",
                        "Type": "TXT",
                        "TTL": 3600,
                        "ResourceRecords": [],
                    },
                ]
            }
        ]

        with patch.object(backend, "_get_client", return_value=mock_client):
            records = []
            async for record in backend.list_records(zone="example.com", record_type="SVCB"):
                records.append(record)

            assert len(records) == 1
            assert records[0]["type"] == "SVCB"


class TestRoute53BackendZoneExists:
    """Tests for zone existence check."""

    @pytest.mark.asyncio
    async def test_zone_exists_true(self):
        """Test zone exists returns True."""
        backend = Route53Backend(zone_id="Z123")
        result = await backend.zone_exists("example.com")
        assert result is True

    @pytest.mark.asyncio
    async def test_zone_exists_false(self):
        """Test zone exists returns False when not found."""
        backend = Route53Backend()

        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [{"HostedZones": []}]

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend.zone_exists("notfound.com")
            assert result is False


class TestRoute53BackendListZones:
    """Tests for listing zones."""

    @pytest.mark.asyncio
    async def test_list_zones(self):
        """Test listing all zones."""
        backend = Route53Backend()

        mock_client = MagicMock()
        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                "HostedZones": [
                    {
                        "Id": "/hostedzone/Z123",
                        "Name": "example.com.",
                        "ResourceRecordSetCount": 10,
                        "Config": {"PrivateZone": False},
                    },
                    {
                        "Id": "/hostedzone/Z456",
                        "Name": "private.local.",
                        "ResourceRecordSetCount": 5,
                        "Config": {"PrivateZone": True},
                    },
                ]
            }
        ]

        with patch.object(backend, "_get_client", return_value=mock_client):
            zones = await backend.list_zones()

            assert len(zones) == 2
            assert zones[0]["id"] == "Z123"
            assert zones[0]["name"] == "example.com"
            assert zones[0]["private"] is False
            assert zones[1]["private"] is True


class TestRoute53BackendChangeStatus:
    """Tests for change status operations."""

    @pytest.mark.asyncio
    async def test_get_change_status(self):
        """Test getting change status."""
        backend = Route53Backend(zone_id="Z123")

        mock_client = MagicMock()
        mock_client.get_change.return_value = {"ChangeInfo": {"Status": "INSYNC"}}

        with patch.object(backend, "_get_client", return_value=mock_client):
            status = await backend.get_change_status("/change/C123")
            assert status == "INSYNC"

    @pytest.mark.asyncio
    async def test_wait_for_change_success(self):
        """Test waiting for change completion."""
        backend = Route53Backend(zone_id="Z123")

        mock_client = MagicMock()
        mock_client.get_change.return_value = {"ChangeInfo": {"Status": "INSYNC"}}

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend.wait_for_change("/change/C123", max_wait=5)
            assert result is True

    @pytest.mark.asyncio
    async def test_wait_for_change_timeout(self):
        """Test waiting for change timeout."""
        backend = Route53Backend(zone_id="Z123")

        mock_client = MagicMock()
        mock_client.get_change.return_value = {"ChangeInfo": {"Status": "PENDING"}}

        with (
            patch.object(backend, "_get_client", return_value=mock_client),
            patch("asyncio.sleep", return_value=None),
        ):
            result = await backend.wait_for_change("/change/C123", max_wait=2)
            assert result is False


class TestRoute53PublishAgentParamDemotion:
    """Tests for custom SVCB param demotion to TXT on Route53."""

    @pytest.mark.asyncio
    async def test_publish_strips_custom_svcb_params(self):
        """Custom DNS-AID params (key65400+) must not appear in SVCB record."""
        from dns_aid.core.models import AgentRecord, Protocol

        agent = AgentRecord(
            name="lf-test",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="lf-test.example.com",
            port=443,
            capabilities=["testing"],
            realm="demo",
        )

        backend = Route53Backend(zone_id="Z123")
        mock_client = MagicMock()
        mock_client.change_resource_record_sets.return_value = {"ChangeInfo": {"Id": "/change/C1"}}

        with patch.object(backend, "_get_client", return_value=mock_client):
            records = await backend.publish_agent(agent)

        # Should create both SVCB and TXT
        assert len(records) == 2
        assert records[0].startswith("SVCB")
        assert records[1].startswith("TXT")

        # Inspect the SVCB call — must NOT contain key65404
        svcb_call = mock_client.change_resource_record_sets.call_args_list[0]
        svcb_value = svcb_call[1]["ChangeBatch"]["Changes"][0]["ResourceRecordSet"][
            "ResourceRecords"
        ][0]["Value"]
        assert "key65404" not in svcb_value
        assert "alpn" in svcb_value
        assert "port" in svcb_value

        # Inspect the TXT call — must contain the demoted realm
        txt_call = mock_client.change_resource_record_sets.call_args_list[1]
        txt_values = txt_call[1]["ChangeBatch"]["Changes"][0]["ResourceRecordSet"][
            "ResourceRecords"
        ]
        txt_strings = [v["Value"] for v in txt_values]
        assert any("dnsaid_key65404=demo" in s for s in txt_strings)

    @pytest.mark.asyncio
    async def test_publish_no_custom_params_unchanged(self):
        """When no custom params, behavior matches base class."""
        from dns_aid.core.models import AgentRecord, Protocol

        agent = AgentRecord(
            name="simple",
            domain="example.com",
            protocol=Protocol.A2A,
            target_host="simple.example.com",
            port=443,
            capabilities=["chat"],
        )

        backend = Route53Backend(zone_id="Z123")
        mock_client = MagicMock()
        mock_client.change_resource_record_sets.return_value = {"ChangeInfo": {"Id": "/change/C2"}}

        with patch.object(backend, "_get_client", return_value=mock_client):
            records = await backend.publish_agent(agent)

        assert len(records) == 2
        # No dnsaid_ entries in TXT
        txt_call = mock_client.change_resource_record_sets.call_args_list[1]
        txt_values = txt_call[1]["ChangeBatch"]["Changes"][0]["ResourceRecordSet"][
            "ResourceRecords"
        ]
        txt_strings = [v["Value"] for v in txt_values]
        assert not any("dnsaid_" in s for s in txt_strings)

    @pytest.mark.asyncio
    async def test_publish_demotes_multiple_custom_params(self):
        """All custom DNS-AID params get demoted to TXT."""
        from dns_aid.core.models import AgentRecord, Protocol

        agent = AgentRecord(
            name="full",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="full.example.com",
            port=443,
            capabilities=["dns"],
            realm="production",
            policy_uri="urn:policy:strict",
            bap=["mcp/1", "a2a/1"],
        )

        backend = Route53Backend(zone_id="Z123")
        mock_client = MagicMock()
        mock_client.change_resource_record_sets.return_value = {"ChangeInfo": {"Id": "/change/C3"}}

        with patch.object(backend, "_get_client", return_value=mock_client):
            await backend.publish_agent(agent)

        # SVCB must be clean of all custom keys
        svcb_call = mock_client.change_resource_record_sets.call_args_list[0]
        svcb_value = svcb_call[1]["ChangeBatch"]["Changes"][0]["ResourceRecordSet"][
            "ResourceRecords"
        ][0]["Value"]
        for custom_key in ("key65402", "key65403", "key65404"):
            assert custom_key not in svcb_value

        # TXT must contain all three demoted params
        txt_call = mock_client.change_resource_record_sets.call_args_list[1]
        txt_values = txt_call[1]["ChangeBatch"]["Changes"][0]["ResourceRecordSet"][
            "ResourceRecords"
        ]
        txt_strings = " ".join(v["Value"] for v in txt_values)
        assert "dnsaid_key65402" in txt_strings  # bap
        assert "dnsaid_key65403" in txt_strings  # policy
        assert "dnsaid_key65404" in txt_strings  # realm


# ---------------------------------------------------------------------------
# ROUTE53_ZONE_ID end-to-end wiring (regression — bug fix v0.21.2)
# ---------------------------------------------------------------------------


class TestRoute53GetZoneIdEnvShortCircuit:
    """``_get_zone_id`` returns the env-supplied zone ID without an AWS call.

    Prior to the bug fix, the constructor ignored ROUTE53_ZONE_ID so the
    CLI / MCP construction shape ``Route53Backend()`` always fell through
    to ListHostedZones. Pin the end-to-end behaviour: env var alone is
    sufficient to skip the API call entirely.
    """

    @pytest.mark.asyncio
    async def test_get_zone_id_short_circuits_on_env_var(self, monkeypatch):
        monkeypatch.setenv("ROUTE53_ZONE_ID", "ZSHORTCIRCUITENV")
        backend = Route53Backend()  # no kwargs — CLI / MCP construction shape

        # If _get_client were invoked, this would raise — proving no API
        # round-trip happened. That's the operational improvement.
        backend._get_client = MagicMock(
            side_effect=AssertionError("boto3 client must not be created")
        )

        result = await backend._get_zone_id("example.com")
        assert result == "ZSHORTCIRCUITENV"
        backend._get_client.assert_not_called()


class TestRoute53FactoryWiring:
    """``create_backend("route53")`` honours ROUTE53_ZONE_ID.

    This is the path the CLI (``cli/main.py``) and the MCP server
    (``mcp/server.py``) both take: a factory call with no kwargs. Pin
    that the factory shape delivers the env var through to the backend.
    """

    def test_factory_with_env_var(self, monkeypatch):
        from dns_aid.backends import create_backend

        monkeypatch.setenv("ROUTE53_ZONE_ID", "ZFACTORYENV")
        backend = create_backend("route53")
        assert backend._zone_id == "ZFACTORYENV"  # type: ignore[attr-defined]

    def test_factory_without_env_var(self, monkeypatch):
        from dns_aid.backends import create_backend

        monkeypatch.delenv("ROUTE53_ZONE_ID", raising=False)
        backend = create_backend("route53")
        assert backend._zone_id is None  # type: ignore[attr-defined]


class TestRoute53AdvertisedEnvContract:
    """The env var advertised in ``cli/backends.py`` is honoured by the code.

    The original bug was a docs/code drift: the registry entry advertised
    ROUTE53_ZONE_ID but no code read it. Pin the contract so future
    contributors can't reintroduce the drift silently.
    """

    def test_route53_zone_id_in_optional_env_registry(self):
        from dns_aid.cli.backends import BACKEND_REGISTRY

        assert "ROUTE53_ZONE_ID" in BACKEND_REGISTRY["route53"].optional_env
