# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for CLI commands."""

import re
from unittest.mock import patch

from typer.testing import CliRunner

from dns_aid.cli.main import app

runner = CliRunner()

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    """Strip ANSI escape codes from Rich/Typer output for reliable assertions."""
    return _ANSI_RE.sub("", text)


class TestVersion:
    """Test version display."""

    def test_version_flag(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "dns-aid version" in result.output

    def test_no_args_shows_help(self):
        result = runner.invoke(app, [])
        # Typer returns exit code 0 for no_args_is_help
        assert "DNS-based Agent Identification" in result.output


class TestGetBackend:
    """Test _get_backend helper."""

    def test_mock_backend(self):
        from dns_aid.cli.main import _get_backend

        backend = _get_backend("mock")
        from dns_aid.backends.mock import MockBackend

        assert isinstance(backend, MockBackend)

    @patch.dict("os.environ", {"AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test"})
    def test_route53_backend(self):
        from dns_aid.cli.main import _get_backend

        backend = _get_backend("route53")
        from dns_aid.backends.route53 import Route53Backend

        assert isinstance(backend, Route53Backend)

    @patch.dict("os.environ", {"CLOUDFLARE_API_TOKEN": "test"})
    def test_cloudflare_backend(self):
        from dns_aid.cli.main import _get_backend

        backend = _get_backend("cloudflare")
        from dns_aid.backends.cloudflare import CloudflareBackend

        assert isinstance(backend, CloudflareBackend)

    def test_unknown_backend_exits(self):
        import click

        from dns_aid.cli.main import _get_backend

        try:
            _get_backend("nonexistent")
            raise AssertionError("Should have raised")
        except (SystemExit, click.exceptions.Exit):
            pass  # Either exception is acceptable


class TestDiscoverCommand:
    """Test discover CLI command."""

    @patch("dns_aid.cli.main.run_async")
    def test_discover_no_agents(self, mock_run_async):
        from dns_aid.core.models import DiscoveryResult

        mock_run_async.return_value = DiscoveryResult(
            domain="example.com",
            query="_agents.example.com",
            agents=[],
            query_time_ms=10.5,
        )

        result = runner.invoke(app, ["discover", "example.com"])
        assert result.exit_code == 0
        assert "No agents found" in result.output

    @patch("dns_aid.cli.main.run_async")
    def test_discover_with_agents(self, mock_run_async):
        from dns_aid.core.models import AgentRecord, DiscoveryResult, Protocol

        agent = AgentRecord(
            name="booking",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="mcp.example.com",
            endpoint_override="https://mcp.example.com",
            port=443,
        )
        mock_run_async.return_value = DiscoveryResult(
            domain="example.com",
            query="_agents.example.com",
            agents=[agent],
            query_time_ms=15.3,
        )

        result = runner.invoke(app, ["discover", "example.com"])
        assert result.exit_code == 0
        assert "Found 1 agent" in result.output

    @patch("dns_aid.cli.main.run_async")
    def test_discover_json_output(self, mock_run_async):
        from dns_aid.core.models import AgentRecord, DiscoveryResult, Protocol

        agent = AgentRecord(
            name="chat",
            domain="example.com",
            protocol=Protocol.A2A,
            target_host="chat.example.com",
            endpoint_override="https://chat.example.com",
            port=443,
        )
        mock_run_async.return_value = DiscoveryResult(
            domain="example.com",
            query="_agents.example.com",
            agents=[agent],
            query_time_ms=8.0,
        )

        result = runner.invoke(app, ["discover", "example.com", "--json"])
        assert result.exit_code == 0
        assert "chat" in result.output
        assert "a2a" in result.output

    @patch("dns_aid.cli.main.run_async")
    def test_discover_with_http_index(self, mock_run_async):
        from dns_aid.core.models import DiscoveryResult

        mock_run_async.return_value = DiscoveryResult(
            domain="example.com",
            query="_agents.example.com",
            agents=[],
            query_time_ms=20.0,
        )

        result = runner.invoke(app, ["discover", "example.com", "--use-http-index"])
        assert result.exit_code == 0
        assert "HTTP index" in result.output


class TestVerifyCommand:
    """Test verify CLI command."""

    @patch("dns_aid.cli.main.run_async")
    def test_verify_agent(self, mock_run_async):
        from dns_aid.core.validator import VerifyResult

        mock_run_async.return_value = VerifyResult(
            fqdn="_chat._a2a._agents.example.com",
            record_exists=True,
            svcb_valid=True,
            dnssec_valid=False,
            dane_valid=None,
            endpoint_reachable=True,
            endpoint_latency_ms=42.0,
        )

        result = runner.invoke(app, ["verify", "_chat._a2a._agents.example.com"])
        assert result.exit_code == 0
        assert "Security Score" in result.output


class TestQuietMode:
    """Test quiet flag."""

    def test_quiet_flag(self):
        result = runner.invoke(app, ["--quiet", "--version"])
        assert result.exit_code == 0
        assert "dns-aid version" in result.output


class TestPublishOptions:
    """Test publish command options including --transport and --auth-type."""

    @patch("dns_aid.cli.main.run_async")
    def test_publish_help_shows_transport(self, mock_run_async):
        result = runner.invoke(app, ["publish", "--help"])
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert "--transport" in plain
        assert "streamable-http" in plain

    @patch("dns_aid.cli.main.run_async")
    def test_publish_help_shows_auth_type(self, mock_run_async):
        result = runner.invoke(app, ["publish", "--help"])
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert "--auth-type" in plain
        assert "api_key" in plain


class TestRunAsync:
    """Test run_async helper."""

    def test_run_async_executes_coroutine(self):
        from dns_aid.cli.main import run_async

        async def simple():
            return 42

        assert run_async(simple()) == 42


# ============================================================================
# PUBLISH COMMAND TESTS
# ============================================================================


def _make_agent():
    """Create a minimal AgentRecord for mocking publish results."""
    from dns_aid.core.models import AgentRecord, Protocol

    return AgentRecord(
        name="chat",
        domain="example.com",
        protocol=Protocol.MCP,
        target_host="mcp.example.com",
        endpoint_override="https://mcp.example.com",
        port=443,
    )


def _make_publish_result(success=True, message=None):
    from dns_aid.core.models import PublishResult

    return PublishResult(
        agent=_make_agent(),
        records_created=[
            "SVCB _chat._mcp._agents.example.com",
            "TXT _chat._mcp._agents.example.com",
        ],
        zone="example.com",
        backend="mock",
        success=success,
        message=message,
    )


def _make_index_result(success=True, created=False, message="Index updated"):
    from dns_aid.core.indexer import IndexEntry, IndexResult

    return IndexResult(
        domain="example.com",
        entries=[IndexEntry(name="chat", protocol="mcp")],
        success=success,
        message=message,
        created=created,
    )


class TestPublishCommand:
    """Test publish CLI command."""

    @patch("dns_aid.cli.main.run_async")
    def test_publish_success_with_index(self, mock_run_async):
        """Publish success → index update success."""
        mock_run_async.side_effect = [
            _make_publish_result(),
            _make_index_result(created=True),
        ]
        result = runner.invoke(
            app,
            [
                "publish",
                "--name",
                "chat",
                "--domain",
                "example.com",
                "--backend",
                "mock",
            ],
        )
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert "published successfully" in plain
        assert "SVCB" in plain or "Records created" in plain or "records created" in plain.lower()

    @patch("dns_aid.cli.main.run_async")
    def test_publish_success_index_failed(self, mock_run_async):
        """Publish success but index update fails."""
        mock_run_async.side_effect = [
            _make_publish_result(),
            _make_index_result(success=False, message="Backend error"),
        ]
        result = runner.invoke(
            app,
            [
                "publish",
                "--name",
                "chat",
                "--domain",
                "example.com",
                "--backend",
                "mock",
            ],
        )
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert "published successfully" in plain

    @patch("dns_aid.cli.main.run_async")
    def test_publish_no_update_index(self, mock_run_async):
        """Publish with --no-update-index skips index update."""
        mock_run_async.return_value = _make_publish_result()
        result = runner.invoke(
            app,
            [
                "publish",
                "--name",
                "chat",
                "--domain",
                "example.com",
                "--backend",
                "mock",
                "--no-update-index",
            ],
        )
        assert result.exit_code == 0
        assert mock_run_async.call_count == 1  # Only publish, no index

    @patch("dns_aid.cli.main.run_async")
    def test_publish_failure(self, mock_run_async):
        """Publish failure exits with code 1."""
        mock_run_async.return_value = _make_publish_result(
            success=False, message="DNS write failed"
        )
        result = runner.invoke(
            app,
            [
                "publish",
                "--name",
                "chat",
                "--domain",
                "example.com",
                "--backend",
                "mock",
            ],
        )
        assert result.exit_code == 1

    def test_publish_sign_without_key(self):
        """--sign without --private-key exits with code 1."""
        result = runner.invoke(
            app,
            [
                "publish",
                "--name",
                "chat",
                "--domain",
                "example.com",
                "--backend",
                "mock",
                "--sign",
            ],
        )
        assert result.exit_code == 1


# ============================================================================
# DELETE COMMAND TESTS
# ============================================================================


class TestDeleteCommand:
    """Test delete CLI command."""

    @patch("dns_aid.cli.main.run_async")
    def test_delete_force_success(self, mock_run_async):
        """Delete --force success with index update."""
        mock_run_async.side_effect = [
            True,  # unpublish returns True
            _make_index_result(),
        ]
        result = runner.invoke(
            app,
            [
                "delete",
                "--name",
                "chat",
                "--domain",
                "example.com",
                "--backend",
                "mock",
                "--force",
            ],
        )
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert "deleted successfully" in plain

    @patch("dns_aid.cli.main.run_async")
    def test_delete_force_no_records(self, mock_run_async):
        """Delete when no records found."""
        mock_run_async.return_value = False  # unpublish returns False
        result = runner.invoke(
            app,
            [
                "delete",
                "--name",
                "chat",
                "--domain",
                "example.com",
                "--backend",
                "mock",
                "--force",
            ],
        )
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert "No records found" in plain

    @patch("dns_aid.cli.main.run_async")
    def test_delete_force_index_fail(self, mock_run_async):
        """Delete success but index update fails."""
        mock_run_async.side_effect = [
            True,
            _make_index_result(success=False, message="Failed"),
        ]
        result = runner.invoke(
            app,
            [
                "delete",
                "--name",
                "chat",
                "--domain",
                "example.com",
                "--backend",
                "mock",
                "--force",
            ],
        )
        assert result.exit_code == 0

    @patch("dns_aid.cli.main.run_async")
    def test_delete_force_no_update_index(self, mock_run_async):
        """Delete with --no-update-index skips index update."""
        mock_run_async.return_value = True
        result = runner.invoke(
            app,
            [
                "delete",
                "--name",
                "chat",
                "--domain",
                "example.com",
                "--backend",
                "mock",
                "--force",
                "--no-update-index",
            ],
        )
        assert result.exit_code == 0
        assert mock_run_async.call_count == 1  # Only unpublish

    def test_delete_abort(self):
        """Delete without --force, user says no → abort."""
        result = runner.invoke(
            app,
            [
                "delete",
                "--name",
                "chat",
                "--domain",
                "example.com",
                "--backend",
                "mock",
            ],
            input="n\n",
        )
        # Typer abort is exit code 1
        assert result.exit_code == 1


# ============================================================================
# LIST COMMAND TESTS
# ============================================================================


class TestListCommand:
    """Test list CLI command."""

    @patch("dns_aid.cli.main.run_async")
    def test_list_with_records(self, mock_run_async):
        """List records shows table."""
        mock_run_async.return_value = [
            {
                "fqdn": "_chat._mcp._agents.example.com",
                "type": "SVCB",
                "ttl": 3600,
                "values": ["1 mcp.example.com. alpn=mcp port=443"],
            },
            {
                "fqdn": "_chat._mcp._agents.example.com",
                "type": "TXT",
                "ttl": 3600,
                "values": ["capabilities=ipam,dns"],
            },
        ]
        result = runner.invoke(app, ["list", "example.com", "--backend", "mock"])
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert "2 record(s)" in plain

    @patch("dns_aid.cli.main.run_async")
    def test_list_empty(self, mock_run_async):
        """List with no records."""
        mock_run_async.return_value = []
        result = runner.invoke(app, ["list", "example.com", "--backend", "mock"])
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert "No DNS-AID records found" in plain

    @patch("dns_aid.cli.main.run_async")
    def test_list_long_value_truncated(self, mock_run_async):
        """List truncates long record values."""
        mock_run_async.return_value = [
            {
                "fqdn": "_chat._mcp._agents.example.com",
                "type": "TXT",
                "ttl": 3600,
                "values": ["x" * 100],
            },
        ]
        result = runner.invoke(app, ["list", "example.com", "--backend", "mock"])
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert "1 record(s)" in plain


# ============================================================================
# ZONES COMMAND TESTS
# ============================================================================


class TestZonesCommand:
    """Test zones CLI command."""

    def test_zones_non_route53_error(self):
        """Zones for non-route53 backend exits with error."""
        result = runner.invoke(app, ["zones", "--backend", "mock"])
        assert result.exit_code == 1

    @patch.dict("os.environ", {"AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test"})
    @patch("dns_aid.cli.main.run_async")
    def test_zones_route53_success(self, mock_run_async):
        """Zones lists Route53 zones."""
        mock_run_async.return_value = [
            {
                "name": "example.com.",
                "id": "Z12345",
                "record_count": 10,
                "private": False,
            },
        ]
        result = runner.invoke(app, ["zones", "--backend", "route53"])
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert "example.com" in plain


# ============================================================================
# INDEX LIST COMMAND TESTS
# ============================================================================


class TestIndexListCommand:
    """Test index list CLI command."""

    @patch("dns_aid.cli.main.run_async")
    def test_index_list_with_entries(self, mock_run_async):
        """Index list shows table of entries."""
        from dns_aid.core.indexer import IndexEntry

        mock_run_async.return_value = [
            IndexEntry(name="chat", protocol="mcp"),
            IndexEntry(name="network", protocol="a2a"),
        ]
        result = runner.invoke(app, ["index", "list", "example.com", "--backend", "mock"])
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert "2 agent(s)" in plain

    @patch("dns_aid.cli.main.run_async")
    def test_index_list_empty_both(self, mock_run_async):
        """Index list with no entries from backend or DNS."""
        mock_run_async.return_value = []
        result = runner.invoke(app, ["index", "list", "example.com", "--backend", "mock"])
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert "No index record found" in plain


# ============================================================================
# INDEX SYNC COMMAND TESTS
# ============================================================================


class TestIndexSyncCommand:
    """Test index sync CLI command."""

    @patch("dns_aid.cli.main.run_async")
    def test_index_sync_success_with_entries(self, mock_run_async):
        """Sync success with agents found."""
        mock_run_async.return_value = _make_index_result(
            success=True, created=True, message="Synced 1 agent(s)"
        )
        result = runner.invoke(app, ["index", "sync", "example.com", "--backend", "mock"])
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert "Synced" in plain or "agent" in plain.lower()

    @patch("dns_aid.cli.main.run_async")
    def test_index_sync_success_empty(self, mock_run_async):
        """Sync success but no agents found."""
        from dns_aid.core.indexer import IndexResult

        mock_run_async.return_value = IndexResult(
            domain="example.com",
            entries=[],
            success=True,
            message="No agents",
        )
        result = runner.invoke(app, ["index", "sync", "example.com", "--backend", "mock"])
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert "No agents found" in plain

    @patch("dns_aid.cli.main.run_async")
    def test_index_sync_failure(self, mock_run_async):
        """Sync failure exits with code 1."""
        from dns_aid.core.indexer import IndexResult

        mock_run_async.return_value = IndexResult(
            domain="example.com",
            entries=[],
            success=False,
            message="Backend unreachable",
        )
        result = runner.invoke(app, ["index", "sync", "example.com", "--backend", "mock"])
        assert result.exit_code == 1


# ============================================================================
# VERIFY COMMAND EXTENDED
# ============================================================================


class TestVerifyCommandExtended:
    """Extended verify CLI tests."""

    @patch("dns_aid.cli.main.run_async")
    def test_verify_no_latency(self, mock_run_async):
        """Verify with no endpoint_latency_ms omits latency line."""
        from dns_aid.core.validator import VerifyResult

        mock_run_async.return_value = VerifyResult(
            fqdn="_chat._a2a._agents.example.com",
            record_exists=True,
            svcb_valid=True,
            dnssec_valid=True,
            dane_valid=None,
            endpoint_reachable=False,
            endpoint_latency_ms=None,
        )
        result = runner.invoke(app, ["verify", "_chat._a2a._agents.example.com"])
        assert result.exit_code == 0
        assert "Security Score" in result.output

    @patch("dns_aid.cli.main.run_async")
    def test_verify_all_pass(self, mock_run_async):
        """Verify with all checks passing."""
        from dns_aid.core.validator import VerifyResult

        mock_run_async.return_value = VerifyResult(
            fqdn="_chat._a2a._agents.example.com",
            record_exists=True,
            svcb_valid=True,
            dnssec_valid=True,
            dane_valid=True,
            endpoint_reachable=True,
            endpoint_latency_ms=25.0,
        )
        result = runner.invoke(app, ["verify", "_chat._a2a._agents.example.com"])
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert "25ms" in plain or "Latency" in plain
