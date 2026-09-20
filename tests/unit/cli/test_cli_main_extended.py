# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Extended unit tests for ``dns_aid.cli.main``.

Covers the CLI commands and branches not exercised by ``test_cli.py`` /
``test_policy_cli.py`` / ``test_search_command.py``:

- message / call / list-tools (agent communication)
- dcv issue / place / verify / revoke
- keys generate / export-jwks
- index publish-catalog / unpublish-catalog / sync error paths
- policy show/compile edge cases and policy rollback
- the full enforce pipeline (validation, auto-policy, enforce-mode pushes,
  report generation)
- _get_backend error paths
- output-formatting branches of publish / discover / search / verify / list

All backend / network boundaries are mocked (``dns_aid.cli.main.run_async``
or the library entry points) — no network, deterministic.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from typer.testing import CliRunner

from dns_aid.cli.main import app
from dns_aid.core.invoke import InvokeResult

runner = CliRunner()

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
SAMPLE_POLICY = FIXTURES / "sample-policy.json"

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

# A minimal policy document that compiles cleanly (RPZ directive, no skips).
MINIMAL_POLICY = {
    "agent": "_svc._mcp._agents.example.com",
    "rules": {"blocked_caller_domains": ["evil.example.com"]},
}


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


def _combined_output(result) -> str:
    """stdout + stderr (if captured separately), ANSI-stripped."""
    out = result.output
    try:
        err = result.stderr or ""
    except Exception:
        err = ""
    return _strip_ansi(out + err)


# ============================================================================
# MESSAGE COMMAND
# ============================================================================


class TestMessageCommand:
    def test_message_requires_endpoint_or_domain_name(self):
        result = runner.invoke(app, ["message", "hello"])
        assert result.exit_code == 1
        assert "Provide --endpoint" in _combined_output(result)

    def test_message_rejects_empty_text(self):
        result = runner.invoke(app, ["message", "   ", "-e", "https://chat.example.com"])
        assert result.exit_code == 1
        assert "cannot be empty" in _combined_output(result)

    @patch("dns_aid.cli.main.run_async")
    def test_message_failure_exits_1(self, mock_run_async):
        mock_run_async.return_value = InvokeResult(success=False, error="connection refused")
        result = runner.invoke(app, ["message", "hi", "-e", "https://chat.example.com"])
        assert result.exit_code == 1
        assert "connection refused" in _combined_output(result)

    @patch("dns_aid.cli.main.run_async")
    def test_message_success_with_agent_info_and_text(self, mock_run_async):
        mock_run_async.return_value = InvokeResult(
            success=True,
            data={
                "agent_info": {
                    "resolved_via": "dns",
                    "canonical_endpoint": "https://chat.example.com/a2a",
                    "name": "chat-agent",
                },
                "response_text": "Hello back!",
                "raw": {"jsonrpc": "2.0", "result": {}},
            },
        )
        result = runner.invoke(app, ["message", "hi", "-d", "example.com", "-n", "chat"])
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert "Resolved via: dns" in plain
        assert "Canonical URL" in plain
        assert "Agent: chat-agent" in plain
        assert "Hello back!" in plain

    @patch("dns_aid.cli.main.run_async")
    def test_message_json_output_uses_raw(self, mock_run_async):
        mock_run_async.return_value = InvokeResult(
            success=True,
            data={
                "agent_info": {"resolved_via": "direct"},
                "response_text": "unused",
                "raw": {"jsonrpc": "2.0", "id": 7},
            },
        )
        result = runner.invoke(app, ["message", "hi", "-e", "https://chat.example.com", "--json"])
        assert result.exit_code == 0
        assert '"jsonrpc"' in result.output
        assert "unused" not in result.output

    @patch("dns_aid.cli.main.run_async")
    def test_message_fallback_prints_json_data(self, mock_run_async):
        """No response_text and no agent_info → raw data dumped as JSON."""
        mock_run_async.return_value = InvokeResult(success=True, data={"weird": "shape"})
        result = runner.invoke(app, ["message", "hi", "-e", "https://chat.example.com"])
        assert result.exit_code == 0
        assert "weird" in result.output


# ============================================================================
# CALL COMMAND
# ============================================================================


class TestCallCommand:
    def test_call_invalid_json_arguments(self):
        result = runner.invoke(
            app, ["call", "https://mcp.example.com/mcp", "my_tool", "-a", "{not json"]
        )
        assert result.exit_code == 1
        assert "Invalid JSON" in _combined_output(result)

    @patch("dns_aid.cli.main.run_async")
    def test_call_failure_exits_1(self, mock_run_async):
        mock_run_async.return_value = InvokeResult(success=False, error="tool not found")
        result = runner.invoke(app, ["call", "https://mcp.example.com/mcp", "nope"])
        assert result.exit_code == 1
        assert "tool not found" in _combined_output(result)

    @patch("dns_aid.cli.main.run_async")
    def test_call_json_output(self, mock_run_async):
        mock_run_async.return_value = InvokeResult(success=True, data={"content": []})
        result = runner.invoke(
            app,
            [
                "call",
                "https://mcp.example.com/mcp",
                "my_tool",
                "-a",
                '{"domain": "example.com"}',
                "--json",
            ],
        )
        assert result.exit_code == 0
        assert '"content"' in result.output

    @patch("dns_aid.cli.main.run_async")
    def test_call_renders_mcp_content_array(self, mock_run_async):
        mock_run_async.return_value = InvokeResult(
            success=True,
            data={"content": [{"type": "text", "text": "analysis done"}, {"type": "image"}]},
        )
        result = runner.invoke(app, ["call", "https://mcp.example.com/mcp", "analyze"])
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert "analysis done" in plain
        assert "image" in plain

    @patch("dns_aid.cli.main.run_async")
    def test_call_renders_string_data(self, mock_run_async):
        mock_run_async.return_value = InvokeResult(success=True, data="plain result")
        result = runner.invoke(app, ["call", "https://mcp.example.com/mcp", "tool"])
        assert result.exit_code == 0
        assert "plain result" in _strip_ansi(result.output)

    @patch("dns_aid.cli.main.run_async")
    def test_call_renders_other_data_as_json(self, mock_run_async):
        mock_run_async.return_value = InvokeResult(success=True, data={"answer": 42})
        result = runner.invoke(app, ["call", "https://mcp.example.com/mcp", "tool"])
        assert result.exit_code == 0
        assert "42" in result.output


# ============================================================================
# LIST-TOOLS COMMAND
# ============================================================================


class TestListToolsCommand:
    @patch("dns_aid.cli.main.run_async")
    def test_list_tools_failure_exits_1(self, mock_run_async):
        mock_run_async.return_value = InvokeResult(success=False, error="unreachable")
        result = runner.invoke(app, ["list-tools", "https://mcp.example.com/mcp"])
        assert result.exit_code == 1
        assert "unreachable" in _combined_output(result)

    @patch("dns_aid.cli.main.run_async")
    def test_list_tools_json_output(self, mock_run_async):
        mock_run_async.return_value = InvokeResult(
            success=True, data=[{"name": "analyze", "description": "Analyze things"}]
        )
        result = runner.invoke(app, ["list-tools", "https://mcp.example.com/mcp", "--json"])
        assert result.exit_code == 0
        assert '"analyze"' in result.output

    @patch("dns_aid.cli.main.run_async")
    def test_list_tools_empty(self, mock_run_async):
        mock_run_async.return_value = InvokeResult(success=True, data=[])
        result = runner.invoke(app, ["list-tools", "https://mcp.example.com/mcp"])
        assert result.exit_code == 0
        assert "No tools found" in _strip_ansi(result.output)

    @patch("dns_aid.cli.main.run_async")
    def test_list_tools_non_list_data_treated_as_empty(self, mock_run_async):
        mock_run_async.return_value = InvokeResult(success=True, data={"oops": True})
        result = runner.invoke(app, ["list-tools", "https://mcp.example.com/mcp"])
        assert result.exit_code == 0
        assert "No tools found" in _strip_ansi(result.output)

    @patch("dns_aid.cli.main.run_async")
    def test_list_tools_table(self, mock_run_async):
        mock_run_async.return_value = InvokeResult(
            success=True,
            data=[
                {"name": "analyze", "description": "Analyze security posture"},
                {"name": "report"},  # missing description → "-"
            ],
        )
        result = runner.invoke(app, ["list-tools", "https://mcp.example.com/mcp"])
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert "analyze" in plain
        assert "2 tool(s)" in plain


# ============================================================================
# PUBLISH / DISCOVER / VERIFY / LIST / DELETE / INDEX branches
# ============================================================================


def _make_publish_result():
    from dns_aid.core.models import AgentRecord, Protocol, PublishResult

    agent = AgentRecord(
        name="chat",
        domain="example.com",
        protocol=Protocol.MCP,
        target_host="mcp.example.com",
        endpoint_override="https://mcp.example.com",
        port=443,
    )
    return PublishResult(
        agent=agent,
        records_created=["SVCB chat.example.com"],
        zone="example.com",
        backend="mock",
        success=True,
    )


def _make_index_result(success=True, created=False):
    from dns_aid.core.indexer import IndexEntry, IndexResult

    return IndexResult(
        domain="example.com",
        entries=[IndexEntry(name="chat", protocol="mcp")],
        success=success,
        message="ok" if success else "boom",
        created=created,
    )


class TestPublishExplicitEndpoint:
    @patch("dns_aid.cli.main.run_async")
    def test_publish_with_explicit_endpoint(self, mock_run_async):
        """--endpoint set → the default-endpoint branch is skipped."""
        mock_run_async.side_effect = [_make_publish_result(), _make_index_result()]
        result = runner.invoke(
            app,
            [
                "publish",
                "-n",
                "chat",
                "-d",
                "example.com",
                "-e",
                "custom.example.com",
                "--backend",
                "mock",
                "--ipv4hint",
                "203.0.113.10",
                "--ipv6hint",
                "2001:db8::1",
            ],
        )
        assert result.exit_code == 0
        assert "published successfully" in _strip_ansi(result.output)


class TestVerifyDetailBranches:
    @patch("dns_aid.cli.main.run_async")
    def test_verify_prints_dnssec_detail_and_skips_empty_notes(self, mock_run_async):
        from dns_aid.core.models import DNSSECDetail
        from dns_aid.core.validator import VerifyResult

        mock_run_async.return_value = VerifyResult(
            fqdn="chat.example.com",
            record_exists=True,
            svcb_valid=True,
            dnssec_valid=True,
            dnssec_note="",
            dane_valid=True,
            dane_note="",
            endpoint_reachable=True,
            endpoint_latency_ms=12.0,
            dnssec_detail=DNSSECDetail(
                validated=True,
                algorithm="ECDSAP256SHA256",
                algorithm_strength="strong",
                chain_complete=True,
                chain_depth=3,
            ),
        )
        result = runner.invoke(app, ["verify", "chat.example.com"])
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert "ECDSAP256SHA256" in plain
        assert "chain depth: 3" in plain


class TestListCommandBranches:
    @patch("dns_aid.cli.main.run_async")
    def test_list_backend_exception_exits_1(self, mock_run_async):
        mock_run_async.side_effect = RuntimeError("backend down")
        result = runner.invoke(app, ["list", "example.com", "--backend", "mock"])
        assert result.exit_code == 1
        assert "Failed to list records" in _combined_output(result)

    @patch("dns_aid.cli.main.run_async")
    def test_list_zone_not_found_exits_1(self, mock_run_async):
        mock_run_async.return_value = None  # sentinel: zone missing
        result = runner.invoke(app, ["list", "nozone.example", "--backend", "mock"])
        assert result.exit_code == 1
        assert "does not exist" in _combined_output(result)

    @patch("dns_aid.cli.main.run_async")
    def test_list_non_list_values_rendered(self, mock_run_async):
        mock_run_async.return_value = [
            {
                "fqdn": "chat.example.com",
                "type": "TXT",
                "ttl": 300,
                "values": "scalar-value",
            },
        ]
        result = runner.invoke(app, ["list", "example.com", "--backend", "mock"])
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert "scalar-value" in plain
        assert "1 record(s)" in plain


class TestDeleteCommandBranches:
    @patch("dns_aid.cli.main.run_async")
    def test_delete_confirmed_interactively(self, mock_run_async):
        mock_run_async.side_effect = [True, _make_index_result()]
        result = runner.invoke(
            app,
            ["delete", "-n", "chat", "-d", "example.com", "--backend", "mock"],
            input="y\n",
        )
        assert result.exit_code == 0
        assert "deleted successfully" in _strip_ansi(result.output)

    @patch("dns_aid.cli.main.run_async")
    def test_delete_backend_exception_exits_1(self, mock_run_async):
        mock_run_async.side_effect = RuntimeError("kaboom")
        result = runner.invoke(
            app,
            ["delete", "-n", "chat", "-d", "example.com", "--backend", "mock", "--force"],
        )
        assert result.exit_code == 1
        assert "Failed to delete" in _combined_output(result)


class TestIndexSyncBranches:
    @patch("dns_aid.cli.main.run_async")
    def test_index_sync_exception_exits_1(self, mock_run_async):
        mock_run_async.side_effect = RuntimeError("sync blew up")
        result = runner.invoke(app, ["index", "sync", "example.com", "--backend", "mock"])
        assert result.exit_code == 1
        assert "Failed to sync index" in _combined_output(result)

    @patch("dns_aid.cli.main.run_async")
    def test_index_sync_success_not_created(self, mock_run_async):
        """created=False → no 'Index record created' footer."""
        mock_run_async.return_value = _make_index_result(success=True, created=False)
        result = runner.invoke(app, ["index", "sync", "example.com", "--backend", "mock"])
        assert result.exit_code == 0
        assert "Index record created" not in _strip_ansi(result.output)


# ============================================================================
# INDEX CATALOG POINTER COMMANDS
# ============================================================================


class TestIndexCatalogCommands:
    @patch("dns_aid.cli.main.run_async")
    def test_publish_catalog_success(self, mock_run_async):
        mock_run_async.return_value = [
            "_catalog._agents.example.com",
            "_index._agents.example.com",
        ]
        result = runner.invoke(
            app,
            [
                "index",
                "publish-catalog",
                "example.com",
                "ard.example.com",
                "--backend",
                "mock",
            ],
        )
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert "Catalog pointer published" in plain
        assert "_catalog._agents.example.com" in plain
        assert "https://ard.example.com/.well-known/ai-catalog.json" in plain

    @patch("dns_aid.cli.main.run_async")
    def test_publish_catalog_failure_exits_1(self, mock_run_async):
        mock_run_async.side_effect = RuntimeError("write denied")
        result = runner.invoke(
            app,
            [
                "index",
                "publish-catalog",
                "example.com",
                "ard.example.com",
                "--backend",
                "mock",
                "--catalog-only",
            ],
        )
        assert result.exit_code == 1
        assert "Failed to publish catalog pointer" in _combined_output(result)

    @patch("dns_aid.cli.main.run_async")
    def test_unpublish_catalog_success(self, mock_run_async):
        mock_run_async.return_value = ["_catalog._agents.example.com"]
        result = runner.invoke(
            app, ["index", "unpublish-catalog", "example.com", "--backend", "mock"]
        )
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert "Catalog pointer removed" in plain
        assert "deleted SVCB" in plain

    @patch("dns_aid.cli.main.run_async")
    def test_unpublish_catalog_nothing_to_remove(self, mock_run_async):
        mock_run_async.return_value = []
        result = runner.invoke(
            app,
            [
                "index",
                "unpublish-catalog",
                "example.com",
                "--backend",
                "mock",
                "--catalog-only",
            ],
        )
        assert result.exit_code == 0
        assert "No catalog pointer records found" in _strip_ansi(result.output)

    @patch("dns_aid.cli.main.run_async")
    def test_unpublish_catalog_failure_exits_1(self, mock_run_async):
        mock_run_async.side_effect = RuntimeError("delete denied")
        result = runner.invoke(
            app, ["index", "unpublish-catalog", "example.com", "--backend", "mock"]
        )
        assert result.exit_code == 1
        assert "Failed to remove catalog pointer" in _combined_output(result)


# ============================================================================
# KEYS COMMANDS
# ============================================================================


class TestKeysGenerate:
    def test_generate_unencrypted(self, tmp_path):
        result = runner.invoke(app, ["keys", "generate", "-o", str(tmp_path)])
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert "Keypair generated successfully" in plain
        assert "NOT encrypted" in plain
        assert (tmp_path / "private.pem").exists()
        assert (tmp_path / "public.pem").exists()

    def test_generate_with_password(self, tmp_path):
        result = runner.invoke(
            app,
            ["keys", "generate", "-o", str(tmp_path), "--kid", "test-key", "-p", "secret"],
        )
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert "password-protected" in plain
        assert "test-key" in plain
        assert b"ENCRYPTED" in (tmp_path / "private.pem").read_bytes()


class TestKeysExportJwks:
    def _generate(self, tmp_path):
        result = runner.invoke(app, ["keys", "generate", "-o", str(tmp_path)])
        assert result.exit_code == 0

    def test_export_missing_file(self):
        result = runner.invoke(app, ["keys", "export-jwks", "-i", "/no/such/key.pem"])
        assert result.exit_code == 1
        assert "Key file not found" in _combined_output(result)

    def test_export_from_public_key_stdout(self, tmp_path):
        self._generate(tmp_path)
        result = runner.invoke(app, ["keys", "export-jwks", "-i", str(tmp_path / "public.pem")])
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert '"kty"' in plain
        assert "dns-aid-jwks.json" in plain

    def test_export_from_private_key_to_file(self, tmp_path):
        self._generate(tmp_path)
        out = tmp_path / "jwks.json"
        result = runner.invoke(
            app,
            [
                "keys",
                "export-jwks",
                "-i",
                str(tmp_path / "private.pem"),
                "-o",
                str(out),
                "--kid",
                "my-kid",
            ],
        )
        assert result.exit_code == 0
        assert "JWKS exported to" in _strip_ansi(result.output)
        jwks = json.loads(out.read_text())
        assert jwks["keys"][0]["kid"] == "my-kid"

    def test_export_rejects_non_ec_public_key(self, tmp_path):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pub_pem = rsa_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_file = tmp_path / "rsa-pub.pem"
        key_file.write_bytes(pub_pem)
        result = runner.invoke(app, ["keys", "export-jwks", "-i", str(key_file)])
        assert result.exit_code == 1

    def test_export_rejects_non_ec_private_key(self, tmp_path):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        priv_pem = rsa_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_file = tmp_path / "rsa-priv.pem"
        key_file.write_bytes(priv_pem)
        result = runner.invoke(app, ["keys", "export-jwks", "-i", str(key_file)])
        assert result.exit_code == 1

    def test_export_garbage_file(self, tmp_path):
        key_file = tmp_path / "garbage.pem"
        key_file.write_text("this is not a key")
        result = runner.invoke(app, ["keys", "export-jwks", "-i", str(key_file)])
        assert result.exit_code == 1
        assert "Failed to load key" in _combined_output(result)


# ============================================================================
# _get_backend ERROR PATHS
# ============================================================================


class TestGetBackendErrorPaths:
    def test_detect_backend_valueerror_exits_1(self, monkeypatch):
        monkeypatch.delenv("DNS_AID_BACKEND", raising=False)
        with patch(
            "dns_aid.cli.backends.detect_backend",
            side_effect=ValueError("Multiple backends configured"),
        ):
            result = runner.invoke(app, ["list", "example.com"])
        assert result.exit_code == 1
        assert "Multiple backends configured" in _combined_output(result)

    def test_missing_required_env_shows_setup_steps(self, monkeypatch):
        monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
        result = runner.invoke(app, ["list", "example.com", "--backend", "cloudflare"])
        assert result.exit_code == 1
        plain = _combined_output(result)
        assert "requires environment variables" in plain
        assert "CLOUDFLARE_API_TOKEN" in plain
        assert "Setup steps" in plain

    def test_create_backend_importerror(self):
        with patch(
            "dns_aid.backends.create_backend",
            side_effect=ImportError("No module named 'boto3'"),
        ):
            result = runner.invoke(app, ["list", "example.com", "--backend", "mock"])
        assert result.exit_code == 1
        assert "Missing dependency" in _combined_output(result)

    def test_create_backend_valueerror(self, monkeypatch):
        monkeypatch.setenv("CLOUDFLARE_API_TOKEN", "token")
        with patch(
            "dns_aid.backends.create_backend",
            side_effect=ValueError("bad credentials"),
        ):
            result = runner.invoke(app, ["list", "example.com", "--backend", "cloudflare"])
        assert result.exit_code == 1
        plain = _combined_output(result)
        assert "Failed to initialize" in plain
        assert "Setup steps" in plain

    def test_create_backend_oserror_without_setup_steps(self):
        """A registry entry without setup_steps skips the guidance block."""
        from dns_aid.cli.backends import BackendInfo

        bare = BackendInfo(name="mock", display_name="Bare Mock")
        with (
            patch.dict("dns_aid.cli.backends.BACKEND_REGISTRY", {"mock": bare}),
            patch(
                "dns_aid.backends.create_backend",
                side_effect=OSError("filesystem error"),
            ),
        ):
            result = runner.invoke(app, ["list", "example.com", "--backend", "mock"])
        assert result.exit_code == 1
        plain = _combined_output(result)
        assert "Failed to initialize" in plain
        assert "Setup steps" not in plain

    def test_missing_env_without_setup_guidance(self):
        """Missing required env for a backend with no setup steps/url."""
        from dns_aid.cli.backends import BackendInfo

        fake = BackendInfo(
            name="fake",
            display_name="Fake DNS",
            required_env={"FAKE_DNS_TOKEN": "API token"},
        )
        with patch.dict("dns_aid.cli.backends.BACKEND_REGISTRY", {"fake": fake}):
            result = runner.invoke(app, ["list", "example.com", "--backend", "fake"])
        assert result.exit_code == 1
        plain = _combined_output(result)
        assert "requires environment variables" in plain
        assert "FAKE_DNS_TOKEN" in plain
        assert "Setup steps" not in plain
        assert "Docs:" not in plain


# ============================================================================
# SEARCH — JSON error envelopes and pagination-exhausted branch
# ============================================================================


class TestSearchExtraBranches:
    def test_config_error_json_envelope(self):
        from dns_aid.sdk.exceptions import DirectoryConfigError

        with patch(
            "dns_aid.sdk.client.AgentClient.search",
            new_callable=AsyncMock,
            side_effect=DirectoryConfigError(
                "no url",
                details={
                    "missing_field": "directory_api_url",
                    "env_var": "DNS_AID_SDK_DIRECTORY_API_URL",
                },
            ),
        ):
            result = runner.invoke(app, ["search", "x", "--json"])
        assert result.exit_code == 78
        assert "DirectoryConfigError" in _combined_output(result)

    def test_auth_error_json_envelope(self):
        from dns_aid.sdk.exceptions import DirectoryAuthError

        with patch(
            "dns_aid.sdk.client.AgentClient.search",
            new_callable=AsyncMock,
            side_effect=DirectoryAuthError("forbidden", details={"status": 403}),
        ):
            result = runner.invoke(
                app,
                ["search", "x", "--json", "--directory-url", "https://directory.test.example"],
                env={"DNS_AID_FETCH_ALLOWLIST": "directory.test.example"},
            )
        assert result.exit_code == 77
        assert "DirectoryAuthError" in _combined_output(result)

    def test_unavailable_error_json_envelope(self):
        from dns_aid.sdk.exceptions import DirectoryUnavailableError

        with patch(
            "dns_aid.sdk.client.AgentClient.search",
            new_callable=AsyncMock,
            side_effect=DirectoryUnavailableError("503", details={"status": 503}),
        ):
            result = runner.invoke(
                app,
                ["search", "x", "--json", "--directory-url", "https://directory.test.example"],
                env={"DNS_AID_FETCH_ALLOWLIST": "directory.test.example"},
            )
        assert result.exit_code == 75
        assert "DirectoryUnavailableError" in _combined_output(result)

    def test_human_table_without_next_page_hint(self):
        from dns_aid.core.models import AgentRecord, Protocol
        from dns_aid.sdk.search import SearchResponse, SearchResult, TrustAttestation

        response = SearchResponse(
            query="payments",
            results=[
                SearchResult(
                    agent=AgentRecord(
                        name="agent0",
                        domain="example.com",
                        protocol=Protocol.MCP,
                        target_host="agent0.example.com",
                        port=443,
                        capabilities=[],
                    ),
                    score=10.0,
                    trust=TrustAttestation(
                        security_score=80,
                        trust_score=75,
                        popularity_score=60,
                        trust_tier=2,
                        safety_status="active",
                        dnssec_valid=True,
                        dane_valid=False,
                        svcb_valid=True,
                        endpoint_reachable=True,
                        protocol_verified=True,
                        badges=[],
                    ),
                )
            ],
            total=1,
            limit=20,
            offset=0,
        )
        with patch(
            "dns_aid.sdk.client.AgentClient.search",
            new_callable=AsyncMock,
            return_value=response,
        ):
            result = runner.invoke(
                app,
                ["search", "payments", "--directory-url", "https://directory.test.example"],
                env={"DNS_AID_FETCH_ALLOWLIST": "directory.test.example"},
            )
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert "Showing 1-1 of 1 results" in plain
        assert "Use --offset" not in plain


# ============================================================================
# POLICY COMMANDS — edge branches + rollback
# ============================================================================


class TestPolicyCompileBranches:
    def test_compile_invalid_format(self, tmp_path):
        result = runner.invoke(
            app,
            [
                "policy",
                "compile",
                "-i",
                str(SAMPLE_POLICY),
                "-o",
                str(tmp_path / "out"),
                "-f",
                "bogus",
            ],
        )
        assert result.exit_code == 1
        assert "must be rpz, bindaid, or both" in _combined_output(result)

    def test_compile_without_skipped_rules(self, tmp_path):
        policy = tmp_path / "minimal.json"
        policy.write_text(json.dumps(MINIMAL_POLICY))
        out = tmp_path / "zone"
        result = runner.invoke(
            app, ["policy", "compile", "-i", str(policy), "-o", str(out), "-f", "both"]
        )
        assert result.exit_code == 0
        assert "rule(s) skipped" not in _strip_ansi(result.output)


class TestPolicyShowBranches:
    def test_show_missing_input(self):
        result = runner.invoke(app, ["policy", "show", "-i", "/nonexistent-policy.json"])
        assert result.exit_code == 1
        assert "Input file not found" in _combined_output(result)

    def test_show_invalid_json(self, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{nope")
        result = runner.invoke(app, ["policy", "show", "-i", str(bad)])
        assert result.exit_code == 1
        assert "Failed to parse policy document" in _combined_output(result)

    def test_show_empty_policy_prints_none_sections(self, tmp_path):
        policy = tmp_path / "empty.json"
        policy.write_text(json.dumps({"agent": "_svc._mcp._agents.example.com"}))
        result = runner.invoke(app, ["policy", "show", "-i", str(policy)])
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert "RPZ Directives (0)" in plain
        assert "bind-aid Directives (0)" in plain
        assert "Skipped Rules (0)" in plain
        assert "None" in plain


def _make_snapshot(directives=None):
    from dns_aid.sdk.policy.snapshot import RPZSnapshot

    return RPZSnapshot(
        timestamp="2026-07-29T00:00:00+00:00",
        rpz_zone="rpz.example.com",
        backend="nios",
        mode="enforce",
        directives=directives
        or [
            {
                "owner": "evil.example.com",
                "action": "NXDOMAIN",
                "source_rule": "block-evil",
                "comment": "bad",
            },
            {
                "owner": "worse.example.com",
                "action": "DROP",
                "source_rule": "block-worse",
                "comment": "worse",
            },
        ],
    )


class TestPolicyRollback:
    def test_rollback_no_snapshot(self):
        with patch("dns_aid.sdk.policy.snapshot.load_latest_snapshot", return_value=None):
            result = runner.invoke(
                app,
                ["policy", "rollback", "--rpz-zone", "rpz.example.com", "-b", "nios"],
            )
        assert result.exit_code == 1
        assert "No snapshots found" in _combined_output(result)

    def test_rollback_dry_run(self):
        with patch(
            "dns_aid.sdk.policy.snapshot.load_latest_snapshot",
            return_value=_make_snapshot(),
        ):
            result = runner.invoke(
                app,
                [
                    "policy",
                    "rollback",
                    "--rpz-zone",
                    "rpz.example.com",
                    "-b",
                    "nios",
                    "--dry-run",
                ],
            )
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert "Dry run" in plain
        assert "evil.example.com" in plain

    def test_rollback_nios_with_errors(self):
        """Real run_async drives the _rollback_nios closure against a mocked NIOS."""

        async def create_record(**kwargs):
            if kwargs["owner"] == "worse.example.com":
                raise RuntimeError("api error")

        nios = MagicMock()
        nios.ensure_rpz_zone = AsyncMock()
        nios.create_rpz_cname_record = AsyncMock(side_effect=create_record)
        nios.close = AsyncMock()

        with (
            patch(
                "dns_aid.sdk.policy.snapshot.load_latest_snapshot",
                return_value=_make_snapshot(),
            ),
            patch("dns_aid.backends.infoblox.nios.InfobloxNIOSBackend", return_value=nios),
        ):
            result = runner.invoke(
                app,
                ["policy", "rollback", "--rpz-zone", "rpz.example.com", "-b", "nios"],
            )
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert "Rolled back 1/2" in plain
        assert "api error" in plain
        nios.close.assert_awaited()

    def test_rollback_infoblox(self):
        bx = MagicMock()
        bx.create_or_update_named_list = AsyncMock(return_value={"updated": True})
        bx.close = AsyncMock()

        with (
            patch(
                "dns_aid.sdk.policy.snapshot.load_latest_snapshot",
                return_value=_make_snapshot(),
            ),
            patch("dns_aid.backends.infoblox.bloxone.InfobloxBloxOneBackend", return_value=bx),
        ):
            result = runner.invoke(
                app,
                ["policy", "rollback", "--rpz-zone", "rpz.example.com", "-b", "infoblox"],
            )
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert "Rolled back TD named list" in plain
        assert "2 domains" in plain
        bx.close.assert_awaited()

    def test_rollback_unsupported_backend(self):
        with patch(
            "dns_aid.sdk.policy.snapshot.load_latest_snapshot",
            return_value=_make_snapshot(),
        ):
            result = runner.invoke(
                app,
                ["policy", "rollback", "--rpz-zone", "rpz.example.com", "-b", "route53"],
            )
        assert result.exit_code == 1
        assert "Rollback not supported" in _combined_output(result)


# ============================================================================
# ENFORCE COMMAND
# ============================================================================


def _ns_agent(name="agent1", policy_uri=None):
    """Discovery-result agent stub with only the attributes enforce touches."""
    return SimpleNamespace(
        name=name,
        protocol="mcp",
        endpoint=f"https://{name}.example.com",
        policy_uri=policy_uri,
    )


def _ns_discovery(agents):
    return SimpleNamespace(count=len(agents), agents=agents)


def _ok_policy_response():
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.text = json.dumps(MINIMAL_POLICY)
    return resp


class TestEnforceValidation:
    def test_requires_policy_source(self):
        result = runner.invoke(app, ["enforce", "-d", "example.com"])
        assert result.exit_code == 1
        assert "Provide --policy-file or --auto-policy" in _combined_output(result)

    def test_rejects_bad_mode(self):
        result = runner.invoke(
            app,
            ["enforce", "-d", "example.com", "-p", str(SAMPLE_POLICY), "--mode", "yolo"],
        )
        assert result.exit_code == 1
        assert "must be shadow or enforce" in _combined_output(result)

    def test_rejects_bad_format(self):
        result = runner.invoke(
            app,
            ["enforce", "-d", "example.com", "-p", str(SAMPLE_POLICY), "-f", "yaml"],
        )
        assert result.exit_code == 1
        assert "must be rpz, bindaid, or both" in _combined_output(result)

    @patch("dns_aid.cli.main.run_async")
    def test_policy_file_missing(self, mock_run_async):
        mock_run_async.return_value = _ns_discovery([])
        result = runner.invoke(app, ["enforce", "-d", "example.com", "-p", "/no/such/policy.json"])
        assert result.exit_code == 1
        assert "Policy file not found" in _combined_output(result)

    @patch("dns_aid.cli.main.run_async")
    def test_policy_file_invalid_json(self, mock_run_async, tmp_path):
        mock_run_async.return_value = _ns_discovery([])
        bad = tmp_path / "bad.json"
        bad.write_text("{invalid")
        result = runner.invoke(app, ["enforce", "-d", "example.com", "-p", str(bad)])
        assert result.exit_code == 1
        assert "Failed to parse policy document" in _combined_output(result)


class TestEnforceShadowAndReports:
    @patch("dns_aid.cli.main.run_async")
    def test_shadow_with_json_report(self, mock_run_async, tmp_path):
        agents = [_ns_agent("a1", policy_uri="https://a1.example.com/policy.json"), _ns_agent("a2")]
        mock_run_async.return_value = _ns_discovery(agents)
        report = tmp_path / "inventory.json"
        result = runner.invoke(
            app,
            [
                "enforce",
                "-d",
                "example.com",
                "-p",
                str(SAMPLE_POLICY),
                "--mode",
                "shadow",
                "--report",
                str(report),
            ],
        )
        assert result.exit_code == 0, result.output
        plain = _strip_ansi(result.output)
        assert "Agents with policy_uri: 1" in plain
        assert "JSON report written" in plain
        data = json.loads(report.read_text())
        assert data["summary"]["total_agents"] == 2
        assert data["summary"]["agents_with_policy"] == 1
        assert data["mode"] == "shadow"
        assert len(data["rpz_directives"]) > 0

    @patch("dns_aid.cli.main.run_async")
    def test_shadow_with_csv_report(self, mock_run_async, tmp_path):
        agents = [_ns_agent("a1", policy_uri="https://a1.example.com/policy.json")]
        mock_run_async.return_value = _ns_discovery(agents)
        report = tmp_path / "inventory.csv"
        result = runner.invoke(
            app,
            [
                "enforce",
                "-d",
                "example.com",
                "-p",
                str(SAMPLE_POLICY),
                "--report",
                str(report),
            ],
        )
        assert result.exit_code == 0, result.output
        assert "CSV inventory written" in _strip_ansi(result.output)
        lines = report.read_text().strip().splitlines()
        assert lines[0].startswith("name,protocol,endpoint")
        assert "a1" in lines[1]

    @patch("dns_aid.cli.main.run_async")
    def test_shadow_rpz_only_output_dir(self, mock_run_async, tmp_path):
        mock_run_async.return_value = _ns_discovery([])
        result = runner.invoke(
            app,
            [
                "enforce",
                "-d",
                "example.com",
                "-p",
                str(SAMPLE_POLICY),
                "-f",
                "rpz",
                "-o",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0, result.output
        assert (tmp_path / "rpz.example.com.rpz").exists()
        assert not (tmp_path / "policy.example.com.bindaid").exists()

    @patch("dns_aid.cli.main.run_async")
    def test_shadow_bindaid_only_output_dir(self, mock_run_async, tmp_path):
        mock_run_async.return_value = _ns_discovery([])
        result = runner.invoke(
            app,
            [
                "enforce",
                "-d",
                "example.com",
                "-p",
                str(SAMPLE_POLICY),
                "-f",
                "bindaid",
                "-o",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0, result.output
        assert (tmp_path / "policy.example.com.bindaid").exists()
        assert not (tmp_path / "rpz.example.com.rpz").exists()


class TestEnforceAutoPolicy:
    @patch("dns_aid.cli.main.run_async")
    def test_auto_policy_no_agents_with_policy_uri(self, mock_run_async):
        mock_run_async.return_value = _ns_discovery([_ns_agent("plain")])
        result = runner.invoke(app, ["enforce", "-d", "example.com", "--auto-policy"])
        assert result.exit_code == 0
        assert "nothing to compile" in _strip_ansi(result.output)

    @patch("dns_aid.cli.main.run_async")
    def test_auto_policy_fetch_success_and_failure(self, mock_run_async):
        agents = [
            _ns_agent("good", policy_uri="https://good.example.com/policy.json"),
            _ns_agent("bad", policy_uri="https://bad.example.com/policy.json"),
        ]
        mock_run_async.side_effect = [
            _ns_discovery(agents),
            _ok_policy_response(),
            RuntimeError("fetch boom"),
        ]
        result = runner.invoke(
            app, ["enforce", "-d", "example.com", "--auto-policy", "--mode", "shadow"]
        )
        assert result.exit_code == 0, result.output
        plain = _strip_ansi(result.output)
        assert "Fetched: 1, Failed: 1" in plain
        assert "fetch boom" in plain
        assert "Shadow mode" in plain


class TestEnforceEnforceMode:
    @patch("dns_aid.cli.main.run_async")
    def test_enforce_mode_requires_backend(self, mock_run_async):
        mock_run_async.return_value = _ns_discovery([])
        result = runner.invoke(
            app,
            ["enforce", "-d", "example.com", "-p", str(SAMPLE_POLICY), "--mode", "enforce"],
        )
        assert result.exit_code == 1
        assert "Enforce mode requires --backend" in _combined_output(result)

    def test_enforce_mode_nios_push(self, tmp_path, monkeypatch):
        """Real run_async drives _push_nios; one record push fails."""
        monkeypatch.chdir(tmp_path)  # snapshots write to CWD/.dns-aid/snapshots

        calls = {"n": 0}

        async def create_record(**kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("api refused")

        nios = MagicMock()
        nios.ensure_rpz_zone = AsyncMock()
        nios.create_rpz_cname_record = AsyncMock(side_effect=create_record)
        nios.close = AsyncMock()

        with (
            patch(
                "dns_aid.core.discoverer.discover",
                new=AsyncMock(return_value=_ns_discovery([])),
            ),
            patch("dns_aid.backends.infoblox.nios.InfobloxNIOSBackend", return_value=nios),
        ):
            result = runner.invoke(
                app,
                [
                    "enforce",
                    "-d",
                    "example.com",
                    "-p",
                    str(SAMPLE_POLICY),
                    "--mode",
                    "enforce",
                    "-b",
                    "nios",
                ],
            )
        assert result.exit_code == 0, result.output
        plain = _strip_ansi(result.output)
        assert "Snapshot saved" in plain
        assert "Pushed" in plain
        assert "api refused" in plain
        assert list((tmp_path / ".dns-aid" / "snapshots").glob("*.json"))
        nios.ensure_rpz_zone.assert_awaited_once_with("rpz.example.com")
        nios.close.assert_awaited()

    def _bloxone_mock(self, nl_result, bind_result):
        bx = MagicMock()
        bx.create_or_update_named_list = AsyncMock(return_value=nl_result)
        bx.bind_named_list_to_policy = AsyncMock(return_value=bind_result)
        bx.close = AsyncMock()
        return bx

    def test_enforce_mode_infoblox_bound(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        bx = self._bloxone_mock(
            {"updated": False},
            {
                "action": "bound",
                "policy_name": "Default Global Policy",
                "policy_id": 7,
                "rule_count": 3,
            },
        )
        with (
            patch(
                "dns_aid.core.discoverer.discover",
                new=AsyncMock(return_value=_ns_discovery([])),
            ),
            patch("dns_aid.backends.infoblox.bloxone.InfobloxBloxOneBackend", return_value=bx),
        ):
            result = runner.invoke(
                app,
                [
                    "enforce",
                    "-d",
                    "example.com",
                    "-p",
                    str(SAMPLE_POLICY),
                    "--mode",
                    "enforce",
                    "-b",
                    "infoblox",
                ],
            )
        assert result.exit_code == 0, result.output
        plain = _strip_ansi(result.output)
        assert "Created TD named list" in plain
        assert "Bound to security policy 'Default Global Policy'" in plain
        assert "NXDOMAIN from Threat Defense" in plain
        bx.close.assert_awaited()

    def test_enforce_mode_infoblox_already_bound(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        bx = self._bloxone_mock(
            {"updated": True},
            {"action": "already_bound", "policy_name": "Default Global Policy"},
        )
        with (
            patch(
                "dns_aid.core.discoverer.discover",
                new=AsyncMock(return_value=_ns_discovery([])),
            ),
            patch("dns_aid.backends.infoblox.bloxone.InfobloxBloxOneBackend", return_value=bx),
        ):
            result = runner.invoke(
                app,
                [
                    "enforce",
                    "-d",
                    "example.com",
                    "-p",
                    str(SAMPLE_POLICY),
                    "--mode",
                    "enforce",
                    "-b",
                    "infoblox",
                ],
            )
        assert result.exit_code == 0, result.output
        plain = _strip_ansi(result.output)
        assert "Updated TD named list" in plain
        assert "Already bound" in plain

    def test_enforce_mode_infoblox_bind_failed_silently(self, tmp_path, monkeypatch):
        """bind_status neither 'bound' nor 'already_bound' → no bind message."""
        monkeypatch.chdir(tmp_path)
        bx = self._bloxone_mock({"updated": False}, {"action": "failed"})
        with (
            patch(
                "dns_aid.core.discoverer.discover",
                new=AsyncMock(return_value=_ns_discovery([])),
            ),
            patch("dns_aid.backends.infoblox.bloxone.InfobloxBloxOneBackend", return_value=bx),
        ):
            result = runner.invoke(
                app,
                [
                    "enforce",
                    "-d",
                    "example.com",
                    "-p",
                    str(SAMPLE_POLICY),
                    "--mode",
                    "enforce",
                    "-b",
                    "infoblox",
                ],
            )
        assert result.exit_code == 0, result.output
        plain = _strip_ansi(result.output)
        assert "Created TD named list" in plain
        assert "Bound to security policy" not in plain
        assert "Already bound" not in plain

    @patch("dns_aid.cli.main.run_async")
    def test_enforce_mode_other_backend_with_output_dir(
        self, mock_run_async, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        mock_run_async.return_value = _ns_discovery([])
        out = tmp_path / "zones"
        result = runner.invoke(
            app,
            [
                "enforce",
                "-d",
                "example.com",
                "-p",
                str(SAMPLE_POLICY),
                "--mode",
                "enforce",
                "-b",
                "file",
                "-o",
                str(out),
            ],
        )
        assert result.exit_code == 0, result.output
        assert "Zone files written to" in _strip_ansi(result.output)

    @patch("dns_aid.cli.main.run_async")
    def test_enforce_mode_other_backend_without_output_dir(
        self, mock_run_async, tmp_path, monkeypatch
    ):
        monkeypatch.chdir(tmp_path)
        mock_run_async.return_value = _ns_discovery([])
        result = runner.invoke(
            app,
            [
                "enforce",
                "-d",
                "example.com",
                "-p",
                str(SAMPLE_POLICY),
                "--mode",
                "enforce",
                "-b",
                "file",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "does not support direct RPZ push" in _strip_ansi(result.output)


# ============================================================================
# DCV COMMANDS
# ============================================================================


class TestDcvIssue:
    def test_issue_human_output_with_bnd_req(self):
        result = runner.invoke(
            app,
            ["dcv", "issue", "example.com", "--agent", "chat", "--issuer", "issuer.example"],
        )
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert "DCV Challenge" in plain
        assert "bnd-req" in plain
        assert "TXT record to place" in plain

    def test_issue_human_output_without_bnd_req(self):
        result = runner.invoke(app, ["dcv", "issue", "example.com"])
        assert result.exit_code == 0
        plain = _strip_ansi(result.output)
        assert "DCV Challenge" in plain
        assert "bnd-req" not in plain

    def test_issue_json_output(self):
        result = runner.invoke(app, ["dcv", "issue", "example.com", "--json"])
        assert result.exit_code == 0
        assert '"token"' in result.output
        assert '"fqdn"' in result.output


class TestDcvPlace:
    @patch("dns_aid.cli.main.run_async")
    def test_place_success_human(self, mock_run_async):
        from dns_aid.core.dcv import DCVPlaceResult

        mock_run_async.return_value = DCVPlaceResult(
            fqdn="_dnsaid-challenge.example.com",
            domain="example.com",
            expires_at=datetime(2026, 7, 30, tzinfo=UTC),
        )
        result = runner.invoke(app, ["dcv", "place", "example.com", "sometoken"])
        assert result.exit_code == 0
        assert "Challenge placed at" in _strip_ansi(result.output)

    @patch("dns_aid.cli.main.run_async")
    def test_place_success_json(self, mock_run_async):
        from dns_aid.core.dcv import DCVPlaceResult

        mock_run_async.return_value = DCVPlaceResult(
            fqdn="_dnsaid-challenge.example.com",
            domain="example.com",
            expires_at=datetime(2026, 7, 30, tzinfo=UTC),
        )
        result = runner.invoke(app, ["dcv", "place", "example.com", "sometoken", "--json"])
        assert result.exit_code == 0
        assert '"success"' in result.output

    @patch("dns_aid.cli.main.run_async")
    def test_place_failure_human(self, mock_run_async):
        mock_run_async.side_effect = RuntimeError("no backend")
        result = runner.invoke(app, ["dcv", "place", "example.com", "sometoken"])
        assert result.exit_code == 1
        assert "no backend" in _combined_output(result)

    @patch("dns_aid.cli.main.run_async")
    def test_place_failure_json(self, mock_run_async):
        mock_run_async.side_effect = RuntimeError("no backend")
        result = runner.invoke(app, ["dcv", "place", "example.com", "sometoken", "--json"])
        assert result.exit_code == 1
        assert '"success"' in result.output


def _dcv_verify_result(verified=True, expired=False, error=None):
    from dns_aid.core.dcv import DCVVerifyResult

    return DCVVerifyResult(
        verified=verified,
        domain="example.com",
        token="sometoken",
        fqdn="_dnsaid-challenge.example.com",
        expired=expired,
        error=error,
    )


class TestDcvVerify:
    @patch("dns_aid.cli.main.run_async")
    def test_verify_success_human(self, mock_run_async):
        mock_run_async.return_value = _dcv_verify_result(verified=True)
        result = runner.invoke(app, ["dcv", "verify", "example.com", "sometoken"])
        assert result.exit_code == 0
        assert "DCV verified" in _strip_ansi(result.output)

    @patch("dns_aid.cli.main.run_async")
    def test_verify_expired_human(self, mock_run_async):
        mock_run_async.return_value = _dcv_verify_result(
            verified=False, expired=True, error="token expired"
        )
        result = runner.invoke(
            app,
            ["dcv", "verify", "example.com", "sometoken", "-s", "192.0.2.53", "--port", "5353"],
        )
        assert result.exit_code == 1
        plain = _strip_ansi(result.output)
        assert "DCV expired" in plain
        assert "token expired" in plain

    @patch("dns_aid.cli.main.run_async")
    def test_verify_failed_human_without_error_text(self, mock_run_async):
        mock_run_async.return_value = _dcv_verify_result(verified=False)
        result = runner.invoke(app, ["dcv", "verify", "example.com", "sometoken"])
        assert result.exit_code == 1
        assert "DCV failed" in _strip_ansi(result.output)

    @patch("dns_aid.cli.main.run_async")
    def test_verify_success_json(self, mock_run_async):
        mock_run_async.return_value = _dcv_verify_result(verified=True)
        result = runner.invoke(app, ["dcv", "verify", "example.com", "sometoken", "--json"])
        assert result.exit_code == 0
        assert '"verified"' in result.output

    @patch("dns_aid.cli.main.run_async")
    def test_verify_failure_json_exits_1(self, mock_run_async):
        mock_run_async.return_value = _dcv_verify_result(verified=False)
        result = runner.invoke(app, ["dcv", "verify", "example.com", "sometoken", "--json"])
        assert result.exit_code == 1


class TestDcvRevoke:
    @patch("dns_aid.cli.main.run_async")
    def test_revoke_success_human(self, mock_run_async):
        from dns_aid.core.dcv import DCVRevokeResult

        mock_run_async.return_value = DCVRevokeResult(
            removed=True, domain="example.com", fqdn="_dnsaid-challenge.example.com"
        )
        result = runner.invoke(app, ["dcv", "revoke", "example.com", "sometoken"])
        assert result.exit_code == 0
        assert "Challenge record removed" in _strip_ansi(result.output)

    @patch("dns_aid.cli.main.run_async")
    def test_revoke_success_json(self, mock_run_async):
        from dns_aid.core.dcv import DCVRevokeResult

        mock_run_async.return_value = DCVRevokeResult(
            removed=True, domain="example.com", fqdn="_dnsaid-challenge.example.com"
        )
        result = runner.invoke(app, ["dcv", "revoke", "example.com", "sometoken", "--json"])
        assert result.exit_code == 0
        assert '"success"' in result.output

    @patch("dns_aid.cli.main.run_async")
    def test_revoke_not_found_exits_1(self, mock_run_async):
        from dns_aid.core.dcv import DCVRevokeResult

        mock_run_async.return_value = DCVRevokeResult(
            removed=False, domain="example.com", fqdn="_dnsaid-challenge.example.com"
        )
        result = runner.invoke(app, ["dcv", "revoke", "example.com", "sometoken"])
        assert result.exit_code == 1
        assert "not found" in _combined_output(result)

    @patch("dns_aid.cli.main.run_async")
    def test_revoke_backend_error_exits_1(self, mock_run_async):
        mock_run_async.side_effect = RuntimeError("dns down")
        result = runner.invoke(app, ["dcv", "revoke", "example.com", "sometoken"])
        assert result.exit_code == 1
        assert "dns down" in _combined_output(result)

    @patch("dns_aid.cli.main.run_async")
    def test_revoke_backend_error_json(self, mock_run_async):
        mock_run_async.side_effect = RuntimeError("dns down")
        result = runner.invoke(app, ["dcv", "revoke", "example.com", "sometoken", "--json"])
        assert result.exit_code == 1
        assert '"success"' in result.output
