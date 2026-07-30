# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for the MCP server tool handlers in dns_aid.mcp.server.

Calls the tool functions directly (no transport) with the mock DNS backend
and mocked core-layer calls. Focuses on:
- returned payload structure for success paths
- error handling (validation errors, backend failures, missing records)
- helper functions (_run_async, _get_dns_backend, _dcv_safe_error)
- main() argument parsing / transport selection with mocked servers
"""

from __future__ import annotations

import asyncio
import json
import sys
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dns_aid.backends.mock import MockBackend
from dns_aid.core.dcv import DCVPlaceResult, DCVRevokeResult, DCVVerifyResult
from dns_aid.core.indexer import IndexEntry, IndexResult
from dns_aid.core.invoke import InvokeResult
from dns_aid.mcp import server
from dns_aid.sdk.policy.models import PolicyResult, PolicyViolation
from dns_aid.utils.validation import ValidationError

POLICY_JSON = json.dumps(
    {
        "agent": "_test._mcp._agents.example.com",
        "rules": {"blocked_caller_domains": ["evil.example.com"]},
    }
)


def _mock_backend(backend: MockBackend | None = None):
    """Patch the server's backend factory to return a shared MockBackend."""
    return patch.object(server, "_get_dns_backend", return_value=backend or MockBackend())


# =============================================================================
# Helpers: _run_async / executor lifecycle
# =============================================================================


class TestRunAsync:
    def test_sync_context_uses_asyncio_run(self):
        async def coro():
            return "sync-ok"

        assert server._run_async(coro()) == "sync-ok"

    async def test_async_context_uses_thread_pool(self):
        async def coro():
            return "threaded-ok"

        # Called from a running event loop -> shared executor path.
        assert server._run_async(coro()) == "threaded-ok"

    async def test_timeout_raises_timeout_error(self):
        with pytest.raises(TimeoutError, match="did not complete"):
            server._run_async(asyncio.sleep(1), timeout=0.05)

    def test_executor_shutdown_and_cleanup(self):
        assert server._get_executor() is not None
        server._shutdown_executor()
        assert server._executor is None
        # _cleanup is idempotent and clears a live executor too.
        server._get_executor()
        server._cleanup()
        assert server._executor is None


# =============================================================================
# _get_dns_backend resolution
# =============================================================================


class TestGetDnsBackend:
    def test_env_var_selects_backend(self, monkeypatch):
        monkeypatch.setenv("DNS_AID_BACKEND", "mock")
        assert isinstance(server._get_dns_backend(None), MockBackend)

    def test_detect_returns_none_falls_back_to_mock(self, monkeypatch):
        monkeypatch.delenv("DNS_AID_BACKEND", raising=False)
        with patch("dns_aid.cli.backends.detect_backend", return_value=None):
            assert isinstance(server._get_dns_backend(None), MockBackend)

    def test_detect_value_error_falls_back_to_mock(self, monkeypatch):
        monkeypatch.delenv("DNS_AID_BACKEND", raising=False)
        with patch("dns_aid.cli.backends.detect_backend", side_effect=ValueError("ambiguous")):
            assert isinstance(server._get_dns_backend(None), MockBackend)

    def test_unknown_name_falls_back_to_mock(self):
        assert isinstance(server._get_dns_backend("bogus-backend"), MockBackend)

    def test_import_error_raises_value_error_with_install_hint(self):
        with patch("dns_aid.backends.create_backend", side_effect=ImportError("no boto3")):
            with pytest.raises(ValueError, match="Missing dependency"):
                server._get_dns_backend("route53")

    def test_init_value_error_raises_with_setup_hint(self):
        with patch("dns_aid.backends.create_backend", side_effect=ValueError("no creds")):
            with pytest.raises(ValueError, match="Failed to initialize"):
                server._get_dns_backend("route53")

    def test_init_os_error_raises_with_setup_hint(self):
        with patch("dns_aid.backends.create_backend", side_effect=OSError("network down")):
            with pytest.raises(ValueError, match="Failed to initialize"):
                server._get_dns_backend("route53")


# =============================================================================
# publish_agent_to_dns error / index paths
# =============================================================================


class TestPublishAgentErrors:
    def test_invalid_name_returns_validation_error(self):
        result = server.publish_agent_to_dns(name="Bad_Name!", domain="example.com", backend="mock")
        assert result["success"] is False
        assert result["error"] == "validation_error"
        assert result["field"] == "name"
        assert "message" in result

    def test_publish_exception_returns_publish_error(self):
        with patch(
            "dns_aid.core.publisher.publish", new=AsyncMock(side_effect=RuntimeError("boom"))
        ):
            result = server.publish_agent_to_dns(name="chat", domain="example.com", backend="mock")
        assert result == {"success": False, "error": "publish_error", "message": "boom"}

    def test_index_update_disabled(self):
        result = server.publish_agent_to_dns(
            name="chat", domain="example.com", backend="mock", update_index=False
        )
        assert result["success"] is True
        assert result["index_updated"] is False
        assert result["index_message"] is None

    def test_index_update_reports_failure_message(self):
        failed = IndexResult(
            domain="example.com", entries=[], success=False, message="index write failed"
        )
        with patch("dns_aid.core.indexer.update_index", new=AsyncMock(return_value=failed)):
            result = server.publish_agent_to_dns(name="chat", domain="example.com", backend="mock")
        assert result["success"] is True
        assert result["index_updated"] is False
        assert result["index_message"] == "index write failed"

    def test_index_update_exception_is_captured(self):
        with patch(
            "dns_aid.core.indexer.update_index", new=AsyncMock(side_effect=RuntimeError("kaboom"))
        ):
            result = server.publish_agent_to_dns(name="chat", domain="example.com", backend="mock")
        assert result["success"] is True
        assert result["index_updated"] is False
        assert result["index_message"] == "Index update failed: kaboom"


# =============================================================================
# Catalog pointer tools
# =============================================================================


class TestPublishCatalogPointer:
    def test_success_dual_labels(self):
        written = ["SVCB _catalog._agents.example.com", "SVCB _index._agents.example.com"]
        mock_pub = AsyncMock(return_value=written)
        with (
            _mock_backend(),
            patch("dns_aid.core.catalog_pointer.publish_catalog_pointer", new=mock_pub),
        ):
            result = server.publish_catalog_pointer(
                domain="example.com", catalog_host="catalog.example.com", backend="mock"
            )
        assert result["success"] is True
        assert result["records"] == written
        assert result["catalog_url"] == ("https://catalog.example.com/.well-known/ai-catalog.json")
        assert mock_pub.await_args.kwargs["labels"] == ("_catalog._agents", "_index._agents")

    def test_catalog_only_restricts_labels(self):
        mock_pub = AsyncMock(return_value=["SVCB _catalog._agents.example.com"])
        with (
            _mock_backend(),
            patch("dns_aid.core.catalog_pointer.publish_catalog_pointer", new=mock_pub),
        ):
            result = server.publish_catalog_pointer(
                domain="example.com",
                catalog_host="catalog.example.com",
                catalog_only=True,
                backend="mock",
            )
        assert result["success"] is True
        assert mock_pub.await_args.kwargs["labels"] == ("_catalog._agents",)

    def test_failure_returns_error_envelope(self):
        with (
            _mock_backend(),
            patch(
                "dns_aid.core.catalog_pointer.publish_catalog_pointer",
                new=AsyncMock(side_effect=ValueError("underscored target")),
            ),
        ):
            result = server.publish_catalog_pointer(
                domain="example.com", catalog_host="_bad.example.com", backend="mock"
            )
        assert result["success"] is False
        assert result["error"] == "publish_catalog_error"
        assert "underscored target" in result["message"]


class TestUnpublishCatalogPointer:
    def test_success(self):
        removed = ["_catalog._agents.example.com", "_index._agents.example.com"]
        mock_unpub = AsyncMock(return_value=removed)
        with (
            _mock_backend(),
            patch("dns_aid.core.catalog_pointer.unpublish_catalog_pointer", new=mock_unpub),
        ):
            result = server.unpublish_catalog_pointer(domain="example.com", backend="mock")
        assert result == {"success": True, "domain": "example.com", "removed": removed}
        assert mock_unpub.await_args.kwargs["labels"] == ("_catalog._agents", "_index._agents")

    def test_catalog_only_restricts_labels(self):
        mock_unpub = AsyncMock(return_value=[])
        with (
            _mock_backend(),
            patch("dns_aid.core.catalog_pointer.unpublish_catalog_pointer", new=mock_unpub),
        ):
            result = server.unpublish_catalog_pointer(
                domain="example.com", catalog_only=True, backend="mock"
            )
        assert result["success"] is True
        assert mock_unpub.await_args.kwargs["labels"] == ("_catalog._agents",)

    def test_failure_returns_error_envelope(self):
        with (
            _mock_backend(),
            patch(
                "dns_aid.core.catalog_pointer.unpublish_catalog_pointer",
                new=AsyncMock(side_effect=RuntimeError("backend down")),
            ),
        ):
            result = server.unpublish_catalog_pointer(domain="example.com", backend="mock")
        assert result["success"] is False
        assert result["error"] == "unpublish_catalog_error"


# =============================================================================
# discover_agents_via_dns / search_agents error paths
# =============================================================================


class TestDiscoverErrors:
    def test_invalid_domain_returns_validation_error(self):
        result = server.discover_agents_via_dns(domain="exa mple!.com")
        assert result["success"] is False
        assert result["error"] == "validation_error"
        assert result["field"] == "domain"

    def test_discover_exception_returns_error_envelope(self):
        with patch(
            "dns_aid.core.discoverer.discover",
            new=AsyncMock(side_effect=RuntimeError("resolver down")),
        ):
            result = server.discover_agents_via_dns(domain="example.com")
        assert result == {
            "success": False,
            "error": "discover_error",
            "message": "resolver down",
        }

    def test_name_filter_is_validated_and_propagated(self):
        from dns_aid.core.models import DiscoveryResult

        empty = DiscoveryResult(
            query="_index._agents.example.com",
            domain="example.com",
            agents=[],
            dnssec_validated=False,
            cached=False,
            query_time_ms=1.0,
        )
        mock_discover = AsyncMock(return_value=empty)
        with patch("dns_aid.core.discoverer.discover", new=mock_discover):
            result = server.discover_agents_via_dns(domain="example.com", name="chat")
        assert result["count"] == 0
        assert mock_discover.await_args.kwargs["name"] == "chat"


class TestSearchAgentsValidationError:
    def test_validation_error_returns_invalid_arguments(self):
        with patch(
            "dns_aid.sdk.client.AgentClient.search",
            new_callable=AsyncMock,
            side_effect=ValidationError("limit", "must be between 1 and 10000", "0"),
        ):
            result = server.search_agents(q="x", limit=0)
        assert result["success"] is False
        assert result["error"] == "invalid_arguments"
        assert result["validation_errors"]["field"] == "limit"


# =============================================================================
# call_agent_tool
# =============================================================================

ALLOWED = PolicyResult(allowed=True)
DENIED = PolicyResult(
    allowed=False,
    violations=[PolicyViolation(rule="required_auth_types", detail="oauth2 required", layer="l1")],
)


class TestCallAgentTool:
    def test_success_with_policy_and_telemetry(self):
        invoke_result = InvokeResult(success=True, data={"answer": 42}, telemetry={"ms": 5})
        with (
            patch(
                "dns_aid.sdk.policy.guard.check_target_policy",
                new=AsyncMock(return_value=ALLOWED),
            ),
            patch("dns_aid.core.invoke.call_mcp_tool", new=AsyncMock(return_value=invoke_result)),
        ):
            result = server.call_agent_tool(
                endpoint="https://agent.example.com/mcp",
                tool_name="echo",
                arguments={"text": "hi"},
                policy_uri="https://example.com/policy.json",
            )
        assert result["success"] is True
        assert result["result"] == {"answer": 42}
        assert result["telemetry"] == {"ms": 5}
        assert result["policy"] == {"result": "allowed"}

    def test_invocation_failure_surfaces_error(self):
        invoke_result = InvokeResult(success=False, error="tool exploded")
        with patch("dns_aid.core.invoke.call_mcp_tool", new=AsyncMock(return_value=invoke_result)):
            result = server.call_agent_tool(endpoint="https://a.example.com", tool_name="echo")
        assert result["success"] is False
        assert result["error"] == "tool exploded"

    def test_invocation_failure_without_message_uses_default(self):
        invoke_result = InvokeResult(success=False, error=None)
        with patch("dns_aid.core.invoke.call_mcp_tool", new=AsyncMock(return_value=invoke_result)):
            result = server.call_agent_tool(endpoint="https://a.example.com", tool_name="echo")
        assert result["error"] == "Invocation failed"

    def test_policy_denied_strict_blocks_invocation(self, monkeypatch):
        monkeypatch.setenv("DNS_AID_POLICY_MODE", "strict")
        mock_call = AsyncMock()
        with (
            patch(
                "dns_aid.sdk.policy.guard.check_target_policy",
                new=AsyncMock(return_value=DENIED),
            ),
            patch("dns_aid.core.invoke.call_mcp_tool", new=mock_call),
        ):
            result = server.call_agent_tool(
                endpoint="https://a.example.com",
                tool_name="echo",
                policy_uri="https://example.com/policy.json",
            )
        assert result["success"] is False
        assert "Policy denied" in result["error"]
        assert result["policy"]["result"] == "denied"
        assert result["policy"]["violations"][0]["rule"] == "required_auth_types"
        mock_call.assert_not_awaited()

    def test_policy_denied_permissive_proceeds(self, monkeypatch):
        monkeypatch.delenv("DNS_AID_POLICY_MODE", raising=False)
        invoke_result = InvokeResult(success=True, data="ok")
        with (
            patch(
                "dns_aid.sdk.policy.guard.check_target_policy",
                new=AsyncMock(return_value=DENIED),
            ),
            patch("dns_aid.core.invoke.call_mcp_tool", new=AsyncMock(return_value=invoke_result)),
        ):
            result = server.call_agent_tool(
                endpoint="https://a.example.com",
                tool_name="echo",
                policy_uri="https://example.com/policy.json",
            )
        assert result["success"] is True
        assert result["policy"] == {"result": "denied"}

    def test_exception_returns_error(self):
        with patch(
            "dns_aid.core.invoke.call_mcp_tool",
            new=AsyncMock(side_effect=RuntimeError("connect refused")),
        ):
            result = server.call_agent_tool(endpoint="https://a.example.com", tool_name="echo")
        assert result == {"success": False, "error": "connect refused"}


# =============================================================================
# list_agent_tools
# =============================================================================


class TestListAgentTools:
    def test_success_returns_tools_and_telemetry(self):
        invoke_result = InvokeResult(
            success=True, data=[{"name": "echo"}, {"name": "sum"}], telemetry={"ms": 3}
        )
        with patch("dns_aid.core.invoke.list_mcp_tools", new=AsyncMock(return_value=invoke_result)):
            result = server.list_agent_tools(endpoint="https://a.example.com/mcp")
        assert result["success"] is True
        assert result["count"] == 2
        assert result["tools"][0]["name"] == "echo"
        assert result["telemetry"] == {"ms": 3}

    def test_non_list_data_yields_empty_tools(self):
        invoke_result = InvokeResult(success=True, data={"unexpected": True})
        with patch("dns_aid.core.invoke.list_mcp_tools", new=AsyncMock(return_value=invoke_result)):
            result = server.list_agent_tools(endpoint="https://a.example.com/mcp")
        assert result["success"] is True
        assert result["tools"] == []
        assert result["count"] == 0

    def test_failure_surfaces_error(self):
        invoke_result = InvokeResult(success=False, error=None)
        with patch("dns_aid.core.invoke.list_mcp_tools", new=AsyncMock(return_value=invoke_result)):
            result = server.list_agent_tools(endpoint="https://a.example.com/mcp")
        assert result["success"] is False
        assert result["error"] == "Invocation failed"

    def test_exception_returns_error(self):
        with patch(
            "dns_aid.core.invoke.list_mcp_tools",
            new=AsyncMock(side_effect=RuntimeError("timeout")),
        ):
            result = server.list_agent_tools(endpoint="https://a.example.com/mcp")
        assert result == {"success": False, "error": "timeout"}


# =============================================================================
# verify_agent_dns error paths
# =============================================================================


class TestVerifyAgentErrors:
    def test_invalid_fqdn_returns_validation_error(self):
        result = server.verify_agent_dns(fqdn="bad..fqdn!")
        assert result["success"] is False
        assert result["error"] == "validation_error"

    def test_verify_exception_returns_error_envelope(self):
        with patch(
            "dns_aid.core.validator.verify",
            new=AsyncMock(side_effect=RuntimeError("resolver exploded")),
        ):
            result = server.verify_agent_dns(fqdn="chat.example.com")
        assert result == {
            "success": False,
            "error": "verify_error",
            "message": "resolver exploded",
        }


# =============================================================================
# list_published_agents
# =============================================================================


class TestListPublishedAgents:
    def test_invalid_domain_returns_validation_error(self):
        result = server.list_published_agents(domain="exa mple!.com", backend="mock")
        assert result["error"] == "validation_error"

    def test_zone_not_found(self):
        backend = MockBackend(zones=["other.com"])
        with _mock_backend(backend):
            result = server.list_published_agents(domain="example.com", backend="mock")
        assert result["success"] is False
        assert result["error"] == "zone_not_found"
        assert "example.com" in result["message"]

    def test_records_formatted_and_long_values_truncated(self):
        backend = MockBackend()
        with _mock_backend(backend):
            publish = server.publish_agent_to_dns(
                name="chat",
                domain="example.com",
                backend="mock",
                capabilities=[f"capability-{i:02d}-padding" for i in range(8)],
                update_index=False,
            )
            assert publish["success"] is True
            result = server.list_published_agents(domain="example.com", backend="mock")
        assert result["domain"] == "example.com"
        assert result["count"] >= 2
        types = {r["type"] for r in result["records"]}
        assert {"SVCB", "TXT"} <= types
        txt = next(r for r in result["records"] if r["type"] == "TXT")
        assert txt["value"].endswith("...")
        assert len(txt["value"]) == 103  # 100 chars + ellipsis

    def test_exception_returns_list_error(self):
        with (
            _mock_backend(),
            patch(
                "dns_aid.core.lister.list_dns_aid_records",
                new=AsyncMock(side_effect=RuntimeError("api down")),
            ),
        ):
            result = server.list_published_agents(domain="example.com", backend="mock")
        assert result == {"success": False, "error": "list_error", "message": "api down"}


# =============================================================================
# delete_agent_from_dns
# =============================================================================


class TestDeleteAgentErrors:
    def test_invalid_name_returns_validation_error(self):
        result = server.delete_agent_from_dns(
            name="Bad_Name!", domain="example.com", backend="mock"
        )
        assert result["error"] == "validation_error"

    def test_delete_updates_index_on_success(self):
        backend = MockBackend()
        with _mock_backend(backend):
            server.publish_agent_to_dns(name="chat", domain="example.com", backend="mock")
            result = server.delete_agent_from_dns(name="chat", domain="example.com", backend="mock")
        assert result["success"] is True
        assert result["fqdn"] == "chat.example.com"
        assert result["index_updated"] is True
        assert "agent(s) remaining" in result["index_message"]

    def test_delete_index_failure_message(self):
        backend = MockBackend()
        failed = IndexResult(domain="example.com", entries=[], success=False, message="no txn")
        with _mock_backend(backend):
            server.publish_agent_to_dns(name="chat", domain="example.com", backend="mock")
            with patch("dns_aid.core.indexer.update_index", new=AsyncMock(return_value=failed)):
                result = server.delete_agent_from_dns(
                    name="chat", domain="example.com", backend="mock"
                )
        assert result["success"] is True
        assert result["index_updated"] is False
        assert result["index_message"] == "no txn"

    def test_delete_index_exception_is_captured(self):
        backend = MockBackend()
        with _mock_backend(backend):
            server.publish_agent_to_dns(name="chat", domain="example.com", backend="mock")
            with patch(
                "dns_aid.core.indexer.update_index",
                new=AsyncMock(side_effect=RuntimeError("kaboom")),
            ):
                result = server.delete_agent_from_dns(
                    name="chat", domain="example.com", backend="mock"
                )
        assert result["index_updated"] is False
        assert result["index_message"] == "Index update failed: kaboom"

    def test_unpublish_exception_returns_delete_error(self):
        with patch(
            "dns_aid.core.publisher.unpublish",
            new=AsyncMock(side_effect=RuntimeError("api down")),
        ):
            result = server.delete_agent_from_dns(name="chat", domain="example.com", backend="mock")
        assert result == {"success": False, "error": "delete_error", "message": "api down"}


# =============================================================================
# list_agent_index / sync_agent_index
# =============================================================================


class TestListAgentIndex:
    def test_invalid_domain_returns_validation_error(self):
        result = server.list_agent_index(domain="exa mple!.com", backend="mock")
        assert result["error"] == "validation_error"

    def test_lists_indexed_agents(self):
        backend = MockBackend()
        with _mock_backend(backend):
            server.publish_agent_to_dns(name="chat", domain="example.com", backend="mock")
            result = server.list_agent_index(domain="example.com", backend="mock")
        assert result["index_exists"] is True
        assert result["count"] == 1
        assert result["agents"][0] == {
            "name": "chat",
            "protocol": "mcp",
            "fqdn": "chat.example.com",
        }

    def test_empty_index(self):
        with _mock_backend():
            result = server.list_agent_index(domain="example.com", backend="mock")
        assert result["index_exists"] is False
        assert result["count"] == 0
        assert result["agents"] == []

    def test_exception_returns_list_index_error(self):
        with (
            _mock_backend(),
            patch(
                "dns_aid.core.indexer.read_index",
                new=AsyncMock(side_effect=RuntimeError("api down")),
            ),
        ):
            result = server.list_agent_index(domain="example.com", backend="mock")
        assert result == {"success": False, "error": "list_index_error", "message": "api down"}


class TestSyncAgentIndex:
    def test_invalid_ttl_returns_validation_error(self):
        result = server.sync_agent_index(domain="example.com", backend="mock", ttl=-1)
        assert result["error"] == "validation_error"

    def test_zone_not_found(self):
        backend = MockBackend(zones=["other.com"])
        with _mock_backend(backend):
            result = server.sync_agent_index(domain="example.com", backend="mock")
        assert result["success"] is False
        assert result["error"] == "zone_not_found"

    def test_sync_success(self):
        synced = IndexResult(
            domain="example.com",
            entries=[IndexEntry(name="chat", protocol="mcp")],
            success=True,
            message="synced 1 agent",
            created=True,
        )
        with (
            _mock_backend(),
            patch("dns_aid.core.indexer.sync_index", new=AsyncMock(return_value=synced)),
        ):
            result = server.sync_agent_index(domain="example.com", backend="mock")
        assert result["success"] is True
        assert result["created"] is True
        assert result["count"] == 1
        assert result["agents"] == [{"name": "chat", "protocol": "mcp"}]
        assert result["message"] == "synced 1 agent"

    def test_exception_returns_sync_index_error(self):
        with (
            _mock_backend(),
            patch(
                "dns_aid.core.indexer.sync_index",
                new=AsyncMock(side_effect=RuntimeError("scan failed")),
            ),
        ):
            result = server.sync_agent_index(domain="example.com", backend="mock")
        assert result == {
            "success": False,
            "error": "sync_index_error",
            "message": "scan failed",
        }


# =============================================================================
# Policy compilation tools
# =============================================================================


class TestCompilePolicyToRpz:
    def test_both_formats(self):
        result = server.compile_policy_to_rpz(POLICY_JSON)
        assert result["success"] is True
        assert "rpz_zone" in result
        assert "bindaid_zone" in result
        assert result["report"]["agent_fqdn"] == "_test._mcp._agents.example.com"
        assert result["report"]["rpz_directives"] == 1

    def test_rpz_only(self):
        result = server.compile_policy_to_rpz(POLICY_JSON, format="rpz")
        assert result["success"] is True
        assert "rpz_zone" in result
        assert "bindaid_zone" not in result

    def test_bindaid_only(self):
        result = server.compile_policy_to_rpz(POLICY_JSON, format="bindaid")
        assert result["success"] is True
        assert "bindaid_zone" in result
        assert "rpz_zone" not in result

    def test_invalid_format(self):
        result = server.compile_policy_to_rpz(POLICY_JSON, format="yaml")
        assert result["success"] is False
        assert "Invalid format" in result["error"]

    def test_invalid_json(self):
        result = server.compile_policy_to_rpz("{not json")
        assert result["success"] is False
        assert "Failed to parse policy document" in result["error"]


class TestPublishRpzZone:
    def test_invalid_backend_returns_validation_error(self):
        result = server.publish_rpz_zone(
            policy_json=POLICY_JSON, backend="bogus", rpz_zone="rpz.example.com"
        )
        assert result["error"] == "validation_error"

    def test_invalid_policy_json(self):
        result = server.publish_rpz_zone(
            policy_json="{not json", backend="mock", rpz_zone="rpz.example.com"
        )
        assert result["success"] is False
        assert "Failed to parse policy" in result["error"]

    def test_unsupported_backend_returns_zone_content(self):
        result = server.publish_rpz_zone(
            policy_json=POLICY_JSON, backend="mock", rpz_zone="rpz.example.com"
        )
        assert result["success"] is True
        assert result["backend"] == "mock"
        assert result["record_count"] == 1
        assert "zone_content" in result
        assert "does not support direct RPZ push" in result["message"]

    def test_nios_push_success(self):
        nios = MagicMock()
        nios.ensure_rpz_zone = AsyncMock()
        nios.create_rpz_cname_record = AsyncMock()
        nios.close = AsyncMock()
        with patch("dns_aid.backends.infoblox.nios.InfobloxNIOSBackend", return_value=nios):
            result = server.publish_rpz_zone(
                policy_json=POLICY_JSON, backend="nios", rpz_zone="rpz.example.com"
            )
        assert result["success"] is True
        assert result["record_count"] == 1
        assert result["errors"] == []
        nios.ensure_rpz_zone.assert_awaited_once_with("rpz.example.com")
        nios.close.assert_awaited_once()

    def test_nios_per_record_errors_reported(self):
        nios = MagicMock()
        nios.ensure_rpz_zone = AsyncMock()
        nios.create_rpz_cname_record = AsyncMock(side_effect=RuntimeError("wapi error"))
        nios.close = AsyncMock()
        with patch("dns_aid.backends.infoblox.nios.InfobloxNIOSBackend", return_value=nios):
            result = server.publish_rpz_zone(
                policy_json=POLICY_JSON, backend="nios", rpz_zone="rpz.example.com"
            )
        assert result["success"] is False
        assert result["record_count"] == 0
        assert "wapi error" in result["errors"][0]

    def test_nios_connection_failure(self):
        nios = MagicMock()
        nios.ensure_rpz_zone = AsyncMock(side_effect=RuntimeError("cannot connect"))
        nios.close = AsyncMock()
        with patch("dns_aid.backends.infoblox.nios.InfobloxNIOSBackend", return_value=nios):
            result = server.publish_rpz_zone(
                policy_json=POLICY_JSON, backend="nios", rpz_zone="rpz.example.com"
            )
        assert result["success"] is False
        assert "NIOS push failed" in result["error"]

    def test_infoblox_push_and_bind(self):
        bx = MagicMock()
        bx.create_or_update_named_list = AsyncMock(return_value={"updated": True})
        bx.bind_named_list_to_policy = AsyncMock(
            return_value={"policy_id": 7, "policy_name": "Default", "action": "bound"}
        )
        bx.close = AsyncMock()
        with patch("dns_aid.backends.infoblox.bloxone.InfobloxBloxOneBackend", return_value=bx):
            result = server.publish_rpz_zone(
                policy_json=POLICY_JSON,
                backend="infoblox",
                rpz_zone="rpz.example.com",
                td_policy_id=7,
            )
        assert result["success"] is True
        assert result["named_list"] == "dns-aid-rpz-rpz-example-com"
        assert result["td_policy"]["policy_id"] == 7
        assert result["td_policy"]["action"] == "action_block"
        assert result["message"].startswith("Updated TD named list")
        bx.close.assert_awaited_once()

    def test_infoblox_failure(self):
        bx = MagicMock()
        bx.create_or_update_named_list = AsyncMock(side_effect=RuntimeError("401"))
        bx.close = AsyncMock()
        with patch("dns_aid.backends.infoblox.bloxone.InfobloxBloxOneBackend", return_value=bx):
            result = server.publish_rpz_zone(
                policy_json=POLICY_JSON, backend="infoblox", rpz_zone="rpz.example.com"
            )
        assert result["success"] is False
        assert "Infoblox push failed" in result["error"]


class TestListRpzRules:
    def test_nios_success(self):
        nios = MagicMock()
        nios.list_rpz_cname_records = AsyncMock(return_value=[{"owner": "evil.example.com"}])
        nios.close = AsyncMock()
        with patch("dns_aid.backends.infoblox.nios.InfobloxNIOSBackend", return_value=nios):
            result = server.list_rpz_rules(rpz_zone="rpz.example.com", backend="nios")
        assert result["success"] is True
        assert result["count"] == 1
        assert result["rules"][0]["owner"] == "evil.example.com"

    def test_nios_failure(self):
        nios = MagicMock()
        nios.list_rpz_cname_records = AsyncMock(side_effect=RuntimeError("wapi down"))
        nios.close = AsyncMock()
        with patch("dns_aid.backends.infoblox.nios.InfobloxNIOSBackend", return_value=nios):
            result = server.list_rpz_rules(rpz_zone="rpz.example.com", backend="nios")
        assert result["success"] is False
        assert "NIOS query failed" in result["error"]

    def test_infoblox_success(self):
        bx = MagicMock()
        bx.list_named_lists = AsyncMock(return_value=[{"name": "dns-aid-rpz-rpz-example-com"}])
        bx.list_security_policies = AsyncMock(return_value=[{"id": 1, "name": "Default"}])
        bx.close = AsyncMock()
        with patch("dns_aid.backends.infoblox.bloxone.InfobloxBloxOneBackend", return_value=bx):
            result = server.list_rpz_rules(rpz_zone="rpz.example.com", backend="infoblox")
        assert result["success"] is True
        assert result["count"] == 1
        assert result["security_policies"][0]["name"] == "Default"

    def test_infoblox_failure(self):
        bx = MagicMock()
        bx.list_named_lists = AsyncMock(side_effect=RuntimeError("403"))
        bx.close = AsyncMock()
        with patch("dns_aid.backends.infoblox.bloxone.InfobloxBloxOneBackend", return_value=bx):
            result = server.list_rpz_rules(rpz_zone="rpz.example.com", backend="infoblox")
        assert result["success"] is False
        assert "Infoblox query failed" in result["error"]

    def test_unsupported_backend(self):
        result = server.list_rpz_rules(rpz_zone="rpz.example.com", backend="mock")
        assert result["success"] is False
        assert "does not support RPZ rule listing" in result["error"]


class TestListTdSecurityPolicies:
    def test_success(self):
        bx = MagicMock()
        bx.list_security_policies = AsyncMock(
            return_value=[{"id": 1, "name": "Default", "is_default": True}]
        )
        bx.close = AsyncMock()
        with patch("dns_aid.backends.infoblox.bloxone.InfobloxBloxOneBackend", return_value=bx):
            result = server.list_td_security_policies()
        assert result["success"] is True
        assert result["count"] == 1
        bx.close.assert_awaited_once()

    def test_failure(self):
        bx = MagicMock()
        bx.list_security_policies = AsyncMock(side_effect=RuntimeError("401"))
        bx.close = AsyncMock()
        with patch("dns_aid.backends.infoblox.bloxone.InfobloxBloxOneBackend", return_value=bx):
            result = server.list_td_security_policies()
        assert result["success"] is False
        assert "Failed to list TD policies" in result["error"]


# =============================================================================
# diagnose_environment
# =============================================================================


class TestDiagnoseEnvironment:
    def test_returns_report_dict(self):
        report = MagicMock()
        report.to_dict.return_value = {"version": "1.0", "pass_count": 3, "fail_count": 0}
        with patch("dns_aid.doctor.run_checks", return_value=report) as run_checks:
            result = server.diagnose_environment(domain="example.com")
        assert result == {"version": "1.0", "pass_count": 3, "fail_count": 0}
        run_checks.assert_called_once_with(domain="example.com")


# =============================================================================
# send_a2a_message
# =============================================================================


class TestSendA2AMessage:
    def test_requires_endpoint_or_domain_and_name(self):
        result = server.send_a2a_message(message="hi")
        assert result["success"] is False
        assert "Provide either" in result["error"]

    def test_success_with_agent_info(self):
        invoke_result = InvokeResult(
            success=True,
            data={
                "response_text": "hello back",
                "agent_info": {
                    "canonical_endpoint": "https://canon.example.com",
                    "name": "sec-agent",
                },
            },
            telemetry={"ms": 12},
        )
        with patch(
            "dns_aid.core.invoke.send_a2a_message", new=AsyncMock(return_value=invoke_result)
        ):
            result = server.send_a2a_message(message="hi", endpoint="https://agent.example.com")
        assert result["success"] is True
        assert result["response"] == "hello back"
        assert result["agent_endpoint"] == "https://canon.example.com"
        assert result["agent_info"]["name"] == "sec-agent"
        assert result["telemetry"] == {"ms": 12}

    def test_success_without_canonical_endpoint_keeps_original(self):
        invoke_result = InvokeResult(
            success=True,
            data={"response_text": "ok", "agent_info": {"resolved_via": "dns"}},
        )
        with patch(
            "dns_aid.core.invoke.send_a2a_message", new=AsyncMock(return_value=invoke_result)
        ):
            result = server.send_a2a_message(message="hi", endpoint="https://agent.example.com")
        assert result["agent_endpoint"] == "https://agent.example.com"

    def test_success_with_plain_string_data(self):
        invoke_result = InvokeResult(success=True, data="plain response")
        with patch(
            "dns_aid.core.invoke.send_a2a_message", new=AsyncMock(return_value=invoke_result)
        ):
            result = server.send_a2a_message(message="hi", endpoint="https://agent.example.com")
        assert result["response"] == "plain response"

    def test_failure_with_blank_error_uses_default(self):
        invoke_result = InvokeResult(success=False, error="   ")
        with patch(
            "dns_aid.core.invoke.send_a2a_message", new=AsyncMock(return_value=invoke_result)
        ):
            result = server.send_a2a_message(message="hi", endpoint="https://agent.example.com")
        assert result["success"] is False
        assert result["error"] == "Invocation failed"

    def test_policy_denied_strict_blocks_send(self, monkeypatch):
        monkeypatch.setenv("DNS_AID_POLICY_MODE", "strict")
        mock_send = AsyncMock()
        with (
            patch(
                "dns_aid.sdk.policy.guard.check_target_policy",
                new=AsyncMock(return_value=DENIED),
            ),
            patch("dns_aid.core.invoke.send_a2a_message", new=mock_send),
        ):
            result = server.send_a2a_message(
                message="hi",
                domain="example.com",
                name="sec-agent",
                policy_uri="https://example.com/policy.json",
            )
        assert result["success"] is False
        assert "Policy denied" in result["error"]
        assert result["agent_endpoint"] == "sec-agent.example.com"
        assert result["policy"]["result"] == "denied"
        mock_send.assert_not_awaited()

    def test_exception_with_empty_message_uses_default(self):
        with patch(
            "dns_aid.core.invoke.send_a2a_message",
            new=AsyncMock(side_effect=RuntimeError("")),
        ):
            result = server.send_a2a_message(message="hi", endpoint="https://agent.example.com")
        assert result["success"] is False
        assert result["error"] == "Unknown invocation error"


# =============================================================================
# HTTP health endpoints
# =============================================================================


class TestHealthEndpoints:
    async def test_health_check(self):
        response = await server.health_check(MagicMock())
        assert response.status_code == 200
        body = json.loads(response.body)
        assert body["status"] == "healthy"
        assert body["service"] == "dns-aid-mcp"
        assert "publish_agent_to_dns" in body["tools"]
        assert body["uptime_seconds"] >= 0

    async def test_readiness_check(self):
        response = await server.readiness_check(MagicMock())
        assert response.status_code == 200
        body = json.loads(response.body)
        assert body["ready"] is True
        assert body["checks"] == {
            "publisher": "ok",
            "discoverer": "ok",
            "mock_backend": "ok",
        }

    async def test_root_info(self):
        response = await server.root_info(MagicMock())
        assert response.status_code == 200
        body = json.loads(response.body)
        assert body["service"] == "DNS-AID MCP Server"
        assert "/mcp" in body["endpoints"]


# =============================================================================
# DCV tools
# =============================================================================


class TestDcvSafeError:
    def test_validation_error_is_passed_through(self):
        err = ValidationError("domain", "invalid domain", "!!")
        assert "invalid domain" in server._dcv_safe_error(err)

    def test_value_error_is_passed_through(self):
        assert server._dcv_safe_error(ValueError("bad token")) == "bad token"

    def test_unexpected_error_is_masked(self):
        message = server._dcv_safe_error(RuntimeError("secret backend detail"))
        assert "secret backend detail" not in message
        assert "Check server logs" in message


class TestDcvIssueChallenge:
    def test_issue_success_with_binding(self):
        result = server.dcv_issue_challenge(
            domain="example.com", agent_name="chat", issuer_domain="issuer.com"
        )
        assert result["success"] is True
        assert result["fqdn"] == "_agents-challenge.example.com"
        assert result["bnd_req"] == "svc:chat@issuer.com"
        assert "token" in result and "txt_value" in result

    def test_issue_invalid_ttl(self):
        result = server.dcv_issue_challenge(domain="example.com", ttl_seconds=5)
        assert result["success"] is False
        assert "ttl_seconds" in result["error"]


class TestDcvPlaceChallenge:
    def test_place_success(self):
        placed = DCVPlaceResult(
            fqdn="_agents-challenge.example.com",
            domain="example.com",
            expires_at=datetime.now(UTC),
        )
        with patch("dns_aid.core.dcv.place", new=AsyncMock(return_value=placed)):
            result = server.dcv_place_challenge(domain="example.com", token="a" * 32)
        assert result == {"success": True, "fqdn": "_agents-challenge.example.com"}

    def test_place_invalid_token(self):
        with patch(
            "dns_aid.core.dcv.place",
            new=AsyncMock(side_effect=ValueError("token must be a 32-character string")),
        ):
            result = server.dcv_place_challenge(domain="example.com", token="short")
        assert result["success"] is False
        assert "32-character" in result["error"]


class TestDcvVerifyChallenge:
    def test_verify_success_omits_token(self):
        verified = DCVVerifyResult(
            verified=True,
            domain="example.com",
            token="a" * 32,
            fqdn="_agents-challenge.example.com",
        )
        with patch("dns_aid.core.dcv.verify", new=AsyncMock(return_value=verified)):
            result = server.dcv_verify_challenge(domain="example.com", token="a" * 32)
        assert result["success"] is True
        assert result["verified"] is True
        assert "token" not in result

    def test_verify_unexpected_error_is_masked(self):
        with patch(
            "dns_aid.core.dcv.verify", new=AsyncMock(side_effect=RuntimeError("infra detail"))
        ):
            result = server.dcv_verify_challenge(domain="example.com", token="a" * 32)
        assert result["success"] is False
        assert result["verified"] is False
        assert "infra detail" not in result["error"]


class TestDcvRevokeChallenge:
    def test_revoke_success(self):
        revoked = DCVRevokeResult(
            removed=True, domain="example.com", fqdn="_agents-challenge.example.com"
        )
        with patch("dns_aid.core.dcv.revoke", new=AsyncMock(return_value=revoked)):
            result = server.dcv_revoke_challenge(domain="example.com", token="a" * 32)
        assert result == {"success": True}

    def test_revoke_error(self):
        with patch(
            "dns_aid.core.dcv.revoke",
            new=AsyncMock(side_effect=ValueError("token must be placed first")),
        ):
            result = server.dcv_revoke_challenge(domain="example.com", token="a" * 32)
        assert result["success"] is False
        assert "token must be placed first" in result["error"]


# =============================================================================
# main() argument parsing / transport selection
# =============================================================================


class TestMain:
    def test_help_prints_usage_and_returns(self, monkeypatch, capsys):
        monkeypatch.setattr(sys, "argv", ["dns-aid-mcp", "--help"])
        server.main()
        out = capsys.readouterr().out
        assert "Usage: dns-aid-mcp" in out
        assert "--transport" in out

    def test_default_runs_stdio_transport(self, monkeypatch):
        # A stray argument exercises the parser's skip branch too.
        monkeypatch.setattr(sys, "argv", ["dns-aid-mcp", "stray-arg"])
        with patch.object(server.mcp, "run") as mock_run:
            server.main()
        mock_run.assert_called_once_with(transport="stdio")

    def test_http_transport_runs_uvicorn(self, monkeypatch, capsys):
        monkeypatch.setattr(
            sys,
            "argv",
            ["dns-aid-mcp", "--transport", "http", "--port", "9000", "--host", "0.0.0.0"],
        )
        app = MagicMock()
        with (
            patch("uvicorn.run") as mock_uvicorn,
            patch.object(server.mcp, "streamable_http_app", return_value=app),
        ):
            server.main()
        out = capsys.readouterr().out
        assert "WARNING" in out  # 0.0.0.0 bind warning
        assert "http://0.0.0.0:9000" in out
        mock_uvicorn.assert_called_once()
        assert mock_uvicorn.call_args.args[0] is app
        assert mock_uvicorn.call_args.kwargs["host"] == "0.0.0.0"
        assert mock_uvicorn.call_args.kwargs["port"] == 9000
