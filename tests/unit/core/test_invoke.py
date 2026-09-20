# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for dns_aid.core.invoke — shared invocation functions."""

from __future__ import annotations

import importlib
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from dns_aid.core.invoke import (
    InvokeResult,
    ResolvedAgent,
    _build_agent_record_from_endpoint,
    _invoke_raw_a2a,
    _invoke_via_sdk,
    build_a2a_message_params,
    call_mcp_tool,
    extract_a2a_response_text,
    extract_mcp_content,
    list_mcp_tools,
    normalize_endpoint,
    resolve_a2a_endpoint,
    resolve_mcp_endpoint,
    send_a2a_message,
)


def _mock_async_client(mock_client_cls, *, post=None, get=None):
    """Wire a mocked httpx.AsyncClient context manager."""
    mock_client = AsyncMock()
    if post is not None:
        if isinstance(post, Exception):
            mock_client.post.side_effect = post
        else:
            mock_client.post.return_value = post
    if get is not None:
        if isinstance(get, Exception):
            mock_client.get.side_effect = get
        else:
            mock_client.get.return_value = get
    mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
    return mock_client


def _sdk_result(*, success=True, data=None, latency=10.0, status="success"):
    """Duck-typed SDK InvocationResult."""
    return SimpleNamespace(
        success=success,
        data=data,
        signal=SimpleNamespace(
            invocation_latency_ms=latency,
            status=SimpleNamespace(value=status),
        ),
    )


def _mock_agent_client(mock_client_cls, *, invoke_return=None, invoke_side_effect=None):
    """Wire a mocked AgentClient async context manager."""
    mock_client = AsyncMock()
    if invoke_side_effect is not None:
        mock_client.invoke.side_effect = invoke_side_effect
    else:
        mock_client.invoke.return_value = invoke_return
    mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
    return mock_client


def _card(url, name="Chat Agent", description="A chat agent", skill_names=("chatting",)):
    """Duck-typed A2A agent card."""
    return SimpleNamespace(
        url=url,
        name=name,
        description=description,
        skills=[SimpleNamespace(name=s) for s in skill_names],
    )


# ---------------------------------------------------------------------------
# Pure utility tests
# ---------------------------------------------------------------------------


class TestNormalizeEndpoint:
    def test_adds_https(self):
        assert normalize_endpoint("example.com") == "https://example.com"

    def test_strips_trailing_slash(self):
        assert normalize_endpoint("https://example.com/") == "https://example.com"

    def test_preserves_http(self):
        assert normalize_endpoint("http://localhost:8080") == "http://localhost:8080"

    def test_preserves_path(self):
        assert normalize_endpoint("https://example.com/mcp") == "https://example.com/mcp"


class TestBuildA2AMessageParams:
    def test_structure(self):
        params = build_a2a_message_params("Hello")
        assert "message" in params
        msg = params["message"]
        assert msg["role"] == "user"
        assert msg["parts"] == [{"kind": "text", "text": "Hello"}]
        assert "messageId" in msg  # UUID generated

    def test_unique_message_ids(self):
        p1 = build_a2a_message_params("a")
        p2 = build_a2a_message_params("b")
        assert p1["message"]["messageId"] != p2["message"]["messageId"]


class TestExtractA2AResponseText:
    def test_artifacts_parts(self):
        data = {
            "result": {
                "artifacts": [
                    {
                        "parts": [
                            {"kind": "text", "text": "Hello"},
                            {"kind": "text", "text": "World"},
                        ]
                    }
                ]
            }
        }
        assert extract_a2a_response_text(data) == "Hello\nWorld"

    def test_direct_parts(self):
        data = {"result": {"parts": [{"kind": "text", "text": "Direct"}]}}
        assert extract_a2a_response_text(data) == "Direct"

    def test_content_array(self):
        data = {"result": {"content": [{"text": "Content"}]}}
        assert extract_a2a_response_text(data) == "Content"

    def test_content_string(self):
        data = {"result": {"content": ["Plain string"]}}
        assert extract_a2a_response_text(data) == "Plain string"

    def test_empty_result(self):
        assert extract_a2a_response_text({}) is None
        assert extract_a2a_response_text({"result": {}}) is None


class TestExtractMCPContent:
    def test_content_array_json(self):
        result = {"result": {"content": [{"text": '{"key": "value"}'}]}}
        assert extract_mcp_content(result) == {"key": "value"}

    def test_content_array_plain_text(self):
        result = {"result": {"content": [{"text": "just text"}]}}
        assert extract_mcp_content(result) == "just text"

    def test_passthrough(self):
        result = {"result": {"tools": [{"name": "t1"}]}}
        assert extract_mcp_content(result) == {"tools": [{"name": "t1"}]}

    def test_none_result(self):
        assert extract_mcp_content({}) is None
        assert extract_mcp_content({"result": None}) is None


class TestBuildAgentRecord:
    def test_simple_url(self):
        agent = _build_agent_record_from_endpoint("https://booking.example.com:443")
        assert agent.target_host == "booking.example.com"
        assert agent.port == 443
        assert agent.domain == "example.com"

    def test_url_with_path(self):
        agent = _build_agent_record_from_endpoint("https://mcp.example.com/mcp")
        assert agent.endpoint_override == "https://mcp.example.com/mcp"

    def test_protocol_mapping(self):
        from dns_aid.core.models import Protocol

        mcp = _build_agent_record_from_endpoint("https://h.com", protocol="mcp")
        assert mcp.protocol == Protocol.MCP
        a2a = _build_agent_record_from_endpoint("https://h.com", protocol="a2a")
        assert a2a.protocol == Protocol.A2A


# ---------------------------------------------------------------------------
# Raw invocation tests (mocked httpx)
# ---------------------------------------------------------------------------


class TestInvokeRawA2A:
    @pytest.mark.asyncio
    async def test_success(self):
        mock_response = httpx.Response(
            200,
            json={"result": {"artifacts": [{"parts": [{"kind": "text", "text": "Hi"}]}]}},
            request=httpx.Request("POST", "https://agent.example.com"),
        )

        with patch("dns_aid.core.invoke.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await _invoke_raw_a2a("https://agent.example.com", "Hello", 25.0)

        assert result.success is True
        assert isinstance(result.data, dict)

    @pytest.mark.asyncio
    async def test_timeout(self):
        with patch("dns_aid.core.invoke.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post.side_effect = httpx.TimeoutException("timed out")
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await _invoke_raw_a2a("https://agent.example.com", "Hello", 5.0)

        assert result.success is False
        assert "5" in result.error

    @pytest.mark.asyncio
    async def test_http_403(self):
        mock_response = httpx.Response(
            403,
            text="Forbidden",
            request=httpx.Request("POST", "https://agent.example.com"),
        )

        with patch("dns_aid.core.invoke.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await _invoke_raw_a2a("https://agent.example.com", "Hello", 25.0)

        assert result.success is False
        assert "403" in result.error


# NOTE: TestInvokeRawMCP and TestCallMCPToolNoSDK / TestListMCPToolsNoSDK were
# removed when MCP transport was unified onto the modern Streamable HTTP path
# (feature 001-mcp-streamable-http). The legacy `_invoke_raw_mcp` helper has
# been deleted; the _sdk_available toggle no longer gates MCP. Modern transport
# behavior is covered by tests/unit/sdk/protocols/test_mcp_streamable.py and
# legacy fallback by tests/unit/sdk/test_mcp_handler.py.


# ---------------------------------------------------------------------------
# Public API tests (A2A no-SDK path retained — A2A is out of scope for the
# transport unification; its raw helper still exists.)
# ---------------------------------------------------------------------------


class TestSendA2AMessageNoSDK:
    @pytest.mark.asyncio
    async def test_extracts_response_text(self):
        mock_response = httpx.Response(
            200,
            json={
                "result": {"artifacts": [{"parts": [{"kind": "text", "text": "I am an agent"}]}]}
            },
            request=httpx.Request("POST", "https://a.example.com"),
        )

        with (
            patch("dns_aid.core.invoke._sdk_available", False),
            patch("dns_aid.core.invoke.httpx.AsyncClient") as MockClient,
        ):
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await send_a2a_message("https://a.example.com", "Hello")

        assert result.success is True
        assert result.data["response_text"] == "I am an agent"


# NOTE: TestCallMCPToolNoSDK / TestListMCPToolsNoSDK removed alongside the
# deletion of `_invoke_raw_mcp` and the `_sdk_available` toggle gating MCP.
# Coverage of the modern path lives in tests/unit/sdk/protocols/test_mcp_streamable.py
# and the legacy fallback in tests/unit/sdk/test_mcp_handler.py.


class TestInvokeResult:
    def test_defaults(self):
        r = InvokeResult(success=True)
        assert r.data is None
        assert r.error is None
        assert r.telemetry is None

    def test_with_telemetry(self):
        r = InvokeResult(
            success=True,
            data={"key": "val"},
            telemetry={"latency_ms": 42.0, "status": "success"},
        )
        assert r.telemetry["latency_ms"] == 42.0


# ---------------------------------------------------------------------------
# extract_a2a_response_text — malformed / partial payload branches
# ---------------------------------------------------------------------------


class TestExtractA2AResponseTextEdgeCases:
    def test_non_dict_artifact_falls_through_to_parts(self):
        data = {
            "result": {
                "artifacts": ["not-a-dict"],
                "parts": [{"kind": "text", "text": "from parts"}],
            }
        }
        assert extract_a2a_response_text(data) == "from parts"

    def test_non_dict_part_in_artifact_skipped(self):
        data = {"result": {"artifacts": [{"parts": ["not-a-dict"]}]}}
        assert extract_a2a_response_text(data) is None

    def test_artifact_part_without_text_skipped(self):
        data = {"result": {"artifacts": [{"parts": [{"kind": "data", "data": {}}]}]}}
        assert extract_a2a_response_text(data) is None

    def test_non_dict_entry_in_parts_skipped(self):
        data = {"result": {"parts": [42, {"kind": "text", "text": "ok"}]}}
        assert extract_a2a_response_text(data) == "ok"

    def test_parts_without_text_fall_through_to_content(self):
        data = {
            "result": {
                "parts": [{"kind": "data"}],
                "content": [{"text": "from content"}],
            }
        }
        assert extract_a2a_response_text(data) == "from content"

    def test_content_with_unusable_items_returns_none(self):
        data = {"result": {"content": [42, {"kind": "image"}]}}
        assert extract_a2a_response_text(data) is None

    def test_none_text_values_coerced_to_empty(self):
        data = {"result": {"artifacts": [{"parts": [{"kind": "text", "text": None}]}]}}
        assert extract_a2a_response_text(data) == ""


# ---------------------------------------------------------------------------
# resolve_mcp_endpoint — path discovery via /.well-known/agent.json
# ---------------------------------------------------------------------------


class TestResolveMCPEndpoint:
    @pytest.mark.asyncio
    async def test_endpoint_with_path_returned_as_is(self):
        with patch("dns_aid.core.invoke.httpx.AsyncClient") as MockClient:
            result = await resolve_mcp_endpoint("https://x.example.com/api/mcp")
        assert result == "https://x.example.com/api/mcp"
        MockClient.assert_not_called()

    @pytest.mark.asyncio
    async def test_agent_json_absolute_path(self):
        resp = httpx.Response(
            200,
            json={"endpoints": {"mcp": "/rpc"}},
            request=httpx.Request("GET", "https://x.example.com/.well-known/agent.json"),
        )
        with patch("dns_aid.core.invoke.httpx.AsyncClient") as MockClient:
            _mock_async_client(MockClient, get=resp)
            result = await resolve_mcp_endpoint("x.example.com")
        assert result == "https://x.example.com/rpc"

    @pytest.mark.asyncio
    async def test_agent_json_relative_path(self):
        resp = httpx.Response(
            200,
            json={"endpoints": {"mcp": "rpc"}},
            request=httpx.Request("GET", "https://x.example.com/.well-known/agent.json"),
        )
        with patch("dns_aid.core.invoke.httpx.AsyncClient") as MockClient:
            _mock_async_client(MockClient, get=resp)
            result = await resolve_mcp_endpoint("https://x.example.com")
        assert result == "https://x.example.com/rpc"

    @pytest.mark.asyncio
    async def test_agent_json_endpoints_not_dict_falls_back(self):
        resp = httpx.Response(
            200,
            json={"endpoints": ["not-a-dict"]},
            request=httpx.Request("GET", "https://x.example.com/.well-known/agent.json"),
        )
        with patch("dns_aid.core.invoke.httpx.AsyncClient") as MockClient:
            _mock_async_client(MockClient, get=resp)
            result = await resolve_mcp_endpoint("https://x.example.com")
        assert result == "https://x.example.com/mcp"

    @pytest.mark.asyncio
    async def test_agent_json_mcp_path_not_string_falls_back(self):
        resp = httpx.Response(
            200,
            json={"endpoints": {"mcp": 42}},
            request=httpx.Request("GET", "https://x.example.com/.well-known/agent.json"),
        )
        with patch("dns_aid.core.invoke.httpx.AsyncClient") as MockClient:
            _mock_async_client(MockClient, get=resp)
            result = await resolve_mcp_endpoint("https://x.example.com")
        assert result == "https://x.example.com/mcp"

    @pytest.mark.asyncio
    async def test_agent_json_non_200_falls_back(self):
        resp = httpx.Response(
            404,
            text="not found",
            request=httpx.Request("GET", "https://x.example.com/.well-known/agent.json"),
        )
        with patch("dns_aid.core.invoke.httpx.AsyncClient") as MockClient:
            _mock_async_client(MockClient, get=resp)
            result = await resolve_mcp_endpoint("https://x.example.com")
        assert result == "https://x.example.com/mcp"

    @pytest.mark.asyncio
    async def test_agent_json_fetch_error_falls_back(self):
        with patch("dns_aid.core.invoke.httpx.AsyncClient") as MockClient:
            _mock_async_client(MockClient, get=httpx.ConnectError("refused"))
            result = await resolve_mcp_endpoint("https://x.example.com")
        assert result == "https://x.example.com/mcp"


# ---------------------------------------------------------------------------
# _invoke_via_sdk — SDK path with mocked AgentClient
# ---------------------------------------------------------------------------


class TestInvokeViaSDK:
    @pytest.mark.asyncio
    async def test_success_with_agent_record(self):
        agent = _build_agent_record_from_endpoint("https://mcp.example.com/mcp")
        sdk_result = _sdk_result(data={"answer": 42})

        with patch("dns_aid.core.invoke.AgentClient") as MockClient:
            mock_client = _mock_agent_client(MockClient, invoke_return=sdk_result)
            result = await _invoke_via_sdk(
                "https://mcp.example.com/mcp",
                protocol="mcp",
                method="tools/call",
                arguments={"name": "t", "arguments": {}},
                timeout=30.0,
                caller_id="test",
                agent_record=agent,
            )

        assert result.success is True
        assert result.data == {"answer": 42}
        assert result.telemetry == {"latency_ms": 10.0, "status": "success"}
        # The discovery-provided record must be used verbatim
        assert mock_client.invoke.call_args[0][0] is agent

    @pytest.mark.asyncio
    async def test_success_builds_synthetic_record(self):
        sdk_result = _sdk_result(data={"ok": True})

        with patch("dns_aid.core.invoke.AgentClient") as MockClient:
            mock_client = _mock_agent_client(MockClient, invoke_return=sdk_result)
            result = await _invoke_via_sdk(
                "https://mcp.example.com/mcp",
                protocol="mcp",
                method="tools/call",
                arguments=None,
                timeout=30.0,
                caller_id="test",
                auth_type="bearer",
                auth_config={"header": "Authorization"},
                policy_uri="https://example.com/policy.json",
            )

        assert result.success is True
        synthetic = mock_client.invoke.call_args[0][0]
        assert synthetic.target_host == "mcp.example.com"
        assert synthetic.auth_type == "bearer"
        assert synthetic.auth_config == {"header": "Authorization"}
        assert synthetic.policy_uri == "https://example.com/policy.json"

    @pytest.mark.asyncio
    async def test_failure_uses_data_as_error(self):
        sdk_result = _sdk_result(success=False, data="boom", status="error")

        with patch("dns_aid.core.invoke.AgentClient") as MockClient:
            _mock_agent_client(MockClient, invoke_return=sdk_result)
            result = await _invoke_via_sdk(
                "https://mcp.example.com/mcp",
                protocol="mcp",
                method="tools/call",
                arguments=None,
                timeout=30.0,
                caller_id="test",
            )

        assert result.success is False
        assert result.error == "boom"
        assert result.telemetry == {"latency_ms": 10.0, "status": "error"}

    @pytest.mark.asyncio
    async def test_failure_with_empty_data_uses_status(self):
        sdk_result = _sdk_result(success=False, data=None, status="timeout")

        with patch("dns_aid.core.invoke.AgentClient") as MockClient:
            _mock_agent_client(MockClient, invoke_return=sdk_result)
            result = await _invoke_via_sdk(
                "https://mcp.example.com/mcp",
                protocol="mcp",
                method="tools/call",
                arguments=None,
                timeout=30.0,
                caller_id="test",
            )

        assert result.success is False
        assert result.error == "Invocation failed (status: timeout)"

    @pytest.mark.asyncio
    async def test_failure_with_placeholder_data_uses_status(self):
        sdk_result = _sdk_result(success=False, data="False", status="refused")

        with patch("dns_aid.core.invoke.AgentClient") as MockClient:
            _mock_agent_client(MockClient, invoke_return=sdk_result)
            result = await _invoke_via_sdk(
                "https://mcp.example.com/mcp",
                protocol="mcp",
                method="tools/call",
                arguments=None,
                timeout=30.0,
                caller_id="test",
            )

        assert result.error == "Invocation failed (status: refused)"

    @pytest.mark.asyncio
    async def test_timeout_exception(self):
        with patch("dns_aid.core.invoke.AgentClient") as MockClient:
            _mock_agent_client(MockClient, invoke_side_effect=httpx.TimeoutException("timed out"))
            result = await _invoke_via_sdk(
                "https://mcp.example.com/mcp",
                protocol="mcp",
                method="tools/call",
                arguments=None,
                timeout=7.0,
                caller_id="test",
            )

        assert result.success is False
        assert "7.0s" in result.error
        assert "SDK path" in result.error

    @pytest.mark.asyncio
    async def test_connect_error(self):
        with patch("dns_aid.core.invoke.AgentClient") as MockClient:
            _mock_agent_client(MockClient, invoke_side_effect=httpx.ConnectError("refused"))
            result = await _invoke_via_sdk(
                "https://mcp.example.com/mcp",
                protocol="mcp",
                method="tools/call",
                arguments=None,
                timeout=30.0,
                caller_id="test",
            )

        assert result.success is False
        assert "Connection failed" in result.error
        assert "refused" in result.error

    @pytest.mark.asyncio
    async def test_generic_error_message_preserved(self):
        with patch("dns_aid.core.invoke.AgentClient") as MockClient:
            _mock_agent_client(MockClient, invoke_side_effect=RuntimeError("kaboom"))
            result = await _invoke_via_sdk(
                "https://mcp.example.com/mcp",
                protocol="mcp",
                method="tools/call",
                arguments=None,
                timeout=30.0,
                caller_id="test",
            )

        assert result.success is False
        assert result.error == "kaboom"

    @pytest.mark.asyncio
    async def test_generic_error_without_message_names_type(self):
        with patch("dns_aid.core.invoke.AgentClient") as MockClient:
            _mock_agent_client(MockClient, invoke_side_effect=ValueError())
            result = await _invoke_via_sdk(
                "https://mcp.example.com/mcp",
                protocol="mcp",
                method="tools/call",
                arguments=None,
                timeout=30.0,
                caller_id="test",
            )

        assert result.success is False
        assert result.error == "SDK invocation failed: ValueError"


# ---------------------------------------------------------------------------
# _invoke_raw_a2a — remaining error paths
# ---------------------------------------------------------------------------


class TestInvokeRawA2AErrors:
    @pytest.mark.asyncio
    async def test_caller_domain_header_sent(self, monkeypatch):
        monkeypatch.setenv("DNS_AID_CALLER_DOMAIN", "caller.example.com")
        mock_response = httpx.Response(
            200,
            json={"result": {}},
            request=httpx.Request("POST", "https://agent.example.com"),
        )

        with patch("dns_aid.core.invoke.httpx.AsyncClient") as MockClient:
            mock_client = _mock_async_client(MockClient, post=mock_response)
            result = await _invoke_raw_a2a("https://agent.example.com", "Hello", 25.0)

        assert result.success is True
        headers = mock_client.post.call_args.kwargs["headers"]
        assert headers["X-DNS-AID-Caller-Domain"] == "caller.example.com"

    @pytest.mark.asyncio
    async def test_http_500(self):
        mock_response = httpx.Response(
            500,
            text="internal error",
            request=httpx.Request("POST", "https://agent.example.com"),
        )

        with patch("dns_aid.core.invoke.httpx.AsyncClient") as MockClient:
            _mock_async_client(MockClient, post=mock_response)
            result = await _invoke_raw_a2a("https://agent.example.com", "Hello", 25.0)

        assert result.success is False
        assert "HTTP 500" in result.error
        assert "internal error" in result.error

    @pytest.mark.asyncio
    async def test_connect_error(self):
        with patch("dns_aid.core.invoke.httpx.AsyncClient") as MockClient:
            _mock_async_client(MockClient, post=httpx.ConnectError("refused"))
            result = await _invoke_raw_a2a("https://agent.example.com", "Hello", 25.0)

        assert result.success is False
        assert "Could not connect" in result.error

    @pytest.mark.asyncio
    async def test_unexpected_error(self):
        with patch("dns_aid.core.invoke.httpx.AsyncClient") as MockClient:
            _mock_async_client(MockClient, post=ValueError("bad payload"))
            result = await _invoke_raw_a2a("https://agent.example.com", "Hello", 25.0)

        assert result.success is False
        assert "Unexpected error" in result.error
        assert "bad payload" in result.error


# ---------------------------------------------------------------------------
# resolve_a2a_endpoint — discovery + agent card resolution chain
# ---------------------------------------------------------------------------


def _discovered_agent():
    from dns_aid.core.models import AgentRecord, Protocol

    return AgentRecord(
        name="chat",
        domain="example.com",
        protocol=Protocol.A2A,
        target_host="a2a.example.com",
        port=443,
    )


class TestResolveA2AEndpoint:
    @pytest.mark.asyncio
    async def test_dns_discovery_with_matching_card(self):
        agent = _discovered_agent()
        card = _card("https://a2a.example.com/rpc")

        with (
            patch(
                "dns_aid.core.discoverer.discover",
                AsyncMock(return_value=SimpleNamespace(agents=[agent])),
            ),
            patch("dns_aid.core.a2a_card.fetch_agent_card", AsyncMock(return_value=card)),
        ):
            resolved = await resolve_a2a_endpoint(domain="example.com", name="chat")

        assert resolved.endpoint == "https://a2a.example.com/rpc"
        assert resolved.resolved_via == "dns_discover+agent_card"
        assert resolved.agent_name == "Chat Agent"
        assert resolved.skills == ["chatting"]
        assert resolved.agent_record is agent

    @pytest.mark.asyncio
    async def test_dns_discovery_card_host_mismatch_keeps_dns_endpoint(self):
        agent = _discovered_agent()
        card = _card("https://internal.runtime.example.net/x")

        with (
            patch(
                "dns_aid.core.discoverer.discover",
                AsyncMock(return_value=SimpleNamespace(agents=[agent])),
            ),
            patch("dns_aid.core.a2a_card.fetch_agent_card", AsyncMock(return_value=card)),
        ):
            resolved = await resolve_a2a_endpoint(domain="example.com", name="chat")

        assert resolved.endpoint == agent.endpoint_url
        assert resolved.resolved_via == "dns_discover+agent_card"

    @pytest.mark.asyncio
    async def test_dns_discovery_without_card(self):
        agent = _discovered_agent()

        with (
            patch(
                "dns_aid.core.discoverer.discover",
                AsyncMock(return_value=SimpleNamespace(agents=[agent])),
            ),
            patch("dns_aid.core.a2a_card.fetch_agent_card", AsyncMock(return_value=None)),
        ):
            resolved = await resolve_a2a_endpoint(domain="example.com", name="chat")

        assert resolved.endpoint == agent.endpoint_url
        assert resolved.resolved_via == "dns_discover"
        assert resolved.agent_name == "chat"
        assert resolved.agent_record is agent

    @pytest.mark.asyncio
    async def test_dns_discovery_no_agents_and_no_endpoint(self):
        with patch(
            "dns_aid.core.discoverer.discover",
            AsyncMock(return_value=SimpleNamespace(agents=[])),
        ):
            resolved = await resolve_a2a_endpoint(None, domain="example.com", name="ghost")

        assert resolved.endpoint == ""
        assert resolved.resolved_via == "error"

    @pytest.mark.asyncio
    async def test_dns_discovery_error_falls_back_to_endpoint(self):
        with (
            patch(
                "dns_aid.core.discoverer.discover",
                AsyncMock(side_effect=RuntimeError("dns down")),
            ),
            patch("dns_aid.core.a2a_card.fetch_agent_card", AsyncMock(return_value=None)),
        ):
            resolved = await resolve_a2a_endpoint(
                "agent.example.com", domain="example.com", name="chat"
            )

        assert resolved.endpoint == "https://agent.example.com"
        assert resolved.resolved_via == "direct"

    @pytest.mark.asyncio
    async def test_agent_card_from_endpoint_matching_host(self):
        card = _card("https://agent.example.com/a2a")

        with patch("dns_aid.core.a2a_card.fetch_agent_card", AsyncMock(return_value=card)):
            resolved = await resolve_a2a_endpoint("agent.example.com")

        assert resolved.endpoint == "https://agent.example.com/a2a"
        assert resolved.resolved_via == "agent_card"
        assert resolved.agent_description == "A chat agent"

    @pytest.mark.asyncio
    async def test_agent_card_from_endpoint_host_mismatch(self):
        card = _card("https://elsewhere.example.net/a2a")

        with patch("dns_aid.core.a2a_card.fetch_agent_card", AsyncMock(return_value=card)):
            resolved = await resolve_a2a_endpoint("agent.example.com")

        assert resolved.endpoint == "https://agent.example.com"
        assert resolved.resolved_via == "agent_card"

    @pytest.mark.asyncio
    async def test_agent_card_without_url_keeps_endpoint(self):
        card = _card("")

        with patch("dns_aid.core.a2a_card.fetch_agent_card", AsyncMock(return_value=card)):
            resolved = await resolve_a2a_endpoint("agent.example.com")

        assert resolved.endpoint == "https://agent.example.com"

    @pytest.mark.asyncio
    async def test_agent_card_fetch_error_uses_direct(self):
        with patch(
            "dns_aid.core.a2a_card.fetch_agent_card",
            AsyncMock(side_effect=RuntimeError("boom")),
        ):
            resolved = await resolve_a2a_endpoint("agent.example.com")

        assert resolved.endpoint == "https://agent.example.com"
        assert resolved.resolved_via == "direct"


# ---------------------------------------------------------------------------
# send_a2a_message — SDK path, agent_info enrichment, post-processing
# ---------------------------------------------------------------------------


class TestSendA2AMessageSDK:
    @pytest.mark.asyncio
    async def test_resolution_failure_returns_error(self):
        with patch(
            "dns_aid.core.invoke.resolve_a2a_endpoint",
            AsyncMock(return_value=ResolvedAgent(endpoint="", resolved_via="error")),
        ):
            result = await send_a2a_message(None, "hello", domain="example.com", name="ghost")

        assert result.success is False
        assert "No endpoint provided" in result.error

    @pytest.mark.asyncio
    async def test_sdk_path_with_agent_info(self):
        resolved = ResolvedAgent(
            endpoint="https://canonical.example.com/rpc",
            agent_name="Chat",
            agent_description="A chat agent",
            skills=["chatting"],
            resolved_via="agent_card",
        )
        invoke_result = InvokeResult(
            success=True,
            data={"result": {"parts": [{"kind": "text", "text": "Hi there"}]}},
        )

        with (
            patch("dns_aid.core.invoke._sdk_available", True),
            patch(
                "dns_aid.core.invoke.resolve_a2a_endpoint",
                AsyncMock(return_value=resolved),
            ),
            patch(
                "dns_aid.core.invoke._invoke_via_sdk",
                AsyncMock(return_value=invoke_result),
            ) as mock_invoke,
        ):
            result = await send_a2a_message("agent.example.com", "hello")

        assert result.success is True
        assert result.data["response_text"] == "Hi there"
        info = result.data["agent_info"]
        assert info["name"] == "Chat"
        assert info["description"] == "A chat agent"
        assert info["skills"] == ["chatting"]
        assert info["resolved_via"] == "agent_card"
        assert info["original_endpoint"] == "agent.example.com"
        assert info["canonical_endpoint"] == "https://canonical.example.com/rpc"
        assert mock_invoke.call_args.kwargs["method"] == "message/send"
        assert mock_invoke.call_args.kwargs["protocol"] == "a2a"

    @pytest.mark.asyncio
    async def test_dict_data_without_text_keeps_raw_dict(self):
        resolved = ResolvedAgent(endpoint="https://agent.example.com", resolved_via="direct")
        invoke_result = InvokeResult(success=True, data={"result": {}})

        with (
            patch("dns_aid.core.invoke._sdk_available", True),
            patch(
                "dns_aid.core.invoke.resolve_a2a_endpoint",
                AsyncMock(return_value=resolved),
            ),
            patch(
                "dns_aid.core.invoke._invoke_via_sdk",
                AsyncMock(return_value=invoke_result),
            ),
        ):
            result = await send_a2a_message("agent.example.com", "hello")

        assert result.success is True
        assert "response_text" not in result.data
        assert result.data["agent_info"]["resolved_via"] == "direct"

    @pytest.mark.asyncio
    async def test_non_dict_data_wrapped_with_agent_info(self):
        resolved = ResolvedAgent(endpoint="https://agent.example.com", resolved_via="direct")
        invoke_result = InvokeResult(success=True, data="plain text answer")

        with (
            patch("dns_aid.core.invoke._sdk_available", True),
            patch(
                "dns_aid.core.invoke.resolve_a2a_endpoint",
                AsyncMock(return_value=resolved),
            ),
            patch(
                "dns_aid.core.invoke._invoke_via_sdk",
                AsyncMock(return_value=invoke_result),
            ),
        ):
            result = await send_a2a_message("agent.example.com", "hello")

        assert result.data == {
            "response_text": "plain text answer",
            "agent_info": {"resolved_via": "direct"},
        }


# ---------------------------------------------------------------------------
# call_mcp_tool / list_mcp_tools — endpoint resolution + normalization
# ---------------------------------------------------------------------------


class TestCallMCPTool:
    @pytest.mark.asyncio
    async def test_defaults_empty_arguments(self):
        with (
            patch(
                "dns_aid.core.invoke.resolve_mcp_endpoint",
                AsyncMock(return_value="https://h.example.com/mcp"),
            ) as mock_resolve,
            patch(
                "dns_aid.core.invoke._invoke_via_sdk",
                AsyncMock(return_value=InvokeResult(success=True, data={"ok": 1})),
            ) as mock_invoke,
        ):
            result = await call_mcp_tool("h.example.com", "analyze")

        assert result.success is True
        mock_resolve.assert_awaited_once_with("h.example.com")
        assert mock_invoke.call_args[0][0] == "https://h.example.com/mcp"
        assert mock_invoke.call_args.kwargs["method"] == "tools/call"
        assert mock_invoke.call_args.kwargs["arguments"] == {
            "name": "analyze",
            "arguments": {},
        }

    @pytest.mark.asyncio
    async def test_arguments_and_auth_passthrough(self):
        agent = _build_agent_record_from_endpoint("https://h.example.com/mcp")
        with (
            patch(
                "dns_aid.core.invoke.resolve_mcp_endpoint",
                AsyncMock(return_value="https://h.example.com/mcp"),
            ),
            patch(
                "dns_aid.core.invoke._invoke_via_sdk",
                AsyncMock(return_value=InvokeResult(success=True, data={})),
            ) as mock_invoke,
        ):
            await call_mcp_tool(
                "h.example.com",
                "analyze",
                {"domain": "x.com"},
                credentials={"token": "secret"},
                agent_record=agent,
                policy_uri="https://example.com/p.json",
            )

        kwargs = mock_invoke.call_args.kwargs
        assert kwargs["arguments"] == {"name": "analyze", "arguments": {"domain": "x.com"}}
        assert kwargs["credentials"] == {"token": "secret"}
        assert kwargs["agent_record"] is agent
        assert kwargs["policy_uri"] == "https://example.com/p.json"


class TestListMCPTools:
    @staticmethod
    def _patched(data, *, success=True):
        return (
            patch(
                "dns_aid.core.invoke.resolve_mcp_endpoint",
                AsyncMock(return_value="https://h.example.com/mcp"),
            ),
            patch(
                "dns_aid.core.invoke._invoke_via_sdk",
                AsyncMock(
                    return_value=InvokeResult(
                        success=success,
                        data=data,
                        error=None if success else "boom",
                    )
                ),
            ),
        )

    @pytest.mark.asyncio
    async def test_dict_with_tools_normalized_to_list(self):
        p1, p2 = self._patched({"tools": [{"name": "t1"}]})
        with p1, p2 as mock_invoke:
            result = await list_mcp_tools("h.example.com")

        assert result.data == [{"name": "t1"}]
        assert mock_invoke.call_args.kwargs["method"] == "tools/list"
        assert mock_invoke.call_args.kwargs["arguments"] is None

    @pytest.mark.asyncio
    async def test_dict_without_tools_becomes_empty_list(self):
        p1, p2 = self._patched({"unexpected": "shape"})
        with p1, p2:
            result = await list_mcp_tools("h.example.com")

        assert result.data == []

    @pytest.mark.asyncio
    async def test_non_list_data_becomes_empty_list(self):
        p1, p2 = self._patched("weird string")
        with p1, p2:
            result = await list_mcp_tools("h.example.com")

        assert result.data == []

    @pytest.mark.asyncio
    async def test_list_data_passes_through(self):
        p1, p2 = self._patched([{"name": "t1"}])
        with p1, p2:
            result = await list_mcp_tools("h.example.com")

        assert result.data == [{"name": "t1"}]

    @pytest.mark.asyncio
    async def test_failure_left_untouched(self):
        p1, p2 = self._patched(None, success=False)
        with p1, p2:
            result = await list_mcp_tools("h.example.com")

        assert result.success is False
        assert result.error == "boom"
        assert result.data is None


# ---------------------------------------------------------------------------
# Module import fallback — SDK unavailable at import time
# ---------------------------------------------------------------------------


class TestModuleImportWithoutSDK:
    def test_sdk_import_failure_disables_sdk_flag(self):
        real_mod = sys.modules["dns_aid.core.invoke"]
        try:
            with patch.dict(sys.modules):
                # A None entry makes `from dns_aid.sdk import ...` raise ImportError.
                sys.modules["dns_aid.sdk"] = None  # type: ignore[assignment]
                sys.modules.pop("dns_aid.core.invoke", None)
                fresh = importlib.import_module("dns_aid.core.invoke")
                assert fresh._sdk_available is False
        finally:
            sys.modules["dns_aid.core.invoke"] = real_mod
            import dns_aid.core

            dns_aid.core.invoke = real_mod
