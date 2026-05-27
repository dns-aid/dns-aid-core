# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Integration tests: AgentClient.invoke() with auth handlers."""

from __future__ import annotations

import httpx
import pytest

from dns_aid.core.models import AgentRecord, Protocol
from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.auth.simple import BearerAuthHandler
from dns_aid.sdk.client import AgentClient


@pytest.fixture(autouse=True)
def _autouse_legacy_fallback(force_legacy_mcp_fallback: None) -> None:
    """All MCP integration tests in this module use httpx.MockTransport,
    which exercises the legacy plain JSON-RPC POST path (now reached via
    transparent fallback from the modern Streamable HTTP transport)."""


def _make_agent(
    auth_type: str | None = None,
    auth_config: dict | None = None,
) -> AgentRecord:
    return AgentRecord(
        name="test-agent",
        domain="example.com",
        protocol=Protocol.MCP,
        target_host="mcp.example.com",
        port=443,
        auth_type=auth_type,
        auth_config=auth_config,
    )


def _mock_transport_capturing_headers():
    """Return a transport that captures request headers and returns a valid MCP response."""
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        captured["url"] = str(request.url)
        body = {"jsonrpc": "2.0", "result": {"tools": []}, "id": 1}
        return httpx.Response(
            200,
            json=body,
            headers={"Content-Type": "application/json"},
            request=request,
        )

    return httpx.MockTransport(handler), captured


class TestClientAuthIntegration:
    @pytest.mark.asyncio
    async def test_invoke_with_bearer_credentials(self) -> None:
        """invoke() resolves Bearer auth from agent metadata + credentials."""
        agent = _make_agent(auth_type="bearer")
        transport, captured = _mock_transport_capturing_headers()
        config = SDKConfig(timeout_seconds=5.0)

        async with AgentClient(config=config) as client:
            client._http_client = httpx.AsyncClient(transport=transport)
            result = await client.invoke(
                agent,
                method="tools/list",
                credentials={"token": "my-secret-token"},
            )

        assert result.success
        assert captured["headers"]["authorization"] == "Bearer my-secret-token"

    @pytest.mark.asyncio
    async def test_invoke_with_api_key_credentials(self) -> None:
        """invoke() resolves API key auth from agent metadata + credentials."""
        agent = _make_agent(
            auth_type="api_key",
            auth_config={"header_name": "X-Custom-Key"},
        )
        transport, captured = _mock_transport_capturing_headers()
        config = SDKConfig(timeout_seconds=5.0)

        async with AgentClient(config=config) as client:
            client._http_client = httpx.AsyncClient(transport=transport)
            result = await client.invoke(
                agent,
                method="tools/list",
                credentials={"api_key": "sk-test-123"},
            )

        assert result.success
        assert captured["headers"]["x-custom-key"] == "sk-test-123"

    @pytest.mark.asyncio
    async def test_invoke_with_explicit_auth_handler(self) -> None:
        """Explicit auth_handler overrides agent metadata."""
        agent = _make_agent(auth_type="api_key")  # metadata says api_key
        transport, captured = _mock_transport_capturing_headers()
        config = SDKConfig(timeout_seconds=5.0)

        # Override with a bearer handler
        handler = BearerAuthHandler(token="override-token")

        async with AgentClient(config=config) as client:
            client._http_client = httpx.AsyncClient(transport=transport)
            result = await client.invoke(
                agent,
                method="tools/list",
                auth_handler=handler,
            )

        assert result.success
        assert captured["headers"]["authorization"] == "Bearer override-token"

    @pytest.mark.asyncio
    async def test_invoke_no_auth_when_type_none(self) -> None:
        """No auth applied when agent auth_type is 'none'."""
        agent = _make_agent(auth_type="none")
        transport, captured = _mock_transport_capturing_headers()
        config = SDKConfig(timeout_seconds=5.0)

        async with AgentClient(config=config) as client:
            client._http_client = httpx.AsyncClient(transport=transport)
            result = await client.invoke(agent, method="tools/list")

        assert result.success
        assert "authorization" not in captured["headers"]

    @pytest.mark.asyncio
    async def test_invoke_no_auth_when_no_credentials(self) -> None:
        """Auth skipped when agent requires it but no credentials provided."""
        agent = _make_agent(auth_type="bearer")
        transport, captured = _mock_transport_capturing_headers()
        config = SDKConfig(timeout_seconds=5.0)

        async with AgentClient(config=config) as client:
            client._http_client = httpx.AsyncClient(transport=transport)
            result = await client.invoke(agent, method="tools/list")

        assert result.success
        assert "authorization" not in captured["headers"]

    @pytest.mark.asyncio
    async def test_invoke_no_auth_when_no_auth_type(self) -> None:
        """No auth applied when agent has no auth_type field."""
        agent = _make_agent()  # auth_type=None
        transport, captured = _mock_transport_capturing_headers()
        config = SDKConfig(timeout_seconds=5.0)

        async with AgentClient(config=config) as client:
            client._http_client = httpx.AsyncClient(transport=transport)
            result = await client.invoke(agent, method="tools/list")

        assert result.success
        assert "authorization" not in captured["headers"]

    @pytest.mark.asyncio
    async def test_auth_error_includes_agent_context(self) -> None:
        """ValueError from resolve_auth_handler includes agent FQDN."""
        agent = _make_agent(auth_type="bearer")
        config = SDKConfig(timeout_seconds=5.0)
        transport, _ = _mock_transport_capturing_headers()

        async with AgentClient(config=config) as client:
            client._http_client = httpx.AsyncClient(transport=transport)
            with pytest.raises(ValueError, match="test-agent.*example.com"):
                # Missing 'token' in credentials triggers ValueError
                await client.invoke(
                    agent,
                    method="tools/list",
                    credentials={"wrong_key": "value"},
                )

    @pytest.mark.asyncio
    async def test_signal_captures_auth_metadata(self) -> None:
        """InvocationSignal should record auth_type and auth_applied."""
        agent = _make_agent(auth_type="bearer")
        transport, _ = _mock_transport_capturing_headers()
        config = SDKConfig(timeout_seconds=5.0)

        async with AgentClient(config=config) as client:
            client._http_client = httpx.AsyncClient(transport=transport)
            result = await client.invoke(
                agent,
                method="tools/list",
                credentials={"token": "my-token"},
            )

        assert result.signal.auth_type == "bearer"
        assert result.signal.auth_applied is True

    @pytest.mark.asyncio
    async def test_signal_no_auth_metadata_when_unauthenticated(self) -> None:
        """InvocationSignal should have auth_applied=False when no auth."""
        agent = _make_agent()  # no auth_type
        transport, _ = _mock_transport_capturing_headers()
        config = SDKConfig(timeout_seconds=5.0)

        async with AgentClient(config=config) as client:
            client._http_client = httpx.AsyncClient(transport=transport)
            result = await client.invoke(agent, method="tools/list")

        assert result.signal.auth_type is None
        assert result.signal.auth_applied is False
