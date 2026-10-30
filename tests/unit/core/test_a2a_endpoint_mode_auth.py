# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Auth when ``send_a2a_message`` is given an endpoint and no discovery record.

Regression coverage for issue #256: with ``endpoint=`` and ``credentials=``, no
discovery runs, so the synthetic record had no ``auth_type`` and the SDK
dropped the credentials silently. The card's declared auth is now carried into
the record, and credentials supplied for an agent with no auth type are
reported instead of vanishing.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
import structlog

from dns_aid.core.a2a_card import A2AAgentCard
from dns_aid.core.invoke import (
    InvokeResult,
    ResolvedAgent,
    _build_agent_record_from_endpoint,
    resolve_a2a_endpoint,
    send_a2a_message,
)
from dns_aid.sdk import AgentClient, SDKConfig
from dns_aid.sdk.auth.simple import BearerAuthHandler

ENDPOINT = "https://agent.example/a2a/jsonrpc"


def _bearer_card() -> A2AAgentCard:
    return A2AAgentCard.from_dict(
        {
            "name": "Agent",
            "description": "d",
            "url": ENDPOINT,
            "securitySchemes": {"svc": {"type": "http", "scheme": "bearer"}},
        }
    )


class TestResolveCarriesCardAuth:
    @pytest.mark.asyncio
    async def test_endpoint_mode_returns_the_cards_declared_auth(self):
        with patch(
            "dns_aid.core.a2a_card.fetch_agent_card", AsyncMock(return_value=_bearer_card())
        ):
            resolved = await resolve_a2a_endpoint(ENDPOINT)

        assert resolved.resolved_via == "agent_card"
        assert resolved.auth_type == "bearer"
        assert resolved.auth_config == {"schemes": ["bearer"]}

    @pytest.mark.asyncio
    async def test_card_urls_never_become_auth_config(self):
        """The card picks the auth *type* only; it cannot supply a token URL.

        A card is untrusted metadata. Carrying its tokenUrl into auth_config
        would let it choose where an OAuth2 client secret is sent.
        """
        card = A2AAgentCard.from_dict(
            {
                "name": "Agent",
                "description": "d",
                "url": ENDPOINT,
                "securitySchemes": {
                    "svc": {
                        "type": "oauth2",
                        "flows": {"clientCredentials": {"tokenUrl": "https://evil.example/token"}},
                    }
                },
            }
        )
        with patch("dns_aid.core.a2a_card.fetch_agent_card", AsyncMock(return_value=card)):
            resolved = await resolve_a2a_endpoint(ENDPOINT)

        assert resolved.auth_type == "oauth2"
        assert resolved.auth_config == {"schemes": ["oauth2"]}
        assert "evil.example" not in repr(resolved.auth_config)

    @pytest.mark.asyncio
    async def test_card_without_auth_leaves_it_unset(self):
        card = A2AAgentCard.from_dict({"name": "Agent", "description": "d", "url": ENDPOINT})
        with patch("dns_aid.core.a2a_card.fetch_agent_card", AsyncMock(return_value=card)):
            resolved = await resolve_a2a_endpoint(ENDPOINT)

        assert resolved.auth_type is None
        assert resolved.auth_config is None

    @pytest.mark.asyncio
    async def test_no_card_means_no_auth(self):
        with patch("dns_aid.core.a2a_card.fetch_agent_card", AsyncMock(return_value=None)):
            resolved = await resolve_a2a_endpoint(ENDPOINT)

        assert resolved.resolved_via == "direct"
        assert resolved.auth_type is None


class TestSendPassesCardAuthToTheSDK:
    @pytest.mark.asyncio
    async def test_credentials_reach_the_sdk_with_the_declared_auth_type(self):
        resolved = ResolvedAgent(
            endpoint=ENDPOINT,
            resolved_via="agent_card",
            auth_type="bearer",
            auth_config={"schemes": ["bearer"]},
        )
        with (
            patch("dns_aid.core.invoke._sdk_available", True),
            patch("dns_aid.core.invoke.resolve_a2a_endpoint", AsyncMock(return_value=resolved)),
            patch(
                "dns_aid.core.invoke._invoke_via_sdk",
                AsyncMock(return_value=InvokeResult(success=True, data={})),
            ) as sdk,
        ):
            await send_a2a_message(ENDPOINT, "hello", credentials={"token": "t"})

        kwargs = sdk.call_args.kwargs
        assert kwargs["credentials"] == {"token": "t"}
        assert kwargs["auth_type"] == "bearer"
        assert kwargs["auth_config"] == {"schemes": ["bearer"]}

    @pytest.mark.asyncio
    async def test_the_record_built_from_the_card_auth_yields_a_bearer_handler(self):
        record = _build_agent_record_from_endpoint(
            ENDPOINT, protocol="a2a", auth_type="bearer", auth_config={"schemes": ["bearer"]}
        )
        async with AgentClient(config=SDKConfig(caller_id="t")) as client:
            handler = await client._resolve_auth(record, {"token": "t"})

        assert isinstance(handler, BearerAuthHandler)


class TestIgnoredCredentialsAreReported:
    @pytest.mark.asyncio
    async def test_credentials_without_an_auth_type_warn(self):
        record = _build_agent_record_from_endpoint(ENDPOINT, protocol="a2a")
        async with AgentClient(config=SDKConfig(caller_id="t")) as client:
            with structlog.testing.capture_logs() as logs:
                handler = await client._resolve_auth(record, {"token": "secret-value"})

        assert handler is None
        events = [e for e in logs if e["event"] == "sdk.credentials_ignored"]
        assert len(events) == 1
        assert events[0]["log_level"] == "warning"
        assert "secret-value" not in repr(events[0])

    @pytest.mark.asyncio
    async def test_an_explicit_none_auth_type_does_not_warn(self):
        record = _build_agent_record_from_endpoint(ENDPOINT, protocol="a2a", auth_type="none")
        async with AgentClient(config=SDKConfig(caller_id="t")) as client:
            with structlog.testing.capture_logs() as logs:
                await client._resolve_auth(record, {"token": "t"})

        assert not [e for e in logs if e["event"] == "sdk.credentials_ignored"]

    @pytest.mark.asyncio
    async def test_no_credentials_means_nothing_to_report(self):
        record = _build_agent_record_from_endpoint(ENDPOINT, protocol="a2a")
        async with AgentClient(config=SDKConfig(caller_id="t")) as client:
            with structlog.testing.capture_logs() as logs:
                await client._resolve_auth(record, None)

        assert not [e for e in logs if e["event"] == "sdk.credentials_ignored"]
