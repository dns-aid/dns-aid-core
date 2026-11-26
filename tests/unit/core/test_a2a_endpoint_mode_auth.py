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

import httpx
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


def _bearer_card_at(url: str) -> A2AAgentCard:
    return A2AAgentCard.from_dict(
        {
            "name": "Agent",
            "description": "d",
            "url": url,
            "securitySchemes": {"svc": {"type": "http", "scheme": "bearer"}},
        }
    )


class TestCardCannotMoveCredentialsToAnotherOrigin:
    """The card's url only replaces the given endpoint when the origin matches.

    Credentials go to whatever endpoint ``resolve_a2a_endpoint`` returns, and
    the card is untrusted metadata. A hostname match alone would let a card
    pull the caller's bearer token to plain http or to another port.
    """

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "card_url",
        [
            "http://agent.example:8080/a2a/jsonrpc",  # downgrade + port
            "http://agent.example/a2a/jsonrpc",  # downgrade, same host
            "https://agent.example:8443/a2a/jsonrpc",  # same scheme, other port
            "https://other.example/a2a/jsonrpc",  # other host
        ],
    )
    async def test_cross_origin_card_url_keeps_the_given_endpoint(self, card_url: str):
        with patch(
            "dns_aid.core.a2a_card.fetch_agent_card",
            AsyncMock(return_value=_bearer_card_at(card_url)),
        ):
            resolved = await resolve_a2a_endpoint(ENDPOINT)

        assert resolved.endpoint == ENDPOINT
        assert resolved.auth_type == "bearer"

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "card_url",
        [
            "https://agent.example/a2a/v1",
            "https://agent.example:443/a2a/v1",  # explicit default port
            "https://AGENT.example/a2a/v1",  # hostnames are case-insensitive
        ],
    )
    async def test_same_origin_card_url_is_still_used(self, card_url: str):
        with patch(
            "dns_aid.core.a2a_card.fetch_agent_card",
            AsyncMock(return_value=_bearer_card_at(card_url)),
        ):
            resolved = await resolve_a2a_endpoint(ENDPOINT)

        assert resolved.endpoint == card_url

    @pytest.mark.asyncio
    async def test_token_is_only_sent_to_the_given_endpoint(self):
        """End to end through send_a2a_message: the SDK gets the caller's endpoint."""
        card = _bearer_card_at("http://agent.example:8080/a2a/jsonrpc")
        with (
            patch("dns_aid.core.invoke._sdk_available", True),
            patch("dns_aid.core.a2a_card.fetch_agent_card", AsyncMock(return_value=card)),
            patch(
                "dns_aid.core.invoke._invoke_via_sdk",
                AsyncMock(return_value=InvokeResult(success=True, data={})),
            ) as sdk,
        ):
            await send_a2a_message(ENDPOINT, "hello", credentials={"token": "t"})

        assert sdk.call_args.args[0] == ENDPOINT
        assert sdk.call_args.kwargs["credentials"] == {"token": "t"}


class TestSameOrigin:
    @pytest.mark.parametrize(
        ("a", "b", "expected"),
        [
            ("https://h.example/x", "https://h.example/y", True),
            ("https://h.example", "https://h.example:443/", True),
            ("http://h.example", "http://h.example:80", True),
            ("https://H.Example/x", "https://h.example/x", True),
            ("https://h.example", "http://h.example", False),
            ("https://h.example", "https://h.example:8443", False),
            ("https://h.example", "https://g.example", False),
            ("https://h.example:notaport", "https://h.example", False),
            ("ftp://h.example", "ftp://h.example", False),
            ("", "https://h.example", False),
        ],
    )
    def test_origin_comparison(self, a: str, b: str, expected: bool):
        from dns_aid.core.invoke import _same_origin

        assert _same_origin(a, b) is expected


def _api_key_card(scheme: dict) -> A2AAgentCard:
    return A2AAgentCard.from_dict(
        {"name": "Agent", "description": "d", "url": ENDPOINT, "securitySchemes": {"k": scheme}}
    )


class TestApiKeySchemesMapToTheRegistry:
    """Cards say ``apiKey``; the SDK registry only knows ``api_key``.

    Unmapped, an apiKey card plus credentials failed with "Unknown auth_type:
    apiKey" once the card's auth started reaching the SDK.
    """

    def test_openapi_header_scheme(self):
        auth = _api_key_card({"type": "apiKey", "in": "header", "name": "X-Agent-Key"})
        assert auth.authentication.sdk_auth() == (
            "api_key",
            {"schemes": ["api_key"], "location": "header", "header_name": "X-Agent-Key"},
        )

    def test_openapi_query_scheme(self):
        auth = _api_key_card({"type": "apiKey", "in": "query", "name": "key"})
        assert auth.authentication.sdk_auth() == (
            "api_key",
            {"schemes": ["api_key"], "location": "query", "query_param": "key"},
        )

    def test_proto_style_scheme(self):
        auth = _api_key_card(
            {"apiKeySecurityScheme": {"location": "header", "name": "X-Agent-Key"}}
        )
        assert auth.authentication.sdk_auth()[1]["header_name"] == "X-Agent-Key"

    @pytest.mark.parametrize(
        "scheme",
        [
            {"type": "apiKey", "in": "cookie", "name": "session"},  # no handler support
            {"type": "apiKey", "in": "header", "name": "X-Key\r\nX-Evil: 1"},  # not a token
            {"type": "apiKey", "in": "query", "name": "a&b=c"},
            {"type": "apiKey"},
        ],
    )
    def test_unusable_placement_falls_back_to_handler_defaults(self, scheme):
        auth = _api_key_card(scheme)
        assert auth.authentication.sdk_auth() == ("api_key", {"schemes": ["api_key"]})

    def test_v02_scheme_names_are_normalized(self):
        card = A2AAgentCard.from_dict(
            {
                "name": "Agent",
                "url": ENDPOINT,
                "authentication": {"schemes": ["Bearer", "apiKey", "bearer"]},
            }
        )
        assert card.authentication.schemes == ["bearer", "api_key"]

    @pytest.mark.asyncio
    async def test_endpoint_mode_api_key_card_applies_the_key_where_declared(self):
        card = _api_key_card({"type": "apiKey", "in": "header", "name": "X-Agent-Key"})
        with patch("dns_aid.core.a2a_card.fetch_agent_card", AsyncMock(return_value=card)):
            resolved = await resolve_a2a_endpoint(ENDPOINT)

        record = _build_agent_record_from_endpoint(
            resolved.endpoint,
            protocol="a2a",
            auth_type=resolved.auth_type,
            auth_config=resolved.auth_config,
        )
        async with AgentClient(config=SDKConfig(caller_id="t")) as client:
            handler = await client._resolve_auth(record, {"api_key": "k-123"})

        request = await handler.apply(httpx.Request("POST", resolved.endpoint))
        assert request.headers["X-Agent-Key"] == "k-123"
        assert "k-123" not in str(request.url)
