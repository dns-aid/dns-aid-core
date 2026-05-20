# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Live SDK auth integration tests against real AWS infrastructure.

Tests every SDK auth pattern from the developer guide:
1. No auth (public agent)
2. Bearer token (httpbin echo)
3. API key (httpbin echo)
4. OAuth2 client-credentials (AWS Cognito)
5. SigV4 (API Gateway with IAM auth)
6. Explicit handler override
7. Auth enrichment from agent-card.json
8. Multi-agent with different auth types

Requires:
- Public agent: https://1ls9mi4dp2.execute-api.us-east-1.amazonaws.com
- SigV4 agent: https://lixqgn0ttl.execute-api.us-east-1.amazonaws.com
- AWS okta-sso profile configured
- Environment variables for OAuth2 (not hardcoded — see conftest.py):
    DNS_AID_TEST_COGNITO_CLIENT_ID
    DNS_AID_TEST_COGNITO_CLIENT_SECRET

Run with:
    pytest tests/integration/test_sdk_auth_live.py -v
"""

from __future__ import annotations

import os

import pytest

from dns_aid.core.a2a_card import fetch_agent_card
from dns_aid.core.discoverer import (
    _apply_agent_card,
    _apply_auth_from_metadata,
    _fetch_agent_json_auth,
)
from dns_aid.core.models import AgentRecord, Protocol
from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.auth.simple import BearerAuthHandler
from dns_aid.sdk.client import AgentClient

pytestmark = [pytest.mark.integration, pytest.mark.live]

PUBLIC_HOST = "1ls9mi4dp2.execute-api.us-east-1.amazonaws.com"
SIGV4_HOST = "lixqgn0ttl.execute-api.us-east-1.amazonaws.com"

# OAuth2 credentials from environment — never hardcoded.
# Set DNS_AID_TEST_COGNITO_CLIENT_ID and DNS_AID_TEST_COGNITO_CLIENT_SECRET.
COGNITO_CLIENT_ID = os.environ.get("DNS_AID_TEST_COGNITO_CLIENT_ID", "")
COGNITO_CLIENT_SECRET = os.environ.get("DNS_AID_TEST_COGNITO_CLIENT_SECRET", "")
COGNITO_DISCOVERY = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_NE34GkEdc/.well-known/openid-configuration"


def _agent(host: str, name: str = "test", **kwargs: object) -> AgentRecord:
    return AgentRecord(
        name=name,
        domain="test.example.com",
        protocol=Protocol.A2A,
        target_host=host,
        port=443,
        **kwargs,
    )


def _a2a_payload(text: str) -> dict:
    return {
        "message": {
            "messageId": "live-test",
            "role": "user",
            "parts": [{"kind": "text", "text": text}],
        }
    }


# ─────────────────────────────────────────────────────────
# 1. NO AUTH — public agent
# ─────────────────────────────────────────────────────────


class TestNoAuth:
    @pytest.mark.asyncio
    async def test_public_agent_no_credentials(self) -> None:
        """Invoke a public agent with no credentials — should succeed."""
        agent = _agent(PUBLIC_HOST, "public-test")

        async with AgentClient(SDKConfig(timeout_seconds=15.0)) as client:
            result = await client.invoke(
                agent,
                method="message/send",
                arguments=_a2a_payload("hello public agent"),
            )

        assert result.success
        assert "[PUBLIC] Echo:" in str(result.data)


# ─────────────────────────────────────────────────────────
# 2. BEARER TOKEN — httpbin echo
# ─────────────────────────────────────────────────────────


class TestBearerAuth:
    @pytest.mark.asyncio
    async def test_bearer_token_reaches_endpoint(self) -> None:
        """Bearer token applied via SDK credentials reaches the endpoint."""
        agent = _agent(
            "httpbin.org",
            "bearer-test",
            auth_type="bearer",
            endpoint_override="https://httpbin.org/post",
        )

        async with AgentClient(SDKConfig(timeout_seconds=15.0)) as client:
            result = await client.invoke(
                agent,
                method=None,
                arguments={"test": "bearer"},
                credentials={"token": "live-bearer-token-xyz"},
            )

        assert result.success
        data = result.data
        assert data["headers"]["Authorization"] == "Bearer live-bearer-token-xyz"


# ─────────────────────────────────────────────────────────
# 3. API KEY — httpbin echo
# ─────────────────────────────────────────────────────────


class TestApiKeyAuth:
    @pytest.mark.asyncio
    async def test_api_key_header_reaches_endpoint(self) -> None:
        """API key injected via SDK credentials reaches the endpoint."""
        agent = _agent(
            "httpbin.org",
            "apikey-test",
            auth_type="api_key",
            auth_config={"header_name": "X-Custom-Key"},
            endpoint_override="https://httpbin.org/post",
        )

        async with AgentClient(SDKConfig(timeout_seconds=15.0)) as client:
            result = await client.invoke(
                agent,
                method=None,
                arguments={"test": "api_key"},
                credentials={"api_key": "sk-live-test-key"},
            )

        assert result.success
        assert result.data["headers"]["X-Custom-Key"] == "sk-live-test-key"


# ─────────────────────────────────────────────────────────
# 4. OAUTH2 — AWS Cognito
# ─────────────────────────────────────────────────────────


class TestOAuth2Auth:
    @pytest.mark.asyncio
    @pytest.mark.skipif(not COGNITO_CLIENT_ID, reason="DNS_AID_TEST_COGNITO_CLIENT_ID not set")
    async def test_oauth2_token_applied_to_request(self) -> None:
        """OAuth2 client-credentials token fetched from Cognito and applied."""
        agent = _agent(
            "httpbin.org",
            "oauth2-test",
            auth_type="oauth2",
            auth_config={"oauth_discovery": COGNITO_DISCOVERY},
            endpoint_override="https://httpbin.org/post",
        )

        async with AgentClient(SDKConfig(timeout_seconds=15.0)) as client:
            result = await client.invoke(
                agent,
                method=None,
                arguments={"test": "oauth2"},
                credentials={
                    "client_id": COGNITO_CLIENT_ID,
                    "client_secret": COGNITO_CLIENT_SECRET,
                    "scopes": "dns-aid-api/invoke",
                },
            )

        assert result.success
        auth_header = result.data["headers"]["Authorization"]
        assert auth_header.startswith("Bearer ")
        # Verify it's a real JWT (3 dot-separated parts)
        token = auth_header.split(" ", 1)[1]
        assert len(token.split(".")) == 3


# ─────────────────────────────────────────────────────────
# 5. AWS SIGV4 — API Gateway with IAM auth
# ─────────────────────────────────────────────────────────


class TestSigV4Auth:
    @pytest.mark.asyncio
    async def test_sigv4_invoke_succeeds(self) -> None:
        """SigV4 signed request passes API Gateway IAM auth."""
        agent = _agent(
            SIGV4_HOST,
            "sigv4-test",
            auth_type="sigv4",
            auth_config={"region": "us-east-1", "service": "execute-api"},
        )

        async with AgentClient(SDKConfig(timeout_seconds=15.0)) as client:
            result = await client.invoke(
                agent,
                method="message/send",
                arguments=_a2a_payload("SigV4 live test"),
                credentials={"profile_name": "okta-sso"},
            )

        assert result.success
        assert "Auth verified!" in str(result.data)

    @pytest.mark.asyncio
    async def test_sigv4_without_credentials_fails(self) -> None:
        """Request without SigV4 to IAM-protected endpoint returns error."""
        agent = _agent(SIGV4_HOST, "sigv4-noauth")

        async with AgentClient(SDKConfig(timeout_seconds=15.0)) as client:
            result = await client.invoke(
                agent,
                method="message/send",
                arguments=_a2a_payload("should fail"),
            )

        assert not result.success
        assert result.signal.http_status_code == 403


# ─────────────────────────────────────────────────────────
# 6. EXPLICIT HANDLER OVERRIDE
# ─────────────────────────────────────────────────────────


class TestExplicitHandler:
    @pytest.mark.asyncio
    async def test_explicit_handler_overrides_metadata(self) -> None:
        """Explicit auth_handler ignores agent metadata auth_type."""
        agent = _agent(
            "httpbin.org",
            "override-test",
            auth_type="api_key",  # metadata says api_key
            endpoint_override="https://httpbin.org/post",
        )

        # But we override with bearer
        handler = BearerAuthHandler(token="explicit-override-token")

        async with AgentClient(SDKConfig(timeout_seconds=15.0)) as client:
            result = await client.invoke(
                agent,
                method=None,
                arguments={"test": "override"},
                auth_handler=handler,
            )

        assert result.success
        assert result.data["headers"]["Authorization"] == "Bearer explicit-override-token"


# ─────────────────────────────────────────────────────────
# 7. AUTH ENRICHMENT FROM agent-card.json
# ─────────────────────────────────────────────────────────


class TestAuthEnrichment:
    @pytest.mark.asyncio
    async def test_auth_from_agent_card_json(self) -> None:
        """Auth populated from agent-card.json authentication.schemes."""
        agent = _agent(SIGV4_HOST, "enrich-card")

        card = await fetch_agent_card(f"https://{SIGV4_HOST}")
        assert card is not None
        assert card.authentication is not None
        assert "sigv4" in card.authentication.schemes

        _apply_agent_card(agent, card)

        assert agent.auth_type == "sigv4"
        assert agent.auth_config == {"schemes": ["sigv4"]}

    @pytest.mark.asyncio
    async def test_auth_from_agent_json_fallback(self) -> None:
        """Auth populated from agent.json when agent-card.json has no auth."""
        agent = _agent(SIGV4_HOST, "enrich-native")

        auth_data = await _fetch_agent_json_auth(SIGV4_HOST)
        assert auth_data is not None
        assert auth_data["type"] == "sigv4"

        _apply_auth_from_metadata(agent, {"auth": auth_data})

        assert agent.auth_type == "sigv4"
        assert agent.auth_config["region"] == "us-east-1"
        assert agent.auth_config["service"] == "execute-api"

    @pytest.mark.asyncio
    async def test_enrichment_then_invoke(self) -> None:
        """Full flow: enrich from agent-card.json → invoke with credentials."""
        agent = _agent(SIGV4_HOST, "enrich-invoke")

        # Enrich
        card = await fetch_agent_card(f"https://{SIGV4_HOST}")
        _apply_agent_card(agent, card)
        assert agent.auth_type == "sigv4"

        # Override with richer config from agent.json
        auth_data = await _fetch_agent_json_auth(SIGV4_HOST)
        _apply_auth_from_metadata(agent, {"auth": auth_data})

        # Invoke
        async with AgentClient(SDKConfig(timeout_seconds=15.0)) as client:
            result = await client.invoke(
                agent,
                method="message/send",
                arguments=_a2a_payload("enrichment + invoke"),
                credentials={"profile_name": "okta-sso"},
            )

        assert result.success
        assert "Auth verified!" in str(result.data)


# ─────────────────────────────────────────────────────────
# 8. MULTI-AGENT WITH DIFFERENT AUTH
# ─────────────────────────────────────────────────────────


class TestMultiAgent:
    @pytest.mark.asyncio
    async def test_different_auth_per_agent(self) -> None:
        """Multiple agents with different auth types — SDK handles each."""
        agents = [
            _agent(PUBLIC_HOST, "public"),
            _agent(
                "httpbin.org",
                "bearer-agent",
                auth_type="bearer",
                endpoint_override="https://httpbin.org/post",
            ),
            _agent(
                SIGV4_HOST,
                "sigv4-agent",
                auth_type="sigv4",
                auth_config={"region": "us-east-1", "service": "execute-api"},
            ),
        ]

        credentials_map = {
            "public": None,
            "bearer-agent": {"token": "multi-test-token"},
            "sigv4-agent": {"profile_name": "okta-sso"},
        }

        results = {}
        async with AgentClient(SDKConfig(timeout_seconds=15.0)) as client:
            for agent in agents:
                result = await client.invoke(
                    agent,
                    method="message/send" if agent.name != "bearer-agent" else None,
                    arguments=(
                        _a2a_payload(f"hello {agent.name}")
                        if agent.name != "bearer-agent"
                        else {"test": agent.name}
                    ),
                    credentials=credentials_map[agent.name],
                )
                results[agent.name] = result

        # All should succeed
        assert results["public"].success, "Public agent failed"
        assert results["bearer-agent"].success, "Bearer agent failed"
        assert results["sigv4-agent"].success, "SigV4 agent failed"

        # Verify correct auth was applied
        assert "[PUBLIC] Echo:" in str(results["public"].data)
        assert results["bearer-agent"].data["headers"]["Authorization"] == "Bearer multi-test-token"
        assert "Auth verified!" in str(results["sigv4-agent"].data)


# ─────────────────────────────────────────────────────────
# 9. HARDENING — signal auth fields (Enhancement 2)
# ─────────────────────────────────────────────────────────


class TestSignalAuthFields:
    @pytest.mark.asyncio
    async def test_signal_records_auth_type_on_bearer(self) -> None:
        """Signal captures auth_type='bearer' and auth_applied=True."""
        agent = _agent(
            "httpbin.org",
            "signal-bearer",
            auth_type="bearer",
            endpoint_override="https://httpbin.org/post",
        )

        async with AgentClient(SDKConfig(timeout_seconds=15.0)) as client:
            result = await client.invoke(
                agent,
                method=None,
                arguments={"test": "signal"},
                credentials={"token": "signal-test-token"},
            )

        assert result.signal.auth_type == "bearer"
        assert result.signal.auth_applied is True

    @pytest.mark.asyncio
    async def test_signal_records_no_auth_on_public(self) -> None:
        """Signal has auth_applied=False for public agents."""
        agent = _agent(PUBLIC_HOST, "signal-public")

        async with AgentClient(SDKConfig(timeout_seconds=15.0)) as client:
            result = await client.invoke(
                agent,
                method="message/send",
                arguments=_a2a_payload("signal test"),
            )

        assert result.signal.auth_type is None
        assert result.signal.auth_applied is False

    @pytest.mark.asyncio
    async def test_signal_records_sigv4_auth(self) -> None:
        """Signal captures auth_type='sigv4' for IAM-authed requests."""
        agent = _agent(
            SIGV4_HOST,
            "signal-sigv4",
            auth_type="sigv4",
            auth_config={"region": "us-east-1", "service": "execute-api"},
        )

        async with AgentClient(SDKConfig(timeout_seconds=15.0)) as client:
            result = await client.invoke(
                agent,
                method="message/send",
                arguments=_a2a_payload("signal sigv4"),
                credentials={"profile_name": "okta-sso"},
            )

        assert result.success
        assert result.signal.auth_type == "sigv4"
        assert result.signal.auth_applied is True


# ─────────────────────────────────────────────────────────
# 10. ADVERSARIAL — bad actors & developer mistakes
# ─────────────────────────────────────────────────────────


class TestAdversarialAuthType:
    """Simulate malicious agent-card.json with unknown auth_type."""

    def test_malicious_auth_type_rejected(self) -> None:
        """A malicious agent.json with auth_type='evil_handler' is rejected."""
        agent = _agent(PUBLIC_HOST, "evil-agent")

        _apply_auth_from_metadata(agent, {"auth": {"type": "evil_handler", "location": "header"}})

        # Must NOT be set — unknown type rejected at discovery time
        assert agent.auth_type is None
        assert agent.auth_config is None

    def test_sql_injection_auth_type_rejected(self) -> None:
        """SQL injection attempt in auth_type is rejected."""
        agent = _agent(PUBLIC_HOST, "sqli-agent")

        _apply_auth_from_metadata(agent, {"auth": {"type": "'; DROP TABLE agents; --"}})

        assert agent.auth_type is None

    def test_empty_string_auth_type_rejected(self) -> None:
        """Empty string auth_type is rejected (falsy)."""
        agent = _agent(PUBLIC_HOST, "empty-auth")

        _apply_auth_from_metadata(agent, {"auth": {"type": ""}})

        assert agent.auth_type is None

    def test_ztaip_alias_accepted(self) -> None:
        """ZTAIP canonical names (bearer_token) are accepted."""
        agent = _agent(PUBLIC_HOST, "ztaip-agent")

        _apply_auth_from_metadata(
            agent, {"auth": {"type": "bearer_token", "header_name": "Authorization"}}
        )

        assert agent.auth_type == "bearer_token"


class TestAdversarialMissingCredentials:
    """Simulate developer mistakes with wrong/missing credentials."""

    @pytest.mark.asyncio
    async def test_error_message_includes_agent_fqdn(self) -> None:
        """ValueError from missing credentials includes agent FQDN for debugging."""
        agent = _agent(
            "httpbin.org",
            "debug-agent",
            auth_type="bearer",
            endpoint_override="https://httpbin.org/post",
        )

        async with AgentClient(SDKConfig(timeout_seconds=15.0)) as client:
            with pytest.raises(ValueError) as exc_info:
                await client.invoke(
                    agent,
                    method=None,
                    arguments={"test": "bad-creds"},
                    credentials={"wrong_key": "value"},  # missing 'token'
                )

        # Error must contain agent context for debugging
        error_msg = str(exc_info.value)
        assert "debug-agent" in error_msg or "a2a" in error_msg
        assert "bearer" in error_msg

    @pytest.mark.asyncio
    @pytest.mark.skipif(not COGNITO_CLIENT_ID, reason="DNS_AID_TEST_COGNITO_CLIENT_ID not set")
    async def test_wrong_oauth2_credentials_clear_error(self) -> None:
        """OAuth2 with bad client_secret gives clear error, not silent failure."""
        agent = _agent(
            "httpbin.org",
            "bad-oauth",
            auth_type="oauth2",
            auth_config={"oauth_discovery": COGNITO_DISCOVERY},
            endpoint_override="https://httpbin.org/post",
        )

        from dns_aid.sdk.auth.oauth2 import OAuth2TokenError

        async with AgentClient(SDKConfig(timeout_seconds=15.0)) as client:
            with pytest.raises(OAuth2TokenError, match="Token request failed"):
                await client.invoke(
                    agent,
                    method=None,
                    arguments={"test": "bad-oauth"},
                    credentials={
                        "client_id": COGNITO_CLIENT_ID,
                        "client_secret": "WRONG_SECRET_intentionally_bad",
                        "scopes": "dns-aid-api/invoke",
                    },
                )


class TestAdversarialSignature:
    """Simulate attacks on HTTP Message Signatures (Fix 2)."""

    @pytest.mark.asyncio
    async def test_signing_missing_header_raises(self) -> None:
        """Signing a covered component that's not on the request must raise."""
        from dns_aid.sdk.auth.http_msg_sig import HttpMsgSigAuthHandler
        from tests.unit.sdk.auth.test_http_msg_sig import _generate_ed25519_keypair

        pem, _ = _generate_ed25519_keypair()
        handler = HttpMsgSigAuthHandler(
            private_key_pem=pem,
            key_id="adversarial-test",
            covered_components=("@method", "@target-uri", "authorization"),
        )

        import httpx

        request = httpx.Request("POST", "https://evil.example.com/api")
        # "authorization" header is NOT present — attacker scenario
        with pytest.raises(ValueError, match="not present on the request"):
            await handler.apply(request)

    @pytest.mark.asyncio
    async def test_signing_with_present_header_succeeds(self) -> None:
        """Signing a header that IS present should work normally."""
        from dns_aid.sdk.auth.http_msg_sig import HttpMsgSigAuthHandler
        from tests.unit.sdk.auth.test_http_msg_sig import _generate_ed25519_keypair

        pem, _ = _generate_ed25519_keypair()
        handler = HttpMsgSigAuthHandler(
            private_key_pem=pem,
            key_id="good-test",
            covered_components=("@method", "x-custom"),
        )

        import httpx

        request = httpx.Request(
            "POST",
            "https://good.example.com/api",
            headers={"X-Custom": "present"},
        )
        result = await handler.apply(request)
        assert "signature" in result.headers


class TestAdversarialAgentJson:
    """Simulate malicious .well-known/agent.json responses (Fix 6)."""

    @pytest.mark.asyncio
    async def test_size_limit_on_agent_json(self) -> None:
        """Verify the size limit is enforced on agent.json responses."""
        from unittest.mock import patch

        from dns_aid.utils.url_safety import ResponseTooLargeError

        async def mock_oversized_fetch(url, **kwargs):
            raise ResponseTooLargeError(f"Response exceeded 100000 byte limit: {url}")

        with (
            patch("dns_aid.utils.url_safety.validate_fetch_url", side_effect=lambda u: u),
            patch("dns_aid.utils.url_safety.safe_fetch_bytes", side_effect=mock_oversized_fetch),
        ):
            result = await _fetch_agent_json_auth("evil-server.example.com")

        assert result is None  # Oversized response should be rejected


class TestHandlerRepr:
    """Verify __repr__ methods (Enhancement 4) — never leak secrets."""

    def test_bearer_repr_no_token(self) -> None:
        from dns_aid.sdk.auth.simple import BearerAuthHandler

        handler = BearerAuthHandler(token="super-secret-token")
        repr_str = repr(handler)

        assert "super-secret-token" not in repr_str
        assert "BearerAuthHandler" in repr_str
        assert "Authorization" in repr_str

    def test_api_key_repr_no_key(self) -> None:
        from dns_aid.sdk.auth.simple import ApiKeyAuthHandler

        handler = ApiKeyAuthHandler(api_key="sk-secret-key-123")
        repr_str = repr(handler)

        assert "sk-secret-key-123" not in repr_str
        assert "ApiKeyAuthHandler" in repr_str

    def test_oauth2_repr_no_secret(self) -> None:
        from dns_aid.sdk.auth.oauth2 import OAuth2AuthHandler

        handler = OAuth2AuthHandler(
            client_id="my-client",
            client_secret="ultra-secret",
            token_url="https://auth.example.com/token",
        )
        repr_str = repr(handler)

        assert "ultra-secret" not in repr_str
        assert "my-client" in repr_str
        assert "OAuth2AuthHandler" in repr_str

    def test_sigv4_repr(self) -> None:
        from unittest.mock import patch

        from botocore.credentials import Credentials

        test_creds = Credentials("AKID", "secret")
        with patch("boto3.Session") as mock:
            mock.return_value.get_credentials.return_value.get_frozen_credentials.return_value = (
                test_creds
            )
            from dns_aid.sdk.auth.sigv4 import SigV4AuthHandler

            handler = SigV4AuthHandler(region="us-east-1")

        repr_str = repr(handler)
        assert "secret" not in repr_str
        assert "us-east-1" in repr_str
        assert "SigV4AuthHandler" in repr_str

    def test_http_msg_sig_repr_no_key(self) -> None:
        from tests.unit.sdk.auth.test_http_msg_sig import _generate_ed25519_keypair

        pem, _ = _generate_ed25519_keypair()
        from dns_aid.sdk.auth.http_msg_sig import HttpMsgSigAuthHandler

        handler = HttpMsgSigAuthHandler(
            private_key_pem=pem,
            key_id="my-key-id",
        )
        repr_str = repr(handler)

        assert pem not in repr_str  # private key never in repr
        assert "my-key-id" in repr_str
        assert "ed25519" in repr_str
