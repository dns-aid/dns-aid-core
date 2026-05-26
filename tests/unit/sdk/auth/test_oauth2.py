# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for OAuth2 client-credentials auth handler."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from dns_aid.sdk.auth.oauth2 import OAuth2AuthHandler, OAuth2TokenError

_noop_validate = lambda url: url  # noqa: E731


@pytest.fixture(autouse=True)
def _bypass_ssrf(request):
    """Bypass SSRF validation for tests using fake hostnames.

    Skips for tests marked with ``real_ssrf`` — those test the actual
    SSRF protection and need the real ``validate_fetch_url``.
    """
    if "real_ssrf" in {m.name for m in request.node.iter_markers()}:
        yield
    else:
        with patch("dns_aid.utils.url_safety.validate_fetch_url", side_effect=_noop_validate):
            yield


@pytest.fixture
def request_obj() -> httpx.Request:
    return httpx.Request(
        "POST",
        "https://agent.example.com/mcp",
        json={"method": "tools/list"},
    )


@pytest.fixture
def token_response() -> dict:
    return {
        "access_token": "eyJ0b2tlbiI6InRlc3QifQ",
        "token_type": "bearer",
        "expires_in": 3600,
    }


@pytest.fixture
def discovery_response() -> dict:
    return {
        "token_endpoint": "https://auth.example.com/oauth/token",
        "issuer": "https://auth.example.com",
    }


class TestOAuth2AuthHandler:
    def test_requires_token_url_or_discovery(self) -> None:
        with pytest.raises(ValueError, match="Either token_url or discovery_url"):
            OAuth2AuthHandler(
                client_id="id",
                client_secret="secret",
            )

    @pytest.mark.asyncio
    async def test_fetches_and_applies_token(
        self, request_obj: httpx.Request, token_response: dict
    ) -> None:
        mock_resp = httpx.Response(200, json=token_response)

        handler = OAuth2AuthHandler(
            client_id="my-client",
            client_secret="my-secret",
            token_url="https://auth.example.com/oauth/token",
        )

        with patch("dns_aid.sdk.auth.oauth2.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            result = await handler.apply(request_obj)

        assert result.headers["Authorization"] == "Bearer eyJ0b2tlbiI6InRlc3QifQ"

    @pytest.mark.asyncio
    async def test_caches_token(self, request_obj: httpx.Request, token_response: dict) -> None:
        mock_resp = httpx.Response(200, json=token_response)

        handler = OAuth2AuthHandler(
            client_id="id",
            client_secret="secret",
            token_url="https://auth.example.com/oauth/token",
        )

        with patch("dns_aid.sdk.auth.oauth2.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            await handler.apply(request_obj)
            await handler.apply(request_obj)

            # Token endpoint called only once (cached)
            assert mock_client.post.call_count == 1

    @pytest.mark.asyncio
    async def test_refreshes_expired_token(self, request_obj: httpx.Request) -> None:
        resp1 = httpx.Response(
            200,
            json={
                "access_token": "token-1",
                "expires_in": 1,  # Expires almost immediately
            },
        )
        resp2 = httpx.Response(
            200,
            json={
                "access_token": "token-2",
                "expires_in": 3600,
            },
        )

        handler = OAuth2AuthHandler(
            client_id="id",
            client_secret="secret",
            token_url="https://auth.example.com/oauth/token",
        )

        with patch("dns_aid.sdk.auth.oauth2.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(side_effect=[resp1, resp2])
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            r1 = await handler.apply(request_obj)
            assert r1.headers["Authorization"] == "Bearer token-1"

            # Force expiry (token expires_in=1 minus 30s buffer = already expired)
            handler._expires_at = time.monotonic() - 1

            r2 = await handler.apply(request_obj)
            assert r2.headers["Authorization"] == "Bearer token-2"
            assert mock_client.post.call_count == 2

    @pytest.mark.asyncio
    async def test_oidc_discovery(
        self,
        request_obj: httpx.Request,
        token_response: dict,
        discovery_response: dict,
    ) -> None:
        handler = OAuth2AuthHandler(
            client_id="id",
            client_secret="secret",
            discovery_url="https://auth.example.com/.well-known/openid-configuration",
        )

        mock_disc_resp = httpx.Response(200, json=discovery_response)
        mock_token_resp = httpx.Response(200, json=token_response)

        with patch("dns_aid.sdk.auth.oauth2.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_disc_resp)
            mock_client.post = AsyncMock(return_value=mock_token_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            result = await handler.apply(request_obj)

        assert result.headers["Authorization"].startswith("Bearer ")

    def test_auth_type(self) -> None:
        handler = OAuth2AuthHandler(
            client_id="id",
            client_secret="secret",
            token_url="https://auth.example.com/token",
        )
        assert handler.auth_type == "oauth2"


class TestOAuth2SSRFProtection:
    """SSRF protection — prevent credential exfiltration to internal hosts."""

    @pytest.mark.real_ssrf
    @pytest.mark.asyncio
    async def test_token_url_ssrf_blocked(self, request_obj: httpx.Request) -> None:
        """Token URL pointing to private IP must be rejected."""
        handler = OAuth2AuthHandler(
            client_id="id",
            client_secret="secret",
            token_url="https://169.254.169.254/latest/meta-data/",
        )

        with pytest.raises(OAuth2TokenError, match="SSRF protection"):
            await handler.apply(request_obj)

    @pytest.mark.real_ssrf
    @pytest.mark.asyncio
    async def test_discovery_url_ssrf_blocked(self, request_obj: httpx.Request) -> None:
        """Discovery URL pointing to non-HTTPS scheme must be rejected."""
        handler = OAuth2AuthHandler(
            client_id="id",
            client_secret="secret",
            discovery_url="http://10.0.0.1/.well-known/openid-configuration",
        )

        with pytest.raises(OAuth2TokenError, match="SSRF protection"):
            await handler.apply(request_obj)

    @pytest.mark.asyncio
    async def test_discovered_token_endpoint_ssrf_blocked(self, request_obj: httpx.Request) -> None:
        """A legit discovery URL that returns a malicious token_endpoint must be rejected."""
        from dns_aid.utils.url_safety import UnsafeURLError

        handler = OAuth2AuthHandler(
            client_id="id",
            client_secret="secret",
            discovery_url="https://legit-auth.example.com/.well-known/openid-configuration",
        )

        # Discovery response points token_endpoint at cloud metadata
        malicious_discovery = {
            "token_endpoint": "https://169.254.169.254/latest/meta-data/",
            "issuer": "https://legit-auth.example.com",
        }
        mock_disc_resp = httpx.Response(200, json=malicious_discovery)

        def ssrf_check(url: str) -> str:
            """Allow the discovery URL, block the malicious token_endpoint."""
            if "169.254" in url:
                raise UnsafeURLError(f"URL resolves to non-public IP: {url}")
            return url

        with patch("dns_aid.utils.url_safety.validate_fetch_url", side_effect=ssrf_check):
            with patch("dns_aid.sdk.auth.oauth2.httpx.AsyncClient") as mock_cls:
                mock_client = AsyncMock()
                mock_client.get = AsyncMock(return_value=mock_disc_resp)
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_cls.return_value = mock_client

                with pytest.raises(OAuth2TokenError, match="token_endpoint blocked"):
                    await handler.apply(request_obj)
