# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""OAuth 2.0 client-credentials auth handler with token caching."""

from __future__ import annotations

import asyncio
import time

import httpx
import structlog

from dns_aid.sdk.auth.base import AuthHandler

logger = structlog.get_logger(__name__)

# Buffer before actual expiry to avoid using nearly-expired tokens.
_EXPIRY_BUFFER_SECONDS = 30


class OAuth2AuthHandler(AuthHandler):
    """OAuth 2.0 client-credentials flow with in-memory token caching.

    Thread-safe: concurrent ``apply()`` calls will not stampede the
    token endpoint — an asyncio lock serialises refresh attempts.

    Args:
        client_id: OAuth client ID.
        client_secret: OAuth client secret.
        token_url: Token endpoint URL.  When *None*, the handler
            attempts OpenID Connect discovery via *discovery_url*.
        discovery_url: ``/.well-known/openid-configuration`` URL.
            Used to resolve *token_url* when not provided explicitly.
        scopes: Space-separated scopes to request (optional).
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        *,
        token_url: str | None = None,
        discovery_url: str | None = None,
        scopes: str | None = None,
    ) -> None:
        if not token_url and not discovery_url:
            raise ValueError("Either token_url or discovery_url must be provided")
        self._client_id = client_id
        self._client_secret = client_secret
        self._token_url = token_url
        self._discovery_url = discovery_url
        self._scopes = scopes

        # Cached token state
        self._access_token: str | None = None
        self._expires_at: float = 0.0
        self._lock = asyncio.Lock()

    @property
    def auth_type(self) -> str:
        return "oauth2"

    def __repr__(self) -> str:
        return f"OAuth2AuthHandler(client_id={self._client_id!r}, token_url={self._token_url!r})"

    async def apply(self, request: httpx.Request) -> httpx.Request:
        token = await self._get_token()
        request.headers["Authorization"] = f"Bearer {token}"
        return request

    async def _get_token(self) -> str:
        """Return a cached token or fetch a new one (lock-protected)."""
        # Fast path: token is valid
        if self._access_token and time.monotonic() < self._expires_at:
            return self._access_token

        async with self._lock:
            # Double-check after acquiring lock (another coroutine may have refreshed)
            if self._access_token and time.monotonic() < self._expires_at:
                return self._access_token

            # Resolve token URL from discovery if needed
            token_url = self._token_url or await self._discover_token_url()

            # SSRF protection: validate token URL before sending credentials.
            # token_url may come from untrusted agent metadata (oauth_discovery).
            try:
                from dns_aid.utils.url_safety import UnsafeURLError, validate_fetch_url_async

                await validate_fetch_url_async(token_url)
            except UnsafeURLError as e:
                raise OAuth2TokenError(f"Token URL blocked by SSRF protection: {e}") from e

            async with httpx.AsyncClient(timeout=10.0) as client:
                data: dict[str, str] = {
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                }
                if self._scopes:
                    data["scope"] = self._scopes

                resp = await client.post(token_url, data=data)
                if resp.status_code >= 400:
                    body_preview = resp.text[:200] if resp.text else "(empty)"
                    logger.warning(
                        "oauth2.token_request_failed",
                        token_url=token_url,
                        status_code=resp.status_code,
                        body=body_preview,
                    )
                    raise OAuth2TokenError(
                        f"Token request failed: HTTP {resp.status_code}: {body_preview}"
                    )
                body = resp.json()

            access_token = body.get("access_token")
            if not access_token:
                raise OAuth2TokenError("Token response missing 'access_token' field")

            self._access_token = access_token
            expires_in = int(body.get("expires_in", 3600))
            self._expires_at = time.monotonic() + expires_in - _EXPIRY_BUFFER_SECONDS

            logger.debug(
                "oauth2.token_fetched",
                token_url=token_url,
                expires_in=expires_in,
            )
            return self._access_token

    async def _discover_token_url(self) -> str:
        """Fetch token endpoint from OpenID Connect discovery."""
        if not self._discovery_url:
            raise ValueError("No token_url or discovery_url configured")

        # SSRF protection: discovery_url may come from untrusted agent metadata.
        try:
            from dns_aid.utils.url_safety import UnsafeURLError, validate_fetch_url_async

            await validate_fetch_url_async(self._discovery_url)
        except UnsafeURLError as e:
            raise OAuth2TokenError(f"Discovery URL blocked by SSRF protection: {e}") from e

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(self._discovery_url)
            if resp.status_code >= 400:
                raise OAuth2TokenError(f"OIDC discovery failed: HTTP {resp.status_code}")
            config = resp.json()

        token_endpoint = config.get("token_endpoint")
        if not token_endpoint:
            raise ValueError(f"No token_endpoint found in OIDC discovery at {self._discovery_url}")

        # SSRF protection: the token_endpoint comes from an untrusted OIDC
        # response — a malicious discovery server could redirect credentials
        # to an internal host (e.g., cloud metadata at 169.254.169.254).
        try:
            await validate_fetch_url_async(token_endpoint)
        except UnsafeURLError as e:
            raise OAuth2TokenError(
                f"Discovered token_endpoint blocked by SSRF protection: {e}"
            ) from e

        # Cache the resolved URL for future calls
        self._token_url = token_endpoint
        logger.debug("oauth2.discovery_resolved", token_url=token_endpoint)
        return token_endpoint


class OAuth2TokenError(Exception):
    """Raised when OAuth2 token acquisition fails."""
