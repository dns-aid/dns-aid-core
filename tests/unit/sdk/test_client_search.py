# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Tests for ``AgentClient.search()`` — Path B cross-domain agent search.

Validates the full HTTP contract:
- happy path: request URL, query params, response deserialization
- configuration: ``DirectoryConfigError`` when ``directory_api_url`` is unset
- transient failures: connect errors, 5xx, 4xx → ``DirectoryUnavailableError``
- rate limit: 429 → ``DirectoryRateLimitedError`` carrying ``retry_after_seconds``
- auth failures: 401/403 → ``DirectoryAuthError``
- schema drift: response Pydantic validation failure → ``DirectoryUnavailableError``
- isolation: ``search()`` failure paths do not corrupt the client for subsequent calls

All tests are offline (no live HTTP) using ``unittest.mock`` to stub ``AsyncClient.get``.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.client import AgentClient
from dns_aid.sdk.exceptions import (
    DirectoryAuthError,
    DirectoryConfigError,
    DirectoryRateLimitedError,
    DirectoryUnavailableError,
)
from dns_aid.sdk.search import SearchResponse


def _agent_payload(name: str = "payments", domain: str = "example.com") -> dict[str, Any]:
    """Build a directory-shaped agent payload with flat trust + provenance signals.

    Mirrors ``dns_aid_directory.api.schemas.AgentResponse`` exactly: uses
    ``endpoint_url`` (no ``target_host``), encodes ``bap`` as a comma-separated
    string, and carries trust scores + verification flags + provenance flat on
    the agent. The SDK's ``_adapt_search_payload`` lifts these into typed nested
    objects before Pydantic validation.
    """
    return {
        "fqdn": f"_{name}._mcp._agents.{domain}",
        "name": name,
        "domain": domain,
        "protocol": "mcp",
        "endpoint_url": f"https://{name}.{domain}",
        "port": 443,
        "capabilities": ["payment-processing"],
        "bap": "mcp=1.0",
        # Trust signals flat on the agent (directory contract).
        "security_score": 80,
        "trust_score": 75,
        "popularity_score": 60,
        "trust_tier": 2,
        "safety_status": "active",
        "dnssec_valid": True,
        "dane_valid": False,
        "svcb_valid": True,
        "endpoint_reachable": True,
        "protocol_verified": True,
        "threat_flags": {},
        "trust_breakdown": {"dnssec": 1.0, "tls_strength": 0.9},
        "trust_badges": ["Verified"],
        # Provenance signals flat on the agent (directory contract).
        "discovery_level": 2,
        "first_seen": "2026-01-01T00:00:00Z",
        "last_seen": "2026-05-01T00:00:00Z",
        "last_verified": "2026-04-30T00:00:00Z",
    }


def _success_body(
    *,
    results: int = 1,
    total: int = 1,
    limit: int = 20,
    offset: int = 0,
    query: str = "payments",
) -> dict[str, Any]:
    """Build a directory-shaped /api/v1/search response body."""
    return {
        "query": query,
        "results": [
            {
                "agent": _agent_payload(name=f"agent{i}"),
                # Directory uses raw scores (not normalized to 0..1).
                "score": 39.2 - (i * 0.1),
            }
            for i in range(results)
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


def _mock_response(
    status_code: int,
    *,
    body: Any = None,
    headers: dict[str, str] | None = None,
) -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.headers = headers or {}
    resp.json = MagicMock(return_value=body)
    resp.text = "" if body is None else str(body)
    return resp


@pytest.fixture
def public_directory_url(monkeypatch: pytest.MonkeyPatch) -> str:
    """Use the URL allowlist so SSRF validation accepts our test hostname offline."""
    url = "https://directory.test.example/"
    monkeypatch.setenv("DNS_AID_FETCH_ALLOWLIST", "directory.test.example")
    return url


class TestNotConfigured:
    @pytest.mark.asyncio
    async def test_raises_config_error_when_directory_url_missing(self) -> None:
        config = SDKConfig()
        async with AgentClient(config=config) as client:
            with pytest.raises(DirectoryConfigError) as exc_info:
                await client.search(q="anything")
        assert exc_info.value.details["missing_field"] == "directory_api_url"
        assert exc_info.value.details["env_var"] == "DNS_AID_SDK_DIRECTORY_API_URL"

    @pytest.mark.asyncio
    async def test_raises_runtime_error_outside_context_manager(self) -> None:
        config = SDKConfig(directory_api_url="https://directory.example.com")
        client = AgentClient(config=config)
        with pytest.raises(RuntimeError, match="async context manager"):
            await client.search(q="x")


class TestHappyPath:
    @pytest.mark.asyncio
    async def test_returns_typed_search_response(self, public_directory_url: str) -> None:
        config = SDKConfig(directory_api_url=public_directory_url)
        async with AgentClient(config=config) as client:
            assert client._http_client is not None
            client._http_client.get = AsyncMock(  # type: ignore[method-assign]
                return_value=_mock_response(200, body=_success_body(results=2, total=5))
            )
            response = await client.search(q="payments", limit=20)

        assert isinstance(response, SearchResponse)
        assert response.total == 5
        assert len(response.results) == 2
        assert response.results[0].agent.name == "agent0"
        assert response.has_more is True
        assert response.next_offset == 2

    @pytest.mark.asyncio
    async def test_serializes_all_filter_kwargs_to_query_params(
        self, public_directory_url: str
    ) -> None:
        config = SDKConfig(directory_api_url=public_directory_url)
        async with AgentClient(config=config) as client:
            assert client._http_client is not None
            captured: dict[str, Any] = {}

            async def fake_get(url: str, params: Any = None, **kwargs: Any) -> MagicMock:
                captured["url"] = url
                captured["params"] = params
                return _mock_response(200, body=_success_body())

            client._http_client.get = fake_get  # type: ignore[method-assign]
            await client.search(
                q="payments",
                protocol="mcp",
                domain="ACME.example",
                capabilities=["payment-processing", "fraud-detection"],
                min_security_score=70,
                verified_only=True,
                intent="transaction",
                auth_type="oauth2",
                transport="streamable-http",
                realm="prod",
                limit=10,
                offset=20,
            )

        assert captured["url"].endswith("/api/v1/search")
        params: list[tuple[str, Any]] = captured["params"]
        param_keys = [k for k, _ in params]
        assert ("q", "payments") in params
        assert ("protocol", "mcp") in params
        # Domain MUST be lowercased on the wire.
        assert ("domain", "acme.example") in params
        # Capabilities is repeatable.
        assert param_keys.count("capabilities") == 2
        assert ("min_security_score", "70") in params
        assert ("verified_only", "true") in params
        assert ("limit", "10") in params
        assert ("offset", "20") in params

    @pytest.mark.asyncio
    async def test_omits_unset_optional_params(self, public_directory_url: str) -> None:
        config = SDKConfig(directory_api_url=public_directory_url)
        async with AgentClient(config=config) as client:
            assert client._http_client is not None
            captured: dict[str, Any] = {}

            async def fake_get(url: str, params: Any = None, **kwargs: Any) -> MagicMock:
                captured["params"] = params
                return _mock_response(200, body=_success_body())

            client._http_client.get = fake_get  # type: ignore[method-assign]
            await client.search()

        param_keys = [k for k, _ in captured["params"]]
        assert "q" not in param_keys
        assert "protocol" not in param_keys
        assert "verified_only" not in param_keys
        # limit and offset always sent so the directory has a deterministic page.
        assert "limit" in param_keys
        assert "offset" in param_keys


class TestErrorMapping:
    @pytest.mark.asyncio
    async def test_connect_error_maps_to_unavailable(self, public_directory_url: str) -> None:
        config = SDKConfig(directory_api_url=public_directory_url)
        async with AgentClient(config=config) as client:
            assert client._http_client is not None
            client._http_client.get = AsyncMock(  # type: ignore[method-assign]
                side_effect=httpx.ConnectError("connection refused")
            )
            with pytest.raises(DirectoryUnavailableError) as exc_info:
                await client.search(q="x")

        assert exc_info.value.details["status_code"] is None
        assert exc_info.value.details["underlying"] == "ConnectError"

    @pytest.mark.asyncio
    async def test_500_maps_to_unavailable(self, public_directory_url: str) -> None:
        config = SDKConfig(directory_api_url=public_directory_url)
        async with AgentClient(config=config) as client:
            assert client._http_client is not None
            client._http_client.get = AsyncMock(  # type: ignore[method-assign]
                return_value=_mock_response(500, body={"error": "internal"})
            )
            with pytest.raises(DirectoryUnavailableError) as exc_info:
                await client.search(q="x")

        assert exc_info.value.details["status_code"] == 500

    @pytest.mark.asyncio
    async def test_404_maps_to_unavailable(self, public_directory_url: str) -> None:
        config = SDKConfig(directory_api_url=public_directory_url)
        async with AgentClient(config=config) as client:
            assert client._http_client is not None
            client._http_client.get = AsyncMock(  # type: ignore[method-assign]
                return_value=_mock_response(404)
            )
            with pytest.raises(DirectoryUnavailableError) as exc_info:
                await client.search(q="x")

        assert exc_info.value.details["status_code"] == 404

    @pytest.mark.asyncio
    async def test_429_maps_to_rate_limited_with_retry_after(
        self, public_directory_url: str
    ) -> None:
        config = SDKConfig(directory_api_url=public_directory_url)
        async with AgentClient(config=config) as client:
            assert client._http_client is not None
            client._http_client.get = AsyncMock(  # type: ignore[method-assign]
                return_value=_mock_response(429, headers={"Retry-After": "30"})
            )
            with pytest.raises(DirectoryRateLimitedError) as exc_info:
                await client.search(q="x")

        # Specific subclass; also covered by base catch.
        assert isinstance(exc_info.value, DirectoryUnavailableError)
        assert exc_info.value.details["retry_after_seconds"] == 30

    @pytest.mark.asyncio
    async def test_429_with_unparseable_retry_after(self, public_directory_url: str) -> None:
        config = SDKConfig(directory_api_url=public_directory_url)
        async with AgentClient(config=config) as client:
            assert client._http_client is not None
            client._http_client.get = AsyncMock(  # type: ignore[method-assign]
                return_value=_mock_response(
                    429, headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}
                )
            )
            with pytest.raises(DirectoryRateLimitedError) as exc_info:
                await client.search(q="x")

        # HTTP-date format is intentionally not parsed; retry policy is caller's choice.
        assert exc_info.value.details["retry_after_seconds"] is None

    @pytest.mark.asyncio
    async def test_401_maps_to_auth_error(self, public_directory_url: str) -> None:
        config = SDKConfig(directory_api_url=public_directory_url)
        async with AgentClient(config=config) as client:
            assert client._http_client is not None
            client._http_client.get = AsyncMock(  # type: ignore[method-assign]
                return_value=_mock_response(401)
            )
            with pytest.raises(DirectoryAuthError) as exc_info:
                await client.search(q="x")

        assert exc_info.value.details["status_code"] == 401
        # Auth errors are NOT transient: must NOT inherit from Unavailable.
        assert not isinstance(exc_info.value, DirectoryUnavailableError)

    @pytest.mark.asyncio
    async def test_403_maps_to_auth_error(self, public_directory_url: str) -> None:
        config = SDKConfig(directory_api_url=public_directory_url)
        async with AgentClient(config=config) as client:
            assert client._http_client is not None
            client._http_client.get = AsyncMock(  # type: ignore[method-assign]
                return_value=_mock_response(403)
            )
            with pytest.raises(DirectoryAuthError):
                await client.search(q="x")

    @pytest.mark.asyncio
    async def test_malformed_response_body_maps_to_unavailable(
        self, public_directory_url: str
    ) -> None:
        config = SDKConfig(directory_api_url=public_directory_url)
        async with AgentClient(config=config) as client:
            assert client._http_client is not None
            # Body missing required ``query`` key — Pydantic ValidationError.
            client._http_client.get = AsyncMock(  # type: ignore[method-assign]
                return_value=_mock_response(200, body={"results": [], "total": 0})
            )
            with pytest.raises(DirectoryUnavailableError) as exc_info:
                await client.search(q="x")

        # Explicit signal that the directory's response shape was not recognized.
        assert "ValidationError" in str(exc_info.value.details["underlying"])


class TestSecurityGuards:
    """Security regressions: redirect rejection, response size guard, userinfo
    rejection. Each is a defense the SDK adds beyond what httpx provides natively.
    """

    @pytest.mark.asyncio
    async def test_3xx_redirect_rejected_with_clear_error(self, public_directory_url: str) -> None:
        # follow_redirects=False is set on the search call; a directory that
        # responds with a redirect is misconfigured. Surface that explicitly
        # instead of letting the body parse fail with a confusing JSON error.
        config = SDKConfig(directory_api_url=public_directory_url)
        async with AgentClient(config=config) as client:
            assert client._http_client is not None
            client._http_client.get = AsyncMock(  # type: ignore[method-assign]
                return_value=_mock_response(302, headers={"Location": "https://internal.local/"})
            )
            with pytest.raises(DirectoryUnavailableError) as exc_info:
                await client.search(q="x")

        assert exc_info.value.details["status_code"] == 302
        assert exc_info.value.details["underlying"] == "UnexpectedRedirect"

    @pytest.mark.asyncio
    async def test_oversized_response_rejected_before_json_parse(
        self, public_directory_url: str
    ) -> None:
        # The SDK refuses to parse responses bigger than _SEARCH_MAX_RESPONSE_BYTES,
        # protecting against directory bugs (e.g. forgot pagination) returning
        # a multi-GB body.
        config = SDKConfig(directory_api_url=public_directory_url)
        async with AgentClient(config=config) as client:
            assert client._http_client is not None

            # Build a Mock response whose ``content`` exceeds the cap. We don't
            # actually need 10 MB of bytes — bypass via ``len()`` patching.
            from unittest.mock import PropertyMock

            from dns_aid.sdk.client import _SEARCH_MAX_RESPONSE_BYTES

            oversized = MagicMock(spec=httpx.Response)
            oversized.status_code = 200
            oversized.headers = {}
            type(oversized).content = PropertyMock(
                return_value=b"x" * (_SEARCH_MAX_RESPONSE_BYTES + 1)
            )

            client._http_client.get = AsyncMock(  # type: ignore[method-assign]
                return_value=oversized
            )
            with pytest.raises(DirectoryUnavailableError) as exc_info:
                await client.search(q="x")

        assert exc_info.value.details["underlying"] == "ResponseTooLarge"
        assert exc_info.value.details["body_bytes"] == _SEARCH_MAX_RESPONSE_BYTES + 1

    @pytest.mark.asyncio
    async def test_userinfo_in_directory_url_rejected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # SDKConfig allows constructing a config with creds-in-URL (the rejection
        # happens at validate_fetch_url inside search()) — but the search call
        # MUST surface DirectoryUnavailableError without ever logging or echoing
        # the password.
        monkeypatch.setenv("DNS_AID_FETCH_ALLOWLIST", "directory.test.example")
        config = SDKConfig(directory_api_url="https://igor:s3cret@directory.test.example/")
        async with AgentClient(config=config) as client:
            with pytest.raises(DirectoryUnavailableError) as exc_info:
                await client.search(q="x")

        # Critical: the password must NOT appear in any user-visible field.
        details = exc_info.value.details
        assert "s3cret" not in str(exc_info.value)
        assert "s3cret" not in str(details.get("directory_url", ""))
        # And the redacted URL retains scheme + host so callers can still
        # identify which directory failed.
        assert "directory.test.example" in str(details.get("directory_url", ""))


class TestPathIsolation:
    """Search failures must not corrupt the client for subsequent calls."""

    @pytest.mark.asyncio
    async def test_failure_then_success_on_same_client(self, public_directory_url: str) -> None:
        config = SDKConfig(directory_api_url=public_directory_url)
        async with AgentClient(config=config) as client:
            assert client._http_client is not None

            # Round 1: 500 error.
            client._http_client.get = AsyncMock(  # type: ignore[method-assign]
                return_value=_mock_response(500)
            )
            with pytest.raises(DirectoryUnavailableError):
                await client.search(q="x")

            # Round 2: success on the same client instance.
            client._http_client.get = AsyncMock(  # type: ignore[method-assign]
                return_value=_mock_response(200, body=_success_body())
            )
            response = await client.search(q="x")
            assert isinstance(response, SearchResponse)
            assert response.total == 1


class TestSSRFGuard:
    @pytest.mark.asyncio
    async def test_unsafe_directory_url_raises_unavailable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("DNS_AID_FETCH_ALLOWLIST", raising=False)
        # Localhost / loopback resolves to 127.0.0.1 → should be rejected by url_safety.
        config = SDKConfig(directory_api_url="https://localhost/")
        async with AgentClient(config=config) as client:
            with pytest.raises(DirectoryUnavailableError) as exc_info:
                await client.search(q="x")
        assert exc_info.value.details["underlying"] == "UnsafeURLError"
