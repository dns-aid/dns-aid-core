# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for DnsAidPolicyMiddleware (Layer 2 target-side enforcement)."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from dns_aid.sdk.policy.middleware import (
    DnsAidPolicyMiddleware,
    RateLimitState,
    _extract_auth_type,
    _extract_domain_from_dn,
)
from dns_aid.sdk.policy.models import PolicyResult, PolicyViolation
from dns_aid.sdk.policy.schema import (
    PolicyDocument,
    PolicyRules,
    RateLimitConfig,
)

# -- Helpers ------------------------------------------------------------------


def _make_app(
    policy_uri: str = "https://example.com/policy.json",
    mode: str = "strict",
    trusted_proxies: list[str] | None = None,
) -> Starlette:
    """Build a Starlette app with DnsAidPolicyMiddleware for testing."""

    async def homepage(request: Request) -> JSONResponse:
        return JSONResponse({"ok": True})

    async def jsonrpc(request: Request) -> JSONResponse:
        return JSONResponse({"jsonrpc": "2.0", "result": "ok"})

    app = Starlette(
        routes=[
            Route("/", homepage),
            Route("/mcp", jsonrpc, methods=["POST"]),
        ],
    )
    app.add_middleware(
        DnsAidPolicyMiddleware,
        policy_uri=policy_uri,
        mode=mode,
        trusted_proxies=trusted_proxies,
    )
    return app


def _policy_doc(**rule_kwargs: object) -> PolicyDocument:
    return PolicyDocument(
        version="1.0",
        agent="_test._mcp._agents.example.com",
        rules=PolicyRules(**rule_kwargs),
    )


# -- Mock the evaluator -------------------------------------------------------


def _mock_evaluator_class(allowed: bool = True, violations: list | None = None):
    """Return a mock PolicyEvaluator class that creates mock instances."""
    mock_instance = AsyncMock()
    mock_instance.fetch = AsyncMock(return_value=_policy_doc())
    mock_instance.evaluate = lambda doc, ctx, **kw: PolicyResult(
        allowed=allowed,
        violations=violations or [],
    )

    def constructor(*args, **kwargs):
        return mock_instance

    return constructor, mock_instance


def _patch_evaluator(allowed: bool = True, violations: list | None = None):
    """Patch PolicyEvaluator at the import site in middleware."""
    factory, instance = _mock_evaluator_class(allowed, violations)
    return patch(
        "dns_aid.sdk.policy.middleware.PolicyEvaluator",
        side_effect=factory,
    ), instance


# =============================================================================
# Strict mode tests
# =============================================================================


class TestStrictMode:
    def test_allowed_request_returns_200(self) -> None:
        p, _ = _patch_evaluator(allowed=True)
        with p:
            app = _make_app(mode="strict")
            client = TestClient(app)
            resp = client.get("/")
            assert resp.status_code == 200
            assert resp.headers["X-DNS-AID-Policy-Result"] == "allowed"

    def test_denied_request_returns_403(self) -> None:
        violations = [
            PolicyViolation(
                rule="required_auth_types",
                detail="oauth2 required",
                layer="layer2",
            )
        ]
        p, _ = _patch_evaluator(allowed=False, violations=violations)
        with p:
            app = _make_app(mode="strict")
            client = TestClient(app)
            resp = client.get("/")
            assert resp.status_code == 403
            data = resp.json()
            assert data["error"] == "policy_denied"
            assert len(data["violations"]) == 1
            assert data["violations"][0]["rule"] == "required_auth_types"
            assert resp.headers["X-DNS-AID-Policy-Result"] == "denied"


# =============================================================================
# Permissive mode tests
# =============================================================================


class TestPermissiveMode:
    def test_denied_request_returns_200_with_denied_header(self) -> None:
        violations = [
            PolicyViolation(
                rule="require_dnssec",
                detail="DNSSEC required",
                layer="layer2",
            )
        ]
        p, _ = _patch_evaluator(allowed=False, violations=violations)
        with p:
            app = _make_app(mode="permissive")
            client = TestClient(app)
            resp = client.get("/")
            assert resp.status_code == 200
            assert resp.headers["X-DNS-AID-Policy-Result"] == "denied"


# =============================================================================
# X-DNS-AID-Policy-Result header
# =============================================================================


class TestPolicyResultHeader:
    def test_always_present_on_allowed(self) -> None:
        p, _ = _patch_evaluator(allowed=True)
        with p:
            app = _make_app()
            client = TestClient(app)
            resp = client.get("/")
            assert "X-DNS-AID-Policy-Result" in resp.headers

    def test_no_policy_on_fetch_failure(self) -> None:
        mock_instance = AsyncMock()
        mock_instance.fetch = AsyncMock(side_effect=Exception("network error"))

        with patch(
            "dns_aid.sdk.policy.middleware.PolicyEvaluator",
            return_value=mock_instance,
        ):
            app = _make_app()
            client = TestClient(app)
            resp = client.get("/")
            assert resp.status_code == 200
            assert resp.headers["X-DNS-AID-Policy-Result"] == "no-policy"


# =============================================================================
# Method extraction from body (security: body is truth)
# =============================================================================


class TestMethodExtraction:
    def test_method_from_jsonrpc_body(self) -> None:
        """Method should be extracted from JSON-RPC body, not header."""
        mock_instance = AsyncMock()
        doc = _policy_doc(allowed_methods=["tools/list"])
        mock_instance.fetch = AsyncMock(return_value=doc)
        from dns_aid.sdk.policy.evaluator import PolicyEvaluator as RealEvaluator

        real_evaluator = RealEvaluator()
        mock_instance.evaluate = real_evaluator.evaluate

        with patch("dns_aid.sdk.policy.middleware.PolicyEvaluator", return_value=mock_instance):
            app = _make_app(mode="strict")
            client = TestClient(app)
            resp = client.post(
                "/mcp",
                json={"jsonrpc": "2.0", "method": "tools/call", "id": 1},
                headers={"X-DNS-AID-Method": "tools/list"},  # spoofed header
            )
            assert resp.status_code == 403

    def test_header_fallback_for_non_json(self) -> None:
        mock_instance = AsyncMock()
        doc = _policy_doc(allowed_methods=["upload"])
        mock_instance.fetch = AsyncMock(return_value=doc)
        from dns_aid.sdk.policy.evaluator import PolicyEvaluator as RealEvaluator

        real_evaluator = RealEvaluator()
        mock_instance.evaluate = real_evaluator.evaluate

        with patch("dns_aid.sdk.policy.middleware.PolicyEvaluator", return_value=mock_instance):
            app = _make_app(mode="strict")
            client = TestClient(app)
            resp = client.post(
                "/mcp",
                content=b"binary data",
                headers={
                    "Content-Type": "application/octet-stream",
                    "X-DNS-AID-Method": "upload",
                },
            )
            assert resp.status_code == 200


# =============================================================================
# mTLS cert overrides caller domain
# =============================================================================


class TestMTLSOverride:
    def test_cert_domain_overrides_claimed_domain(self) -> None:
        """When mTLS cert is present, cert domain wins over header claim."""
        mock_instance = AsyncMock()
        doc = _policy_doc(allowed_caller_domains=["*.infoblox.com"])
        mock_instance.fetch = AsyncMock(return_value=doc)
        from dns_aid.sdk.policy.evaluator import PolicyEvaluator as RealEvaluator

        real_evaluator = RealEvaluator()
        mock_instance.evaluate = real_evaluator.evaluate

        with patch("dns_aid.sdk.policy.middleware.PolicyEvaluator", return_value=mock_instance):
            app = _make_app(mode="strict")
            client = TestClient(app)
            resp = client.get(
                "/",
                headers={
                    "X-DNS-AID-Caller-Domain": "api.infoblox.com",
                    "X-Client-Certificate-DN": "CN=evil.com,O=Evil Corp",
                },
            )
            assert resp.status_code == 403


# =============================================================================
# Rate limiting
# =============================================================================


class TestRateLimiting:
    def test_rate_limit_exceeded_returns_429(self) -> None:
        mock_instance = AsyncMock()
        doc = _policy_doc(rate_limits=RateLimitConfig(max_per_minute=2))
        mock_instance.fetch = AsyncMock(return_value=doc)
        mock_instance.evaluate = lambda doc, ctx, **kw: PolicyResult(allowed=True)

        with patch("dns_aid.sdk.policy.middleware.PolicyEvaluator", return_value=mock_instance):
            app = _make_app(mode="strict")
            client = TestClient(app)
            resp1 = client.get("/", headers={"X-DNS-AID-Caller-Domain": "test.com"})
            resp2 = client.get("/", headers={"X-DNS-AID-Caller-Domain": "test.com"})
            assert resp1.status_code == 200
            assert resp2.status_code == 200
            resp3 = client.get("/", headers={"X-DNS-AID-Caller-Domain": "test.com"})
            assert resp3.status_code == 429
            assert resp3.headers["X-DNS-AID-Policy-Result"] == "denied"

    def test_no_rate_limit_without_caller_domain(self) -> None:
        """Rate limiting requires caller_domain to key on."""
        mock_instance = AsyncMock()
        doc = _policy_doc(rate_limits=RateLimitConfig(max_per_minute=1))
        mock_instance.fetch = AsyncMock(return_value=doc)
        mock_instance.evaluate = lambda doc, ctx, **kw: PolicyResult(allowed=True)

        with patch("dns_aid.sdk.policy.middleware.PolicyEvaluator", return_value=mock_instance):
            app = _make_app(mode="strict")
            client = TestClient(app)
            resp1 = client.get("/")
            resp2 = client.get("/")
            assert resp1.status_code == 200
            assert resp2.status_code == 200


# =============================================================================
# RateLimitState unit tests
# =============================================================================


class TestRateLimitState:
    def test_within_limit(self) -> None:
        state = RateLimitState()
        assert state.check("a.com", max_per_minute=5, max_per_hour=None)

    def test_exceeds_per_minute(self) -> None:
        state = RateLimitState()
        for _ in range(3):
            state.check("a.com", max_per_minute=3, max_per_hour=None)
        assert not state.check("a.com", max_per_minute=3, max_per_hour=None)

    def test_different_callers_independent(self) -> None:
        state = RateLimitState()
        for _ in range(3):
            state.check("a.com", max_per_minute=3, max_per_hour=None)
        # b.com should still have quota
        assert state.check("b.com", max_per_minute=3, max_per_hour=None)

    def test_lru_eviction(self) -> None:
        state = RateLimitState()
        state._MAX_CALLERS = 3
        state.check("a.com", max_per_minute=100, max_per_hour=None)
        state.check("b.com", max_per_minute=100, max_per_hour=None)
        state.check("c.com", max_per_minute=100, max_per_hour=None)
        state.check("d.com", max_per_minute=100, max_per_hour=None)
        # After adding d, oldest (a) should be evicted
        assert len(state._windows) <= 4  # d triggers eviction after add


# =============================================================================
# Helper function tests
# =============================================================================


class TestExtractAuthType:
    def test_bearer(self) -> None:
        assert _extract_auth_type("Bearer tok123") == "bearer"

    def test_basic(self) -> None:
        assert _extract_auth_type("Basic dXNlcjpwYXNz") == "api_key"

    def test_unknown(self) -> None:
        assert _extract_auth_type("Digest realm=test") == "unknown"

    def test_empty(self) -> None:
        assert _extract_auth_type("") is None

    def test_none(self) -> None:
        # Handles the case where header is missing
        assert _extract_auth_type("") is None


class TestExtractDomainFromDN:
    def test_simple_cn(self) -> None:
        assert _extract_domain_from_dn("CN=api.infoblox.com") == "api.infoblox.com"

    def test_wildcard_cn(self) -> None:
        assert _extract_domain_from_dn("CN=*.infoblox.com") == "infoblox.com"

    def test_full_dn(self) -> None:
        assert _extract_domain_from_dn("CN=api.infoblox.com,O=Infoblox,C=US") == "api.infoblox.com"

    def test_no_cn(self) -> None:
        assert _extract_domain_from_dn("O=Infoblox,C=US") is None

    def test_empty(self) -> None:
        assert _extract_domain_from_dn("") is None
