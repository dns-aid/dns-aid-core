# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
End-to-end integration test for the 3-layer policy enforcement model.

Spins up a real FastAPI app with DnsAidPolicyMiddleware (Layer 2),
then calls it via AgentClient.invoke() with policy gate (Layer 1).
Verifies the full flow:
  discover → Layer 1 policy check → invoke → Layer 2 enforcement
  → X-DNS-AID-Policy-Result header → signal enrichment

No mocks on the policy evaluation path — this tests real code.
The only mock is httpx transport (to avoid network calls).
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import patch
from urllib.parse import urlparse

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from dns_aid.core.models import AgentRecord, Protocol
from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.client import AgentClient
from dns_aid.sdk.policy.middleware import DnsAidPolicyMiddleware
from dns_aid.sdk.policy.models import PolicyViolationError
from dns_aid.sdk.policy.schema import PolicyDocument, PolicyRules


@pytest.fixture(autouse=True)
def _allow_localhost_http():
    """Allow HTTP URLs to localhost for integration tests.

    Production enforces HTTPS-only via validate_fetch_url(). In tests,
    we run a local HTTP policy server, so we bypass the scheme check
    for 127.0.0.1 URLs only.
    """
    original = None
    try:
        from dns_aid.utils.url_safety import validate_fetch_url as _orig

        original = _orig
    except ImportError:
        pass

    def _test_validate(url: str) -> str:
        parsed = urlparse(url)
        if parsed.hostname == "127.0.0.1":
            return url  # Allow localhost HTTP in tests
        return original(url) if original else url

    with (
        patch("dns_aid.sdk.policy.evaluator.validate_fetch_url", side_effect=_test_validate),
        patch("dns_aid.utils.url_safety.validate_fetch_url", side_effect=_test_validate),
    ):
        yield


# =============================================================================
# Test infrastructure: policy server + target agent
# =============================================================================


POLICY_DOC_ALLOW_ALL = PolicyDocument(
    version="1.0",
    agent="_test._mcp._agents.example.com",
    rules=PolicyRules(),
)

POLICY_DOC_STRICT = PolicyDocument(
    version="1.0",
    agent="_test._mcp._agents.example.com",
    rules=PolicyRules(
        required_auth_types=["oauth2"],
        allowed_caller_domains=["*.infoblox.com"],
        allowed_methods=["tools/list", "tools/call"],
        require_dnssec=True,
    ),
)

POLICY_DOC_GEO_RESTRICTED = PolicyDocument(
    version="1.0",
    agent="_test._mcp._agents.example.com",
    rules=PolicyRules(
        geo_restrictions=["US", "CA"],
    ),
)


class PolicyServer:
    """Simple HTTP server that serves policy documents."""

    def __init__(self, doc: PolicyDocument, port: int = 0) -> None:
        self.doc = doc
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.port = port

    def start(self) -> str:
        doc_json = self.doc.model_dump_json()

        class Handler(BaseHTTPRequestHandler):
            # `inner_self` deliberately disambiguates the nested-class instance
            # from the enclosing test-server `self`; the outer `self` is closed
            # over by `doc_json` above. Ruff's N805 is suppressed via `noqa`;
            # CodeQL's `py/not-named-self` is suppressed via `lgtm`.
            def do_GET(inner_self) -> None:  # noqa: N805  # lgtm[py/not-named-self]
                inner_self.send_response(200)
                inner_self.send_header("Content-Type", "application/json")
                inner_self.end_headers()
                inner_self.wfile.write(doc_json.encode())

            def log_message(inner_self, format, *args) -> None:  # noqa: N805  # lgtm[py/not-named-self]
                pass  # Suppress request logging

        self._server = HTTPServer(("127.0.0.1", self.port), Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return f"http://127.0.0.1:{self.port}/policy.json"

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()


def _make_target_app(policy_uri: str, mode: str = "strict") -> Starlette:
    """Build a target agent FastAPI app with DnsAidPolicyMiddleware."""

    async def mcp_endpoint(request: Request) -> JSONResponse:
        """Simulated MCP tools/list endpoint."""
        body = await request.body()
        data = json.loads(body) if body else {}

        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "id": data.get("id", 1),
                "result": {
                    "tools": [{"name": "test-tool", "description": "A test tool"}],
                },
            }
        )

    app = Starlette(
        routes=[Route("/mcp", mcp_endpoint, methods=["POST"])],
    )
    app.add_middleware(
        DnsAidPolicyMiddleware,
        policy_uri=policy_uri,
        mode=mode,
    )
    return app


def _make_agent_record(
    endpoint: str,
    policy_uri: str | None = None,
) -> AgentRecord:
    """Build an AgentRecord pointing at the test target."""
    parsed = urlparse(endpoint)
    return AgentRecord(
        name="test-agent",
        domain="example.com",
        protocol=Protocol.MCP,
        target_host=parsed.hostname or "127.0.0.1",
        port=parsed.port or 443,
        endpoint_override=endpoint,
        policy_uri=policy_uri,
    )


# =============================================================================
# E2E Tests
# =============================================================================


class TestE2EPolicyAllowAll:
    """Test with a permissive policy — everything should pass both layers."""

    def test_full_flow_allowed(self) -> None:
        # 1. Start policy server
        policy_server = PolicyServer(POLICY_DOC_ALLOW_ALL)
        policy_uri = policy_server.start()

        try:
            # 2. Build target app with middleware
            app = _make_target_app(policy_uri, mode="strict")
            client = TestClient(app)

            # 3. Send request — should pass Layer 2
            resp = client.post(
                "/mcp",
                json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
                headers={"X-DNS-AID-Caller-Domain": "api.infoblox.com"},
            )

            assert resp.status_code == 200
            assert resp.headers["X-DNS-AID-Policy-Result"] == "allowed"
            data = resp.json()
            assert data["result"]["tools"][0]["name"] == "test-tool"
        finally:
            policy_server.stop()


class TestE2EPolicyStrictDenied:
    """Test with strict policy — caller without oauth2 should be denied at Layer 2."""

    def test_denied_at_layer2_returns_403(self) -> None:
        policy_server = PolicyServer(POLICY_DOC_STRICT)
        policy_uri = policy_server.start()

        try:
            app = _make_target_app(policy_uri, mode="strict")
            client = TestClient(app)

            # Send without oauth2 auth — should be denied by required_auth_types
            resp = client.post(
                "/mcp",
                json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
                headers={
                    "X-DNS-AID-Caller-Domain": "api.infoblox.com",
                    "Authorization": "Bearer some-token",  # bearer, not oauth2
                },
            )

            assert resp.status_code == 403
            data = resp.json()
            assert data["error"] == "policy_denied"
            assert any(v["rule"] == "required_auth_types" for v in data["violations"])
            assert resp.headers["X-DNS-AID-Policy-Result"] == "denied"
        finally:
            policy_server.stop()


class TestE2EPolicyPermissiveMode:
    """Test permissive mode — violations logged but request proceeds."""

    def test_permissive_allows_with_denied_header(self) -> None:
        policy_server = PolicyServer(POLICY_DOC_STRICT)
        policy_uri = policy_server.start()

        try:
            app = _make_target_app(policy_uri, mode="permissive")
            client = TestClient(app)

            # Same violation as above, but permissive mode lets it through
            resp = client.post(
                "/mcp",
                json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
                headers={"Authorization": "Bearer some-token"},
            )

            assert resp.status_code == 200
            assert resp.headers["X-DNS-AID-Policy-Result"] == "denied"
            # Response still contains the actual tool data
            data = resp.json()
            assert data["result"]["tools"][0]["name"] == "test-tool"
        finally:
            policy_server.stop()


class TestE2EMethodFromBody:
    """Test that Layer 2 extracts method from JSON-RPC body, not header."""

    def test_spoofed_header_ignored(self) -> None:
        # Policy only allows tools/list
        policy_doc = PolicyDocument(
            version="1.0",
            agent="_test._mcp._agents.example.com",
            rules=PolicyRules(allowed_methods=["tools/list"]),
        )
        policy_server = PolicyServer(policy_doc)
        policy_uri = policy_server.start()

        try:
            app = _make_target_app(policy_uri, mode="strict")
            client = TestClient(app)

            # Header says tools/list (allowed) but body says tools/call (not allowed)
            resp = client.post(
                "/mcp",
                json={"jsonrpc": "2.0", "method": "tools/call", "id": 1},
                headers={"X-DNS-AID-Method": "tools/list"},  # spoofed!
            )

            # Should be denied because body method (tools/call) is not allowed
            assert resp.status_code == 403
            data = resp.json()
            assert any(v["rule"] == "allowed_methods" for v in data["violations"])
        finally:
            policy_server.stop()


class TestE2EMTLSOverride:
    """Test that mTLS cert domain overrides claimed X-DNS-AID-Caller-Domain."""

    def test_cert_domain_wins(self) -> None:
        policy_doc = PolicyDocument(
            version="1.0",
            agent="_test._mcp._agents.example.com",
            rules=PolicyRules(allowed_caller_domains=["*.infoblox.com"]),
        )
        policy_server = PolicyServer(policy_doc)
        policy_uri = policy_server.start()

        try:
            app = _make_target_app(policy_uri, mode="strict")
            client = TestClient(app)

            # Header claims infoblox.com but cert says evil.com
            resp = client.post(
                "/mcp",
                json={"jsonrpc": "2.0", "method": "tools/list", "id": 1},
                headers={
                    "X-DNS-AID-Caller-Domain": "api.infoblox.com",
                    "X-Client-Certificate-DN": "CN=evil.com,O=Evil Corp",
                },
            )

            # Denied — cert domain evil.com doesn't match *.infoblox.com
            assert resp.status_code == 403
        finally:
            policy_server.stop()


class TestE2ERateLimiting:
    """Test rate limiting with real policy server."""

    def test_rate_limit_enforced(self) -> None:
        policy_doc = PolicyDocument(
            version="1.0",
            agent="_test._mcp._agents.example.com",
            rules=PolicyRules(rate_limits={"max_per_minute": 2}),
        )
        policy_server = PolicyServer(policy_doc)
        policy_uri = policy_server.start()

        try:
            app = _make_target_app(policy_uri, mode="strict")
            client = TestClient(app)

            headers = {
                "X-DNS-AID-Caller-Domain": "rate-test.com",
            }

            # First 2 requests pass
            r1 = client.post(
                "/mcp", json={"jsonrpc": "2.0", "method": "test", "id": 1}, headers=headers
            )
            r2 = client.post(
                "/mcp", json={"jsonrpc": "2.0", "method": "test", "id": 2}, headers=headers
            )
            assert r1.status_code == 200
            assert r2.status_code == 200

            # Third request hits rate limit
            r3 = client.post(
                "/mcp", json={"jsonrpc": "2.0", "method": "test", "id": 3}, headers=headers
            )
            assert r3.status_code == 429
            assert r3.json()["error"] == "rate_limited"
        finally:
            policy_server.stop()


class TestE2ELayer1CallerSide:
    """Test Layer 1 (caller SDK) policy gate with real policy server.

    Uses AgentClient.invoke() which checks the agent's policy_uri
    before calling handler.invoke().
    """

    @pytest.mark.asyncio
    async def test_strict_mode_raises_on_violation(self) -> None:
        """Layer 1 in strict mode should raise PolicyViolationError."""
        policy_server = PolicyServer(POLICY_DOC_STRICT)
        policy_uri = policy_server.start()

        try:
            agent = _make_agent_record(
                endpoint="https://unreachable.example.com/mcp",
                policy_uri=policy_uri,
            )

            config = SDKConfig(
                timeout_seconds=5,
                policy_mode="strict",
                caller_domain="evil.com",  # Not in *.infoblox.com allowlist
            )

            async with AgentClient(config=config) as client:
                with pytest.raises(PolicyViolationError) as exc_info:
                    await client.invoke(agent, method="tools/list")

                # Verify the violation details
                result = exc_info.value.result
                assert result.denied
                # Should have multiple violations (auth, dnssec, domain)
                rule_names = {v.rule for v in result.violations}
                # At minimum, required_auth_types should fire (no auth provided)
                assert "required_auth_types" in rule_names
        finally:
            policy_server.stop()

    @pytest.mark.asyncio
    async def test_permissive_mode_proceeds_with_warning(self) -> None:
        """Layer 1 in permissive mode should log warning but not raise."""
        policy_server = PolicyServer(POLICY_DOC_STRICT)
        policy_uri = policy_server.start()

        try:
            agent = _make_agent_record(
                endpoint="https://unreachable.example.com/mcp",
                policy_uri=policy_uri,
            )

            config = SDKConfig(
                timeout_seconds=2,
                policy_mode="permissive",
                caller_domain="evil.com",
            )

            async with AgentClient(config=config) as client:
                # Should NOT raise — permissive mode logs warning
                # It will fail at the network level (unreachable), not policy
                try:
                    await client.invoke(agent, method="tools/list")
                except Exception as e:
                    # Expected: network error, NOT PolicyViolationError
                    assert not isinstance(e, PolicyViolationError)
                    assert "PolicyViolation" not in type(e).__name__
        finally:
            policy_server.stop()

    @pytest.mark.asyncio
    async def test_disabled_mode_skips_policy(self) -> None:
        """Disabled mode should not fetch policy at all."""
        # Use a bad URI — if policy were fetched, it would fail
        agent = _make_agent_record(
            endpoint="https://unreachable.example.com/mcp",
            policy_uri="https://also-unreachable.example.com/bad-policy",
        )

        config = SDKConfig(
            timeout_seconds=2,
            policy_mode="disabled",
        )

        async with AgentClient(config=config) as client:
            try:
                await client.invoke(agent, method="tools/list")
            except PolicyViolationError:
                pytest.fail("PolicyViolationError should not be raised in disabled mode")
            except Exception:
                pass  # Expected: network error

    @pytest.mark.asyncio
    async def test_no_policy_uri_skips_check(self) -> None:
        """Agent without policy_uri should skip policy check entirely."""
        agent = _make_agent_record(
            endpoint="https://unreachable.example.com/mcp",
            policy_uri=None,
        )

        config = SDKConfig(
            timeout_seconds=2,
            policy_mode="strict",  # Even strict mode should skip
        )

        async with AgentClient(config=config) as client:
            try:
                await client.invoke(agent, method="tools/list")
            except PolicyViolationError:
                pytest.fail("PolicyViolationError should not be raised without policy_uri")
            except Exception:
                pass  # Expected: network error


class TestE2EPolicyGuard:
    """Test the MCP server policy guard (check_target_policy)."""

    @pytest.mark.asyncio
    async def test_guard_with_real_policy_server(self) -> None:
        """Guard fetches from real HTTP server and evaluates."""
        from dns_aid.sdk.policy.guard import check_target_policy

        policy_server = PolicyServer(POLICY_DOC_STRICT)
        policy_uri = policy_server.start()

        try:
            with pytest.MonkeyPatch.context() as mp:
                mp.setenv("DNS_AID_POLICY_MODE", "strict")
                mp.setenv("DNS_AID_CALLER_DOMAIN", "api.infoblox.com")

                # Reset module-level evaluator to pick up fresh env
                import dns_aid.sdk.policy.guard as guard_mod

                guard_mod._evaluator = None

                result = await check_target_policy(
                    policy_uri,
                    protocol="mcp",
                    method="tools/list",
                )

                # Should be denied — no auth type provided, but oauth2 required
                assert result.denied
                rule_names = {v.rule for v in result.violations}
                assert "required_auth_types" in rule_names
        finally:
            policy_server.stop()

    @pytest.mark.asyncio
    async def test_guard_no_policy_uri_allowed(self) -> None:
        from dns_aid.sdk.policy.guard import check_target_policy

        result = await check_target_policy(None)
        assert result.allowed
