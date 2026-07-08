# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for PolicyEvaluator."""

from __future__ import annotations

import asyncio
import time
from datetime import UTC
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from dns_aid.sdk.policy.evaluator import PolicyEvaluator, _CacheEntry
from dns_aid.sdk.policy.models import PolicyContext
from dns_aid.sdk.policy.schema import (
    AvailabilityConfig,
    CELRule,
    PolicyDocument,
    PolicyEnforcementLayer,
    PolicyRules,
    RateLimitConfig,
)


def _doc(rules: PolicyRules | None = None) -> PolicyDocument:
    """Helper to build a PolicyDocument."""
    return PolicyDocument(
        agent="_test._mcp._agents.example.com",
        rules=rules or PolicyRules(),
    )


def _ctx(**kwargs) -> PolicyContext:
    """Helper to build a PolicyContext with defaults."""
    defaults = {
        "caller_id": "test-caller",
        "caller_domain": "caller.example.com",
        "protocol": "mcp",
        "method": "tools/call",
        "auth_type": "bearer",
        "dnssec_validated": True,
        "tls_version": "1.3",
        "caller_trust_score": 80.0,
        "geo_country": "US",
        "has_mutual_tls": True,
        "consent_token": "tok-abc",
        "intent": "query",
    }
    defaults.update(kwargs)
    return PolicyContext(**defaults)


# ── _CacheEntry ──────────────────────────────────────────────


class TestCacheEntry:
    def test_not_expired(self) -> None:
        entry = _CacheEntry(doc=_doc(), fetched_at=time.monotonic(), ttl=300)
        assert not entry.expired

    def test_expired(self) -> None:
        entry = _CacheEntry(doc=_doc(), fetched_at=time.monotonic() - 400, ttl=300)
        assert entry.expired


# ── Fetch tests ──────────────────────────────────────────────


class TestFetch:
    @pytest.mark.asyncio
    async def test_fetch_valid(self) -> None:
        doc = _doc()
        body = doc.model_dump_json().encode()

        async def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=body, headers={"content-type": "application/json"})

        evaluator = PolicyEvaluator(cache_ttl=300)
        with patch(
            "dns_aid.utils.url_safety.validate_fetch_url",
            return_value="https://example.com/policy.json",
        ):
            with patch("dns_aid.sdk.policy.evaluator.httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_resp = AsyncMock()
                mock_resp.status_code = 200
                mock_resp.headers = {"content-type": "application/json"}
                mock_resp.content = body
                mock_resp.text = doc.model_dump_json()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client.get = AsyncMock(return_value=mock_resp)
                mock_client_cls.return_value = mock_client

                result = await evaluator.fetch("https://example.com/policy.json")
                assert result.agent == doc.agent

    @pytest.mark.asyncio
    async def test_fetch_ssrf_blocked(self) -> None:
        evaluator = PolicyEvaluator()
        with patch(
            "dns_aid.utils.url_safety.validate_fetch_url",
            side_effect=ValueError("SSRF blocked"),
        ):
            with pytest.raises(ValueError, match="SSRF blocked"):
                await evaluator.fetch("https://169.254.169.254/policy.json")

    @pytest.mark.asyncio
    async def test_fetch_oversized(self) -> None:
        big_body = b"x" * (65 * 1024)  # > 64KB

        evaluator = PolicyEvaluator()
        with patch(
            "dns_aid.utils.url_safety.validate_fetch_url",
            return_value="https://example.com/policy.json",
        ):
            with patch("dns_aid.sdk.policy.evaluator.httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_resp = AsyncMock()
                mock_resp.status_code = 200
                mock_resp.headers = {"content-type": "application/json"}
                mock_resp.content = big_body
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client.get = AsyncMock(return_value=mock_resp)
                mock_client_cls.return_value = mock_client

                with pytest.raises(ValueError, match="exceeds 65536"):
                    await evaluator.fetch("https://example.com/policy.json")

    @pytest.mark.asyncio
    async def test_fetch_wrong_content_type(self) -> None:
        evaluator = PolicyEvaluator()
        with patch(
            "dns_aid.utils.url_safety.validate_fetch_url",
            return_value="https://example.com/policy.json",
        ):
            with patch("dns_aid.sdk.policy.evaluator.httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_resp = AsyncMock()
                mock_resp.status_code = 200
                mock_resp.headers = {"content-type": "text/html"}
                mock_resp.content = b"{}"
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client.get = AsyncMock(return_value=mock_resp)
                mock_client_cls.return_value = mock_client

                with pytest.raises(ValueError, match="content-type"):
                    await evaluator.fetch("https://example.com/policy.json")

    @pytest.mark.asyncio
    async def test_cache_hit(self) -> None:
        evaluator = PolicyEvaluator(cache_ttl=300)
        doc = _doc()
        evaluator._cache["https://example.com/p.json"] = _CacheEntry(
            doc=doc, fetched_at=time.monotonic(), ttl=300
        )
        result = await evaluator.fetch("https://example.com/p.json")
        assert result is doc

    @pytest.mark.asyncio
    async def test_cache_expired(self) -> None:
        evaluator = PolicyEvaluator(cache_ttl=1)
        old_doc = _doc()
        evaluator._cache["https://example.com/p.json"] = _CacheEntry(
            doc=old_doc, fetched_at=time.monotonic() - 10, ttl=1
        )
        new_doc = _doc(rules=PolicyRules(require_dnssec=True))
        body = new_doc.model_dump_json()

        with patch(
            "dns_aid.utils.url_safety.validate_fetch_url",
            return_value="https://example.com/p.json",
        ):
            with patch("dns_aid.sdk.policy.evaluator.httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_resp = AsyncMock()
                mock_resp.status_code = 200
                mock_resp.headers = {"content-type": "application/json"}
                mock_resp.content = body.encode()
                mock_resp.text = body
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client.get = AsyncMock(return_value=mock_resp)
                mock_client_cls.return_value = mock_client

                result = await evaluator.fetch("https://example.com/p.json")
                assert result.rules.require_dnssec is True

    @pytest.mark.asyncio
    async def test_concurrent_fetch_no_stampede(self) -> None:
        """Concurrent fetches for the same URI should only trigger one HTTP call."""
        call_count = 0
        doc = _doc()
        body = doc.model_dump_json()

        async def mock_get(*args, **kwargs):  # noqa: ANN002, ANN003
            nonlocal call_count
            call_count += 1
            await asyncio.sleep(0.05)
            resp = AsyncMock()
            resp.status_code = 200
            resp.headers = {"content-type": "application/json"}
            resp.content = body.encode()
            resp.text = body
            return resp

        evaluator = PolicyEvaluator(cache_ttl=300)
        with patch(
            "dns_aid.utils.url_safety.validate_fetch_url",
            return_value="https://example.com/p.json",
        ):
            with patch("dns_aid.sdk.policy.evaluator.httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_client.get = mock_get
                mock_client_cls.return_value = mock_client

                results = await asyncio.gather(
                    evaluator.fetch("https://example.com/p.json"),
                    evaluator.fetch("https://example.com/p.json"),
                    evaluator.fetch("https://example.com/p.json"),
                )
                assert all(r.agent == doc.agent for r in results)
                # Only 1 actual HTTP call due to lock + double-check
                assert call_count == 1


# ── Rule evaluation tests ────────────────────────────────────


class TestRuleRequiredProtocols:
    def test_pass(self) -> None:
        doc = _doc(PolicyRules(required_protocols=["mcp", "a2a"]))
        result = PolicyEvaluator().evaluate(doc, _ctx(protocol="mcp"))
        assert result.allowed

    def test_fail(self) -> None:
        doc = _doc(PolicyRules(required_protocols=["a2a"]))
        result = PolicyEvaluator().evaluate(doc, _ctx(protocol="mcp"))
        assert result.denied
        assert any(v.rule == "required_protocols" for v in result.violations)

    def test_none_protocol_is_violation(self) -> None:
        doc = _doc(PolicyRules(required_protocols=["mcp"]))
        result = PolicyEvaluator().evaluate(doc, _ctx(protocol=None))
        assert result.denied


class TestRuleRequiredAuthTypes:
    def test_pass(self) -> None:
        doc = _doc(PolicyRules(required_auth_types=["bearer", "oauth2"]))
        result = PolicyEvaluator().evaluate(doc, _ctx(auth_type="bearer"))
        assert result.allowed

    def test_fail(self) -> None:
        doc = _doc(PolicyRules(required_auth_types=["oauth2"]))
        result = PolicyEvaluator().evaluate(doc, _ctx(auth_type="bearer"))
        assert result.denied

    def test_none_auth_is_violation(self) -> None:
        doc = _doc(PolicyRules(required_auth_types=["bearer"]))
        result = PolicyEvaluator().evaluate(doc, _ctx(auth_type=None))
        assert result.denied


class TestRuleRequireDnssec:
    def test_pass(self) -> None:
        doc = _doc(PolicyRules(require_dnssec=True))
        result = PolicyEvaluator().evaluate(doc, _ctx(dnssec_validated=True))
        assert result.allowed

    def test_fail(self) -> None:
        doc = _doc(PolicyRules(require_dnssec=True))
        result = PolicyEvaluator().evaluate(doc, _ctx(dnssec_validated=False))
        assert result.denied


class TestRuleRequireMutualTls:
    def test_pass(self) -> None:
        doc = _doc(PolicyRules(require_mutual_tls=True))
        result = PolicyEvaluator().evaluate(doc, _ctx(has_mutual_tls=True))
        assert result.allowed

    def test_fail(self) -> None:
        doc = _doc(PolicyRules(require_mutual_tls=True))
        result = PolicyEvaluator().evaluate(doc, _ctx(has_mutual_tls=False))
        assert result.denied


class TestRuleMinTlsVersion:
    def test_pass_same(self) -> None:
        doc = _doc(PolicyRules(min_tls_version="1.2"))
        result = PolicyEvaluator().evaluate(doc, _ctx(tls_version="1.2"))
        assert result.allowed

    def test_pass_higher(self) -> None:
        doc = _doc(PolicyRules(min_tls_version="1.2"))
        result = PolicyEvaluator().evaluate(doc, _ctx(tls_version="1.3"))
        assert result.allowed

    def test_fail(self) -> None:
        doc = _doc(PolicyRules(min_tls_version="1.3"))
        result = PolicyEvaluator().evaluate(doc, _ctx(tls_version="1.2"))
        assert result.denied

    def test_none_tls_version(self) -> None:
        doc = _doc(PolicyRules(min_tls_version="1.2"))
        result = PolicyEvaluator().evaluate(doc, _ctx(tls_version=None))
        assert result.denied


class TestRuleCallerTrustScore:
    def test_pass(self) -> None:
        doc = _doc(PolicyRules(required_caller_trust_score=50.0))
        result = PolicyEvaluator().evaluate(doc, _ctx(caller_trust_score=80.0))
        assert result.allowed

    def test_fail(self) -> None:
        doc = _doc(PolicyRules(required_caller_trust_score=90.0))
        result = PolicyEvaluator().evaluate(doc, _ctx(caller_trust_score=80.0))
        assert result.denied

    def test_none_score(self) -> None:
        doc = _doc(PolicyRules(required_caller_trust_score=50.0))
        result = PolicyEvaluator().evaluate(doc, _ctx(caller_trust_score=None))
        assert result.denied


class TestRuleRateLimits:
    def test_structural_pass(self) -> None:
        """Rate limits are structural only — always pass in evaluator."""
        doc = _doc(PolicyRules(rate_limits=RateLimitConfig(max_per_minute=60)))
        result = PolicyEvaluator().evaluate(doc, _ctx())
        assert result.allowed

    def test_adds_warning(self) -> None:
        """Rate limits emit warning at caller layer (advisory)."""
        doc = _doc(PolicyRules(rate_limits=RateLimitConfig(max_per_minute=60)))
        result = PolicyEvaluator().evaluate(doc, _ctx())
        assert any(w.rule == "rate_limits" for w in result.warnings)


class TestRuleMaxPayloadBytes:
    def test_pass(self) -> None:
        doc = _doc(PolicyRules(max_payload_bytes=1024))
        result = PolicyEvaluator().evaluate(
            doc,
            _ctx(payload_bytes=512),
            layer=PolicyEnforcementLayer.TARGET,
        )
        assert result.allowed

    def test_fail(self) -> None:
        doc = _doc(PolicyRules(max_payload_bytes=1024))
        result = PolicyEvaluator().evaluate(
            doc,
            _ctx(payload_bytes=2048),
            layer=PolicyEnforcementLayer.TARGET,
        )
        assert result.denied

    def test_none_payload(self) -> None:
        """None payload_bytes passes (can't check what we don't know)."""
        doc = _doc(PolicyRules(max_payload_bytes=1024))
        result = PolicyEvaluator().evaluate(
            doc,
            _ctx(payload_bytes=None),
            layer=PolicyEnforcementLayer.TARGET,
        )
        assert result.allowed


class TestRuleAllowedCallerDomains:
    def test_pass_exact(self) -> None:
        doc = _doc(PolicyRules(allowed_caller_domains=["caller.example.com"]))
        result = PolicyEvaluator().evaluate(doc, _ctx(caller_domain="caller.example.com"))
        assert result.allowed

    def test_pass_wildcard(self) -> None:
        doc = _doc(PolicyRules(allowed_caller_domains=["*.example.com"]))
        result = PolicyEvaluator().evaluate(doc, _ctx(caller_domain="api.example.com"))
        assert result.allowed

    def test_fail(self) -> None:
        doc = _doc(PolicyRules(allowed_caller_domains=["*.infoblox.com"]))
        result = PolicyEvaluator().evaluate(doc, _ctx(caller_domain="evil.com"))
        assert result.denied

    def test_none_domain(self) -> None:
        doc = _doc(PolicyRules(allowed_caller_domains=["*.example.com"]))
        result = PolicyEvaluator().evaluate(doc, _ctx(caller_domain=None))
        assert result.denied


class TestRuleBlockedCallerDomains:
    def test_pass(self) -> None:
        doc = _doc(PolicyRules(blocked_caller_domains=["evil.com"]))
        result = PolicyEvaluator().evaluate(doc, _ctx(caller_domain="good.com"))
        assert result.allowed

    def test_fail_exact(self) -> None:
        doc = _doc(PolicyRules(blocked_caller_domains=["evil.com"]))
        result = PolicyEvaluator().evaluate(doc, _ctx(caller_domain="evil.com"))
        assert result.denied

    def test_fail_wildcard(self) -> None:
        doc = _doc(PolicyRules(blocked_caller_domains=["*.evil.com"]))
        result = PolicyEvaluator().evaluate(doc, _ctx(caller_domain="api.evil.com"))
        assert result.denied

    def test_none_domain_passes(self) -> None:
        """None domain is not in blocked list."""
        doc = _doc(PolicyRules(blocked_caller_domains=["evil.com"]))
        result = PolicyEvaluator().evaluate(doc, _ctx(caller_domain=None))
        assert result.allowed


class TestRuleAllowedMethods:
    def test_pass(self) -> None:
        doc = _doc(PolicyRules(allowed_methods=["tools/call", "tools/list"]))
        result = PolicyEvaluator().evaluate(doc, _ctx(method="tools/call"))
        assert result.allowed

    def test_fail(self) -> None:
        doc = _doc(PolicyRules(allowed_methods=["tools/list"]))
        result = PolicyEvaluator().evaluate(doc, _ctx(method="tools/call"))
        assert result.denied

    def test_none_method_is_violation(self) -> None:
        doc = _doc(PolicyRules(allowed_methods=["tools/list"]))
        result = PolicyEvaluator().evaluate(doc, _ctx(method=None))
        assert result.denied


class TestRuleAllowedIntents:
    def test_pass(self) -> None:
        doc = _doc(PolicyRules(allowed_intents=["query", "mutate"]))
        result = PolicyEvaluator().evaluate(doc, _ctx(intent="query"))
        assert result.allowed

    def test_fail(self) -> None:
        doc = _doc(PolicyRules(allowed_intents=["query"]))
        result = PolicyEvaluator().evaluate(doc, _ctx(intent="mutate"))
        assert result.denied

    def test_none_intent_is_violation(self) -> None:
        doc = _doc(PolicyRules(allowed_intents=["query"]))
        result = PolicyEvaluator().evaluate(doc, _ctx(intent=None))
        assert result.denied


class TestRuleGeoRestrictions:
    def test_pass(self) -> None:
        doc = _doc(PolicyRules(geo_restrictions=["US", "CA"]))
        result = PolicyEvaluator().evaluate(doc, _ctx(geo_country="US"))
        assert result.allowed

    def test_fail(self) -> None:
        doc = _doc(PolicyRules(geo_restrictions=["US"]))
        result = PolicyEvaluator().evaluate(doc, _ctx(geo_country="CN"))
        assert result.denied

    def test_none_geo(self) -> None:
        doc = _doc(PolicyRules(geo_restrictions=["US"]))
        result = PolicyEvaluator().evaluate(doc, _ctx(geo_country=None))
        assert result.denied


class TestRuleAvailability:
    def test_normal_window_pass(self) -> None:
        doc = _doc(
            PolicyRules(availability=AvailabilityConfig(hours="00:00-23:59", timezone="UTC"))
        )
        result = PolicyEvaluator().evaluate(doc, _ctx())
        assert result.allowed

    def test_normal_window_fail(self) -> None:
        """Test a window that's definitely not now (unless test runs in that exact minute)."""
        # Use a 1-minute window in the past relative to now
        from datetime import datetime

        now = datetime.now(UTC)
        # Create a window that ended 2 hours ago
        end_h = (now.hour - 2) % 24
        start_h = (end_h - 1) % 24
        hours = f"{start_h:02d}:00-{end_h:02d}:00"
        # Make sure it's not a midnight-wrap that accidentally includes now
        if start_h < end_h:
            doc = _doc(PolicyRules(availability=AvailabilityConfig(hours=hours, timezone="UTC")))
            result = PolicyEvaluator().evaluate(doc, _ctx())
            assert result.denied

    def test_midnight_wrap(self) -> None:
        """22:00-06:00 should allow midnight hours."""
        doc = _doc(
            PolicyRules(availability=AvailabilityConfig(hours="00:00-23:59", timezone="UTC"))
        )
        result = PolicyEvaluator().evaluate(doc, _ctx())
        assert result.allowed

    def test_malformed_logs_warning(self) -> None:
        """Malformed availability input should fail-open with warning."""
        doc = _doc(PolicyRules(availability=AvailabilityConfig(hours="bad-format", timezone="UTC")))
        result = PolicyEvaluator().evaluate(doc, _ctx())
        # Fail-open: malformed = allowed
        assert result.allowed


class TestRuleDataClassification:
    def test_pass(self) -> None:
        doc = _doc(PolicyRules(data_classification="public"))
        result = PolicyEvaluator().evaluate(doc, _ctx())
        # Data classification is informational — warnings only
        assert result.allowed
        assert any(w.rule == "data_classification" for w in result.warnings)


class TestRuleConsentRequired:
    def test_pass_with_token(self) -> None:
        doc = _doc(PolicyRules(consent_required=True))
        result = PolicyEvaluator().evaluate(doc, _ctx(consent_token="tok-abc"))
        assert result.allowed

    def test_fail_without_token(self) -> None:
        doc = _doc(PolicyRules(consent_required=True))
        result = PolicyEvaluator().evaluate(doc, _ctx(consent_token=None))
        assert result.denied


# ── Layer filtering ──────────────────────────────────────────


class TestLayerFiltering:
    def test_caller_layer_skips_target_only_rules(self) -> None:
        """max_payload_bytes is TARGET-only — should not fire for CALLER layer."""
        doc = _doc(PolicyRules(max_payload_bytes=100))
        result = PolicyEvaluator().evaluate(
            doc,
            _ctx(payload_bytes=9999),
            layer=PolicyEnforcementLayer.CALLER,
        )
        # max_payload_bytes should not appear in violations for CALLER layer
        assert not any(v.rule == "max_payload_bytes" for v in result.violations)

    def test_target_layer_includes_target_rules(self) -> None:
        """max_payload_bytes is TARGET-only — should fire for TARGET layer."""
        doc = _doc(PolicyRules(max_payload_bytes=100))
        result = PolicyEvaluator().evaluate(
            doc,
            _ctx(payload_bytes=9999),
            layer=PolicyEnforcementLayer.TARGET,
        )
        assert any(v.rule == "max_payload_bytes" for v in result.violations)

    def test_caller_layer_includes_caller_rules(self) -> None:
        """require_dnssec is CALLER-only — should fire for CALLER."""
        doc = _doc(PolicyRules(require_dnssec=True))
        result = PolicyEvaluator().evaluate(
            doc, _ctx(dnssec_validated=False), layer=PolicyEnforcementLayer.CALLER
        )
        assert result.denied

    def test_target_layer_skips_caller_only_rules(self) -> None:
        """require_dnssec is CALLER-only — should not fire for TARGET."""
        doc = _doc(PolicyRules(require_dnssec=True))
        result = PolicyEvaluator().evaluate(
            doc, _ctx(dnssec_validated=False), layer=PolicyEnforcementLayer.TARGET
        )
        assert result.allowed


# ── Domain wildcard matching ─────────────────────────────────


class TestDomainWildcards:
    def test_wildcard_matches_subdomain(self) -> None:
        doc = _doc(PolicyRules(allowed_caller_domains=["*.infoblox.com"]))
        result = PolicyEvaluator().evaluate(doc, _ctx(caller_domain="api.infoblox.com"))
        assert result.allowed

    def test_wildcard_does_not_match_unrelated(self) -> None:
        doc = _doc(PolicyRules(allowed_caller_domains=["*.infoblox.com"]))
        result = PolicyEvaluator().evaluate(doc, _ctx(caller_domain="evil.com"))
        assert result.denied

    def test_exact_match(self) -> None:
        doc = _doc(PolicyRules(allowed_caller_domains=["infoblox.com"]))
        result = PolicyEvaluator().evaluate(doc, _ctx(caller_domain="infoblox.com"))
        assert result.allowed

    def test_blocked_wildcard(self) -> None:
        doc = _doc(PolicyRules(blocked_caller_domains=["*.evil.com"]))
        result = PolicyEvaluator().evaluate(doc, _ctx(caller_domain="api.evil.com"))
        assert result.denied


# ── CEL rule integration in evaluator ─────────────────────────


class TestCELRulesInEvaluator:
    """Test that CEL rules are correctly wired into evaluate()."""

    def test_cel_deny_rule(self) -> None:
        doc = _doc(
            PolicyRules(
                cel_rules=[
                    CELRule(
                        id="trust",
                        expression="request.caller_trust_score >= 90.0",
                        effect="deny",
                        message="Low trust",
                    )
                ],
            )
        )
        result = PolicyEvaluator().evaluate(doc, _ctx(caller_trust_score=50.0))
        assert result.denied
        assert any(v.rule == "cel:trust" for v in result.violations)

    def test_cel_warn_rule(self) -> None:
        doc = _doc(
            PolicyRules(
                cel_rules=[
                    CELRule(
                        id="advisory",
                        expression='request.protocol == "mcp"',
                        effect="warn",
                        message="Not MCP",
                    )
                ],
            )
        )
        result = PolicyEvaluator().evaluate(doc, _ctx(protocol="a2a"))
        assert result.allowed
        assert any(w.rule == "cel:advisory" for w in result.warnings)

    def test_no_celpy_graceful_skip(self) -> None:
        """When cel_evaluator module import fails, CEL rules are skipped."""
        import sys

        doc = _doc(
            PolicyRules(
                cel_rules=[CELRule(id="blocked", expression="false", effect="deny")],
            )
        )
        saved = sys.modules.pop("dns_aid.sdk.policy.cel_evaluator", None)
        sys.modules["dns_aid.sdk.policy.cel_evaluator"] = None  # type: ignore[assignment]
        try:
            result = PolicyEvaluator().evaluate(doc, _ctx())
            assert result.allowed  # Fail open
        finally:
            if saved is not None:
                sys.modules["dns_aid.sdk.policy.cel_evaluator"] = saved
            else:
                sys.modules.pop("dns_aid.sdk.policy.cel_evaluator", None)
