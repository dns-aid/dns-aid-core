# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for MCP server policy guard."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from dns_aid.sdk.policy.guard import check_target_policy
from dns_aid.sdk.policy.models import PolicyResult, PolicyViolation
from dns_aid.sdk.policy.schema import PolicyDocument, PolicyRules

# =============================================================================
# check_target_policy tests
# =============================================================================


class TestCheckTargetPolicy:
    @pytest.mark.asyncio
    async def test_no_policy_uri_returns_allowed(self) -> None:
        """No policy_uri means no policy — always allowed."""
        result = await check_target_policy(None)
        assert result.allowed

    @pytest.mark.asyncio
    async def test_disabled_mode_returns_allowed(self) -> None:
        """Disabled mode skips policy check entirely."""
        with patch.dict("os.environ", {"DNS_AID_POLICY_MODE": "disabled"}):
            result = await check_target_policy("https://example.com/policy.json")
            assert result.allowed

    @pytest.mark.asyncio
    async def test_policy_allowed(self) -> None:
        """Policy check passes — invocation allowed."""
        doc = PolicyDocument(
            version="1.0",
            agent="_test._mcp._agents.example.com",
            rules=PolicyRules(),  # No rules = everything allowed
        )
        mock_eval = AsyncMock()
        mock_eval.fetch = AsyncMock(return_value=doc)
        mock_eval.evaluate = lambda doc, ctx, **kw: PolicyResult(allowed=True)

        with (
            patch("dns_aid.sdk.policy.guard._get_evaluator", return_value=mock_eval),
            patch.dict("os.environ", {"DNS_AID_POLICY_MODE": "strict"}),
        ):
            result = await check_target_policy(
                "https://example.com/policy.json",
                protocol="mcp",
                method="tools/call",
            )
            assert result.allowed

    @pytest.mark.asyncio
    async def test_policy_denied(self) -> None:
        """Policy check fails — returns denied result."""
        doc = PolicyDocument(
            version="1.0",
            agent="_test._mcp._agents.example.com",
            rules=PolicyRules(required_auth_types=["oauth2"]),
        )
        violations = [
            PolicyViolation(
                rule="required_auth_types",
                detail="no auth provided, requires ['oauth2']",
                layer="layer1",
            )
        ]
        mock_eval = AsyncMock()
        mock_eval.fetch = AsyncMock(return_value=doc)
        mock_eval.evaluate = lambda doc, ctx, **kw: PolicyResult(
            allowed=False,
            violations=violations,
        )

        with (
            patch("dns_aid.sdk.policy.guard._get_evaluator", return_value=mock_eval),
            patch.dict("os.environ", {"DNS_AID_POLICY_MODE": "strict"}),
        ):
            result = await check_target_policy(
                "https://example.com/policy.json",
                protocol="mcp",
                method="tools/call",
            )
            assert result.denied
            assert len(result.violations) == 1
            assert result.violations[0].rule == "required_auth_types"

    @pytest.mark.asyncio
    async def test_fetch_failure_is_fail_open(self) -> None:
        """Fetch failure should not block invocation (fail-open)."""
        mock_eval = AsyncMock()
        mock_eval.fetch = AsyncMock(side_effect=Exception("network error"))

        with (
            patch("dns_aid.sdk.policy.guard._get_evaluator", return_value=mock_eval),
            patch.dict("os.environ", {"DNS_AID_POLICY_MODE": "strict"}),
        ):
            result = await check_target_policy(
                "https://example.com/policy.json",
            )
            assert result.allowed

    @pytest.mark.asyncio
    async def test_respects_policy_mode_env(self) -> None:
        """Guard reads DNS_AID_POLICY_MODE from environment."""
        with patch.dict("os.environ", {"DNS_AID_POLICY_MODE": "disabled"}):
            result = await check_target_policy("https://example.com/policy.json")
            assert result.allowed

    @pytest.mark.asyncio
    async def test_passes_caller_domain_from_env(self) -> None:
        """Guard reads DNS_AID_CALLER_DOMAIN from environment."""
        doc = PolicyDocument(
            version="1.0",
            agent="_test._mcp._agents.example.com",
            rules=PolicyRules(allowed_caller_domains=["*.infoblox.com"]),
        )
        mock_eval = AsyncMock()
        mock_eval.fetch = AsyncMock(return_value=doc)
        # Use real evaluator to check domain matching
        from dns_aid.sdk.policy.evaluator import PolicyEvaluator

        real_evaluator = PolicyEvaluator()
        mock_eval.evaluate = real_evaluator.evaluate

        with (
            patch("dns_aid.sdk.policy.guard._get_evaluator", return_value=mock_eval),
            patch.dict(
                "os.environ",
                {
                    "DNS_AID_POLICY_MODE": "strict",
                    "DNS_AID_CALLER_DOMAIN": "api.infoblox.com",
                },
            ),
        ):
            result = await check_target_policy(
                "https://example.com/policy.json",
                protocol="mcp",
                method="tools/call",
            )
            assert result.allowed

    @pytest.mark.asyncio
    async def test_protocol_forwarded_to_context(self) -> None:
        """Protocol and method are forwarded to PolicyContext."""
        captured_ctx = {}

        def capture_evaluate(doc, ctx, **kw):
            captured_ctx["protocol"] = ctx.protocol
            captured_ctx["method"] = ctx.method
            return PolicyResult(allowed=True)

        doc = PolicyDocument(
            version="1.0",
            agent="_test._mcp._agents.example.com",
            rules=PolicyRules(),
        )
        mock_eval = AsyncMock()
        mock_eval.fetch = AsyncMock(return_value=doc)
        mock_eval.evaluate = capture_evaluate

        with (
            patch("dns_aid.sdk.policy.guard._get_evaluator", return_value=mock_eval),
            patch.dict("os.environ", {"DNS_AID_POLICY_MODE": "permissive"}),
        ):
            await check_target_policy(
                "https://example.com/policy.json",
                protocol="a2a",
                method="message/send",
            )
            assert captured_ctx["protocol"] == "a2a"
            assert captured_ctx["method"] == "message/send"
