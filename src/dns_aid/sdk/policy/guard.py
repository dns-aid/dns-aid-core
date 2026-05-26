# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
MCP server policy guard — pre-invocation policy check.

Checks the target agent's policy_uri before invocation via
call_agent_tool or send_a2a_message. Uses the same PolicyEvaluator
as the SDK client and target middleware — single evaluation engine,
three enforcement points.
"""

from __future__ import annotations

import os

import structlog

from dns_aid.sdk.policy.evaluator import PolicyEvaluator
from dns_aid.sdk.policy.models import PolicyContext, PolicyResult
from dns_aid.sdk.policy.schema import PolicyEnforcementLayer

logger = structlog.get_logger(__name__)

# Module-level evaluator instance shared across guard calls
_evaluator: PolicyEvaluator | None = None


def _get_evaluator() -> PolicyEvaluator:
    """Get or create the module-level PolicyEvaluator."""
    global _evaluator
    if _evaluator is None:
        ttl = int(os.getenv("DNS_AID_POLICY_CACHE_TTL", "300"))
        _evaluator = PolicyEvaluator(cache_ttl=ttl)
    return _evaluator


async def check_target_policy(
    policy_uri: str | None,
    *,
    protocol: str = "mcp",
    method: str | None = None,
    tool_name: str | None = None,
    caller_id: str = "dns-aid-mcp-server",
) -> PolicyResult:
    """Check target agent's policy before invocation.

    Args:
        policy_uri: The target agent's policy document URL (from SVCB key65403
                    or agent card). If None, returns allowed (no-policy).
        protocol: Protocol being used (mcp, a2a, https).
        method: Method being invoked (e.g., tools/call).
        tool_name: For MCP tools/call, the name of the tool being invoked
                   (e.g., "explore_network"). Forwarded to ``PolicyContext``
                   so policy rules can match on tool name (e.g.,
                   ``denied_tools`` or per-tool ``allowed_caller_domains``).
        caller_id: Identifier for the calling MCP server.

    Returns:
        PolicyResult indicating whether invocation is allowed.
    """
    if not policy_uri:
        return PolicyResult(allowed=True)

    policy_mode = os.getenv("DNS_AID_POLICY_MODE", "permissive")
    if policy_mode == "disabled":
        return PolicyResult(allowed=True)

    evaluator = _get_evaluator()

    try:
        policy_doc = await evaluator.fetch(policy_uri)
        ctx = PolicyContext(
            caller_id=caller_id,
            caller_domain=os.getenv("DNS_AID_CALLER_DOMAIN"),
            protocol=protocol,
            method=method,
            tool_name=tool_name,
        )
        result = evaluator.evaluate(
            policy_doc,
            ctx,
            layer=PolicyEnforcementLayer.CALLER,
        )

        if result.denied:
            logger.warning(
                "mcp.policy_denied",
                policy_uri=policy_uri,
                protocol=protocol,
                method=method,
                tool_name=tool_name,
                violations=[f"{v.rule}:{v.detail}" for v in result.violations],
                mode=policy_mode,
            )

        return result

    except Exception as exc:
        logger.warning(
            "mcp.policy_check_failed",
            policy_uri=policy_uri,
            error=str(exc),
        )
        # Fail-open: allow invocation when policy fetch fails
        return PolicyResult(allowed=True)
