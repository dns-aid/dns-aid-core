# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for PolicyContext, PolicyResult, PolicyViolationError models."""

from __future__ import annotations

import pytest

from dns_aid.sdk.policy.models import (
    PolicyContext,
    PolicyResult,
    PolicyViolation,
    PolicyViolationError,
)

# =============================================================================
# PolicyContext tests
# =============================================================================


class TestPolicyContext:
    """Test PolicyContext creation."""

    def test_creation_with_all_fields(self) -> None:
        """PolicyContext with all fields populated."""
        ctx = PolicyContext(
            caller_id="agent-123",
            caller_domain="infoblox.com",
            protocol="mcp",
            method="tools/call",
            intent="query",
            auth_type="oauth2",
            dnssec_validated=True,
            tls_version="1.3",
            caller_trust_score=0.85,
            geo_country="US",
            payload_bytes=4096,
            has_mutual_tls=True,
            consent_token="tok-abc",
        )
        assert ctx.caller_id == "agent-123"
        assert ctx.caller_domain == "infoblox.com"
        assert ctx.protocol == "mcp"
        assert ctx.method == "tools/call"
        assert ctx.intent == "query"
        assert ctx.auth_type == "oauth2"
        assert ctx.dnssec_validated is True
        assert ctx.tls_version == "1.3"
        assert ctx.caller_trust_score == 0.85
        assert ctx.geo_country == "US"
        assert ctx.payload_bytes == 4096
        assert ctx.has_mutual_tls is True
        assert ctx.consent_token == "tok-abc"

    def test_creation_with_defaults(self) -> None:
        """PolicyContext with all defaults (no arguments)."""
        ctx = PolicyContext()
        assert ctx.caller_id is None
        assert ctx.caller_domain is None
        assert ctx.protocol is None
        assert ctx.method is None
        assert ctx.intent is None
        assert ctx.auth_type is None
        assert ctx.dnssec_validated is False
        assert ctx.tls_version is None
        assert ctx.caller_trust_score is None
        assert ctx.geo_country is None
        assert ctx.payload_bytes is None
        assert ctx.has_mutual_tls is False
        assert ctx.consent_token is None

    def test_partial_fields(self) -> None:
        """PolicyContext with only some fields set."""
        ctx = PolicyContext(
            caller_domain="example.com",
            protocol="a2a",
            dnssec_validated=True,
        )
        assert ctx.caller_domain == "example.com"
        assert ctx.protocol == "a2a"
        assert ctx.dnssec_validated is True
        assert ctx.caller_id is None


# =============================================================================
# PolicyViolation tests
# =============================================================================


class TestPolicyViolation:
    """Test PolicyViolation creation."""

    def test_creation(self) -> None:
        violation = PolicyViolation(
            rule="required_auth_types",
            detail="oauth2 required, got bearer",
            layer="layer1",
        )
        assert violation.rule == "required_auth_types"
        assert violation.detail == "oauth2 required, got bearer"
        assert violation.layer == "layer1"

    def test_target_layer(self) -> None:
        violation = PolicyViolation(
            rule="rate_limits",
            detail="exceeded 60 req/min",
            layer="layer2",
        )
        assert violation.layer == "layer2"


# =============================================================================
# PolicyResult tests
# =============================================================================


class TestPolicyResult:
    """Test PolicyResult model and computed properties."""

    def test_denied_is_true_when_not_allowed(self) -> None:
        result = PolicyResult(
            allowed=False,
            violations=[
                PolicyViolation(
                    rule="require_dnssec",
                    detail="DNSSEC required but not validated",
                    layer="layer1",
                )
            ],
        )
        assert result.denied is True
        assert result.allowed is False

    def test_denied_is_false_when_allowed(self) -> None:
        result = PolicyResult(allowed=True)
        assert result.denied is False

    def test_reason_formats_violations(self) -> None:
        result = PolicyResult(
            allowed=False,
            violations=[
                PolicyViolation(
                    rule="require_dnssec",
                    detail="DNSSEC required",
                    layer="layer1",
                ),
                PolicyViolation(
                    rule="min_tls_version",
                    detail="TLS 1.3 required, got 1.2",
                    layer="layer1",
                ),
            ],
        )
        reason = result.reason
        assert "require_dnssec: DNSSEC required" in reason
        assert "min_tls_version: TLS 1.3 required, got 1.2" in reason
        assert "; " in reason

    def test_reason_returns_allowed_when_no_violations(self) -> None:
        result = PolicyResult(allowed=True)
        assert result.reason == "allowed"

    def test_reason_returns_allowed_with_empty_violations(self) -> None:
        result = PolicyResult(allowed=True, violations=[])
        assert result.reason == "allowed"

    def test_warnings_separate_from_violations(self) -> None:
        result = PolicyResult(
            allowed=True,
            warnings=[
                PolicyViolation(
                    rule="data_classification",
                    detail="accessing confidential data",
                    layer="layer1",
                )
            ],
        )
        assert result.allowed is True
        assert len(result.warnings) == 1
        assert len(result.violations) == 0
        assert result.reason == "allowed"


# =============================================================================
# PolicyViolationError tests
# =============================================================================


class TestPolicyViolationError:
    """Test PolicyViolationError exception."""

    def test_message_includes_violation_details(self) -> None:
        result = PolicyResult(
            allowed=False,
            violations=[
                PolicyViolation(
                    rule="require_dnssec",
                    detail="DNSSEC required but not validated",
                    layer="layer1",
                ),
            ],
        )
        error = PolicyViolationError(result)
        assert "Policy violation" in str(error)
        assert "require_dnssec" in str(error)
        assert "DNSSEC required but not validated" in str(error)

    def test_result_attached(self) -> None:
        result = PolicyResult(
            allowed=False,
            violations=[
                PolicyViolation(
                    rule="min_tls_version",
                    detail="TLS 1.3 required",
                    layer="layer1",
                ),
            ],
        )
        error = PolicyViolationError(result)
        assert error.result is result
        assert error.result.denied is True

    def test_raises_correctly(self) -> None:
        result = PolicyResult(
            allowed=False,
            violations=[
                PolicyViolation(rule="consent_required", detail="no consent", layer="layer1"),
            ],
        )
        with pytest.raises(PolicyViolationError, match="Policy violation"):
            raise PolicyViolationError(result)

    def test_multiple_violations_in_message(self) -> None:
        result = PolicyResult(
            allowed=False,
            violations=[
                PolicyViolation(rule="rule_a", detail="detail_a", layer="layer1"),
                PolicyViolation(rule="rule_b", detail="detail_b", layer="layer2"),
            ],
        )
        error = PolicyViolationError(result)
        msg = str(error)
        assert "rule_a: detail_a" in msg
        assert "rule_b: detail_b" in msg
