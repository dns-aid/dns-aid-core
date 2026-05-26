# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for CEL custom rule evaluation."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from pydantic import ValidationError

from dns_aid.sdk.policy.evaluator import PolicyEvaluator
from dns_aid.sdk.policy.models import PolicyContext
from dns_aid.sdk.policy.schema import (
    CELRule,
    PolicyDocument,
    PolicyEnforcementLayer,
    PolicyRules,
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


def _doc(cel_rules: list[CELRule], native_rules: dict | None = None) -> PolicyDocument:
    """Helper to build a PolicyDocument with CEL rules."""
    rules_kwargs = native_rules or {}
    rules_kwargs["cel_rules"] = cel_rules
    return PolicyDocument(
        version="1.1",
        agent="_test._mcp._agents.example.com",
        rules=PolicyRules(**rules_kwargs),
    )


# =============================================================================
# CELRuleEvaluator unit tests
# =============================================================================


class TestCELRuleEvaluator:
    """Test the CELRuleEvaluator class directly."""

    def test_trust_score_pass(self) -> None:
        from dns_aid.sdk.policy.cel_evaluator import CELRuleEvaluator

        evaluator = CELRuleEvaluator()
        rules = [
            CELRule(id="trust", expression="request.caller_trust_score >= 50.0", effect="deny")
        ]
        violations, warnings = evaluator.evaluate(rules, _ctx(caller_trust_score=80.0), "layer1")
        assert len(violations) == 0

    def test_trust_score_fail(self) -> None:
        from dns_aid.sdk.policy.cel_evaluator import CELRuleEvaluator

        evaluator = CELRuleEvaluator()
        rules = [
            CELRule(
                id="trust",
                expression="request.caller_trust_score >= 90.0",
                effect="deny",
                message="Too low",
            )
        ]
        violations, warnings = evaluator.evaluate(rules, _ctx(caller_trust_score=80.0), "layer1")
        assert len(violations) == 1
        assert violations[0].rule == "cel:trust"
        assert violations[0].detail == "Too low"

    def test_method_starts_with(self) -> None:
        from dns_aid.sdk.policy.cel_evaluator import CELRuleEvaluator

        evaluator = CELRuleEvaluator()
        rules = [
            CELRule(id="no-admin", expression='!request.method.startsWith("admin/")', effect="deny")
        ]
        # Should pass for tools/call
        v, w = evaluator.evaluate(rules, _ctx(method="tools/call"), "layer1")
        assert len(v) == 0
        # Should fail for admin/delete
        v, w = evaluator.evaluate(rules, _ctx(method="admin/delete"), "layer1")
        assert len(v) == 1

    def test_geo_sanctions(self) -> None:
        from dns_aid.sdk.policy.cel_evaluator import CELRuleEvaluator

        evaluator = CELRuleEvaluator()
        rules = [
            CELRule(
                id="geo",
                expression='!(request.geo_country in ["KP", "IR", "SY"])',
                effect="deny",
                message="Sanctioned country",
            )
        ]
        v, _ = evaluator.evaluate(rules, _ctx(geo_country="US"), "layer1")
        assert len(v) == 0
        v, _ = evaluator.evaluate(rules, _ctx(geo_country="KP"), "layer1")
        assert len(v) == 1

    def test_warn_effect(self) -> None:
        from dns_aid.sdk.policy.cel_evaluator import CELRuleEvaluator

        evaluator = CELRuleEvaluator()
        rules = [
            CELRule(
                id="protocol-warn",
                expression='request.protocol == "mcp"',
                effect="warn",
                message="Not MCP",
            )
        ]
        v, w = evaluator.evaluate(rules, _ctx(protocol="a2a"), "layer1")
        assert len(v) == 0
        assert len(w) == 1
        assert w[0].rule == "cel:protocol-warn"

    def test_boolean_field_dnssec(self) -> None:
        from dns_aid.sdk.policy.cel_evaluator import CELRuleEvaluator

        evaluator = CELRuleEvaluator()
        rules = [CELRule(id="dnssec", expression="request.dnssec_validated", effect="deny")]
        v, _ = evaluator.evaluate(rules, _ctx(dnssec_validated=True), "layer1")
        assert len(v) == 0
        v, _ = evaluator.evaluate(rules, _ctx(dnssec_validated=False), "layer1")
        assert len(v) == 1

    def test_payload_bytes_int(self) -> None:
        from dns_aid.sdk.policy.cel_evaluator import CELRuleEvaluator

        evaluator = CELRuleEvaluator()
        rules = [
            CELRule(id="payload", expression="request.payload_bytes <= 1048576", effect="deny")
        ]
        v, _ = evaluator.evaluate(rules, _ctx(payload_bytes=512), "layer1")
        assert len(v) == 0
        v, _ = evaluator.evaluate(rules, _ctx(payload_bytes=2_000_000), "layer1")
        assert len(v) == 1

    def test_none_coercion_to_zero_values(self) -> None:
        """None fields coerce to zero-values: '' for str, 0 for int, 0.0 for float, false for bool."""
        from dns_aid.sdk.policy.cel_evaluator import CELRuleEvaluator

        evaluator = CELRuleEvaluator()
        # None trust score → 0.0, so >= 50.0 fails
        rules = [
            CELRule(id="trust", expression="request.caller_trust_score >= 50.0", effect="deny")
        ]
        v, _ = evaluator.evaluate(rules, _ctx(caller_trust_score=None), "layer1")
        assert len(v) == 1

    def test_compilation_caching(self) -> None:
        """Second evaluation of same expression should use cached runner."""
        from dns_aid.sdk.policy.cel_evaluator import CELRuleEvaluator

        evaluator = CELRuleEvaluator()
        rules = [
            CELRule(id="cached", expression="request.caller_trust_score >= 0.5", effect="deny")
        ]
        evaluator.evaluate(rules, _ctx(), "layer1")
        assert "request.caller_trust_score >= 0.5" in evaluator._cache
        # Evaluate again — should hit cache
        evaluator.evaluate(rules, _ctx(), "layer1")
        assert len(evaluator._cache) == 1

    def test_multiple_rules_all_evaluated(self) -> None:
        from dns_aid.sdk.policy.cel_evaluator import CELRuleEvaluator

        evaluator = CELRuleEvaluator()
        rules = [
            CELRule(
                id="r1",
                expression="request.caller_trust_score >= 90.0",
                effect="deny",
                message="r1 fail",
            ),
            CELRule(
                id="r2", expression='request.protocol == "a2a"', effect="deny", message="r2 fail"
            ),
        ]
        v, _ = evaluator.evaluate(rules, _ctx(caller_trust_score=80.0, protocol="mcp"), "layer1")
        assert len(v) == 2
        assert {x.rule for x in v} == {"cel:r1", "cel:r2"}

    def test_layer_filtering(self) -> None:
        """Rules with enforcement_layers should only run on matching layers."""
        from dns_aid.sdk.policy.cel_evaluator import CELRuleEvaluator

        evaluator = CELRuleEvaluator()
        rules = [
            CELRule(
                id="l2-only",
                expression="request.caller_trust_score >= 90.0",
                effect="deny",
                enforcement_layers=["layer2"],
            )
        ]
        # Layer 1 → should skip
        v, _ = evaluator.evaluate(rules, _ctx(caller_trust_score=10.0), "layer1")
        assert len(v) == 0
        # Layer 2 → should fire
        v, _ = evaluator.evaluate(rules, _ctx(caller_trust_score=10.0), "layer2")
        assert len(v) == 1

    def test_no_enforcement_layers_runs_everywhere(self) -> None:
        from dns_aid.sdk.policy.cel_evaluator import CELRuleEvaluator

        evaluator = CELRuleEvaluator()
        rules = [
            CELRule(id="global", expression="request.caller_trust_score >= 90.0", effect="deny")
        ]
        for layer in ("layer0", "layer1", "layer2"):
            v, _ = evaluator.evaluate(rules, _ctx(caller_trust_score=10.0), layer)
            assert len(v) == 1, f"Expected violation on {layer}"


# =============================================================================
# CEL error handling
# =============================================================================


class TestCELErrorHandling:
    """Test CEL fail-open behavior on errors."""

    def test_syntax_error_fails_open(self) -> None:
        from dns_aid.sdk.policy.cel_evaluator import CELRuleEvaluator

        evaluator = CELRuleEvaluator()
        rules = [CELRule(id="bad-syntax", expression="!!! invalid CEL ???", effect="deny")]
        v, w = evaluator.evaluate(rules, _ctx(), "layer1")
        assert len(v) == 0  # Fail open

    def test_runtime_error_fails_open(self) -> None:
        from dns_aid.sdk.policy.cel_evaluator import CELRuleEvaluator

        evaluator = CELRuleEvaluator()
        # Access a key that doesn't exist in the request map
        rules = [
            CELRule(id="missing-key", expression="request.nonexistent_field == 'x'", effect="deny")
        ]
        v, w = evaluator.evaluate(rules, _ctx(), "layer1")
        # Should fail open (either no violation or graceful error)
        assert len(v) == 0

    def test_mixed_good_and_bad_rules(self) -> None:
        """Bad rules fail open, good rules still evaluate."""
        from dns_aid.sdk.policy.cel_evaluator import CELRuleEvaluator

        evaluator = CELRuleEvaluator()
        rules = [
            CELRule(id="bad", expression="!!! invalid", effect="deny"),
            CELRule(
                id="good",
                expression="request.caller_trust_score >= 90.0",
                effect="deny",
                message="Low trust",
            ),
        ]
        v, w = evaluator.evaluate(rules, _ctx(caller_trust_score=50.0), "layer1")
        # Only the good rule should fire
        assert len(v) == 1
        assert v[0].rule == "cel:good"

    def test_celpy_not_installed_graceful(self) -> None:
        """When celpy is not installed, PolicyEvaluator should log warning and skip CEL rules."""
        doc = _doc([CELRule(id="r1", expression="true", effect="deny")])
        with patch("dns_aid.sdk.policy.evaluator.logger") as mock_logger:
            with patch.dict(
                "sys.modules", {"celpy": None, "dns_aid.sdk.policy.cel_evaluator": None}
            ):
                import sys

                # Remove cached module so import fails
                saved = sys.modules.pop("dns_aid.sdk.policy.cel_evaluator", None)
                sys.modules["dns_aid.sdk.policy.cel_evaluator"] = None  # type: ignore[assignment]
                try:
                    result = PolicyEvaluator().evaluate(doc, _ctx())
                    # Should fail open — allowed
                    assert result.allowed
                    mock_logger.warning.assert_called()
                finally:
                    if saved is not None:
                        sys.modules["dns_aid.sdk.policy.cel_evaluator"] = saved
                    else:
                        sys.modules.pop("dns_aid.sdk.policy.cel_evaluator", None)

    def test_empty_cel_rules_list(self) -> None:
        """Empty cel_rules list should be a no-op."""
        from dns_aid.sdk.policy.cel_evaluator import CELRuleEvaluator

        evaluator = CELRuleEvaluator()
        v, w = evaluator.evaluate([], _ctx(), "layer1")
        assert len(v) == 0
        assert len(w) == 0


# =============================================================================
# Integration: native + CEL rules together
# =============================================================================


class TestCELIntegration:
    """Test CEL rules alongside native policy rules via PolicyEvaluator.evaluate()."""

    def test_native_pass_cel_deny(self) -> None:
        """Native rules pass but CEL rule denies → overall denied."""
        doc = _doc(
            cel_rules=[
                CELRule(
                    id="trust",
                    expression="request.caller_trust_score >= 90.0",
                    effect="deny",
                    message="CEL: low trust",
                )
            ],
            native_rules={"required_protocols": ["mcp"]},
        )
        result = PolicyEvaluator().evaluate(doc, _ctx(protocol="mcp", caller_trust_score=50.0))
        assert result.denied
        assert any(v.rule == "cel:trust" for v in result.violations)

    def test_native_deny_cel_pass(self) -> None:
        """Native rules deny, CEL passes → overall denied (from native)."""
        doc = _doc(
            cel_rules=[CELRule(id="ok", expression="true", effect="deny")],
            native_rules={"required_protocols": ["a2a"]},
        )
        result = PolicyEvaluator().evaluate(doc, _ctx(protocol="mcp"))
        assert result.denied
        assert any(v.rule == "required_protocols" for v in result.violations)
        # No CEL violations
        assert not any(v.rule.startswith("cel:") for v in result.violations)

    def test_both_pass(self) -> None:
        """Both native and CEL pass → allowed."""
        doc = _doc(
            cel_rules=[
                CELRule(id="ok", expression="request.caller_trust_score >= 10.0", effect="deny")
            ],
            native_rules={"required_protocols": ["mcp"]},
        )
        result = PolicyEvaluator().evaluate(doc, _ctx(protocol="mcp", caller_trust_score=80.0))
        assert result.allowed

    def test_cel_layer_filtering_via_evaluator(self) -> None:
        """CEL rules with layer restrictions respected through PolicyEvaluator."""
        doc = _doc(
            cel_rules=[
                CELRule(
                    id="target-only",
                    expression="request.caller_trust_score >= 99.0",
                    effect="deny",
                    enforcement_layers=["layer2"],
                )
            ],
        )
        # Caller layer → should skip CEL rule
        result = PolicyEvaluator().evaluate(
            doc,
            _ctx(caller_trust_score=10.0),
            layer=PolicyEnforcementLayer.CALLER,
        )
        assert result.allowed
        # Target layer → should fire
        result = PolicyEvaluator().evaluate(
            doc,
            _ctx(caller_trust_score=10.0),
            layer=PolicyEnforcementLayer.TARGET,
        )
        assert result.denied

    def test_cel_warnings_in_result(self) -> None:
        """CEL warn rules appear in result.warnings."""
        doc = _doc(
            cel_rules=[
                CELRule(
                    id="advisory",
                    expression='request.protocol == "mcp"',
                    effect="warn",
                    message="Not MCP",
                )
            ],
        )
        result = PolicyEvaluator().evaluate(doc, _ctx(protocol="a2a"))
        assert result.allowed  # Warnings don't deny
        assert any(w.rule == "cel:advisory" for w in result.warnings)


# =============================================================================
# Hardening tests
# =============================================================================


class TestCELHardening:
    """Test security hardening: cache bounds, input validation, DoS resistance."""

    def test_cache_eviction_at_max_size(self) -> None:
        """Compilation cache should evict oldest entry when full."""
        from dns_aid.sdk.policy.cel_evaluator import _MAX_CACHE_SIZE, CELRuleEvaluator

        evaluator = CELRuleEvaluator()
        # Fill the cache to max
        for i in range(_MAX_CACHE_SIZE):
            evaluator._compile(f"request.caller_trust_score >= {i}.0")
        assert len(evaluator._cache) == _MAX_CACHE_SIZE

        # One more should evict the oldest
        evaluator._compile("request.caller_trust_score >= 999.0")
        assert len(evaluator._cache) == _MAX_CACHE_SIZE
        # First entry should be evicted
        assert "request.caller_trust_score >= 0.0" not in evaluator._cache
        # New entry should be present
        assert "request.caller_trust_score >= 999.0" in evaluator._cache

    def test_invalid_cel_id_empty_rejected(self) -> None:
        """Empty CEL rule ID should be rejected by schema."""
        with pytest.raises(ValidationError):
            CELRule(id="", expression="true")

    def test_invalid_cel_id_special_chars_rejected(self) -> None:
        """CEL rule IDs with special characters should be rejected."""
        with pytest.raises(ValidationError):
            CELRule(id="rule with spaces", expression="true")

    def test_invalid_cel_id_leading_dash_rejected(self) -> None:
        """CEL rule IDs starting with dash/dot should be rejected."""
        with pytest.raises(ValidationError):
            CELRule(id="-bad-start", expression="true")

    def test_valid_cel_id_patterns(self) -> None:
        """Valid CEL rule IDs: alphanumeric, dots, dashes, underscores."""
        for valid_id in ("rule1", "my-rule", "my_rule", "my.rule", "Rule.v2-beta_1"):
            rule = CELRule(id=valid_id, expression="true")
            assert rule.id == valid_id

    def test_cel_rules_max_count_enforced(self) -> None:
        """PolicyRules should reject more than 64 CEL rules."""
        rules = [CELRule(id=f"r{i}", expression="true") for i in range(65)]
        with pytest.raises(ValidationError):
            PolicyRules(cel_rules=rules)

    def test_cel_rules_at_max_count_accepted(self) -> None:
        """64 CEL rules should be accepted."""
        rules = [CELRule(id=f"r{i}", expression="true") for i in range(64)]
        pr = PolicyRules(cel_rules=rules)
        assert len(pr.cel_rules) == 64

    def test_empty_expression_rejected(self) -> None:
        """Empty expression should be rejected by schema."""
        with pytest.raises(ValidationError):
            CELRule(id="bad", expression="")

    def test_message_max_length(self) -> None:
        """Message over 512 chars should be rejected."""
        with pytest.raises(ValidationError):
            CELRule(id="bad", expression="true", message="x" * 513)

    def test_non_boolean_expression_warns(self) -> None:
        """Expressions returning non-bool should log warning but still evaluate."""
        from dns_aid.sdk.policy.cel_evaluator import CELRuleEvaluator

        evaluator = CELRuleEvaluator()
        # size() returns int, not bool — should warn
        rules = [CELRule(id="size-check", expression="size(request.method)", effect="deny")]
        with patch("dns_aid.sdk.policy.cel_evaluator.logger") as mock_logger:
            v, w = evaluator.evaluate(rules, _ctx(method="tools/call"), "layer1")
            # size("tools/call") = 10, truthy → no violation
            assert len(v) == 0
            mock_logger.warning.assert_called_with(
                "policy.cel_non_boolean_result",
                rule_id="size-check",
                result_type="int",
                hint="CEL rules should return bool; non-bool is coerced via truthiness",
            )

    def test_non_boolean_zero_triggers_violation(self) -> None:
        """Expression returning 0 (falsy non-bool) should trigger violation and warn."""
        from dns_aid.sdk.policy.cel_evaluator import CELRuleEvaluator

        evaluator = CELRuleEvaluator()
        # size("") = 0, falsy → triggers deny
        rules = [CELRule(id="zero", expression="size(request.method)", effect="deny")]
        v, w = evaluator.evaluate(rules, _ctx(method=""), "layer1")
        assert len(v) == 1
        assert v[0].rule == "cel:zero"


# =============================================================================
# Tool-level CEL context (Phase 6.6)
# =============================================================================


class TestToolNameCEL:
    """Test tool_name field in CEL evaluation."""

    def test_tool_name_block_destructive(self) -> None:
        """CEL can block specific tool names."""
        from dns_aid.sdk.policy.cel_evaluator import CELRuleEvaluator

        evaluator = CELRuleEvaluator()
        rules = [
            CELRule(
                id="no-delete",
                expression='!(request.tool_name in ["delete_user", "drop_table"])',
                effect="deny",
                message="Destructive tool blocked",
            )
        ]
        # Safe tool → passes
        v, _ = evaluator.evaluate(rules, _ctx(tool_name="read_user"), "layer1")
        assert len(v) == 0
        # Destructive tool → denied
        v, _ = evaluator.evaluate(rules, _ctx(tool_name="delete_user"), "layer1")
        assert len(v) == 1
        assert v[0].detail == "Destructive tool blocked"

    def test_tool_name_allowlist(self) -> None:
        """CEL can enforce a tool allowlist."""
        from dns_aid.sdk.policy.cel_evaluator import CELRuleEvaluator

        evaluator = CELRuleEvaluator()
        rules = [
            CELRule(
                id="allowlist",
                expression='request.tool_name in ["search", "get_info", ""]',
                effect="deny",
            )
        ]
        v, _ = evaluator.evaluate(rules, _ctx(tool_name="search"), "layer1")
        assert len(v) == 0
        v, _ = evaluator.evaluate(rules, _ctx(tool_name="hack_system"), "layer1")
        assert len(v) == 1

    def test_tool_name_starts_with_admin(self) -> None:
        """CEL can restrict admin-prefixed tools."""
        from dns_aid.sdk.policy.cel_evaluator import CELRuleEvaluator

        evaluator = CELRuleEvaluator()
        rules = [
            CELRule(
                id="admin-restrict",
                expression='!request.tool_name.startsWith("admin_")',
                effect="deny",
            )
        ]
        v, _ = evaluator.evaluate(rules, _ctx(tool_name="read_user"), "layer1")
        assert len(v) == 0
        v, _ = evaluator.evaluate(rules, _ctx(tool_name="admin_delete"), "layer1")
        assert len(v) == 1

    def test_tool_name_none_coerces_to_empty(self) -> None:
        """None tool_name coerces to empty string in CEL."""
        from dns_aid.sdk.policy.cel_evaluator import CELRuleEvaluator

        evaluator = CELRuleEvaluator()
        rules = [
            CELRule(
                id="check",
                expression='request.tool_name == ""',
                effect="deny",
            )
        ]
        # None → "" → expression is true → no violation
        v, _ = evaluator.evaluate(rules, _ctx(tool_name=None), "layer1")
        assert len(v) == 0

    def test_a2a_method_as_tool_name(self) -> None:
        """For A2A, the method itself is the tool_name."""
        from dns_aid.sdk.policy.cel_evaluator import CELRuleEvaluator

        evaluator = CELRuleEvaluator()
        rules = [
            CELRule(
                id="a2a-method",
                expression='request.tool_name == "tasks/send"',
                effect="deny",
            )
        ]
        v, _ = evaluator.evaluate(rules, _ctx(protocol="a2a", tool_name="tasks/send"), "layer1")
        assert len(v) == 0  # Expression true → allowed


# =============================================================================
# Circuit state CEL context (Phase 6.6)
# =============================================================================


class TestCircuitStateCEL:
    """Test target_circuit_state field in CEL evaluation."""

    def test_circuit_state_closed_passes(self) -> None:
        from dns_aid.sdk.policy.cel_evaluator import CELRuleEvaluator

        evaluator = CELRuleEvaluator()
        rules = [
            CELRule(
                id="circuit",
                expression='request.target_circuit_state == "closed"',
                effect="deny",
            )
        ]
        v, _ = evaluator.evaluate(rules, _ctx(target_circuit_state="closed"), "layer1")
        assert len(v) == 0

    def test_circuit_state_open_denied(self) -> None:
        from dns_aid.sdk.policy.cel_evaluator import CELRuleEvaluator

        evaluator = CELRuleEvaluator()
        rules = [
            CELRule(
                id="circuit",
                expression='request.target_circuit_state != "open"',
                effect="deny",
            )
        ]
        v, _ = evaluator.evaluate(rules, _ctx(target_circuit_state="open"), "layer1")
        assert len(v) == 1

    def test_circuit_state_none_defaults_to_closed(self) -> None:
        """None circuit state coerces to 'closed' in CEL."""
        from dns_aid.sdk.policy.cel_evaluator import CELRuleEvaluator

        evaluator = CELRuleEvaluator()
        rules = [
            CELRule(
                id="circuit",
                expression='request.target_circuit_state == "closed"',
                effect="deny",
            )
        ]
        v, _ = evaluator.evaluate(rules, _ctx(target_circuit_state=None), "layer1")
        assert len(v) == 0  # None → "closed" → match → allowed

    def test_circuit_combined_with_trust(self) -> None:
        from dns_aid.sdk.policy.cel_evaluator import CELRuleEvaluator

        evaluator = CELRuleEvaluator()
        rules = [
            CELRule(
                id="circuit-trust",
                expression='request.target_circuit_state == "closed" && request.caller_trust_score >= 50.0',
                effect="deny",
            )
        ]
        # Both conditions met
        v, _ = evaluator.evaluate(
            rules,
            _ctx(target_circuit_state="closed", caller_trust_score=80.0),
            "layer1",
        )
        assert len(v) == 0
        # Circuit half_open → denied
        v, _ = evaluator.evaluate(
            rules,
            _ctx(target_circuit_state="half_open", caller_trust_score=80.0),
            "layer1",
        )
        assert len(v) == 1
