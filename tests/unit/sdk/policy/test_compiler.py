# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for the PolicyCompiler (policy → RPZ + bind-aid directives)."""

from __future__ import annotations

from pathlib import Path

import pytest

from dns_aid.sdk.policy.compiler import (
    BindAidAction,
    PolicyCompiler,
    RPZAction,
)
from dns_aid.sdk.policy.schema import CELRule, PolicyDocument, PolicyRules

FIXTURES = Path(__file__).resolve().parents[3] / "fixtures"


@pytest.fixture
def compiler() -> PolicyCompiler:
    return PolicyCompiler()


@pytest.fixture
def sample_doc() -> PolicyDocument:
    raw = (FIXTURES / "sample-policy.json").read_text()
    return PolicyDocument.model_validate_json(raw)


def _make_doc(**rule_kwargs: object) -> PolicyDocument:
    """Helper to build a minimal PolicyDocument with specific rules."""
    return PolicyDocument(
        agent="_test._mcp._agents.example.com",
        rules=PolicyRules(**rule_kwargs),
    )


# ── blocked_caller_domains ────────────────────────────────────


class TestBlockedDomains:
    def test_blocked_domains_rpz(self, compiler: PolicyCompiler) -> None:
        doc = _make_doc(blocked_caller_domains=["evil.example.com"])
        result = compiler.compile(doc)
        assert len(result.rpz_directives) == 1
        assert result.rpz_directives[0].owner == "evil.example.com"
        assert result.rpz_directives[0].action == RPZAction.NXDOMAIN

    def test_blocked_domains_bindaid(self, compiler: PolicyCompiler) -> None:
        doc = _make_doc(blocked_caller_domains=["evil.example.com"])
        result = compiler.compile(doc)
        assert len(result.bindaid_directives) == 1
        assert result.bindaid_directives[0].action == BindAidAction.NXDOMAIN

    def test_multiple_blocked_domains(self, compiler: PolicyCompiler) -> None:
        doc = _make_doc(blocked_caller_domains=["a.com", "b.com", "c.com"])
        result = compiler.compile(doc)
        assert len(result.rpz_directives) == 3
        owners = {d.owner for d in result.rpz_directives}
        assert owners == {"a.com", "b.com", "c.com"}

    def test_wildcard_blocked_domain(self, compiler: PolicyCompiler) -> None:
        """Broad wildcards require allow_broad_rpz=True to pass the blast-radius guard."""
        doc = _make_doc(blocked_caller_domains=["*.malicious.net"])
        result = compiler.compile(doc, allow_broad_rpz=True)
        assert result.rpz_directives[0].owner == "*.malicious.net"

    def test_source_rule_tracking(self, compiler: PolicyCompiler) -> None:
        doc = _make_doc(blocked_caller_domains=["evil.com"])
        result = compiler.compile(doc)
        assert result.rpz_directives[0].source_rule == "blocked_caller_domains"
        assert result.bindaid_directives[0].source_rule == "blocked_caller_domains"


# ── allowed_caller_domains ────────────────────────────────────


class TestAllowedDomains:
    def test_allowed_domains_rpz_passthru(self, compiler: PolicyCompiler) -> None:
        doc = _make_doc(allowed_caller_domains=["trusted.com"])
        result = compiler.compile(doc)
        # 1 passthru + 1 catch-all NXDOMAIN
        assert len(result.rpz_directives) == 2
        assert result.rpz_directives[0].action == RPZAction.PASSTHRU
        assert result.rpz_directives[0].owner == "trusted.com"

    def test_allowed_domains_catch_all(self, compiler: PolicyCompiler) -> None:
        doc = _make_doc(allowed_caller_domains=["trusted.com"])
        result = compiler.compile(doc)
        catch_all = result.rpz_directives[-1]
        assert catch_all.owner == "*"
        assert catch_all.action == RPZAction.NXDOMAIN

    def test_allowed_domains_bindaid(self, compiler: PolicyCompiler) -> None:
        doc = _make_doc(allowed_caller_domains=["trusted.com"])
        result = compiler.compile(doc)
        assert result.bindaid_directives[0].action == BindAidAction.PASSTHRU
        assert result.bindaid_directives[-1].action == BindAidAction.NXDOMAIN

    def test_allowed_and_blocked_interaction(self, compiler: PolicyCompiler) -> None:
        doc = _make_doc(
            blocked_caller_domains=["evil.com"],
            allowed_caller_domains=["good.com"],
        )
        result = compiler.compile(doc)
        # blocked: 1 NXDOMAIN, allowed: 1 PASSTHRU + 1 catch-all = 3 total
        assert len(result.rpz_directives) == 3


# ── required_protocols ────────────────────────────────────────


class TestRequiredProtocols:
    def test_bindaid_only(self, compiler: PolicyCompiler) -> None:
        doc = _make_doc(required_protocols=["mcp", "a2a"])
        result = compiler.compile(doc)
        # RPZ gets a skip, bind-aid gets a directive
        skipped_names = [s.rule_name for s in result.skipped]
        assert "required_protocols" in skipped_names
        assert any("key65402=whitelist:mcp,a2a" in d.param_ops for d in result.bindaid_directives)

    def test_no_rpz_directives(self, compiler: PolicyCompiler) -> None:
        doc = _make_doc(required_protocols=["mcp"])
        result = compiler.compile(doc)
        assert len(result.rpz_directives) == 0


# ── required_auth_types ───────────────────────────────────────


class TestRequiredAuthTypes:
    def test_bindaid_require_cap(self, compiler: PolicyCompiler) -> None:
        doc = _make_doc(required_auth_types=["oauth2"])
        result = compiler.compile(doc)
        skipped_names = [s.rule_name for s in result.skipped]
        assert "required_auth_types" in skipped_names
        assert any("key65400=require" in d.param_ops for d in result.bindaid_directives)


# ── CEL rules ─────────────────────────────────────────────────


class TestCELRules:
    def test_cel_endswith_wildcard(self, compiler: PolicyCompiler) -> None:
        cel = CELRule(
            id="test-endswith",
            expression='request.caller_domain.endsWith(".evil.io")',
            effect="deny",
        )
        doc = _make_doc(cel_rules=[cel])
        result = compiler.compile(doc, allow_broad_rpz=True)
        assert len(result.rpz_directives) == 1
        assert result.rpz_directives[0].owner == "*.evil.io"
        assert result.rpz_directives[0].action == RPZAction.NXDOMAIN

    def test_cel_exact_match(self, compiler: PolicyCompiler) -> None:
        cel = CELRule(
            id="test-exact",
            expression='request.caller_domain == "bad.example.com"',
            effect="deny",
        )
        doc = _make_doc(cel_rules=[cel])
        result = compiler.compile(doc)
        assert len(result.rpz_directives) == 1
        assert result.rpz_directives[0].owner == "bad.example.com"

    def test_cel_complex_skipped(self, compiler: PolicyCompiler) -> None:
        cel = CELRule(
            id="complex-rule",
            expression="request.caller_trust_score >= 0.7 && request.protocol == 'mcp'",
            effect="deny",
        )
        doc = _make_doc(cel_rules=[cel])
        result = compiler.compile(doc)
        assert len(result.rpz_directives) == 0
        skipped_names = [s.rule_name for s in result.skipped]
        assert "cel:complex-rule" in skipped_names

    def test_cel_layer_filtering(self, compiler: PolicyCompiler) -> None:
        """CEL rule with only layer1 should be skipped."""
        cel = CELRule(
            id="l1-only",
            expression='request.caller_domain == "test.com"',
            effect="deny",
            enforcement_layers=["layer1"],
        )
        doc = _make_doc(cel_rules=[cel])
        result = compiler.compile(doc)
        assert len(result.rpz_directives) == 0
        skipped_names = [s.rule_name for s in result.skipped]
        assert "cel:l1-only" in skipped_names

    def test_cel_negated_endswith(self, compiler: PolicyCompiler) -> None:
        """Evaluator convention: !endsWith with deny = block matching domains."""
        cel = CELRule(
            id="neg-endswith",
            expression='!request.caller_domain.endsWith(".evil.io")',
            effect="deny",
        )
        doc = _make_doc(cel_rules=[cel])
        result = compiler.compile(doc, allow_broad_rpz=True)
        assert len(result.rpz_directives) == 1
        assert result.rpz_directives[0].owner == "*.evil.io"
        assert result.rpz_directives[0].action == RPZAction.NXDOMAIN

    def test_cel_not_equal(self, compiler: PolicyCompiler) -> None:
        """Evaluator convention: != with deny = block matching domain."""
        cel = CELRule(
            id="neq-exact",
            expression='request.caller_domain != "bad.example.com"',
            effect="deny",
        )
        doc = _make_doc(cel_rules=[cel])
        result = compiler.compile(doc)
        assert len(result.rpz_directives) == 1
        assert result.rpz_directives[0].owner == "bad.example.com"
        assert result.rpz_directives[0].action == RPZAction.NXDOMAIN

    def test_cel_no_rules(self, compiler: PolicyCompiler) -> None:
        doc = _make_doc(cel_rules=None)
        result = compiler.compile(doc)
        # No errors, no CEL-related output
        assert not any(s.rule_name.startswith("cel:") for s in result.skipped)


# ── Edge cases and integration ────────────────────────────────


class TestEdgeCases:
    def test_empty_policy(self, compiler: PolicyCompiler) -> None:
        doc = _make_doc()
        result = compiler.compile(doc)
        assert len(result.rpz_directives) == 0
        assert len(result.bindaid_directives) == 0
        assert len(result.skipped) == 0

    def test_all_skipped_rules_report(self, compiler: PolicyCompiler) -> None:
        """All Layer 1/2-only rules should appear in skipped."""
        doc = _make_doc(
            require_dnssec=True,
            require_mutual_tls=True,
            min_tls_version="1.3",
            required_caller_trust_score=0.8,
            max_payload_bytes=1024,
            allowed_methods=["tools/call"],
            allowed_intents=["query"],
            geo_restrictions=["US"],
            data_classification="internal",
            consent_required=True,
        )
        result = compiler.compile(doc)
        skipped_names = {s.rule_name for s in result.skipped}
        expected = {
            "require_dnssec",
            "require_mutual_tls",
            "min_tls_version",
            "required_caller_trust_score",
            "max_payload_bytes",
            "allowed_methods",
            "allowed_intents",
            "geo_restrictions",
            "data_classification",
            "consent_required",
        }
        assert expected.issubset(skipped_names)

    def test_full_document_integration(
        self, compiler: PolicyCompiler, sample_doc: PolicyDocument
    ) -> None:
        result = compiler.compile(sample_doc, allow_broad_rpz=True)
        assert result.agent_fqdn == "_network._mcp._agents.example.com"
        # blocked: 2 RPZ, allowed: 2 passthru + 1 catch-all, cel: 2 (endswith + exact)
        assert len(result.rpz_directives) >= 5
        assert len(result.bindaid_directives) >= 5
        assert len(result.skipped) > 0

    def test_dedup_removes_duplicate_rpz(self, compiler: PolicyCompiler) -> None:
        """Same domain blocked by native rule AND CEL → deduped, warning emitted."""
        doc = _make_doc(
            blocked_caller_domains=["evil.com"],
            cel_rules=[
                CELRule(
                    id="also-block-evil",
                    expression='request.caller_domain != "evil.com"',
                    effect="deny",
                ),
            ],
        )
        result = compiler.compile(doc)
        # Should have only 1 NXDOMAIN for evil.com, not 2
        nxdomain_evil = [
            d
            for d in result.rpz_directives
            if d.owner == "evil.com" and d.action == RPZAction.NXDOMAIN
        ]
        assert len(nxdomain_evil) == 1
        assert any("Duplicate RPZ" in w for w in result.warnings)

    def test_svcparam_ops_bindaid_only(self, compiler: PolicyCompiler) -> None:
        """SvcParam ops produce bind-aid directives and RPZ skip."""
        from dns_aid.sdk.policy.schema import SvcParamOp

        doc = _make_doc(
            svcparam_ops=[
                SvcParamOp(key="port", op="enforce", values=["443"]),
                SvcParamOp(key="ech", op="strip"),
                SvcParamOp(key="alpn", op="whitelist", values=["h2", "h3"]),
                SvcParamOp(key="key65400", op="validate"),
            ]
        )
        result = compiler.compile(doc)
        assert len(result.rpz_directives) == 0
        assert len(result.bindaid_directives) == 4
        # Check param_op strings
        ops = [d.param_ops[0] for d in result.bindaid_directives]
        assert "port=enforce:443" in ops
        assert "ech=strip" in ops
        assert "alpn=whitelist:h2,h3" in ops
        assert "key65400=validate" in ops
        # RPZ skip
        assert any(s.rule_name == "svcparam_ops" for s in result.skipped)

    def test_compilation_warnings_empty(self, compiler: PolicyCompiler) -> None:
        doc = _make_doc(blocked_caller_domains=["evil.com"])
        result = compiler.compile(doc)
        assert result.warnings == []


# ── Blast-radius guard ───────────────────────────────────────


class TestBlastRadiusGuard:
    """Verify that broad wildcards outside _agents.* are rejected by default."""

    def test_broad_wildcard_blocked_by_default(self, compiler: PolicyCompiler) -> None:
        """*.example.net would block ALL DNS — must be rejected."""
        doc = _make_doc(blocked_caller_domains=["*.example.net"])
        result = compiler.compile(doc)
        assert len(result.rpz_directives) == 0
        assert len(result.bindaid_directives) == 0
        assert any("Blocked broad RPZ wildcard" in w for w in result.warnings)

    def test_agents_namespace_wildcard_allowed(self, compiler: PolicyCompiler) -> None:
        """Wildcards under _agents.* are safe — agent-scoped."""
        doc = _make_doc(blocked_caller_domains=["*.shadow._agents.example.com"])
        result = compiler.compile(doc)
        assert len(result.rpz_directives) == 1
        assert result.rpz_directives[0].owner == "*.shadow._agents.example.com"
        assert result.warnings == []

    def test_exact_domain_always_allowed(self, compiler: PolicyCompiler) -> None:
        """Exact domains (no wildcard) are targeted — always safe."""
        doc = _make_doc(blocked_caller_domains=["evil.example.com"])
        result = compiler.compile(doc)
        assert len(result.rpz_directives) == 1
        assert result.warnings == []

    def test_allow_broad_rpz_override(self, compiler: PolicyCompiler) -> None:
        """--allow-broad-rpz lets broad wildcards through."""
        doc = _make_doc(blocked_caller_domains=["*.example.net"])
        result = compiler.compile(doc, allow_broad_rpz=True)
        assert len(result.rpz_directives) == 1
        assert result.rpz_directives[0].owner == "*.example.net"
        assert result.warnings == []

    def test_catch_all_from_allowed_domains_passes(self, compiler: PolicyCompiler) -> None:
        """The internal '*' catch-all from allowed_caller_domains must not be blocked."""
        doc = _make_doc(allowed_caller_domains=["trusted.com"])
        result = compiler.compile(doc)
        # 1 passthru + 1 catch-all NXDOMAIN — both should survive
        assert len(result.rpz_directives) == 2
        assert not any("Blocked broad" in w for w in result.warnings)

    def test_cel_broad_wildcard_blocked(self, compiler: PolicyCompiler) -> None:
        """CEL-produced broad wildcards are also caught."""
        cel = CELRule(
            id="broad-cel",
            expression='request.caller_domain.endsWith(".sandbox.example.com")',
            effect="deny",
        )
        doc = _make_doc(cel_rules=[cel])
        result = compiler.compile(doc)
        assert len(result.rpz_directives) == 0
        assert any("Blocked broad RPZ wildcard" in w for w in result.warnings)

    def test_cel_agents_namespace_wildcard_allowed(self, compiler: PolicyCompiler) -> None:
        """CEL-produced wildcards under _agents.* pass through."""
        cel = CELRule(
            id="agents-cel",
            expression='request.caller_domain.endsWith("._agents.example.com")',
            effect="deny",
        )
        doc = _make_doc(cel_rules=[cel])
        result = compiler.compile(doc)
        assert len(result.rpz_directives) == 1
        assert result.warnings == []

    def test_multiple_domains_mixed_filtering(self, compiler: PolicyCompiler) -> None:
        """Only broad wildcards are rejected; exact + agent-scoped pass through."""
        doc = _make_doc(
            blocked_caller_domains=[
                "evil.com",  # exact — allowed
                "*.sandbox.example.com",  # broad — blocked
                "*._agents.example.com",  # agent-scoped — allowed
            ]
        )
        result = compiler.compile(doc)
        owners = [d.owner for d in result.rpz_directives]
        assert "evil.com" in owners
        assert "*._agents.example.com" in owners
        assert "*.sandbox.example.com" not in owners
        assert len(result.warnings) == 2  # RPZ + bind-aid warnings for the broad one
