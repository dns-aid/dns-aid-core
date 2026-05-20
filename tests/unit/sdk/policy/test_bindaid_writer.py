# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for the bind-aid policy zone file writer."""

from __future__ import annotations

import pytest

from dns_aid.sdk.policy.bindaid_writer import write_bindaid_zone
from dns_aid.sdk.policy.compiler import (
    BindAidAction,
    BindAidDirective,
    CompilationResult,
)


@pytest.fixture
def empty_result() -> CompilationResult:
    return CompilationResult(agent_fqdn="_test._mcp._agents.example.com")


@pytest.fixture
def result_with_directives() -> CompilationResult:
    return CompilationResult(
        agent_fqdn="_test._mcp._agents.example.com",
        bindaid_directives=[
            BindAidDirective(
                owner="evil.com",
                action=BindAidAction.NXDOMAIN,
                comment="Block evil",
                source_rule="blocked_caller_domains",
            ),
            BindAidDirective(
                owner="trusted.com",
                action=BindAidAction.PASSTHRU,
                comment="Allow trusted",
                source_rule="allowed_caller_domains",
            ),
            BindAidDirective(
                owner="*",
                action=BindAidAction.PASSTHRU,
                param_ops=["key65402=whitelist:mcp,a2a"],
                comment="Require protocols",
                source_rule="required_protocols",
            ),
            BindAidDirective(
                owner="*",
                action=BindAidAction.PASSTHRU,
                param_ops=["key65400=require"],
                comment="Require auth",
                source_rule="required_auth_types",
            ),
        ],
    )


class TestSOAHeader:
    def test_soa_present(self, empty_result: CompilationResult) -> None:
        zone = write_bindaid_zone(empty_result, "policy.example.com", serial=2026032800)
        assert "SOA" in zone
        assert "2026032800" in zone

    def test_custom_serial(self, empty_result: CompilationResult) -> None:
        zone = write_bindaid_zone(empty_result, "policy.example.com", serial=99999)
        assert "99999" in zone

    def test_origin_directive(self, empty_result: CompilationResult) -> None:
        zone = write_bindaid_zone(empty_result, "rdata-policy.example.com", serial=1)
        assert "$ORIGIN rdata-policy.example.com." in zone


class TestNSRecord:
    def test_ns_record_present(self, empty_result: CompilationResult) -> None:
        zone = write_bindaid_zone(empty_result, "policy.example.com", serial=1)
        assert "NS  localhost." in zone


class TestActionDirectives:
    def test_nxdomain_txt(self, result_with_directives: CompilationResult) -> None:
        zone = write_bindaid_zone(result_with_directives, "policy.example.com", serial=1)
        assert "evil.com" in zone
        assert "ACTION:nxdomain" in zone

    def test_passthru_txt(self, result_with_directives: CompilationResult) -> None:
        zone = write_bindaid_zone(result_with_directives, "policy.example.com", serial=1)
        assert "ACTION:passthru" in zone


class TestParamOps:
    def test_param_op_separate_txt(self, result_with_directives: CompilationResult) -> None:
        """SvcParam ops should be separate TXT records from ACTION."""
        zone = write_bindaid_zone(result_with_directives, "policy.example.com", serial=1)
        # ACTION and param_op should be on separate lines
        assert 'TXT  "ACTION:passthru"' in zone
        assert 'TXT  "key65402=whitelist:mcp,a2a"' in zone
        assert 'TXT  "key65400=require"' in zone

    def test_multiple_param_ops(self) -> None:
        """Multiple param ops on one directive → multiple TXT records."""
        result = CompilationResult(
            agent_fqdn="_test._mcp._agents.example.com",
            bindaid_directives=[
                BindAidDirective(
                    owner="*",
                    action=BindAidAction.PASSTHRU,
                    param_ops=["key65402=whitelist:mcp", "key65400=require", "key65403=enforce"],
                ),
            ],
        )
        zone = write_bindaid_zone(result, "policy.example.com", serial=1)
        lines = zone.splitlines()
        txt_lines = [line for line in lines if "TXT" in line]
        # 1 ACTION + 3 param ops = 4 TXT records
        assert len(txt_lines) == 4


class TestEmptyZone:
    def test_empty_directives(self, empty_result: CompilationResult) -> None:
        zone = write_bindaid_zone(empty_result, "policy.example.com", serial=1)
        assert "SOA" in zone
        assert "NS" in zone
        assert "TXT" not in zone


class TestFullIntegration:
    def test_full_zone(self, result_with_directives: CompilationResult) -> None:
        zone = write_bindaid_zone(
            result_with_directives,
            "rdata-policy.example.com",
            serial=2026032800,
            ttl=300,
        )
        lines = zone.splitlines()
        assert any("$TTL 300" in line for line in lines)
        assert any("$ORIGIN rdata-policy.example.com." in line for line in lines)
        assert any("SOA" in line for line in lines)
        assert any("NS" in line for line in lines)
        txt_lines = [line for line in lines if "TXT" in line]
        # 2 simple ACTIONs + 2 ACTIONs with param_ops (2+2 TXT each) = 6 TXT
        assert len(txt_lines) == 6
