# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for the RPZ zone file writer."""

from __future__ import annotations

import pytest

from dns_aid.sdk.policy.compiler import CompilationResult, RPZAction, RPZDirective
from dns_aid.sdk.policy.rpz_writer import write_rpz_zone


@pytest.fixture
def empty_result() -> CompilationResult:
    return CompilationResult(agent_fqdn="_test._mcp._agents.example.com")


@pytest.fixture
def result_with_directives() -> CompilationResult:
    return CompilationResult(
        agent_fqdn="_test._mcp._agents.example.com",
        rpz_directives=[
            RPZDirective(
                owner="evil.com",
                action=RPZAction.NXDOMAIN,
                comment="Block evil",
                source_rule="blocked_caller_domains",
            ),
            RPZDirective(
                owner="trusted.com",
                action=RPZAction.PASSTHRU,
                comment="Allow trusted",
                source_rule="allowed_caller_domains",
            ),
            RPZDirective(
                owner="sketchy.net",
                action=RPZAction.DROP,
                comment="Drop sketchy",
                source_rule="custom",
            ),
        ],
    )


class TestSOAHeader:
    def test_soa_present(self, empty_result: CompilationResult) -> None:
        zone = write_rpz_zone(empty_result, "rpz.example.com", serial=2026032800)
        assert "SOA" in zone
        assert "2026032800" in zone

    def test_custom_serial(self, empty_result: CompilationResult) -> None:
        zone = write_rpz_zone(empty_result, "rpz.example.com", serial=12345)
        assert "12345" in zone

    def test_default_serial_is_epoch(self, empty_result: CompilationResult) -> None:
        zone = write_rpz_zone(empty_result, "rpz.example.com")
        # Serial should be a large number (epoch seconds)
        for line in zone.splitlines():
            if "; serial" in line:
                serial_str = line.split()[0]
                assert int(serial_str) > 1700000000

    def test_custom_ttl(self, empty_result: CompilationResult) -> None:
        zone = write_rpz_zone(empty_result, "rpz.example.com", serial=1, ttl=600)
        assert "$TTL 600" in zone


class TestNSRecord:
    def test_ns_record_present(self, empty_result: CompilationResult) -> None:
        zone = write_rpz_zone(empty_result, "rpz.example.com", serial=1)
        assert "NS  localhost." in zone

    def test_custom_ns(self, empty_result: CompilationResult) -> None:
        zone = write_rpz_zone(empty_result, "rpz.example.com", serial=1, ns_name="ns1.example.com.")
        assert "ns1.example.com." in zone


class TestCNAMEDirectives:
    def test_nxdomain_cname(self, result_with_directives: CompilationResult) -> None:
        zone = write_rpz_zone(result_with_directives, "rpz.example.com", serial=1)
        assert "evil.com" in zone
        assert "CNAME  ." in zone

    def test_passthru_cname(self, result_with_directives: CompilationResult) -> None:
        zone = write_rpz_zone(result_with_directives, "rpz.example.com", serial=1)
        assert "trusted.com" in zone
        assert "rpz-passthru." in zone

    def test_drop_cname(self, result_with_directives: CompilationResult) -> None:
        zone = write_rpz_zone(result_with_directives, "rpz.example.com", serial=1)
        assert "sketchy.net" in zone
        assert "rpz-drop." in zone

    def test_comment_preservation(self, result_with_directives: CompilationResult) -> None:
        zone = write_rpz_zone(result_with_directives, "rpz.example.com", serial=1)
        assert "; Block evil" in zone
        assert "; Allow trusted" in zone

    def test_source_rule_in_comments(self, result_with_directives: CompilationResult) -> None:
        zone = write_rpz_zone(result_with_directives, "rpz.example.com", serial=1)
        assert "; source: blocked_caller_domains" in zone


class TestEmptyZone:
    def test_empty_directives(self, empty_result: CompilationResult) -> None:
        zone = write_rpz_zone(empty_result, "rpz.example.com", serial=1)
        assert "SOA" in zone
        assert "NS" in zone
        # No CNAME records
        assert "CNAME" not in zone


class TestFullIntegration:
    def test_full_zone(self, result_with_directives: CompilationResult) -> None:
        zone = write_rpz_zone(
            result_with_directives,
            "rpz.example.com",
            serial=2026032800,
            ttl=300,
        )
        lines = zone.splitlines()
        # Has header, SOA, NS, and 3 directives
        assert any("$TTL 300" in line for line in lines)
        assert any("SOA" in line for line in lines)
        assert any("NS" in line for line in lines)
        cname_lines = [line for line in lines if "CNAME" in line]
        assert len(cname_lines) == 3
