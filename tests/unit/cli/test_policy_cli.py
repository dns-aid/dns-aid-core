# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for the ``dns-aid policy`` CLI sub-commands."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from dns_aid.cli.main import app

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
SAMPLE_POLICY = FIXTURES / "sample-policy.json"

runner = CliRunner()


class TestPolicyCompile:
    def test_compile_rpz_output(self, tmp_path: Path) -> None:
        out = tmp_path / "test.rpz"
        result = runner.invoke(
            app, ["policy", "compile", "-i", str(SAMPLE_POLICY), "-o", str(out), "-f", "rpz"]
        )
        assert result.exit_code == 0, result.output
        assert out.exists()
        content = out.read_text()
        assert "SOA" in content
        assert "CNAME" in content

    def test_compile_bindaid_output(self, tmp_path: Path) -> None:
        out = tmp_path / "test.bindaid"
        result = runner.invoke(
            app, ["policy", "compile", "-i", str(SAMPLE_POLICY), "-o", str(out), "-f", "bindaid"]
        )
        assert result.exit_code == 0, result.output
        assert out.exists()
        content = out.read_text()
        assert "SOA" in content
        assert "ACTION:" in content

    def test_compile_both_creates_two_files(self, tmp_path: Path) -> None:
        out = tmp_path / "test"
        result = runner.invoke(
            app, ["policy", "compile", "-i", str(SAMPLE_POLICY), "-o", str(out), "-f", "both"]
        )
        assert result.exit_code == 0, result.output
        assert (tmp_path / "test.rpz").exists()
        assert (tmp_path / "test.bindaid").exists()

    def test_compile_invalid_input(self, tmp_path: Path) -> None:
        bad_file = tmp_path / "bad.json"
        bad_file.write_text("{invalid json")
        out = tmp_path / "out.rpz"
        result = runner.invoke(
            app, ["policy", "compile", "-i", str(bad_file), "-o", str(out), "-f", "rpz"]
        )
        assert result.exit_code == 1

    def test_compile_missing_input(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app,
            [
                "policy",
                "compile",
                "-i",
                "/nonexistent.json",
                "-o",
                str(tmp_path / "out"),
                "-f",
                "rpz",
            ],
        )
        assert result.exit_code == 1


class TestPolicyShow:
    def test_show_report(self) -> None:
        result = runner.invoke(app, ["policy", "show", "-i", str(SAMPLE_POLICY)])
        assert result.exit_code == 0, result.output
        assert "Policy Compilation Report" in result.output
        assert "RPZ Directives" in result.output
        assert "bind-aid Directives" in result.output
        assert "Skipped Rules" in result.output


class TestEnforce:
    def test_enforce_shadow_mode(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app,
            [
                "enforce",
                "-d",
                "example.com",
                "-p",
                str(SAMPLE_POLICY),
                "--mode",
                "shadow",
                "-o",
                str(tmp_path),
            ],
        )
        assert result.exit_code == 0, result.output
        assert "Shadow mode" in result.output
        assert "WOULD be enforced" in result.output
