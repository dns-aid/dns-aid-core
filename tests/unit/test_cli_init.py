# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for the ``dns-aid init`` wizard (``dns_aid.cli.init``)."""

from __future__ import annotations

from unittest.mock import patch

from typer.testing import CliRunner

from dns_aid.cli.main import app

runner = CliRunner()


# ── choice parsing ─────────────────────────────────────────────────


class TestInitChoiceParsing:
    def test_choice_by_name(self, tmp_path, monkeypatch):
        """A backend name (not a number) is matched against the menu."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["init"], input="cloudflare\nn\nn\n")
        assert result.exit_code == 0
        assert "Cloudflare DNS" in result.output

    def test_invalid_choice_string_exits(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["init"], input="bogus\n")
        assert result.exit_code == 1
        combined = result.output + (result.stderr or "")
        assert "Invalid choice" in combined

    def test_out_of_range_numeric_exits(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["init"], input="99\n")
        assert result.exit_code == 1

    def test_negative_numeric_exits(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["init"], input="-1\n")
        assert result.exit_code == 1


# ── backend setup flow ─────────────────────────────────────────────


class TestInitBackendSetup:
    def test_backend_without_required_env(self, tmp_path, monkeypatch):
        """Route 53 (option 1) has no required env vars, only optional ones."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["init"], input="1\nn\nn\n")
        assert result.exit_code == 0
        assert "AWS Route 53" in result.output
        assert "Required environment variables" not in result.output
        assert "Optional:" in result.output
        assert "Steps:" in result.output
        assert not (tmp_path / ".env").exists()

    def test_backend_with_required_env(self, tmp_path, monkeypatch):
        """Cloudflare (option 2) lists its required env vars."""
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["init"], input="2\nn\nn\n")
        assert result.exit_code == 0
        assert "Required environment variables" in result.output
        assert "CLOUDFLARE_API_TOKEN" in result.output

    def test_decline_env_creation_shows_copy_hint(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["init"], input="2\nn\nn\n")
        assert result.exit_code == 0
        assert "Copy the snippet above" in result.output
        assert not (tmp_path / ".env").exists()

    def test_create_env_file(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner.invoke(app, ["init"], input="2\ny\nn\n")
        assert result.exit_code == 0
        assert "Created" in result.output
        env_file = tmp_path / ".env"
        assert env_file.exists()
        content = env_file.read_text()
        assert "DNS_AID_BACKEND=cloudflare" in content
        assert "CLOUDFLARE_API_TOKEN=" in content
        assert "# CLOUDFLARE_ZONE_ID=" in content

    def test_existing_env_file_is_untouched(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text("EXISTING=1\n")
        result = runner.invoke(app, ["init"], input="2\nn\n")
        assert result.exit_code == 0
        assert "Found .env" in result.output
        assert "already exists" in result.output
        assert (tmp_path / ".env").read_text() == "EXISTING=1\n"


# ── doctor handoff ─────────────────────────────────────────────────


class TestInitDoctorHandoff:
    def test_run_doctor_when_confirmed(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with patch("dns_aid.cli.doctor.doctor") as mock_doctor:
            result = runner.invoke(app, ["init"], input="0\ny\n")
        assert result.exit_code == 0
        mock_doctor.assert_called_once_with()

    def test_skip_doctor_when_declined(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        with patch("dns_aid.cli.doctor.doctor") as mock_doctor:
            result = runner.invoke(app, ["init"], input="0\nn\n")
        assert result.exit_code == 0
        mock_doctor.assert_not_called()
