# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for dns_aid.utils.google_auth.

The google-auth package is intentionally absent from the CI dependency set
(the cloud-dns extra is not installed), so these tests install stub modules
into sys.modules before calling the lazy-import helpers.
"""

from __future__ import annotations

import sys
from types import ModuleType
from unittest.mock import MagicMock

import pytest

from dns_aid.utils.google_auth import get_google_access_token, get_google_auth_state

_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


class _FakeCredentials:
    """Minimal stand-in for google.auth.credentials.Credentials."""

    def __init__(
        self,
        token: str | None = None,
        valid: bool = False,
        refreshed_token: str | None = None,
    ):
        self.token = token
        self.valid = valid
        self._refreshed_token = refreshed_token
        self.refresh_calls: list[object] = []

    def refresh(self, request: object) -> None:
        self.refresh_calls.append(request)
        self.token = self._refreshed_token


def _install_fake_google_auth(monkeypatch, default_func, request_cls) -> None:
    """Register stub google.auth modules so the lazy imports succeed."""
    google_mod = ModuleType("google")
    auth_mod = ModuleType("google.auth")
    transport_mod = ModuleType("google.auth.transport")
    requests_mod = ModuleType("google.auth.transport.requests")

    auth_mod.default = default_func
    requests_mod.Request = request_cls
    google_mod.auth = auth_mod
    auth_mod.transport = transport_mod
    transport_mod.requests = requests_mod

    monkeypatch.setitem(sys.modules, "google", google_mod)
    monkeypatch.setitem(sys.modules, "google.auth", auth_mod)
    monkeypatch.setitem(sys.modules, "google.auth.transport", transport_mod)
    monkeypatch.setitem(sys.modules, "google.auth.transport.requests", requests_mod)


class TestGetGoogleAuthState:
    """Tests for get_google_auth_state."""

    def test_returns_valid_credentials_without_refresh(self, monkeypatch):
        credentials = _FakeCredentials(token="cached-token", valid=True)
        default = MagicMock(return_value=(credentials, "adc-project"))
        _install_fake_google_auth(monkeypatch, default, MagicMock())

        result_credentials, project_id = get_google_auth_state(_SCOPES)

        assert result_credentials is credentials
        assert project_id == "adc-project"
        assert credentials.refresh_calls == []
        default.assert_called_once_with(scopes=_SCOPES)

    def test_refreshes_invalid_credentials(self, monkeypatch):
        credentials = _FakeCredentials(valid=False, refreshed_token="fresh-token")
        request_cls = MagicMock()
        _install_fake_google_auth(
            monkeypatch, MagicMock(return_value=(credentials, "adc-project")), request_cls
        )

        result_credentials, project_id = get_google_auth_state(_SCOPES)

        assert result_credentials.token == "fresh-token"
        assert project_id == "adc-project"
        assert credentials.refresh_calls == [request_cls.return_value]

    def test_refreshes_when_token_missing_despite_valid_flag(self, monkeypatch):
        credentials = _FakeCredentials(token=None, valid=True, refreshed_token="fresh-token")
        _install_fake_google_auth(
            monkeypatch, MagicMock(return_value=(credentials, None)), MagicMock()
        )

        result_credentials, project_id = get_google_auth_state(_SCOPES)

        assert result_credentials.token == "fresh-token"
        assert project_id is None
        assert len(credentials.refresh_calls) == 1

    def test_raises_when_refresh_yields_no_token(self, monkeypatch):
        credentials = _FakeCredentials(valid=False, refreshed_token=None)
        _install_fake_google_auth(
            monkeypatch, MagicMock(return_value=(credentials, "adc-project")), MagicMock()
        )

        with pytest.raises(RuntimeError, match="Failed to acquire a Google Cloud access token"):
            get_google_auth_state(_SCOPES)


class TestGetGoogleAccessToken:
    """Tests for get_google_access_token."""

    def test_returns_token_and_project(self, monkeypatch):
        credentials = _FakeCredentials(token="bearer-token", valid=True)
        _install_fake_google_auth(
            monkeypatch, MagicMock(return_value=(credentials, "adc-project")), MagicMock()
        )

        token, project_id = get_google_access_token(_SCOPES)

        assert token == "bearer-token"
        assert project_id == "adc-project"
