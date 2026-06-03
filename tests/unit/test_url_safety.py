# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for URL safety validation (SSRF protection)."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from dns_aid.utils.url_safety import UnsafeURLError, validate_fetch_url


class TestValidateFetchUrl:
    """Tests for validate_fetch_url()."""

    def test_https_url_passes(self):
        """HTTPS URLs with public hosts should pass."""
        # Use a well-known public DNS name
        url = "https://example.com/cap.json"
        # Will resolve to public IP, should pass
        result = validate_fetch_url(url)
        assert result == url

    def test_http_url_blocked(self):
        """HTTP (non-HTTPS) URLs must be blocked."""
        with pytest.raises(UnsafeURLError, match="Only HTTPS"):
            validate_fetch_url("http://example.com/cap.json")

    def test_file_scheme_blocked(self):
        """file:// scheme must be blocked."""
        with pytest.raises(UnsafeURLError, match="Only HTTPS"):
            validate_fetch_url("file:///etc/passwd")

    def test_ftp_scheme_blocked(self):
        """ftp:// scheme must be blocked."""
        with pytest.raises(UnsafeURLError, match="Only HTTPS"):
            validate_fetch_url("ftp://evil.com/data")

    def test_no_hostname_blocked(self):
        """URLs without a hostname must be blocked."""
        with pytest.raises(UnsafeURLError, match="no hostname"):
            validate_fetch_url("https://")

    def test_loopback_ipv4_blocked(self):
        """127.0.0.1 must be blocked."""
        with pytest.raises(UnsafeURLError, match="non-public IP"):
            validate_fetch_url("https://127.0.0.1/secret")

    def test_loopback_localhost_blocked(self):
        """localhost must be blocked (resolves to 127.0.0.1)."""
        with pytest.raises(UnsafeURLError, match="non-public IP"):
            validate_fetch_url("https://localhost/secret")

    def test_private_ip_10_blocked(self):
        """10.x.x.x private IPs must be blocked."""
        with pytest.raises(UnsafeURLError, match="non-public IP"):
            validate_fetch_url("https://10.0.0.1/internal")

    def test_private_ip_172_blocked(self):
        """172.16.x.x private IPs must be blocked."""
        with pytest.raises(UnsafeURLError, match="non-public IP"):
            validate_fetch_url("https://172.16.0.1/internal")

    def test_private_ip_192_blocked(self):
        """192.168.x.x private IPs must be blocked."""
        with pytest.raises(UnsafeURLError, match="non-public IP"):
            validate_fetch_url("https://192.168.1.1/admin")

    def test_link_local_blocked(self):
        """169.254.x.x (AWS metadata) must be blocked."""
        with pytest.raises(UnsafeURLError, match="non-public IP"):
            validate_fetch_url("https://169.254.169.254/latest/meta-data/")

    def test_unresolvable_hostname(self):
        """Unresolvable hostnames should raise UnsafeURLError."""
        with pytest.raises(UnsafeURLError, match="Cannot resolve"):
            validate_fetch_url("https://this-domain-definitely-does-not-exist-12345.invalid/cap")

    def test_allowlist_bypasses_ip_check(self):
        """Hosts in DNS_AID_FETCH_ALLOWLIST should bypass IP checks."""
        with patch.dict(os.environ, {"DNS_AID_FETCH_ALLOWLIST": "localhost,127.0.0.1"}):
            # localhost would normally be blocked, but allowlist overrides
            result = validate_fetch_url("https://localhost/test")
            assert result == "https://localhost/test"

    def test_allowlist_case_insensitive(self):
        """Allowlist matching should be case-insensitive."""
        with patch.dict(os.environ, {"DNS_AID_FETCH_ALLOWLIST": "LocalHost"}):
            result = validate_fetch_url("https://localhost/test")
            assert result == "https://localhost/test"


class TestUserinfoRejection:
    """``https://user:pass@host`` URLs must be rejected at the input boundary."""

    def test_user_only_userinfo_rejected(self):
        with pytest.raises(UnsafeURLError, match="userinfo"):
            validate_fetch_url("https://user@example.com/api/v1/search")

    def test_user_password_userinfo_rejected(self):
        with pytest.raises(UnsafeURLError, match="userinfo"):
            validate_fetch_url("https://user:secret@example.com/api/v1/search")

    def test_userinfo_rejection_does_not_leak_credentials_in_message(self):
        # The raised error message must not echo the password back — the
        # whole point of rejecting userinfo is to avoid credential leakage.
        with pytest.raises(UnsafeURLError) as exc_info:
            validate_fetch_url("https://user:hunter2@example.com/")
        assert "hunter2" not in str(exc_info.value)
        assert "user" not in str(exc_info.value).lower() or "userinfo" in str(exc_info.value)

    def test_userinfo_rejected_even_when_host_is_allowlisted(self):
        # Allowlist controls SSRF behavior, not credential hygiene.
        with patch.dict(os.environ, {"DNS_AID_FETCH_ALLOWLIST": "example.com"}):
            with pytest.raises(UnsafeURLError, match="userinfo"):
                validate_fetch_url("https://user:pass@example.com/")


class TestRedactUrlForLog:
    """:func:`redact_url_for_log` strips userinfo so a URL is safe to log."""

    def test_url_without_userinfo_returns_unchanged(self):
        from dns_aid.utils.url_safety import redact_url_for_log

        url = "https://example.com/api/v1/search?q=x"
        assert redact_url_for_log(url) == url

    def test_user_password_stripped(self):
        from dns_aid.utils.url_safety import redact_url_for_log

        redacted = redact_url_for_log("https://user:secret@example.com/path")
        assert "secret" not in redacted
        assert "user" not in redacted
        assert redacted.startswith("https://example.com/")

    def test_user_only_stripped(self):
        from dns_aid.utils.url_safety import redact_url_for_log

        redacted = redact_url_for_log("https://user@example.com/path")
        assert "user" not in redacted

    def test_port_preserved_when_userinfo_stripped(self):
        from dns_aid.utils.url_safety import redact_url_for_log

        redacted = redact_url_for_log("https://user:pass@example.com:8443/path")
        assert redacted == "https://example.com:8443/path"

    def test_query_string_preserved(self):
        from dns_aid.utils.url_safety import redact_url_for_log

        redacted = redact_url_for_log("https://user:pass@example.com/search?q=foo&limit=10")
        assert redacted.endswith("?q=foo&limit=10")
        assert "pass" not in redacted


class TestCapSha256Verification:
    """Tests for cap_sha256 integrity verification in cap_fetcher."""

    @pytest.mark.asyncio
    async def test_hash_match_passes(self):
        """Correct hash should allow document to be returned."""
        import base64
        import hashlib

        from dns_aid.core.cap_fetcher import fetch_cap_document

        content = b'{"capabilities": ["test"]}'
        expected_hash = (
            base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode("ascii")
        )

        async def mock_fetch(url, **kwargs):
            return content

        with patch("dns_aid.utils.url_safety.validate_fetch_url", return_value="https://ok.com"):
            with patch("dns_aid.utils.url_safety.safe_fetch_bytes", side_effect=mock_fetch):
                doc = await fetch_cap_document(
                    "https://ok.com/cap.json",
                    expected_sha256=expected_hash,
                )
                assert doc is not None
                assert doc.capabilities == ["test"]

    @pytest.mark.asyncio
    async def test_hash_mismatch_raises_digest_error(self):
        """Wrong hash MUST raise CapDigestMismatchError so the discoverer
        can distinguish digest mismatch (refuse the record) from network
        failures (fall back to a lower-priority capability source)."""
        from dns_aid.core.cap_fetcher import CapDigestMismatchError, fetch_cap_document

        content = b'{"capabilities": ["test"]}'

        async def mock_fetch(url, **kwargs):
            return content

        with patch("dns_aid.utils.url_safety.validate_fetch_url", return_value="https://ok.com"):
            with patch("dns_aid.utils.url_safety.safe_fetch_bytes", side_effect=mock_fetch):
                with pytest.raises(CapDigestMismatchError) as excinfo:
                    await fetch_cap_document(
                        "https://ok.com/cap.json",
                        expected_sha256="WRONG_HASH",
                    )
                assert excinfo.value.expected == "WRONG_HASH"
                assert excinfo.value.cap_uri == "https://ok.com/cap.json"

    @pytest.mark.asyncio
    async def test_no_hash_skips_verification(self):
        """When expected_sha256 is None, skip verification."""
        from dns_aid.core.cap_fetcher import fetch_cap_document

        content = b'{"capabilities": ["test"]}'

        async def mock_fetch(url, **kwargs):
            return content

        with patch("dns_aid.utils.url_safety.validate_fetch_url", return_value="https://ok.com"):
            with patch("dns_aid.utils.url_safety.safe_fetch_bytes", side_effect=mock_fetch):
                doc = await fetch_cap_document(
                    "https://ok.com/cap.json",
                    expected_sha256=None,
                )
                assert doc is not None
                assert doc.capabilities == ["test"]
