# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Secondary defects found in review of the JWS / DANE branch.

Each of these reported a real answer as "not checked", "unknown" or "absent" --
the failure mode the branch was written to eliminate, reappearing on a
neighbouring path.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dns_aid.core.a2a_card import A2AAgentCard, A2ASkill
from dns_aid.core.discoverer import _dnssec_check_runs
from dns_aid.core.validator import _check_dane, _url_host


class TestRequireSignedReportsTheDnssecVerdictItComputed:
    """`discover()` turns require_signed into verify_signatures internally.

    The reporting surfaces evaluated the gate with the CALLER's value, so
    `--require-signed` alone ran one DNSSEC lookup per agent and then suppressed
    the verdict, reporting "not checked" for a check that had run.
    """

    def test_caller_value_alone_would_hide_a_real_verdict(self):
        assert _dnssec_check_runs(verify_signatures=False) is False

    def test_effective_value_reports_it(self):
        require_signed, verify_signatures = True, False
        assert _dnssec_check_runs(verify_signatures=verify_signatures or require_signed) is True

    def test_the_gate_is_unchanged_when_nothing_was_asked_for(self):
        assert _dnssec_check_runs() is False


class TestDaneAdvisoryModeDoesNotNeedTheAdFlag:
    """Advisory mode answers "is DANE configured", not "does this cert match".

    Applying the authentication gate first collapsed a correctly DANE-configured
    host behind a non-validating resolver into the same None as a host
    publishing no TLSA at all.
    """

    @staticmethod
    def _resolver(ad: bool, count: int = 1):
        records = [MagicMock(usage=3, selector=1, mtype=1, cert=b"\x11" * 32) for _ in range(count)]
        answers = MagicMock()
        answers.__iter__ = lambda self: iter(records)
        answers.response = MagicMock(flags=0x0020 if ad else 0x0000)
        resolver = MagicMock()
        resolver.resolve = AsyncMock(return_value=answers)
        return resolver

    @pytest.mark.asyncio
    async def test_existence_is_reported_without_a_validating_resolver(self):
        with patch(
            "dns_aid.core.validator.dns.asyncresolver.Resolver",
            return_value=self._resolver(ad=False),
        ):
            assert await _check_dane("mcp.example.com", 443, verify_cert=False) is True

    @pytest.mark.asyncio
    async def test_existence_is_still_reported_with_one(self):
        with patch(
            "dns_aid.core.validator.dns.asyncresolver.Resolver",
            return_value=self._resolver(ad=True),
        ):
            assert await _check_dane("mcp.example.com", 443, verify_cert=False) is True

    @pytest.mark.asyncio
    async def test_certificate_matching_still_requires_authenticated_tlsa(self):
        """The gate is a trust decision, so it stays on the verify_cert path."""
        with patch(
            "dns_aid.core.validator.dns.asyncresolver.Resolver",
            return_value=self._resolver(ad=False),
        ):
            assert await _check_dane("mcp.example.com", 443, verify_cert=True) is None


class TestIpv6LiteralsAreUrlSafe:
    """A vetted IPv6 address must be bracketed before it goes into a URL.

    `asyncio.open_connection` wants the bare form and a URL does not, so the two
    consumers of the same vetted literal need different spellings. Unbracketed,
    httpx rejects the URL outright and every IPv6-only endpoint reported
    unreachable.
    """

    def test_ipv6_is_bracketed(self):
        assert _url_host("2606:4700::6810:85e5") == "[2606:4700::6810:85e5]"

    def test_ipv4_is_untouched(self):
        assert _url_host("192.0.2.10") == "192.0.2.10"

    def test_a_hostname_is_untouched(self):
        assert _url_host("mcp.example.com") == "mcp.example.com"

    def test_the_result_parses_as_a_url_with_a_port(self):
        from urllib.parse import urlparse

        parsed = urlparse(f"https://{_url_host('2606:4700::6810:85e5')}:443/health")
        assert parsed.port == 443
        assert parsed.hostname == "2606:4700::6810:85e5"


class TestAgentCardSecurityRequirementsSurvive:
    """`security` was added to known_keys without a field to land in.

    It was therefore filtered out of `metadata` and dropped entirely -- where
    before it at least survived as raw metadata. A consumer gating invocation on
    the declared scopes saw no requirement at all.
    """

    def test_card_level_security_is_parsed(self):
        card = A2AAgentCard.from_dict(
            {
                "name": "chat",
                "url": "https://mcp.example.com",
                "security": [{"oauth2": ["agent.read"]}],
            }
        )
        assert card.security_requirements == [{"oauth2": ["agent.read"]}]

    def test_the_older_spelling_is_accepted(self):
        card = A2AAgentCard.from_dict(
            {
                "name": "chat",
                "url": "https://mcp.example.com",
                "securityRequirements": [{"apiKey": []}],
            }
        )
        assert card.security_requirements == [{"apiKey": []}]

    def test_absent_stays_empty(self):
        card = A2AAgentCard.from_dict({"name": "chat", "url": "https://mcp.example.com"})
        assert card.security_requirements == []

    def test_skill_level_security_uses_the_schema_spelling(self):
        """The schema calls it `security`; only this reader said
        `securityRequirements`, so it was empty for every real card."""
        skill = A2ASkill.from_dict(
            {"id": "s1", "name": "search", "security": [{"oauth2": ["skill.run"]}]}
        )
        assert skill.security_requirements == [{"oauth2": ["skill.run"]}]

    def test_skill_level_older_spelling_still_read(self):
        skill = A2ASkill.from_dict(
            {"id": "s1", "name": "search", "securityRequirements": [{"apiKey": []}]}
        )
        assert skill.security_requirements == [{"apiKey": []}]


class TestAuthMergeKeepsBothHalves:
    """The 0.3 map can yield a credentials URL with no scheme names, and the 0.2
    object the reverse. Taking either wholesale dropped the other side's half --
    and the guard skipped the merge in exactly the case it was written for."""

    def test_a_credentials_url_from_securityschemes_is_not_dropped(self):
        card = A2AAgentCard.from_dict(
            {
                "name": "chat",
                "url": "https://mcp.example.com",
                # No `type` and no `*SecurityScheme` key, so this yields
                # credentials but no scheme names.
                "securitySchemes": {"oauth": {"tokenUrl": "https://idp.example/token"}},
                "authentication": {"schemes": ["bearer"]},
            }
        )
        assert card.authentication is not None
        assert card.authentication.credentials == "https://idp.example/token"
        assert card.authentication.schemes == ["bearer"]
