# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for the shared DNS-AID FQDN parser (dns_aid.core.fqdn)."""

import pytest

from dns_aid.core.fqdn import DnsAidFqdn, parse_dnsaid_fqdn


class TestParseDnsaidFqdn:
    """parse_dnsaid_fqdn recognizes the three draft shapes and normalizes."""

    # --- Flat draft-02 -----------------------------------------------------

    def test_flat_three_label(self):
        assert parse_dnsaid_fqdn("chat.example.com") == DnsAidFqdn("chat", None, "example.com")

    def test_flat_subdomain_domain(self):
        assert parse_dnsaid_fqdn("chat.eu.example.com") == DnsAidFqdn(
            "chat", None, "eu.example.com"
        )

    def test_flat_two_label_owner_accepted(self):
        """A flat owner in a short/internal zone ({name}.{tld}) parses (P2)."""
        assert parse_dnsaid_fqdn("agent.internal") == DnsAidFqdn("agent", None, "internal")
        assert parse_dnsaid_fqdn("chat.localhost") == DnsAidFqdn("chat", None, "localhost")

    # --- Walkable draft-02 -------------------------------------------------

    def test_walkable(self):
        assert parse_dnsaid_fqdn("chat._agents.example.com") == DnsAidFqdn(
            "chat", None, "example.com"
        )

    # --- Legacy -01 --------------------------------------------------------

    def test_legacy(self):
        assert parse_dnsaid_fqdn("_chat._mcp._agents.example.com") == DnsAidFqdn(
            "chat", "mcp", "example.com"
        )

    def test_legacy_malformed_single_underscore_rejected(self):
        assert parse_dnsaid_fqdn("_booking.mcp._agents.foo.com") is None

    # --- Normalization (P3a) ----------------------------------------------

    def test_case_insensitive(self):
        assert parse_dnsaid_fqdn("Chat.Example.COM") == DnsAidFqdn("chat", None, "example.com")

    def test_trailing_dot_stripped(self):
        assert parse_dnsaid_fqdn("chat.example.com.") == DnsAidFqdn("chat", None, "example.com")

    def test_legacy_normalized(self):
        assert parse_dnsaid_fqdn("_Chat._MCP._agents.Example.com.") == DnsAidFqdn(
            "chat", "mcp", "example.com"
        )

    # --- Rejections --------------------------------------------------------

    @pytest.mark.parametrize("bad", ["", "  ", ".", "localhost", "_chat", "chat."])
    def test_rejected(self, bad):
        assert parse_dnsaid_fqdn(bad) is None

    def test_flat_name_underscore_rejected(self):
        # A leading underscore on the first label is not a flat owner.
        assert parse_dnsaid_fqdn("_chat.example.com") is None
