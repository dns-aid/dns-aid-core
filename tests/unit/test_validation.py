# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for input validation utilities."""

import pytest

from dns_aid.utils.validation import (
    ValidationError,
    validate_agent_name,
    validate_backend,
    validate_capabilities,
    validate_connect_class,
    validate_domain,
    validate_endpoint,
    validate_fqdn,
    validate_no_underscore_in_target,
    validate_port,
    validate_protocol,
    validate_ttl,
    validate_version,
    validate_well_known_path,
)


class TestValidateAgentName:
    """Tests for validate_agent_name."""

    def test_valid_simple_name(self):
        assert validate_agent_name("chat") == "chat"

    def test_valid_hyphenated_name(self):
        assert validate_agent_name("my-agent") == "my-agent"

    def test_valid_with_numbers(self):
        assert validate_agent_name("agent123") == "agent123"

    def test_normalizes_to_lowercase(self):
        assert validate_agent_name("MyAgent") == "myagent"

    def test_strips_whitespace(self):
        assert validate_agent_name("  chat  ") == "chat"

    def test_empty_name_raises(self):
        with pytest.raises(ValidationError) as exc:
            validate_agent_name("")
        assert exc.value.field == "name"

    def test_name_too_long_raises(self):
        with pytest.raises(ValidationError) as exc:
            validate_agent_name("a" * 64)
        assert "exceed 63" in exc.value.message

    def test_name_starting_with_hyphen_raises(self):
        with pytest.raises(ValidationError) as exc:
            validate_agent_name("-agent")
        assert exc.value.field == "name"

    def test_name_ending_with_hyphen_raises(self):
        with pytest.raises(ValidationError) as exc:
            validate_agent_name("agent-")
        assert exc.value.field == "name"

    def test_name_with_underscore_raises(self):
        with pytest.raises(ValidationError) as exc:
            validate_agent_name("my_agent")
        assert exc.value.field == "name"

    def test_name_with_space_raises(self):
        with pytest.raises(ValidationError) as exc:
            validate_agent_name("my agent")
        assert exc.value.field == "name"


class TestValidateDomain:
    """Tests for validate_domain."""

    def test_valid_domain(self):
        assert validate_domain("example.com") == "example.com"

    def test_valid_subdomain(self):
        assert validate_domain("sub.example.com") == "sub.example.com"

    def test_normalizes_to_lowercase(self):
        assert validate_domain("Example.COM") == "example.com"

    def test_removes_trailing_dot(self):
        assert validate_domain("example.com.") == "example.com"

    def test_empty_domain_raises(self):
        with pytest.raises(ValidationError) as exc:
            validate_domain("")
        assert exc.value.field == "domain"

    def test_single_label_raises(self):
        with pytest.raises(ValidationError) as exc:
            validate_domain("localhost")
        assert "at least two labels" in exc.value.message

    def test_label_too_long_raises(self):
        with pytest.raises(ValidationError) as exc:
            validate_domain("a" * 64 + ".com")
        assert "exceeds 63" in exc.value.message

    def test_domain_too_long_raises(self):
        with pytest.raises(ValidationError) as exc:
            validate_domain("a" * 250 + ".com")
        assert "exceed 253" in exc.value.message


class TestValidateProtocol:
    """Tests for validate_protocol."""

    def test_valid_mcp(self):
        assert validate_protocol("mcp") == "mcp"

    def test_valid_a2a(self):
        assert validate_protocol("a2a") == "a2a"

    def test_normalizes_to_lowercase(self):
        assert validate_protocol("MCP") == "mcp"

    def test_invalid_protocol_raises(self):
        with pytest.raises(ValidationError) as exc:
            validate_protocol("http")
        assert exc.value.field == "protocol"

    def test_empty_protocol_raises(self):
        with pytest.raises(ValidationError) as exc:
            validate_protocol("")
        assert exc.value.field == "protocol"


class TestValidateConnectClass:
    """Tests for validate_connect_class."""

    def test_valid_known_class(self):
        assert validate_connect_class("lattice") == "lattice"

    def test_normalizes_whitespace_and_case(self):
        assert validate_connect_class(" AppHub-PSC ") == "apphub-psc"

    def test_none_returns_none(self):
        assert validate_connect_class(None) is None

    def test_empty_returns_none(self):
        assert validate_connect_class("   ") is None

    def test_rejects_invalid_characters(self):
        with pytest.raises(ValidationError) as exc:
            validate_connect_class("bad class")
        assert exc.value.field == "connect_class"

    def test_rejects_unknown_class(self):
        with pytest.raises(ValidationError) as exc:
            validate_connect_class("overlay")
        assert exc.value.field == "connect_class"


class TestValidateEndpoint:
    """Tests for validate_endpoint."""

    def test_valid_endpoint(self):
        assert validate_endpoint("api.example.com") == "api.example.com"

    def test_normalizes_to_lowercase(self):
        assert validate_endpoint("API.Example.COM") == "api.example.com"

    def test_removes_trailing_dot(self):
        assert validate_endpoint("api.example.com.") == "api.example.com"

    def test_empty_endpoint_raises(self):
        with pytest.raises(ValidationError) as exc:
            validate_endpoint("")
        assert exc.value.field == "endpoint"


class TestValidatePort:
    """Tests for validate_port."""

    def test_valid_port(self):
        assert validate_port(443) == 443

    def test_valid_min_port(self):
        assert validate_port(1) == 1

    def test_valid_max_port(self):
        assert validate_port(65535) == 65535

    def test_port_zero_raises(self):
        with pytest.raises(ValidationError) as exc:
            validate_port(0)
        assert exc.value.field == "port"

    def test_port_negative_raises(self):
        with pytest.raises(ValidationError) as exc:
            validate_port(-1)
        assert exc.value.field == "port"

    def test_port_too_high_raises(self):
        with pytest.raises(ValidationError) as exc:
            validate_port(65536)
        assert exc.value.field == "port"


class TestValidateTtl:
    """Tests for validate_ttl."""

    def test_valid_ttl(self):
        assert validate_ttl(3600) == 3600

    def test_valid_min_ttl(self):
        assert validate_ttl(30) == 30

    def test_valid_max_ttl(self):
        assert validate_ttl(604800) == 604800

    def test_ttl_too_low_raises(self):
        with pytest.raises(ValidationError) as exc:
            validate_ttl(29)
        assert "at least 30" in exc.value.message

    def test_ttl_too_high_raises(self):
        with pytest.raises(ValidationError) as exc:
            validate_ttl(604801)
        assert "exceed 604800" in exc.value.message


class TestValidateCapabilities:
    """Tests for validate_capabilities."""

    def test_valid_capabilities(self):
        assert validate_capabilities(["chat", "code-review"]) == ["chat", "code-review"]

    def test_normalizes_to_lowercase(self):
        assert validate_capabilities(["Chat", "CODE"]) == ["chat", "code"]

    def test_removes_duplicates(self):
        assert validate_capabilities(["chat", "chat", "code"]) == ["chat", "code"]

    def test_empty_list_returns_empty(self):
        assert validate_capabilities([]) == []

    def test_none_returns_empty(self):
        assert validate_capabilities(None) == []

    def test_filters_empty_strings(self):
        assert validate_capabilities(["chat", "", "code"]) == ["chat", "code"]

    def test_invalid_capability_raises(self):
        with pytest.raises(ValidationError) as exc:
            validate_capabilities(["chat!", "code"])
        assert exc.value.field == "capabilities"


class TestValidateVersion:
    """Tests for validate_version."""

    def test_valid_version(self):
        assert validate_version("1.0.0") == "1.0.0"

    def test_valid_version_with_prerelease(self):
        assert validate_version("1.0.0-alpha") == "1.0.0-alpha"

    def test_valid_version_with_build(self):
        assert validate_version("1.0.0+build.123") == "1.0.0+build.123"

    def test_empty_version_raises(self):
        with pytest.raises(ValidationError) as exc:
            validate_version("")
        assert exc.value.field == "version"

    def test_invalid_version_raises(self):
        with pytest.raises(ValidationError) as exc:
            validate_version("v1")
        assert exc.value.field == "version"


class TestValidateFqdn:
    """Tests for validate_fqdn."""

    def test_valid_fqdn(self):
        result = validate_fqdn("_chat._mcp._agents.example.com")
        assert result == "_chat._mcp._agents.example.com"

    def test_normalizes_to_lowercase(self):
        result = validate_fqdn("_CHAT._MCP._AGENTS.Example.COM")
        assert result == "_chat._mcp._agents.example.com"

    def test_removes_trailing_dot(self):
        result = validate_fqdn("_chat._mcp._agents.example.com.")
        assert result == "_chat._mcp._agents.example.com"

    def test_empty_fqdn_raises(self):
        with pytest.raises(ValidationError) as exc:
            validate_fqdn("")
        assert exc.value.field == "fqdn"

    def test_missing_agents_raises(self):
        with pytest.raises(ValidationError) as exc:
            validate_fqdn("example.com")
        assert "_agents" in exc.value.message


class TestValidateBackend:
    """Tests for validate_backend."""

    def test_valid_route53(self):
        assert validate_backend("route53") == "route53"

    def test_valid_mock(self):
        assert validate_backend("mock") == "mock"

    def test_valid_cloudflare(self):
        assert validate_backend("cloudflare") == "cloudflare"

    def test_valid_cloud_dns(self):
        assert validate_backend("cloud-dns") == "cloud-dns"

    def test_valid_infoblox(self):
        assert validate_backend("infoblox") == "infoblox"

    def test_valid_nios(self):
        assert validate_backend("nios") == "nios"

    def test_valid_ddns(self):
        assert validate_backend("ddns") == "ddns"

    def test_normalizes_to_lowercase(self):
        assert validate_backend("ROUTE53") == "route53"

    def test_invalid_backend_raises(self):
        with pytest.raises(ValidationError) as exc:
            validate_backend("nonexistent")
        assert exc.value.field == "backend"

    def test_empty_backend_raises(self):
        with pytest.raises(ValidationError) as exc:
            validate_backend("")
        assert exc.value.field == "backend"


class TestValidateNoUnderscoreInTarget:
    """Tests for the SVCB TargetName no-underscore rule (draft-02 §Known Organization)."""

    def test_clean_target_passes(self):
        assert (
            validate_no_underscore_in_target("agent-index.example.com") == "agent-index.example.com"
        )

    def test_trailing_dot_tolerated(self):
        assert (
            validate_no_underscore_in_target("agent-index.example.com.")
            == "agent-index.example.com."
        )

    def test_label_starting_with_underscore_rejected(self):
        with pytest.raises(ValidationError) as exc:
            validate_no_underscore_in_target("_index.example.com")
        assert exc.value.field == "target"
        assert "_index" in str(exc.value)

    def test_label_containing_underscore_rejected(self):
        with pytest.raises(ValidationError) as exc:
            validate_no_underscore_in_target("agent_index.example.com")
        assert exc.value.field == "target"
        assert "agent_index" in str(exc.value)

    def test_multiple_underscored_labels_all_reported(self):
        with pytest.raises(ValidationError) as exc:
            validate_no_underscore_in_target("_a._b.example.com")
        msg = str(exc.value)
        assert "_a" in msg
        assert "_b" in msg

    def test_allow_underscore_downgrades_to_warning(self, caplog):
        import logging

        with caplog.at_level(logging.WARNING):
            result = validate_no_underscore_in_target("_index.example.com", allow_underscore=True)
        assert result == "_index.example.com"
        assert any("_index" in record.message for record in caplog.records)
        assert any(record.levelno == logging.WARNING for record in caplog.records)

    def test_allow_underscore_on_clean_target_is_silent(self, caplog):
        import logging

        with caplog.at_level(logging.WARNING):
            result = validate_no_underscore_in_target("clean.example.com", allow_underscore=True)
        assert result == "clean.example.com"
        assert not caplog.records

    def test_empty_target_raises_regardless_of_flag(self):
        with pytest.raises(ValidationError) as exc:
            validate_no_underscore_in_target("", allow_underscore=True)
        assert exc.value.field == "target"


class TestValidateWellKnownPath:
    """Tests for validate_well_known_path.

    The well-known SvcParamKey value flows from DNS into a URL the
    discoverer fetches. Untrusted input must not be able to slip path
    traversal, query strings, fragments, or embedded slashes through to
    the URL — even though validate_fetch_url pins the host, the path is
    still attacker-influenceable without this check.
    """

    def test_accepts_iana_registered_examples(self):
        # Pull from IANA RFC 8615 examples to show the validator
        # accepts the actual shape of real well-known names.
        for name in (
            "agent-card.json",
            "oauth-authorization-server",
            "did-configuration",
            "change-password",
            "openid-credential-issuer",
            "openid-federation",
            "matrix",
        ):
            assert validate_well_known_path(name) == name

    def test_rejects_empty(self):
        with pytest.raises(ValidationError):
            validate_well_known_path("")

    def test_rejects_path_traversal(self):
        for evil in (
            "..",
            "../etc/passwd",
            "..%2Fetc",
            "agent-card.json/..",
        ):
            with pytest.raises(ValidationError):
                validate_well_known_path(evil)

    def test_rejects_query_or_fragment(self):
        for evil in (
            "agent-card.json?token=x",
            "agent-card.json#section",
            "agent-card.json?",
            "agent-card.json#",
        ):
            with pytest.raises(ValidationError):
                validate_well_known_path(evil)

    def test_rejects_embedded_slash(self):
        for evil in (
            "agent/card.json",
            "/agent-card.json",
            "agent-card.json/extra",
        ):
            with pytest.raises(ValidationError):
                validate_well_known_path(evil)

    def test_rejects_percent_encoded(self):
        for evil in (
            "agent%2Fcard.json",
            "%2E%2E",
            "agent-card%00.json",
        ):
            with pytest.raises(ValidationError):
                validate_well_known_path(evil)

    def test_rejects_oversize(self):
        with pytest.raises(ValidationError):
            validate_well_known_path("a" * 129)

    def test_rejects_non_string(self):
        with pytest.raises(ValidationError):
            validate_well_known_path(None)  # type: ignore[arg-type]
