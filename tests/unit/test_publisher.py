# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for DNS-AID publisher."""

import pytest

from dns_aid.backends.mock import MockBackend
from dns_aid.core.models import Protocol
from dns_aid.core.publisher import publish, unpublish
from dns_aid.utils.validation import ValidationError


class TestPublish:
    """Tests for publish function."""

    @pytest.mark.asyncio
    async def test_publish_basic(self, mock_backend: MockBackend):
        """Test basic agent publishing."""
        result = await publish(
            name="chat",
            domain="example.com",
            protocol="a2a",
            endpoint="chat.example.com",
            backend=mock_backend,
        )

        assert result.success is True
        assert result.agent.name == "chat"
        assert result.agent.fqdn == "_chat._a2a._agents.example.com"
        assert len(result.records_created) == 2  # SVCB + TXT

    @pytest.mark.asyncio
    async def test_publish_with_capabilities(self, mock_backend: MockBackend):
        """Test publishing with capabilities."""
        result = await publish(
            name="network",
            domain="example.com",
            protocol="mcp",
            endpoint="mcp.example.com",
            capabilities=["ipam", "dns", "vpn"],
            backend=mock_backend,
        )

        assert result.success is True
        assert result.agent.capabilities == ["ipam", "dns", "vpn"]

        # Check TXT record was created with capabilities
        txt_values = mock_backend.get_txt_record("example.com", "_network._mcp._agents")
        assert txt_values is not None
        assert "capabilities=ipam,dns,vpn" in txt_values

    @pytest.mark.asyncio
    async def test_publish_creates_svcb_record(self, mock_backend: MockBackend):
        """Test that SVCB record is created correctly."""
        await publish(
            name="chat",
            domain="example.com",
            protocol="a2a",
            endpoint="chat.example.com",
            port=8443,
            backend=mock_backend,
        )

        svcb = mock_backend.get_svcb_record("example.com", "_chat._a2a._agents")

        assert svcb is not None
        assert svcb["target"] == "chat.example.com."
        assert svcb["params"]["alpn"] == "a2a"
        assert svcb["params"]["port"] == "8443"

    @pytest.mark.asyncio
    async def test_publish_with_protocol_enum(self, mock_backend: MockBackend):
        """Test publishing with Protocol enum."""
        result = await publish(
            name="agent",
            domain="example.com",
            protocol=Protocol.MCP,
            endpoint="mcp.example.com",
            backend=mock_backend,
        )

        assert result.success is True
        assert result.agent.protocol == Protocol.MCP

    @pytest.mark.asyncio
    async def test_publish_invalid_zone(self, mock_backend: MockBackend):
        """Test publishing to non-existent zone."""
        # Configure mock to only accept specific zones
        mock_backend._zones = {"allowed.com"}

        result = await publish(
            name="chat",
            domain="notallowed.com",
            protocol="a2a",
            endpoint="chat.notallowed.com",
            backend=mock_backend,
        )

        assert result.success is False
        assert "does not exist" in result.message

    @pytest.mark.asyncio
    async def test_publish_custom_ttl(self, mock_backend: MockBackend):
        """Test publishing with custom TTL."""
        result = await publish(
            name="chat",
            domain="example.com",
            protocol="a2a",
            endpoint="chat.example.com",
            ttl=300,
            backend=mock_backend,
        )

        assert result.success is True
        assert result.agent.ttl == 300

        svcb = mock_backend.get_svcb_record("example.com", "_chat._a2a._agents")
        assert svcb["ttl"] == 300

    @pytest.mark.asyncio
    async def test_publish_with_cap_uri(self, mock_backend: MockBackend):
        """Test publishing with cap_uri includes it in SVCB record."""
        result = await publish(
            name="booking",
            domain="example.com",
            protocol="mcp",
            endpoint="mcp.example.com",
            capabilities=["travel", "booking"],
            cap_uri="https://mcp.example.com/.well-known/agent-cap.json",
            cap_sha256="dGVzdGhhc2g",
            bap=["mcp/1", "a2a/1"],
            policy_uri="https://example.com/agent-policy",
            realm="production",
            backend=mock_backend,
        )

        assert result.success is True
        assert result.agent.cap_uri == "https://mcp.example.com/.well-known/agent-cap.json"
        assert result.agent.cap_sha256 == "dGVzdGhhc2g"
        assert result.agent.bap == ["mcp/1", "a2a/1"]
        assert result.agent.policy_uri == "https://example.com/agent-policy"
        assert result.agent.realm == "production"

        # SVCB params should include custom DNS-AID params
        svcb = mock_backend.get_svcb_record("example.com", "_booking._mcp._agents")
        assert svcb is not None
        # keyNNNNN format by default (RFC 9460 compliant)
        assert svcb["params"]["key65400"] == "https://mcp.example.com/.well-known/agent-cap.json"
        assert svcb["params"]["key65401"] == "dGVzdGhhc2g"
        assert svcb["params"]["key65402"] == "mcp/1,a2a/1"
        assert svcb["params"]["key65403"] == "https://example.com/agent-policy"
        assert svcb["params"]["key65404"] == "production"

    @pytest.mark.asyncio
    async def test_publish_without_cap_uri_unchanged(self, mock_backend: MockBackend):
        """Test publishing without cap_uri doesn't add DNS-AID params (backwards compat)."""
        result = await publish(
            name="chat",
            domain="example.com",
            protocol="a2a",
            endpoint="chat.example.com",
            backend=mock_backend,
        )

        assert result.success is True
        assert result.agent.cap_uri is None
        assert result.agent.cap_sha256 is None
        assert result.agent.bap == []
        assert result.agent.policy_uri is None
        assert result.agent.realm is None

        svcb = mock_backend.get_svcb_record("example.com", "_chat._a2a._agents")
        assert svcb is not None
        assert "cap" not in svcb["params"]
        assert "cap-sha256" not in svcb["params"]
        assert "bap" not in svcb["params"]
        assert "policy" not in svcb["params"]
        assert "realm" not in svcb["params"]

    @pytest.mark.asyncio
    async def test_publish_with_partial_dnsaid_params(self, mock_backend: MockBackend):
        """Test publishing with only some DNS-AID params."""
        result = await publish(
            name="booking",
            domain="example.com",
            protocol="mcp",
            endpoint="mcp.example.com",
            cap_uri="https://mcp.example.com/.well-known/agent-cap.json",
            realm="demo",
            backend=mock_backend,
        )

        assert result.success is True
        svcb = mock_backend.get_svcb_record("example.com", "_booking._mcp._agents")
        assert svcb is not None
        assert svcb["params"]["key65400"] == "https://mcp.example.com/.well-known/agent-cap.json"
        assert svcb["params"]["key65404"] == "demo"
        assert "key65402" not in svcb["params"]
        assert "key65403" not in svcb["params"]

    @pytest.mark.asyncio
    async def test_publish_with_connect_params(self, mock_backend: MockBackend):
        """Test publishing with provider-managed connection metadata."""
        result = await publish(
            name="overlay",
            domain="example.com",
            protocol="mcp",
            endpoint="overlay.example.com",
            connect_class="lattice",
            connect_meta="arn:aws:vpc-lattice:us-east-1:123456789012:service/svc-123",
            enroll_uri="https://overlay.example.com/.well-known/agent-connect",
            backend=mock_backend,
        )

        assert result.success is True
        assert result.agent.connect_class == "lattice"
        assert (
            result.agent.connect_meta
            == "arn:aws:vpc-lattice:us-east-1:123456789012:service/svc-123"
        )
        assert result.agent.enroll_uri == "https://overlay.example.com/.well-known/agent-connect"

        svcb = mock_backend.get_svcb_record("example.com", "_overlay._mcp._agents")
        assert svcb is not None
        assert svcb["params"]["key65406"] == "lattice"
        assert (
            svcb["params"]["key65407"]
            == "arn:aws:vpc-lattice:us-east-1:123456789012:service/svc-123"
        )
        assert svcb["params"]["key65408"] == "https://overlay.example.com/.well-known/agent-connect"


class TestPublishWellKnown:
    """Tests for the draft-02 `well-known` SvcParamKey on the publish path."""

    @pytest.mark.asyncio
    async def test_publish_with_well_known_path(self, mock_backend: MockBackend):
        """Setting well_known_path emits key65409 on the SVCB record."""
        result = await publish(
            name="booking",
            domain="example.com",
            protocol="mcp",
            endpoint="booking.example.com",
            well_known_path="agent-card.json",
            backend=mock_backend,
        )
        assert result.success is True
        assert result.agent.well_known_path == "agent-card.json"

        svcb = mock_backend.get_svcb_record("example.com", "_booking._mcp._agents")
        assert svcb is not None
        assert svcb["params"]["key65409"] == "agent-card.json"

    @pytest.mark.asyncio
    async def test_publish_cap_and_well_known_coexist(self, mock_backend: MockBackend):
        """`cap` and `well-known` are independent — both may be set on one record."""
        result = await publish(
            name="booking",
            domain="example.com",
            protocol="mcp",
            endpoint="booking.example.com",
            cap_uri="urn:example:agent-cap:abc",
            cap_sha256="dGVzdGhhc2g",
            well_known_path="agent-card.json",
            backend=mock_backend,
        )
        assert result.success is True
        assert result.agent.cap_uri == "urn:example:agent-cap:abc"
        assert result.agent.well_known_path == "agent-card.json"

        svcb = mock_backend.get_svcb_record("example.com", "_booking._mcp._agents")
        assert svcb is not None
        assert svcb["params"]["key65400"] == "urn:example:agent-cap:abc"
        assert svcb["params"]["key65401"] == "dGVzdGhhc2g"
        assert svcb["params"]["key65409"] == "agent-card.json"


class TestPublishTargetUnderscoreValidation:
    """Tests for the draft-02 §Known-Organization no-underscore-in-target rule."""

    @pytest.mark.asyncio
    async def test_underscored_endpoint_rejected_by_default(self, mock_backend: MockBackend):
        """Underscored TargetName fails publish unless explicitly allowed."""
        with pytest.raises(ValidationError) as exc:
            await publish(
                name="chat",
                domain="example.com",
                protocol="a2a",
                endpoint="_chat.example.com",
                backend=mock_backend,
            )
        assert exc.value.field == "target"

    @pytest.mark.asyncio
    async def test_underscored_endpoint_allowed_with_flag_and_env(
        self, mock_backend: MockBackend, monkeypatch
    ):
        """allow_underscore_target=True now requires the operator to
        ALSO opt in via the env var. Both together let the publish
        proceed with a structured WARN; one without the other raises."""
        from unittest.mock import patch

        from dns_aid.utils import validation as validation_module

        monkeypatch.setenv("DNS_AID_ALLOW_UNDERSCORE_TARGET", "1")
        with patch.object(validation_module, "logger") as mock_logger:
            result = await publish(
                name="chat",
                domain="example.com",
                protocol="a2a",
                endpoint="_chat.internal.example",
                backend=mock_backend,
                allow_underscore_target=True,
            )
        assert result.success is True
        # The warn fires from each enforcement site (publisher entrypoint
        # + AgentRecord field_validator + SvcbRecord field_validator) —
        # all carrying the same warning_class, all keyed on the same
        # target. That's noisy but coherent: every gate sees the bypass.
        warn_calls = mock_logger.warning.call_args_list
        assert len(warn_calls) >= 1
        assert all(c.kwargs.get("warning_class") == "dns_aid.underscore_bypass" for c in warn_calls)
        assert all("_chat" in c.kwargs.get("target", "") for c in warn_calls)
        # PR #154 v2 review (Igor): the bypass must also surface on
        # PublishResult.warnings as a stable warning_class identifier
        # — log lines alone aren't a usable signal for log aggregators
        # or downstream observability.
        assert "dns_aid.underscore_bypass" in result.warnings

    @pytest.mark.asyncio
    async def test_underscored_endpoint_strict_default_is_bc_break(
        self, mock_backend: MockBackend, monkeypatch
    ):
        """BC-pin — PR #154 strict-by-default tightening.

        Even without explicitly passing ``allow_underscore_target``, a
        plain `publish()` with an underscored endpoint MUST raise. This
        is the BREAKING behaviour called out in CHANGELOG [Unreleased]
        — a deliberate, versioned change per draft-02 §3.2. If a future
        commit accidentally relaxes the default, this test holds the
        line.
        """
        monkeypatch.delenv("DNS_AID_ALLOW_UNDERSCORE_TARGET", raising=False)
        with pytest.raises(ValidationError):
            await publish(
                name="chat",
                domain="example.com",
                protocol="a2a",
                endpoint="my_service.internal.example",
                backend=mock_backend,
            )

    @pytest.mark.asyncio
    async def test_clean_endpoint_no_warnings_emitted(self, mock_backend: MockBackend):
        """A normal endpoint must not populate warnings — the field is
        for advisories, not always-on noise."""
        result = await publish(
            name="chat",
            domain="example.com",
            protocol="a2a",
            endpoint="chat.example.com",
            backend=mock_backend,
        )
        assert result.success is True
        assert result.warnings == []

    @pytest.mark.asyncio
    async def test_underscored_endpoint_flag_without_env_raises(
        self, mock_backend: MockBackend, monkeypatch
    ):
        """Without the env gate, the per-call flag alone is insufficient."""
        monkeypatch.delenv("DNS_AID_ALLOW_UNDERSCORE_TARGET", raising=False)
        with pytest.raises(ValidationError):
            await publish(
                name="chat",
                domain="example.com",
                protocol="a2a",
                endpoint="_chat.internal.example",
                backend=mock_backend,
                allow_underscore_target=True,
            )

    @pytest.mark.asyncio
    async def test_clean_endpoint_passes(self, mock_backend: MockBackend):
        """A normal hostname publishes without warnings or errors."""
        result = await publish(
            name="chat",
            domain="example.com",
            protocol="a2a",
            endpoint="chat.example.com",
            backend=mock_backend,
        )
        assert result.success is True


class TestUnpublish:
    """Tests for unpublish function."""

    @pytest.mark.asyncio
    async def test_unpublish_existing(self, mock_backend: MockBackend):
        """Test unpublishing an existing agent."""
        # First publish
        await publish(
            name="chat",
            domain="example.com",
            protocol="a2a",
            endpoint="chat.example.com",
            backend=mock_backend,
        )

        # Verify records exist
        assert mock_backend.get_svcb_record("example.com", "_chat._a2a._agents") is not None

        # Unpublish
        result = await unpublish(
            name="chat",
            domain="example.com",
            protocol="a2a",
            backend=mock_backend,
        )

        assert result is True
        assert mock_backend.get_svcb_record("example.com", "_chat._a2a._agents") is None

    @pytest.mark.asyncio
    async def test_unpublish_nonexistent(self, mock_backend: MockBackend):
        """Test unpublishing non-existent agent returns False."""
        result = await unpublish(
            name="nonexistent",
            domain="example.com",
            protocol="a2a",
            backend=mock_backend,
        )

        assert result is False

    @pytest.mark.asyncio
    async def test_unpublish_protocol_string(self, mock_backend: MockBackend):
        """Test unpublish accepts a string protocol and normalizes it."""
        await publish(
            name="agent",
            domain="example.com",
            protocol="mcp",
            endpoint="mcp.example.com",
            backend=mock_backend,
        )
        result = await unpublish(
            name="agent",
            domain="example.com",
            protocol="MCP",  # uppercase string
            backend=mock_backend,
        )
        assert result is True


class TestDefaultBackend:
    """Tests for default backend management."""

    def setup_method(self):
        """Reset global state before each test."""
        from dns_aid.core.publisher import reset_default_backend

        reset_default_backend()

    def teardown_method(self):
        """Reset global state after each test."""
        from dns_aid.core.publisher import reset_default_backend

        reset_default_backend()

    def test_set_default_backend(self):
        """Test set_default_backend stores the backend."""
        from dns_aid.core.publisher import get_default_backend, set_default_backend

        backend = MockBackend()
        set_default_backend(backend)
        assert get_default_backend() is backend

    def test_reset_default_backend(self):
        """Test reset_default_backend clears the stored backend."""
        from dns_aid.core.publisher import (
            get_default_backend,
            reset_default_backend,
            set_default_backend,
        )

        set_default_backend(MockBackend())
        reset_default_backend()
        # After reset, calling get_default_backend without env var should raise
        with pytest.raises(ValueError, match="DNS_AID_BACKEND must be set"):
            get_default_backend()

    def test_get_default_backend_mock(self):
        """Test get_default_backend with DNS_AID_BACKEND=mock."""
        from unittest.mock import patch

        from dns_aid.core.publisher import get_default_backend

        with patch.dict("os.environ", {"DNS_AID_BACKEND": "mock"}):
            backend = get_default_backend()
            assert backend.name == "mock"

    def test_get_default_backend_route53(self):
        """Test get_default_backend with DNS_AID_BACKEND=route53."""
        from unittest.mock import patch

        from dns_aid.core.publisher import get_default_backend

        with patch.dict("os.environ", {"DNS_AID_BACKEND": "route53"}):
            backend = get_default_backend()
            assert backend.name == "route53"

    def test_get_default_backend_cloudflare(self):
        """Test get_default_backend with DNS_AID_BACKEND=cloudflare."""
        from unittest.mock import patch

        from dns_aid.core.publisher import get_default_backend

        with patch.dict("os.environ", {"DNS_AID_BACKEND": "cloudflare"}):
            backend = get_default_backend()
            assert backend.name == "cloudflare"

    def test_get_default_backend_no_env_raises(self):
        """Test get_default_backend raises when DNS_AID_BACKEND is not set."""
        from unittest.mock import patch

        from dns_aid.core.publisher import get_default_backend

        with (
            patch.dict("os.environ", {}, clear=True),
            pytest.raises(ValueError, match="DNS_AID_BACKEND must be set"),
        ):
            get_default_backend()

    def test_get_default_backend_unknown_raises(self):
        """Test get_default_backend raises for unknown backend type."""
        from unittest.mock import patch

        from dns_aid.core.publisher import get_default_backend

        with (
            patch.dict("os.environ", {"DNS_AID_BACKEND": "bogus"}),
            pytest.raises(ValueError, match="Unknown backend"),
        ):
            get_default_backend()


class TestPublishEdgeCases:
    """Tests for edge cases in publish function."""

    @pytest.mark.asyncio
    async def test_publish_sign_no_key_raises(self, mock_backend: MockBackend):
        """Test publish with sign=True but no key path raises ValueError."""
        with pytest.raises(ValueError, match="private_key_path is required"):
            await publish(
                name="agent",
                domain="example.com",
                protocol="mcp",
                endpoint="mcp.example.com",
                sign=True,
                private_key_path=None,
                backend=mock_backend,
            )

    @pytest.mark.asyncio
    async def test_publish_exception_returns_failure(self):
        """Test publish returns success=False when backend raises."""
        from unittest.mock import AsyncMock, patch

        from dns_aid.backends.mock import MockBackend

        backend = MockBackend()
        # Make zone_exists return True but publish_agent raise
        with (
            patch.object(backend, "zone_exists", new_callable=AsyncMock, return_value=True),
            patch.object(
                backend,
                "publish_agent",
                new_callable=AsyncMock,
                side_effect=RuntimeError("boom"),
            ),
        ):
            result = await publish(
                name="agent",
                domain="example.com",
                protocol="mcp",
                endpoint="mcp.example.com",
                backend=backend,
            )
            assert result.success is False
            assert "boom" in result.message
