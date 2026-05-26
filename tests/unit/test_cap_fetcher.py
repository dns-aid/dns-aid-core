# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for DNS-AID capability document fetcher."""

from __future__ import annotations

import json
from unittest.mock import patch

import httpx
import pytest

from dns_aid.core.cap_fetcher import CapabilityDocument, fetch_cap_document
from dns_aid.utils.url_safety import ResponseTooLargeError

_SSRF_BYPASS = patch("dns_aid.utils.url_safety.validate_fetch_url", side_effect=lambda u: u)


def _mock_fetch(data: dict | list | str | None = None, *, raw: bytes | None = None):
    """Create an async mock for safe_fetch_bytes."""
    body = raw if raw is not None else (json.dumps(data).encode() if data is not None else None)

    async def _fetch(url, **kwargs):
        return body

    return _fetch


def _mock_fetch_error(exc):
    async def _fetch(url, **kwargs):
        raise exc

    return _fetch


class TestCapabilityDocument:
    """Tests for CapabilityDocument dataclass."""

    def test_default_values(self):
        doc = CapabilityDocument()
        assert doc.capabilities == []
        assert doc.version is None
        assert doc.description is None
        assert doc.use_cases == []
        assert doc.metadata == {}

    def test_with_values(self):
        doc = CapabilityDocument(
            capabilities=["travel", "booking"],
            version="1.0.0",
            description="Booking agent",
            use_cases=["flight-booking"],
            metadata={"contact": "ops@example.com"},
        )
        assert doc.capabilities == ["travel", "booking"]
        assert doc.version == "1.0.0"
        assert doc.description == "Booking agent"
        assert doc.use_cases == ["flight-booking"]
        assert doc.metadata == {"contact": "ops@example.com"}


class TestFetchCapDocument:
    """Tests for fetch_cap_document."""

    @pytest.mark.asyncio
    async def test_successful_fetch(self):
        """Test fetching a valid capability document."""
        cap_data = {
            "capabilities": ["travel", "booking", "calendar"],
            "version": "1.0.0",
            "description": "Booking agent for travel reservations",
            "use_cases": ["flight-booking", "hotel-reservation"],
            "authentication": "oauth2",
            "rate_limit": "100/min",
        }

        with (
            _SSRF_BYPASS,
            patch("dns_aid.utils.url_safety.safe_fetch_bytes", side_effect=_mock_fetch(cap_data)),
        ):
            doc = await fetch_cap_document("https://example.com/.well-known/agent-cap.json")

        assert doc is not None
        assert doc.capabilities == ["travel", "booking", "calendar"]
        assert doc.version == "1.0.0"
        assert doc.description == "Booking agent for travel reservations"
        assert doc.use_cases == ["flight-booking", "hotel-reservation"]
        assert doc.metadata["authentication"] == "oauth2"
        assert doc.metadata["rate_limit"] == "100/min"

    @pytest.mark.asyncio
    async def test_returns_none_on_404(self):
        """Test that 404 returns None."""
        with (
            _SSRF_BYPASS,
            patch("dns_aid.utils.url_safety.safe_fetch_bytes", side_effect=_mock_fetch(None)),
        ):
            doc = await fetch_cap_document("https://example.com/.well-known/agent-cap.json")

        assert doc is None

    @pytest.mark.asyncio
    async def test_returns_none_on_500(self):
        """Test that server error returns None."""
        with (
            _SSRF_BYPASS,
            patch("dns_aid.utils.url_safety.safe_fetch_bytes", side_effect=_mock_fetch(None)),
        ):
            doc = await fetch_cap_document("https://example.com/.well-known/agent-cap.json")

        assert doc is None

    @pytest.mark.asyncio
    async def test_returns_none_on_timeout(self):
        """Test that timeout returns None."""
        with (
            _SSRF_BYPASS,
            patch(
                "dns_aid.utils.url_safety.safe_fetch_bytes",
                side_effect=_mock_fetch_error(httpx.TimeoutException("timeout")),
            ),
        ):
            doc = await fetch_cap_document("https://example.com/.well-known/agent-cap.json")

        assert doc is None

    @pytest.mark.asyncio
    async def test_returns_none_on_connect_error(self):
        """Test that connection error returns None."""
        with (
            _SSRF_BYPASS,
            patch(
                "dns_aid.utils.url_safety.safe_fetch_bytes",
                side_effect=_mock_fetch_error(httpx.ConnectError("refused")),
            ),
        ):
            doc = await fetch_cap_document("https://unreachable.example.com/cap.json")

        assert doc is None

    @pytest.mark.asyncio
    async def test_returns_none_on_invalid_json(self):
        """Test that invalid JSON returns None."""
        with (
            _SSRF_BYPASS,
            patch(
                "dns_aid.utils.url_safety.safe_fetch_bytes",
                side_effect=_mock_fetch(raw=b"not valid json{{{"),
            ),
        ):
            doc = await fetch_cap_document("https://example.com/bad.json")

        assert doc is None

    @pytest.mark.asyncio
    async def test_returns_none_on_non_dict_json(self):
        """Test that non-dict JSON (e.g., array) returns None."""
        with (
            _SSRF_BYPASS,
            patch(
                "dns_aid.utils.url_safety.safe_fetch_bytes",
                side_effect=_mock_fetch(["not", "a", "dict"]),
            ),
        ):
            doc = await fetch_cap_document("https://example.com/array.json")

        assert doc is None

    @pytest.mark.asyncio
    async def test_empty_capabilities_list(self):
        """Test document with empty capabilities list."""
        with (
            _SSRF_BYPASS,
            patch(
                "dns_aid.utils.url_safety.safe_fetch_bytes",
                side_effect=_mock_fetch({"capabilities": [], "version": "1.0.0"}),
            ),
        ):
            doc = await fetch_cap_document("https://example.com/cap.json")

        assert doc is not None
        assert doc.capabilities == []
        assert doc.version == "1.0.0"

    @pytest.mark.asyncio
    async def test_missing_capabilities_field(self):
        """Test document without capabilities field."""
        with (
            _SSRF_BYPASS,
            patch(
                "dns_aid.utils.url_safety.safe_fetch_bytes",
                side_effect=_mock_fetch(
                    {"version": "1.0.0", "description": "An agent without caps"}
                ),
            ),
        ):
            doc = await fetch_cap_document("https://example.com/cap.json")

        assert doc is not None
        assert doc.capabilities == []
        assert doc.version == "1.0.0"

    @pytest.mark.asyncio
    async def test_extra_metadata_preserved(self):
        """Test that unknown fields are preserved in metadata."""
        with (
            _SSRF_BYPASS,
            patch(
                "dns_aid.utils.url_safety.safe_fetch_bytes",
                side_effect=_mock_fetch(
                    {
                        "capabilities": ["travel"],
                        "version": "2.0.0",
                        "description": "Travel agent",
                        "use_cases": ["booking"],
                        "protocols": ["mcp"],
                        "authentication": "oauth2",
                        "rate_limit": "100/min",
                        "contact": "ops@example.com",
                    }
                ),
            ),
        ):
            doc = await fetch_cap_document("https://example.com/cap.json")

        assert doc is not None
        assert doc.capabilities == ["travel"]
        assert "capabilities" not in doc.metadata
        assert "version" not in doc.metadata
        assert "description" not in doc.metadata
        assert "use_cases" not in doc.metadata
        assert doc.metadata["protocols"] == ["mcp"]
        assert doc.metadata["authentication"] == "oauth2"
        assert doc.metadata["rate_limit"] == "100/min"
        assert doc.metadata["contact"] == "ops@example.com"

    @pytest.mark.asyncio
    async def test_oversized_response_rejected(self):
        """Test that oversized responses are rejected."""
        with (
            _SSRF_BYPASS,
            patch(
                "dns_aid.utils.url_safety.safe_fetch_bytes",
                side_effect=_mock_fetch_error(ResponseTooLargeError("too big")),
            ),
        ):
            doc = await fetch_cap_document("https://evil.example.com/cap.json")

        assert doc is None
