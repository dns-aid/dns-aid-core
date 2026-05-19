# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Fetch agent capability document from cap URI (IETF draft-compliant).

Per IETF draft-mozleywilliams-dnsop-dnsaid-01, the SVCB record may contain
a `cap` parameter with a URI pointing to a JSON capability document. This module
fetches and parses that document.

The capability document schema:
{
    "capabilities": ["travel", "booking", "calendar"],
    "version": "1.0.0",
    "description": "Booking agent for travel reservations",
    "use_cases": ["flight-booking", "hotel-reservation"],
    "protocols": ["mcp"],
    "authentication": "oauth2",
    "rate_limit": "100/min",
    "contact": "ops@example.com"
}
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)

# Maximum response size for capability document fetches (256KB).
# Cap documents are structured metadata — 256KB is very generous.
_MAX_CAP_RESPONSE_BYTES = 256_000


@dataclass
class CapabilityDocument:
    """Parsed capability document from a cap URI."""

    capabilities: list[str] = field(default_factory=list)
    version: str | None = None
    description: str | None = None
    use_cases: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    raw_data: dict[str, Any] = field(default_factory=dict)
    # Experimental: publisher's EDNS(0) agent-hint advertisement. Stored as the
    # raw dict from the JSON to avoid coupling core to the experimental package.
    # See docs/experimental/edns-signaling.md.
    edns_signaling: dict[str, Any] | None = None


def _verify_cap_digest(content: bytes, expected_sha256: str, cap_uri: str) -> bool:
    """Verify SHA-256 digest of capability document content.

    Returns True if digest matches, False otherwise.
    """
    import base64
    import hashlib

    actual_digest = (
        base64.urlsafe_b64encode(hashlib.sha256(content).digest()).rstrip(b"=").decode("ascii")
    )
    if actual_digest != expected_sha256:
        logger.warning(
            "Cap document SHA-256 mismatch",
            cap_uri=cap_uri,
            expected=expected_sha256,
            actual=actual_digest,
        )
        return False
    return True


def _extract_string_list(data: dict[str, Any], key: str) -> list[str]:
    """Extract and validate a list-of-strings field from capability data."""
    value = data.get(key, [])
    if isinstance(value, list):
        return [str(item) for item in value if item]
    return []


def _extract_capabilities_multi_format(data: dict[str, Any]) -> list[str]:
    """Extract capabilities from multiple JSON formats.

    Handles three formats encountered in the wild:
    1. DNS-AID native: {"capabilities": ["travel", "booking"]}
    2. Non-standard object list: {"capabilities": [{"name": "travel"}]}
    3. A2A agent card: {"skills": [{"id": "travel", "name": "Travel Booking"}]}

    Priority: capabilities (string list) > capabilities (object list) > skills
    """
    # Try "capabilities" field first
    caps = data.get("capabilities")
    if isinstance(caps, list) and caps:
        first = caps[0]
        if isinstance(first, str):
            # Format 1: string list — DNS-AID native
            return [str(c) for c in caps if c]
        elif isinstance(first, dict):
            # Format 2: object list — extract "name" or "id"
            result = []
            for item in caps:
                if isinstance(item, dict):
                    name = item.get("name") or item.get("id") or ""
                    if name:
                        result.append(str(name))
            return result

    # Try A2A "skills" field
    skills = data.get("skills")
    if isinstance(skills, list) and skills:
        result = []
        for skill in skills:
            if isinstance(skill, dict):
                skill_id = skill.get("id") or skill.get("name") or ""
                if skill_id:
                    result.append(str(skill_id))
        return result

    return []


async def fetch_cap_document(
    cap_uri: str,
    timeout: float = 10.0,
    expected_sha256: str | None = None,
) -> CapabilityDocument | None:
    """
    Fetch and parse the capability document at the given URI.

    Returns None on failure (caller should fall back to TXT).

    Args:
        cap_uri: HTTPS URI to the capability document JSON.
        timeout: HTTP request timeout in seconds.
        expected_sha256: Base64url-encoded SHA-256 digest to verify against
            the fetched content. If provided and the digest doesn't match,
            returns None. If None, skips integrity verification.

    Returns:
        CapabilityDocument if successfully fetched and parsed, None otherwise.
    """
    logger.debug("Fetching capability document", cap_uri=cap_uri)

    # SSRF protection: validate URL before fetching
    try:
        from dns_aid.utils.url_safety import UnsafeURLError, validate_fetch_url

        validate_fetch_url(cap_uri)
    except UnsafeURLError as e:
        logger.warning("Cap URI blocked by SSRF protection", cap_uri=cap_uri, error=str(e))
        return None

    try:
        from dns_aid.utils.url_safety import ResponseTooLargeError, safe_fetch_bytes

        body = await safe_fetch_bytes(
            cap_uri,
            max_bytes=_MAX_CAP_RESPONSE_BYTES,
            timeout=timeout,
            follow_redirects=True,
            max_redirects=3,
        )
        if body is None:
            logger.debug("Cap document fetch failed (non-200)", cap_uri=cap_uri)
            return None

        if expected_sha256 and not _verify_cap_digest(body, expected_sha256, cap_uri):
            return None

        import json

        data = json.loads(body)

        if not isinstance(data, dict):
            logger.debug("Cap document is not a JSON object", cap_uri=cap_uri)
            return None

        capabilities = _extract_capabilities_multi_format(data)
        use_cases = _extract_string_list(data, "use_cases")

        # Experimental: lift the publisher's edns_signaling advertisement if present.
        # Stored as a dict; forward-compat on unknown versions / shapes.
        edns_signaling = data.get("edns_signaling")
        if not isinstance(edns_signaling, dict):
            edns_signaling = None

        known_keys = {"capabilities", "version", "description", "use_cases", "edns_signaling"}
        metadata = {k: v for k, v in data.items() if k not in known_keys}

        doc = CapabilityDocument(
            capabilities=capabilities,
            version=data.get("version"),
            description=data.get("description"),
            use_cases=use_cases,
            metadata=metadata,
            raw_data=data,
            edns_signaling=edns_signaling,
        )

        logger.debug(
            "Cap document fetched successfully",
            cap_uri=cap_uri,
            capabilities_count=len(doc.capabilities),
        )
        return doc

    except ResponseTooLargeError:
        logger.warning(
            "Cap document response too large — skipping",
            cap_uri=cap_uri,
            limit=_MAX_CAP_RESPONSE_BYTES,
        )
        return None
    except httpx.TimeoutException:
        logger.debug("Cap document fetch timed out", cap_uri=cap_uri)
        return None
    except httpx.ConnectError:
        logger.debug("Cap document connection failed", cap_uri=cap_uri)
        return None
    except Exception as e:
        logger.debug(
            "Cap document fetch error",
            cap_uri=cap_uri,
            error=str(e),
        )
        return None
