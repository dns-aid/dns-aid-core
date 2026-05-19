# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
HTTP Index discovery for ANS-style compatibility.

This module provides HTTP-based agent discovery as an alternative to pure DNS
discovery. It fetches agent indexes from well-known HTTP endpoints.

Two discovery patterns are supported:
1. /.well-known/agents-index.json at the domain root (primary)
2. /.well-known/agents.json for backwards compatibility

The HTTP index provides richer metadata than DNS TXT records, including
descriptions, model cards, and capability details.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx
import structlog

logger = structlog.get_logger(__name__)

# HTTP index URL patterns to try (in order)
# Primary: Clean subdomain pattern (demo-friendly, no underscores)
# Secondary: ANS-style subdomain pattern
# Fallback: Well-known path pattern at domain root
HTTP_INDEX_PATTERNS = [
    # Clean subdomain: https://index.aiagents.{domain}/index-wellknown (demo-friendly)
    {"type": "subdomain", "host": "index.aiagents.{domain}", "path": "/index-wellknown"},
    # ANS-style: https://_index._aiagents.{domain}/index-wellknown
    {"type": "subdomain", "host": "_index._aiagents.{domain}", "path": "/index-wellknown"},
    # Fallback: well-known paths at domain root
    {"type": "path", "host": "{domain}", "path": "/.well-known/agents-index.json"},
    {"type": "path", "host": "{domain}", "path": "/.well-known/agents.json"},
]

# Default timeout for HTTP requests
DEFAULT_TIMEOUT = 10.0


@dataclass
class ModelCard:
    """Model card metadata for an agent."""

    description: str | None = None
    provider: str | None = None
    version: str | None = None
    license: str | None = None
    documentation_url: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> ModelCard:
        """Parse model card from dictionary."""
        if not data:
            return cls()
        return cls(
            description=data.get("description"),
            provider=data.get("provider"),
            version=data.get("version"),
            license=data.get("license"),
            documentation_url=data.get("documentation_url") or data.get("documentationUrl"),
        )


@dataclass
class Capability:
    """Capability metadata for an agent."""

    modality: str | None = None  # text, image, audio, multimodal
    protocols: list[str] = field(default_factory=list)  # mcp, a2a, https
    cost: str | None = None  # free, paid, usage-based
    rate_limit: str | None = None
    authentication: str | None = None  # none, api_key, oauth
    capabilities: list[str] = field(default_factory=list)  # agent capabilities

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> Capability:
        """Parse capability from dictionary."""
        if not data:
            return cls()
        protocols = data.get("protocols", [])
        if isinstance(protocols, str):
            protocols = [protocols]
        capabilities = data.get("capabilities", [])
        if isinstance(capabilities, str):
            capabilities = [capabilities]
        return cls(
            modality=data.get("modality"),
            protocols=protocols,
            cost=data.get("cost"),
            rate_limit=data.get("rate_limit") or data.get("rateLimit"),
            authentication=data.get("authentication"),
            capabilities=[str(c) for c in capabilities if c],
        )


@dataclass
class HttpIndexAgent:
    """
    Agent entry from HTTP index.

    Contains richer metadata than DNS-only discovery.
    """

    name: str
    fqdn: str
    endpoint: str | None = None  # Direct endpoint URL if provided
    description: str | None = None
    protocols: list[str] = field(default_factory=list)
    modality: str | None = None
    model_card: ModelCard | None = None
    capability: Capability | None = None
    cost: str | None = None
    # Experimental: publisher's EDNS(0) agent-hint advertisement. Stored as the
    # raw dict from JSON. See docs/experimental/edns-signaling.md.
    edns_signaling: dict[str, Any] | None = None

    @classmethod
    def from_dict(cls, name: str, data: dict[str, Any]) -> HttpIndexAgent:
        """
        Parse agent from stakeholder JSON format.

        Expected format:
        {
          "agent-name": {
            "location": {"fqdn": "...", "endpoint": "https://..."},
            "model-card": {"description": "..."},
            "capability": {"modality": "text", "protocols": ["mcp"], "cost": "free"}
          }
        }
        """
        location = data.get("location", {})
        model_card_data = data.get("model-card") or data.get("modelCard", {})
        capability_data = data.get("capability", {})

        model_card = ModelCard.from_dict(model_card_data)
        capability = Capability.from_dict(capability_data)

        # Experimental: lift edns_signaling advertisement if present
        edns_signaling = data.get("edns_signaling")
        if not isinstance(edns_signaling, dict):
            edns_signaling = None

        return cls(
            name=name,
            fqdn=location.get("fqdn", ""),
            endpoint=location.get("endpoint"),  # Direct endpoint URL
            description=model_card.description,
            protocols=capability.protocols,
            modality=capability.modality,
            model_card=model_card,
            capability=capability,
            cost=capability.cost,
            edns_signaling=edns_signaling,
        )

    @property
    def primary_protocol(self) -> str | None:
        """Get the primary (first) protocol."""
        return self.protocols[0] if self.protocols else None

    def to_index_entry_format(self) -> str:
        """Convert to DNS index entry format (name:protocol)."""
        proto = self.primary_protocol or "https"
        return f"{self.name}:{proto}"


class HttpIndexError(Exception):
    """Error fetching or parsing HTTP index."""


async def fetch_http_index(
    domain: str,
    timeout: float = DEFAULT_TIMEOUT,
    verify_ssl: bool = True,
) -> list[HttpIndexAgent]:
    """
    Fetch agent list from HTTP index endpoint.

    Tries multiple URL patterns in order until one succeeds:
    1. ANS-style: https://_index._aiagents.{domain}/index-wellknown
    2. Well-known: https://{domain}/.well-known/agents-index.json
    3. Fallback: https://{domain}/.well-known/agents.json

    Args:
        domain: Domain to fetch index from (e.g., "example.com")
        timeout: HTTP request timeout in seconds
        verify_ssl: Whether to verify SSL certificates

    Returns:
        List of HttpIndexAgent objects

    Raises:
        HttpIndexError: If all endpoints fail

    Example:
        >>> agents = await fetch_http_index("example.com")
        >>> for agent in agents:
        ...     print(f"{agent.name}: {agent.description}")
    """
    domain = domain.lower().rstrip(".")
    errors: list[str] = []

    # Configure TLS verification.
    # Default is verify=True (system trust store). The opt-out path is gated
    # by the explicit verify_ssl=False kwarg (a documented public API surface
    # for testing against self-signed certs in dev environments). Whenever
    # the opt-out is taken at runtime, log a structured warning so operators
    # can audit insecure usage.
    if not verify_ssl:
        logger.warning(
            "http_index.tls_verification_disabled",
            domain=domain,
            message=(
                "HTTP index fetched with TLS certificate verification DISABLED — "
                "only safe for test/development environments; do NOT use in production."
            ),
        )

    async with httpx.AsyncClient(
        timeout=timeout,
        verify=verify_ssl,  # noqa: S501 — opt-out is gated by explicit caller-supplied kwarg; warning logged above
        follow_redirects=True,
        max_redirects=3,
    ) as client:
        for pattern in HTTP_INDEX_PATTERNS:
            # Build URL from pattern
            host = pattern["host"].format(domain=domain)
            path = pattern["path"]
            url = f"https://{host}{path}"

            logger.debug("Trying HTTP index endpoint", url=url, pattern_type=pattern["type"])

            try:
                response = await client.get(url)

                if response.status_code == 200:
                    data = response.json()
                    agents = parse_http_index(data)
                    logger.info(
                        "HTTP index fetched successfully",
                        url=url,
                        agent_count=len(agents),
                    )
                    return agents

                elif response.status_code == 404:
                    errors.append(f"{url}: Not found (404)")
                    logger.debug("HTTP index not found", url=url)
                else:
                    errors.append(f"{url}: HTTP {response.status_code}")
                    logger.warning(
                        "HTTP index request failed",
                        url=url,
                        status_code=response.status_code,
                    )

            except httpx.TimeoutException:
                errors.append(f"{url}: Timeout")
                logger.warning("HTTP index request timed out", url=url)
            except httpx.ConnectError as e:
                errors.append(f"{url}: Connection error - {e}")
                logger.warning("HTTP index connection failed", url=url, error=str(e))
            except Exception as e:
                errors.append(f"{url}: {e}")
                logger.warning("HTTP index request failed", url=url, error=str(e))

    # All endpoints failed
    logger.warning(
        "All HTTP index endpoints failed",
        domain=domain,
        errors=errors,
    )
    raise HttpIndexError(f"No HTTP index found at {domain}. Tried: {', '.join(errors)}")


def parse_http_index(data: dict[str, Any]) -> list[HttpIndexAgent]:
    """
    Parse stakeholder JSON format into HttpIndexAgent list.

    Handles both formats:
    1. Direct agent dict: {"agent-name": {...}}
    2. Nested under "agents" key: {"agents": {"agent-name": {...}}}

    Args:
        data: JSON data from HTTP index endpoint

    Returns:
        List of HttpIndexAgent objects
    """
    agents: list[HttpIndexAgent] = []

    # Handle nested "agents" key
    if "agents" in data and isinstance(data["agents"], dict):
        data = data["agents"]

    for name, agent_data in data.items():
        # Skip metadata fields (non-dict values)
        if not isinstance(agent_data, dict):
            continue

        try:
            agent = HttpIndexAgent.from_dict(name, agent_data)
            if agent.fqdn:  # Only include agents with valid FQDN
                agents.append(agent)
            else:
                logger.warning(
                    "Skipping agent without FQDN",
                    name=name,
                )
        except Exception as e:
            logger.warning(
                "Failed to parse agent from index",
                name=name,
                error=str(e),
            )

    logger.debug("Parsed HTTP index", agent_count=len(agents))
    return agents


async def fetch_http_index_or_empty(
    domain: str,
    timeout: float = DEFAULT_TIMEOUT,
    verify_ssl: bool = True,
) -> list[HttpIndexAgent]:
    """
    Fetch HTTP index, returning empty list on failure.

    This is a convenience wrapper that doesn't raise exceptions,
    useful for fallback scenarios.

    Args:
        domain: Domain to fetch index from
        timeout: HTTP request timeout in seconds
        verify_ssl: Whether to verify SSL certificates

    Returns:
        List of HttpIndexAgent objects (empty on failure)
    """
    try:
        return await fetch_http_index(domain, timeout, verify_ssl)
    except HttpIndexError:
        return []
    except Exception as e:
        logger.warning(
            "Unexpected error fetching HTTP index",
            domain=domain,
            error=str(e),
        )
        return []
