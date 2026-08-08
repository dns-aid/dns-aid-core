# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
A2A Agent Card — Google's Agent-to-Agent protocol agent description format.

The Agent Card is a JSON document served at `/.well-known/agent-card.json` that
describes an agent's capabilities, authentication requirements, and metadata.

Reference: https://google.github.io/A2A/
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlparse

import httpx
import structlog

logger = structlog.get_logger(__name__)

# Well-known path for A2A Agent Cards
A2A_AGENT_CARD_PATH = "/.well-known/agent-card.json"
_MAX_DNS_LABEL_LENGTH = 63

if TYPE_CHECKING:
    from dns_aid.backends.base import DNSBackend
    from dns_aid.core.models import AgentRecord, PublishResult

# Maximum response size for agent-card.json fetches (1MB).
# A2A cards with many skills and OpenAPI-style schemas can reach 200-300KB.
_MAX_AGENT_CARD_RESPONSE_BYTES = 1_000_000


@dataclass
class A2AProvider:
    """Agent provider/organization information."""

    organization: str
    url: str | None = None


@dataclass
class A2AInterface:
    """One transport a 0.3+ card advertises.

    0.2 described a single `url` and nothing about how to speak to it. 0.3 adds
    `preferredTransport` beside that url, and `supportedInterfaces` listing every
    binding with its own url — which is how an agent offers JSONRPC and gRPC at
    different paths.
    """

    url: str
    protocol_binding: str | None = None
    protocol_version: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> A2AInterface:
        return cls(
            url=data.get("url", ""),
            protocol_binding=data.get("protocolBinding") or data.get("transport"),
            protocol_version=data.get("protocolVersion"),
        )


@dataclass
class A2ASkill:
    """A single skill/capability the agent can perform."""

    id: str
    name: str
    description: str | None = None
    input_modes: list[str] = field(default_factory=lambda: ["text"])
    output_modes: list[str] = field(default_factory=lambda: ["text"])
    tags: list[str] = field(default_factory=list)
    # 0.3 additions. `examples` is prose or JSON showing how to invoke the
    # skill; `security_requirements` lets a single skill demand more than the
    # card-level default.
    examples: list[str] = field(default_factory=list)
    security_requirements: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> A2ASkill:
        """Parse a skill from JSON dict."""
        return cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
            description=data.get("description"),
            input_modes=data.get("inputModes", ["text"]),
            output_modes=data.get("outputModes", ["text"]),
            tags=data.get("tags", []),
            examples=[e for e in data.get("examples", []) if isinstance(e, str)],
            security_requirements=[
                r for r in data.get("securityRequirements", []) if isinstance(r, dict)
            ],
        )


@dataclass
class A2AAuthentication:
    """Authentication requirements for the agent."""

    schemes: list[str] = field(default_factory=list)
    credentials: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> A2AAuthentication:
        """Parse the 0.2 `authentication` object."""
        return cls(
            schemes=data.get("schemes", []),
            credentials=data.get("credentials"),
        )

    @classmethod
    def from_security_schemes(cls, schemes: dict[str, Any]) -> A2AAuthentication:
        """Derive the same shape from a 0.3 `securitySchemes` map.

        0.3 replaced the flat `authentication` object with a named map, and the
        scheme type is expressed two ways in the wild: OpenAPI style, where the
        entry carries `type`, and the proto-derived style, where the entry has a
        single key like `oauth2SecurityScheme`. Both appear on real cards, so
        both are read rather than guessing which a publisher used.
        """
        found: list[str] = []
        credentials: str | None = None
        for entry in schemes.values():
            if not isinstance(entry, dict):
                continue
            kind = entry.get("type")
            inner = entry
            if not kind:
                for key, value in entry.items():
                    if key.endswith("SecurityScheme") and isinstance(value, dict):
                        kind = key[: -len("SecurityScheme")]
                        inner = value
                        break
            if kind and kind not in found:
                found.append(kind)
            for url_field in ("tokenUrl", "openIdConnectUrl", "authorizationUrl"):
                if credentials is None and isinstance(inner.get(url_field), str):
                    credentials = inner[url_field]
            flows = inner.get("flows")
            if credentials is None and isinstance(flows, dict):
                for flow in flows.values():
                    if isinstance(flow, dict) and isinstance(flow.get("tokenUrl"), str):
                        credentials = flow["tokenUrl"]
                        break
        return cls(schemes=found, credentials=credentials)


@dataclass
class A2AAgentCard:
    """
    Google A2A Agent Card — the canonical agent description format.

    Fetched from: https://{domain}/.well-known/agent-card.json

    Attributes:
        name: Human-readable agent name.
        url: Agent's endpoint URL.
        version: Agent version string.
        description: Human-readable description.
        provider: Organization/provider info.
        skills: List of capabilities the agent offers.
        authentication: Auth requirements.
        default_input_modes: Default input formats (text, data, audio, video).
        default_output_modes: Default output formats.
        metadata: Additional fields not in the core schema.
    """

    name: str
    url: str
    version: str = "1.0.0"
    description: str | None = None
    provider: A2AProvider | None = None
    skills: list[A2ASkill] = field(default_factory=list)
    # --- 0.3 additions. All optional, so a 0.2 card parses unchanged. ---
    #: The card's own declared version, e.g. "0.3". Absent on 0.2 cards.
    protocol_version: str | None = None
    #: Transport for the main `url`, e.g. "JSONRPC" or "GRPC".
    preferred_transport: str | None = None
    #: Every other binding the agent offers. 0.3 calls this
    #: `additionalInterfaces`; 1.0 renamed it `supportedInterfaces` and folded
    #: the main url into it. Both are read, because cards in the wild carry
    #: either -- the Infoblox ddi-agent card declares protocolVersion 0.3 and
    #: uses the 1.0 name.
    interfaces: list[A2AInterface] = field(default_factory=list)
    #: streaming / pushNotifications / extendedAgentCard.
    capabilities: dict[str, Any] = field(default_factory=dict)
    #: Card-level JWS signatures (0.3 section 5.5.6). Carried, not verified here.
    signatures: list[dict[str, Any]] = field(default_factory=list)
    #: Whether an authenticated client can fetch a richer card. Top-level in
    #: 0.3, moved under capabilities in 1.0; either spelling sets this.
    supports_extended_card: bool = False
    icon_url: str | None = None
    documentation_url: str | None = None
    authentication: A2AAuthentication | None = None
    default_input_modes: list[str] = field(default_factory=lambda: ["text"])
    default_output_modes: list[str] = field(default_factory=lambda: ["text"])
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> A2AAgentCard:
        """Parse an Agent Card from JSON dict."""
        # Parse provider
        provider = None
        if "provider" in data and isinstance(data["provider"], dict):
            provider = A2AProvider(
                organization=data["provider"].get("organization", ""),
                url=data["provider"].get("url"),
            )

        # Parse skills
        skills = []
        if "skills" in data and isinstance(data["skills"], list):
            skills = [A2ASkill.from_dict(s) for s in data["skills"] if isinstance(s, dict)]

        # Parse authentication
        # 0.3 replaced `authentication` with `securitySchemes`. Prefer the newer
        # map when present -- a card carrying both (as the Infoblox ddi-agent
        # card does, for 0.2 compatibility) is describing the same requirement
        # twice, and the 0.3 form is the richer one.
        auth = None
        schemes = data.get("securitySchemes")
        if isinstance(schemes, dict) and schemes:
            auth = A2AAuthentication.from_security_schemes(schemes)
        if (auth is None or not auth.schemes) and isinstance(data.get("authentication"), dict):
            legacy = A2AAuthentication.from_dict(data["authentication"])
            # Keep a credentials URL the 0.3 map did not carry.
            if auth is not None and auth.credentials is None:
                legacy.schemes = auth.schemes or legacy.schemes
            auth = legacy

        # `additionalInterfaces` is the 0.3 name; `supportedInterfaces` is 1.0.
        raw_interfaces = data.get("additionalInterfaces")
        if not isinstance(raw_interfaces, list):
            raw_interfaces = data.get("supportedInterfaces")
        interfaces = [
            A2AInterface.from_dict(i)
            for i in (raw_interfaces or [])
            if isinstance(i, dict) and i.get("url")
        ]

        caps = data.get("capabilities") if isinstance(data.get("capabilities"), dict) else {}
        # Top-level in 0.3, relocated under capabilities in 1.0.
        extended = bool(
            data.get("supportsAuthenticatedExtendedCard")
            or data.get("supportsExtendedAgentCard")
            or caps.get("extendedAgentCard")
        )

        # Collect unknown fields as metadata
        known_keys = {
            "name",
            "url",
            "version",
            "description",
            "provider",
            "skills",
            "authentication",
            "defaultInputModes",
            "defaultOutputModes",
            # 0.3 / 1.0 keys now parsed into typed fields rather than metadata.
            "protocolVersion",
            "preferredTransport",
            "additionalInterfaces",
            "supportedInterfaces",
            "securitySchemes",
            "securityRequirements",
            "security",
            "capabilities",
            "signatures",
            "supportsAuthenticatedExtendedCard",
            "supportsExtendedAgentCard",
            "iconUrl",
            "documentationUrl",
        }
        metadata = {k: v for k, v in data.items() if k not in known_keys}

        return cls(
            name=data.get("name", ""),
            url=data.get("url", ""),
            version=data.get("version", "1.0.0"),
            description=data.get("description"),
            provider=provider,
            skills=skills,
            authentication=auth,
            default_input_modes=data.get("defaultInputModes", ["text"]),
            default_output_modes=data.get("defaultOutputModes", ["text"]),
            metadata=metadata,
            protocol_version=data.get("protocolVersion"),
            preferred_transport=data.get("preferredTransport"),
            interfaces=interfaces,
            capabilities=caps,
            signatures=[s for s in data.get("signatures", []) if isinstance(s, dict)],
            supports_extended_card=extended,
            icon_url=data.get("iconUrl"),
            documentation_url=data.get("documentationUrl"),
        )

    @classmethod
    def from_agent_record(cls, agent: AgentRecord) -> A2AAgentCard:
        """Convert a discovered DNS-AID A2A record into a public agent card model."""
        skills = [
            A2ASkill(
                id=capability,
                name=capability.replace("-", " ").replace("_", " ").title(),
                description=f"Capability: {capability}",
            )
            for capability in agent.capabilities
        ]
        return cls(
            name=agent.name,
            url=_origin_for_endpoint(agent.target_host, agent.port),
            version=agent.version,
            description=agent.description,
            skills=skills,
        )

    @property
    def skill_ids(self) -> list[str]:
        """Get list of skill IDs (convenience for capability matching)."""
        return [s.id for s in self.skills]

    @property
    def skill_names(self) -> list[str]:
        """Get list of skill names."""
        return [s.name for s in self.skills]

    def to_capabilities(self) -> list[str]:
        """Convert skills to DNS-AID capability format (skill IDs)."""
        return self.skill_ids

    def to_publish_params(
        self,
        domain: str,
        *,
        name: str | None = None,
        endpoint: str | None = None,
        port: int | None = None,
        ttl: int = 3600,
    ) -> dict[str, Any]:
        """Build keyword arguments for ``dns_aid.publish()`` from this card."""
        resolved_endpoint, resolved_port, cap_uri = _resolve_publish_endpoint(
            card_url=self.url,
            endpoint=endpoint,
            port=port,
        )
        return {
            "name": name or _sanitize_dns_label(self.name),
            "domain": domain,
            "protocol": "a2a",
            "endpoint": resolved_endpoint,
            "port": resolved_port,
            "capabilities": self.to_capabilities() or None,
            "version": self.version or "1.0.0",
            "description": self.description,
            "ttl": ttl,
            "cap_uri": cap_uri,
            # Bulk Agent Protocol — scalar versioned identifier per draft-02
            # §FutureWork. A2A agent cards default to "a2a=1.0"; operators
            # publishing a different version of A2A can override before passing
            # to publish().
            "bap": "a2a=1.0",
        }


async def fetch_agent_card(
    endpoint: str,
    timeout: float = 10.0,
) -> A2AAgentCard | None:
    """
    Fetch an A2A Agent Card from the well-known location.

    Given an agent endpoint (e.g., "https://agent.example.com"), fetches
    the Agent Card from "https://agent.example.com/.well-known/agent-card.json".

    Args:
        endpoint: Agent's base URL (scheme + host).
        timeout: HTTP request timeout in seconds.

    Returns:
        A2AAgentCard if successfully fetched and parsed, None otherwise.

    Example:
        >>> card = await fetch_agent_card("https://payment.example.com")
        >>> print(card.skills[0].name)
        "Process Payment"
    """
    # Construct the well-known URL
    if not endpoint.startswith("https://"):
        endpoint = f"https://{endpoint}"

    card_url = urljoin(endpoint.rstrip("/") + "/", A2A_AGENT_CARD_PATH.lstrip("/"))

    # SSRF protection: validate URL before fetching
    try:
        from dns_aid.utils.url_safety import UnsafeURLError, validate_fetch_url_async

        await validate_fetch_url_async(card_url)
    except UnsafeURLError as e:
        logger.warning("Agent Card URL blocked by SSRF protection", url=card_url, error=str(e))
        return None

    logger.debug("Fetching A2A Agent Card", url=card_url)

    try:
        from dns_aid.utils.url_safety import ResponseTooLargeError, safe_fetch_bytes

        body = await safe_fetch_bytes(
            card_url, max_bytes=_MAX_AGENT_CARD_RESPONSE_BYTES, timeout=timeout
        )
        if body is None:
            logger.debug("Agent Card fetch failed (non-200)", url=card_url)
            return None

        import json

        data = json.loads(body)

        if not isinstance(data, dict):
            logger.debug("Agent Card is not a JSON object", url=card_url)
            return None

        card = A2AAgentCard.from_dict(data)

        logger.debug(
            "Agent Card fetched successfully",
            url=card_url,
            name=card.name,
            skills_count=len(card.skills),
        )
        return card

    except ResponseTooLargeError:
        logger.warning(
            "Agent Card response too large — skipping",
            url=card_url,
            limit=_MAX_AGENT_CARD_RESPONSE_BYTES,
        )
        return None
    except httpx.TimeoutException:
        logger.debug("Agent Card fetch timed out", url=card_url)
        return None
    except httpx.ConnectError:
        logger.debug("Agent Card connection failed", url=card_url)
        return None
    except Exception as e:
        logger.debug("Agent Card fetch error", url=card_url, error=str(e))
        return None


async def fetch_agent_card_from_domain(
    domain: str,
    timeout: float = 10.0,
) -> A2AAgentCard | None:
    """
    Fetch an A2A Agent Card from a domain's well-known location.

    Convenience function that constructs the full URL from just a domain.

    Args:
        domain: Domain name (e.g., "example.com").
        timeout: HTTP request timeout in seconds.

    Returns:
        A2AAgentCard if successfully fetched and parsed, None otherwise.

    Example:
        >>> card = await fetch_agent_card_from_domain("example.com")
    """
    return await fetch_agent_card(f"https://{domain}", timeout=timeout)


async def publish_agent_card(
    card: A2AAgentCard,
    *,
    domain: str,
    name: str | None = None,
    endpoint: str | None = None,
    port: int | None = None,
    ttl: int = 3600,
    backend: DNSBackend | None = None,
) -> PublishResult:
    """Publish an A2A agent card through the existing DNS-AID publish entrypoint."""
    from dns_aid.core.publisher import publish

    publish_kwargs = card.to_publish_params(
        domain,
        name=name,
        endpoint=endpoint,
        port=port,
        ttl=ttl,
    )
    publish_kwargs["backend"] = backend
    return await publish(**publish_kwargs)


def _sanitize_dns_label(name: str) -> str:
    """Convert a human-readable name into a DNS-safe label."""
    label = name.lower().strip().replace(" ", "-").replace("_", "-")
    label = "".join(char for char in label if char.isalnum() or char == "-")
    label = label.strip("-")
    label = label[:_MAX_DNS_LABEL_LENGTH].rstrip("-")
    return label or "agent"


def _resolve_publish_endpoint(
    *,
    card_url: str,
    endpoint: str | None,
    port: int | None,
) -> tuple[str, int, str]:
    parsed = _parse_endpoint_url(card_url) if card_url else None
    resolved_port = port or 443
    resolved_endpoint = endpoint
    if resolved_endpoint is None and card_url:
        resolved_endpoint = parsed.hostname if parsed else ""
    if parsed and parsed.port and port is None:
        resolved_port = parsed.port

    if not resolved_endpoint:
        raise ValueError("endpoint must be provided or derivable from card.url")

    if endpoint is not None or port is not None:
        origin_source = resolved_endpoint
    else:
        origin_source = parsed.geturl() if parsed else resolved_endpoint

    origin = _origin_for_endpoint(origin_source, resolved_port)
    return (
        resolved_endpoint,
        resolved_port,
        urljoin(origin.rstrip("/") + "/", A2A_AGENT_CARD_PATH.lstrip("/")),
    )


def _parse_endpoint_url(url: str):
    candidate = url if "://" in url else f"https://{url}"
    return urlparse(candidate)


def _origin_for_endpoint(url_or_host: str, port: int) -> str:
    parsed = _parse_endpoint_url(url_or_host)
    hostname = parsed.hostname or url_or_host
    scheme = parsed.scheme or "https"
    default_port = 443 if scheme == "https" else 80
    effective_port = parsed.port or port
    port_suffix = "" if effective_port == default_port else f":{effective_port}"
    return f"{scheme}://{hostname}{port_suffix}"
