# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
HTTP Index discovery for ANS-style compatibility.

This module provides HTTP-based agent discovery as an alternative to pure DNS
discovery. It fetches agent indexes from well-known HTTP endpoints.

Two index document formats are auto-detected:

1. The legacy keyed-object "stakeholder" format
   (``{"agent-name": {"location": ..., "model-card": ..., "capability": ...}}``),
   served from ``/.well-known/agents-index.json`` / ``/.well-known/agents.json``
   or the ANS-style subdomain endpoints.
2. ARD ai-catalog manifests (https://agenticresourcediscovery.org/spec/) —
   ``{"specVersion": "1.0", "entries": [...]}`` — served from the ARD
   well-known location ``/.well-known/ai-catalog.json`` (or any of the
   probed endpoints). ARD CatalogEntry objects whose artifact type is an
   MCP server card or A2A agent card map to agents; inline nested catalogs
   recurse with depth and count guards; trustManifest data is preserved.

The HTTP index provides richer metadata than DNS TXT records, including
descriptions, model cards, capability details and (for ARD) trust manifests.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import unquote, urlparse

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
    # ARD ai-catalog well-known location (https://agenticresourcediscovery.org/spec/).
    # Appended LAST so legacy formats keep precedence when a domain serves both.
    {"type": "ard_well_known", "host": "{domain}", "path": "/.well-known/ai-catalog.json"},
]

# Default timeout for HTTP requests
DEFAULT_TIMEOUT = 10.0

# Bounds on an untrusted HTTP index. The index drives a fan-out of one
# SVCB + cap + JWKS chain per agent, so an unbounded document or agent list
# is a memory + amplification vector. A real index of a few hundred agents
# is well under 1 MB.
_MAX_HTTP_INDEX_BYTES = 1024 * 1024
_MAX_HTTP_INDEX_AGENTS = 500

# --- ARD ai-catalog constants (https://agenticresourcediscovery.org/spec/) ---

# The only specVersion value the ARD ai-catalog JSON Schema enumerates.
# Unknown versions are NOT treated as ARD documents (fail-safe fall-through
# to legacy parsing) — the spec defines no version-negotiation rules.
ARD_SPEC_VERSION = "1.0"

# CatalogEntry identifier pattern, verbatim from the ARD JSON Schema:
# urn:air:<publisher-fqdn>[:<namespace>...]:<agent-name>
_ARD_URN_RE = re.compile(r"^urn:air:[a-zA-Z0-9.-]+(:[a-zA-Z0-9._-]+)+$")

# Artifact media types that map to a dns-aid protocol. Entries with any
# other type (datasets, skills, ...) are not agents and are skipped.
_ARD_AGENT_MEDIA_TYPES = {
    "application/mcp-server-card+json": "mcp",
    "application/a2a-agent-card+json": "a2a",
}

# Nested catalog + registry media types (recognized so they can be
# recursed / skipped with a precise reason).
_ARD_CATALOG_MEDIA_TYPE = "application/ai-catalog+json"
_ARD_REGISTRY_MEDIA_TYPES = {"application/ai-registry+json", "application/ai-registry"}

# Inline nested catalogs recurse at most this deep. Nesting is legal per
# spec but unbounded recursion over an untrusted document is an attack
# vector; 3 levels covers real-world department/bundle structures.
_MAX_ARD_DEPTH = 3

# Total entries VISITED across all nesting levels. The agent cap only
# bounds *appended* agents — a catalog of thousands of invalid/registry
# entries would otherwise iterate (and, before aggregation, log) per
# entry. This bounds the work regardless of outcome. Well above any real
# catalog; well below the ~24k minimal entries that fit the 1 MB byte cap.
_MAX_ARD_ENTRIES = 5000

# Per-entry list caps (defense-in-depth beyond the document byte cap):
# one entry must not retain an unbounded capabilities[]/representativeQueries[]
# array on a single AgentRecord (memory amplification through serialization,
# telemetry, storage). Also bounds each retained string's length.
_MAX_ARD_LIST_ITEMS = 256
_MAX_ARD_STR_LEN = 1024

# Attacker-controlled identifiers are logged; truncate so an oversized or
# newline-laden identifier can't bloat or forge log lines.
_MAX_LOGGED_IDENTIFIER = 256


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
    # ARD ai-catalog transport fields (defaults keep legacy call sites valid).
    trust_manifest: dict[str, Any] | None = None  # raw trustManifest wire dict
    identifier: str | None = None  # full ARD URN (urn:air:...) for diagnostics
    source_format: str = "legacy"  # "legacy" | "ard"
    use_cases: list[str] = field(default_factory=list)  # ARD representativeQueries
    # ARD entry artifact locator (§3.4 Value-or-Reference). Per §4.2.1 the
    # identifier is an abstract name, NOT a network locator — the agent's real
    # endpoint lives in the referenced/inline card, resolved from exactly one of:
    card_url: str | None = None  # `url`: dereference to fetch the card
    card_data: dict[str, Any] | None = None  # `data`: the card given inline
    # Optional DNS-AID JWS over the (identifier→endpoint) binding, carried on an
    # ARD entry. When present it authenticates an off-domain catalog without
    # DNSSEC: the discoverer verifies it against the publisher domain's JWKS.
    sig: str | None = None
    # Populated by the discoverer (not the wire): the host that actually served
    # this agent's catalog over TLS — the trust anchor for the foreign-publisher
    # check. None on legacy/direct call sites (which fall back to the domain).
    served_host: str | None = None
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


def _is_ard_catalog(data: dict[str, Any]) -> bool:
    """Detect an ARD ai-catalog manifest by structural shape.

    Per the ARD JSON Schema the manifest root carries exactly
    ``specVersion`` (enum ["1.0"]), optional ``host``, and ``entries``
    (array). The legacy stakeholder format is a keyed object whose values
    are objects, so this shape cannot collide with it.
    """
    return data.get("specVersion") == ARD_SPEC_VERSION and isinstance(data.get("entries"), list)


def _protocol_from_media_type(media_type: str) -> str | None:
    """Map an ARD CatalogEntry artifact media type to a dns-aid protocol."""
    return _ARD_AGENT_MEDIA_TYPES.get(media_type)


def _name_from_urn(identifier: str) -> tuple[str | None, str | None]:
    """Extract (agent_name, publisher_domain) from an ARD ``urn:air:`` URN.

    The agent name is the URN's terminal segment normalized to a DNS
    label (lowercased; characters outside ``[a-z0-9-]`` become ``-``).
    Returns ``(None, None)`` when the identifier doesn't match the ARD
    URN pattern or normalization leaves nothing usable.
    """
    if not isinstance(identifier, str) or not _ARD_URN_RE.match(identifier):
        return None, None
    segments = identifier.split(":")  # ["urn", "air", publisher, ..., agent-name]
    publisher = segments[2].lower()
    # DNS labels cap at 63 octets — truncate before AgentRecord validation.
    name = re.sub(r"[^a-z0-9-]", "-", segments[-1].lower()).strip("-")[:63].strip("-")
    return (name or None), publisher


def _safe_log_str(value: Any) -> str:
    """Bound and de-newline an attacker-controlled value for logging.

    Prevents log flooding / forged-line injection from oversized or
    newline-laden identifiers when a non-JSON structlog renderer is used.
    """
    text = value if isinstance(value, str) else repr(value)
    text = text.replace("\n", "\\n").replace("\r", "\\r")
    if len(text) > _MAX_LOGGED_IDENTIFIER:
        text = text[:_MAX_LOGGED_IDENTIFIER] + "…"
    return text


def _ard_identity_domain(identity: str) -> str | None:
    """Extract the trust domain from an ARD trustManifest identity URI.

    Supports the three identity schemes the ARD spec names: SPIFFE ID
    (``spiffe://domain/...``), ``did:web`` (``did:web:domain[:path]``,
    RFC 3986 %-encoding for ports), and HTTPS FQDN URIs. Returns ``None``
    for other/unparseable schemes — callers must then skip alignment
    checking rather than guess.

    Uses ``urlparse().hostname`` (not ``netloc``) so userinfo cannot
    spoof the authority: ``spiffe://acme.com:1@evil.com`` resolves to
    ``evil.com``, not ``acme.com`` — otherwise the alignment check could
    be silenced by embedding the impersonated domain as a username.
    """
    if identity.startswith(("spiffe://", "https://")):
        host = urlparse(identity).hostname
        return host.strip(".") or None if host else None
    if identity.startswith("did:web:"):
        # did:web encodes ports as %3A and path segments as further colons.
        host = unquote(identity[len("did:web:") :].split(":")[0]).split(":")[0]
        host = host.lower().strip(".")
        return host or None
    return None


def _ard_domains_aligned(identity_domain: str, publisher: str) -> bool:
    """True when a trust-identity domain aligns with the URN publisher domain.

    Aligned means equal, or one is a subdomain of the other (a SPIFFE
    trust domain is typically the org apex while agents publish under
    sub-zones, and vice versa).
    """
    return (
        identity_domain == publisher
        or identity_domain.endswith("." + publisher)
        or publisher.endswith("." + identity_domain)
    )


def _truncate(text: str | None) -> str | None:
    """Bound a retained free-text string's length (defense-in-depth)."""
    if text is None:
        return None
    return text if len(text) <= _MAX_ARD_STR_LEN else text[:_MAX_ARD_STR_LEN]


def _ard_str_list(raw: Any) -> list[str]:
    """Coerce an ARD string array to a bounded, cleaned list.

    Caps both the number of items (``_MAX_ARD_LIST_ITEMS``) and each
    item's length so one entry can't retain an unbounded array on a
    single AgentRecord.
    """
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    for item in raw:
        if not item:
            continue
        out.append(str(item)[:_MAX_ARD_STR_LEN])
        if len(out) >= _MAX_ARD_LIST_ITEMS:
            break
    return out


def _ard_entry_to_agent(entry: dict[str, Any]) -> tuple[HttpIndexAgent | None, str | None]:
    """Map one ARD CatalogEntry (agent artifact type) to an HttpIndexAgent.

    Returns ``(agent, None)`` on success or ``(None, skip_reason)`` when
    the entry violates the ARD entry contract. Only called for entries
    whose ``type`` is an agent media type (MCP/A2A card).
    """
    identifier = entry.get("identifier")
    display_name = entry.get("displayName")
    entry_type = entry.get("type")
    if (
        not isinstance(identifier, str)
        or not isinstance(display_name, str)
        or not display_name
        or not isinstance(entry_type, str)
    ):
        return None, "missing_required"

    name, publisher = _name_from_urn(identifier)
    if not name or not publisher:
        return None, "invalid_urn"

    protocol = _protocol_from_media_type(entry_type)
    if protocol is None:  # caller filters, but keep the guard local too
        return None, "non_agent_artifact"

    # Value-or-Reference: exactly one of url / data must be present.
    url = entry.get("url")
    inline_data = entry.get("data")
    if (url is None) == (inline_data is None):
        return None, "locator_violation"
    if url is not None and not isinstance(url, str):
        return None, "locator_violation"

    # fqdn: host of the artifact URL when referenced; the URN's publisher
    # domain for inline artifacts. Never empty (parse keep-filter).
    # ``.hostname``/``.port`` reject userinfo spoofing and a malformed port
    # (e.g. ``https://h:notaport/x``) here as a clean per-entry skip —
    # otherwise the ValueError surfaces later in the DNS-fallback path and
    # the agent is dropped silently, violating skip-with-warning.
    if url:
        try:
            parsed = urlparse(url)
            _ = parsed.port  # forces validation; raises ValueError if malformed
        except ValueError:
            return None, "locator_violation"
        fqdn = (parsed.hostname or "").strip(".") or publisher
    else:
        fqdn = publisher

    description = _truncate(entry.get("description") or display_name)
    capabilities = _ard_str_list(entry.get("capabilities"))
    use_cases = _ard_str_list(entry.get("representativeQueries"))
    version = entry.get("version")
    trust_manifest = entry.get("trustManifest")
    # Optional DNS-AID JWS over the record binding (authenticates an off-domain
    # catalog without DNSSEC). Verified against the queried domain's JWKS.
    sig = entry.get("sig")

    capability = Capability(protocols=[protocol], capabilities=capabilities)
    model_card = ModelCard(
        description=description,
        version=version if isinstance(version, str) else None,
    )
    return (
        HttpIndexAgent(
            name=name,
            fqdn=fqdn,
            # ARD entries never declare a service endpoint directly; the real
            # endpoint is resolved from the card (card_url / card_data).
            endpoint=None,
            description=description,
            protocols=[protocol],
            model_card=model_card,
            capability=capability,
            trust_manifest=trust_manifest if isinstance(trust_manifest, dict) else None,
            identifier=identifier,
            source_format="ard",
            use_cases=use_cases,
            card_url=url if isinstance(url, str) else None,
            card_data=inline_data if isinstance(inline_data, dict) else None,
            sig=sig if isinstance(sig, str) else None,
        ),
        None,
    )


@dataclass
class _ArdParseState:
    """Shared, mutable accounting for one catalog parse (incl. nesting).

    ``entries_seen`` bounds total work regardless of per-entry outcome;
    ``skips`` aggregates skip reasons so a hostile all-invalid catalog
    produces ONE summary log line rather than thousands.
    """

    agents: list[HttpIndexAgent] = field(default_factory=list)
    entries_seen: int = 0
    skips: dict[str, int] = field(default_factory=dict)
    sample_ids: list[str] = field(default_factory=list)

    def skip(self, reason: str, identifier: Any) -> None:
        self.skips[reason] = self.skips.get(reason, 0) + 1
        if len(self.sample_ids) < 10 and identifier is not None:
            self.sample_ids.append(f"{reason}:{_safe_log_str(identifier)}")


def _parse_ard_catalog(data: dict[str, Any]) -> list[HttpIndexAgent]:
    """Parse an ARD ai-catalog manifest into HttpIndexAgent entries.

    Inline nested catalogs (``type == application/ai-catalog+json`` with
    ARD-shaped ``data``) recurse up to ``_MAX_ARD_DEPTH``; the agent
    count across ALL nesting levels shares the ``_MAX_HTTP_INDEX_AGENTS``
    budget and total entries visited share ``_MAX_ARD_ENTRIES``. Registry
    entries, non-agent artifacts, URL-only nested catalogs and malformed
    entries are skipped — one bad entry never fails the catalog, and skip
    reasons are aggregated into a single summary warning.
    """
    entries = data.get("entries")
    if not isinstance(entries, list):
        return []

    logger.info(
        "http_index.ard_catalog_detected",
        entry_count=len(entries),
        spec_version=data.get("specVersion"),
    )

    state = _ArdParseState()
    _ard_parse_into(data, state, depth=0)

    if state.skips:
        logger.warning(
            "http_index.ard_entries_skipped",
            skipped_total=sum(state.skips.values()),
            by_reason=dict(state.skips),
            samples=state.sample_ids,
        )
    logger.debug(
        "Parsed ARD catalog",
        agent_count=len(state.agents),
        entries_seen=state.entries_seen,
    )
    return state.agents


def _ard_parse_into(data: dict[str, Any], state: _ArdParseState, depth: int) -> None:
    """Recursive worker: accumulate agents into ``state`` from one level."""
    entries = data.get("entries")
    if not isinstance(entries, list):
        return

    for entry in entries:
        if len(state.agents) >= _MAX_HTTP_INDEX_AGENTS:
            state.skips["agent_cap_reached"] = state.skips.get("agent_cap_reached", 0) + 1
            return
        if state.entries_seen >= _MAX_ARD_ENTRIES:
            state.skips["entry_cap_reached"] = state.skips.get("entry_cap_reached", 0) + 1
            return
        state.entries_seen += 1

        if not isinstance(entry, dict):
            state.skip("missing_required", None)
            continue

        identifier = entry.get("identifier")
        entry_type = entry.get("type")

        # Nested catalogs: recurse when inline, skip when URL-referenced
        # (no chained fetches from a parse path — SSRF/latency posture).
        if entry_type == _ARD_CATALOG_MEDIA_TYPE:
            inline_data = entry.get("data")
            if isinstance(inline_data, dict) and _is_ard_catalog(inline_data):
                if depth >= _MAX_ARD_DEPTH:
                    state.skip("depth_exceeded", identifier)
                    continue
                _ard_parse_into(inline_data, state, depth=depth + 1)
            else:
                state.skip("nested_url_not_followed", identifier)
            continue

        # Registry endpoints (dynamic search APIs) are a separate future
        # feature — never mapped to agents.
        if entry_type in _ARD_REGISTRY_MEDIA_TYPES:
            state.skip("registry_entry", identifier)
            continue

        # Non-agent artifacts (datasets, skills, ...).
        if not isinstance(entry_type, str) or entry_type not in _ARD_AGENT_MEDIA_TYPES:
            state.skip("non_agent_artifact", identifier)
            continue

        agent, skip_reason = _ard_entry_to_agent(entry)
        if agent is None:
            state.skip(skip_reason or "unknown", identifier)
            continue
        state.agents.append(agent)


async def _fetch_and_parse(
    client: httpx.AsyncClient,
    url: str,
    errors: list[str],
    *,
    follow_redirects: bool = True,
) -> list[HttpIndexAgent] | None:
    """Fetch one URL under the byte cap and parse it, or record why it failed.

    Returns the parsed agents on HTTP 200 + valid JSON; ``None`` on any
    failure (appending a diagnostic to ``errors``). Never raises.

    ``follow_redirects=False`` is used for a DNS-pointer-resolved catalog URL:
    its host is attacker-influenceable (an SVCB target), and the pre-flight
    SSRF check only validated the pre-redirect host — following a redirect to
    an internal/metadata endpoint would bypass it. On a redirect the fetch is
    treated as a failure and discovery falls through to the well-known paths.
    """
    try:
        # Stream the body with a byte cap so a hostile endpoint can't
        # force an OOM — the oversized payload never fully lands in memory.
        async with client.stream("GET", url, follow_redirects=follow_redirects) as response:
            if response.is_redirect:
                errors.append(f"{url}: refused redirect to {response.headers.get('location', '?')}")
                logger.warning(
                    "http_index.redirect_refused",
                    url=url,
                    location=response.headers.get("location"),
                )
                return None
            if response.status_code != 200:
                if response.status_code == 404:
                    errors.append(f"{url}: Not found (404)")
                    logger.debug("HTTP index not found", url=url)
                else:
                    errors.append(f"{url}: HTTP {response.status_code}")
                    logger.warning(
                        "HTTP index request failed", url=url, status_code=response.status_code
                    )
                return None

            body = bytearray()
            too_large = False
            async for chunk in response.aiter_bytes():
                body.extend(chunk)
                if len(body) > _MAX_HTTP_INDEX_BYTES:
                    too_large = True
                    break
            if too_large:
                errors.append(f"{url}: response exceeds {_MAX_HTTP_INDEX_BYTES} bytes")
                logger.warning("HTTP index response too large", url=url, cap=_MAX_HTTP_INDEX_BYTES)
                return None

        data = json.loads(bytes(body))
        agents = parse_http_index(data)
        logger.info("HTTP index fetched successfully", url=url, agent_count=len(agents))
        return agents
    except httpx.TimeoutException:
        errors.append(f"{url}: Timeout")
        logger.warning("HTTP index request timed out", url=url)
    except httpx.ConnectError as e:
        errors.append(f"{url}: Connection error - {e}")
        logger.warning("HTTP index connection failed", url=url, error=str(e))
    except Exception as e:  # noqa: BLE001 — one bad endpoint must not abort the sweep
        errors.append(f"{url}: {e}")
        logger.warning("HTTP index request failed", url=url, error=str(e))
    return None


@dataclass
class HttpIndexResult:
    """Outcome of an HTTP-index / ARD catalog fetch.

    ``served_host`` is the host that actually returned the catalog over TLS
    (the DNS-pointer target or the well-known host) — the discoverer uses it as
    the trust anchor for the foreign-publisher check. ``catalog_trust`` records
    why the served catalog is trusted; it defaults to ``"tls_domain"`` (an
    on-domain / well-known fetch is bound to the domain by TLS) and is refined
    by the discoverer to ``"dnssec"`` / ``"jws"`` when it followed an
    authenticated off-domain pointer.
    """

    agents: list[HttpIndexAgent]
    served_host: str | None = None
    catalog_trust: str = "tls_domain"


def is_on_domain(host: str, domain: str) -> bool:
    """True when ``host`` is the queried ``domain`` or a subdomain of it.

    Label-boundary match (``host == domain`` or ``host`` ends with
    ``"." + domain``) — no public-suffix list needed. A TLS connection to such
    a host authenticates control within the queried domain's own namespace, so
    an on-domain catalog is trusted without DNSSEC or signatures. A host on any
    other registrable domain is off-domain.
    """
    host = host.lower().rstrip(".")
    domain = domain.lower().rstrip(".")
    return host == domain or host.endswith("." + domain)


def _host_of(url: str) -> str:
    """Best-effort host of a URL (lowercased, no port)."""
    return (urlparse(url).hostname or "").lower()


async def _fetch_index_cascade(
    domain: str,
    timeout: float,
    verify_ssl: bool,
    catalog_url: str | None,
) -> HttpIndexResult:
    """Fetch the first usable HTTP index / ARD catalog across the source cascade.

    Source order: the DNS-pointer ``catalog_url`` (if supplied) first, then the
    well-known ``HTTP_INDEX_PATTERNS``. The first source that returns a
    **non-empty** agent list wins. A source that returns HTTP 200 but zero
    usable agents (a valid-but-empty catalog) does NOT terminate the cascade —
    it is remembered and the search continues, so a stale/empty pointer or an
    empty legacy index can never shadow a real catalog further down. When every
    responding source is empty, that empty result is returned; when no source
    responds at all, ``HttpIndexError`` is raised.
    """
    domain = domain.lower().rstrip(".")
    errors: list[str] = []

    # TLS verification defaults on; the verify_ssl=False opt-out (dev/self-signed)
    # is audited with a structured warning.
    if not verify_ssl:
        logger.warning(
            "http_index.tls_verification_disabled",
            domain=domain,
            message=(
                "HTTP index fetched with TLS certificate verification DISABLED — "
                "only safe for test/development environments; do NOT use in production."
            ),
        )

    # Source cascade as (url, follow_redirects) pairs. The DNS-pointer catalog
    # host is attacker-influenceable and SSRF-validated pre-redirect only, so it
    # forbids redirects; the well-known patterns allow them.
    sources: list[tuple[str, bool]] = []
    if catalog_url:
        sources.append((catalog_url, False))
    for pattern in HTTP_INDEX_PATTERNS:
        host = pattern["host"].format(domain=domain)
        sources.append((f"https://{host}{pattern['path']}", True))

    empty_served_host: str | None = None

    async with httpx.AsyncClient(
        timeout=timeout,
        verify=verify_ssl,  # noqa: S501 — opt-out is gated by explicit caller-supplied kwarg; warning logged above
        follow_redirects=True,
        max_redirects=3,
    ) as client:
        for url, follow in sources:
            logger.debug("Trying HTTP index endpoint", url=url, follow_redirects=follow)
            agents = await _fetch_and_parse(client, url, errors, follow_redirects=follow)
            if agents is None:
                continue  # nothing served here — keep trying
            if agents:
                # First non-empty source wins.
                return HttpIndexResult(agents=agents, served_host=_host_of(url))
            # Valid HTTP 200 but zero usable agents: remember and keep searching
            # so an empty source cannot shadow a real catalog downstream (the
            # `[] is not None` fallback-shadowing bug).
            if empty_served_host is None:
                empty_served_host = _host_of(url)

    if empty_served_host is not None:
        logger.debug("HTTP index sources all empty", domain=domain)
        return HttpIndexResult(agents=[], served_host=empty_served_host)

    # No source responded at all.
    logger.warning("All HTTP index endpoints failed", domain=domain, errors=errors)
    raise HttpIndexError(f"No HTTP index found at {domain}. Tried: {', '.join(errors)}")


async def fetch_http_index(
    domain: str,
    timeout: float = DEFAULT_TIMEOUT,
    verify_ssl: bool = True,
    *,
    catalog_url: str | None = None,
) -> list[HttpIndexAgent]:
    """
    Fetch agent list from an HTTP index / ARD catalog endpoint.

    When ``catalog_url`` is supplied (typically resolved from a
    ``_catalog._agents`` / ``_index._agents`` DNS pointer) it is tried
    FIRST — DNS is authoritative for the catalog's location. Otherwise, and
    on pointer-fetch failure, the well-known ``HTTP_INDEX_PATTERNS`` are
    tried in order (legacy index locations, then the ARD well-known path).

    Returns the parsed ``HttpIndexAgent`` list. See
    :func:`fetch_http_index_result` for the richer form that also reports the
    served host. Raises ``HttpIndexError`` if no endpoint responds.
    """
    result = await _fetch_index_cascade(domain, timeout, verify_ssl, catalog_url)
    return result.agents


async def fetch_http_index_result(
    domain: str,
    timeout: float = DEFAULT_TIMEOUT,
    verify_ssl: bool = True,
    *,
    catalog_url: str | None = None,
) -> HttpIndexResult:
    """Like :func:`fetch_http_index` but also reports the served host + trust basis."""
    return await _fetch_index_cascade(domain, timeout, verify_ssl, catalog_url)


def parse_http_index(data: dict[str, Any]) -> list[HttpIndexAgent]:
    """
    Parse an HTTP index document into an HttpIndexAgent list.

    Auto-detects the document format:
    1. ARD ai-catalog manifest: {"specVersion": "1.0", "entries": [...]}
    2. Direct agent dict: {"agent-name": {...}}
    3. Nested under "agents" key: {"agents": {"agent-name": {...}}}

    Args:
        data: JSON data from HTTP index endpoint

    Returns:
        List of HttpIndexAgent objects
    """
    # ARD ai-catalog documents are structurally disjoint from the legacy
    # keyed-object format — detect and route before the legacy loop.
    if _is_ard_catalog(data):
        return _parse_ard_catalog(data)

    agents: list[HttpIndexAgent] = []

    # Handle nested "agents" key
    if "agents" in data and isinstance(data["agents"], dict):
        data = data["agents"]

    for name, agent_data in data.items():
        # Cap the number of agents taken from a single (untrusted) index so a
        # hostile document can't amplify into an unbounded discovery fan-out.
        if len(agents) >= _MAX_HTTP_INDEX_AGENTS:
            logger.warning(
                "HTTP index truncated — too many agents",
                cap=_MAX_HTTP_INDEX_AGENTS,
            )
            break

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
    *,
    catalog_url: str | None = None,
) -> list[HttpIndexAgent]:
    """
    Fetch HTTP index, returning empty list on failure.

    This is a convenience wrapper that doesn't raise exceptions,
    useful for fallback scenarios.

    Args:
        domain: Domain to fetch index from
        timeout: HTTP request timeout in seconds
        verify_ssl: Whether to verify SSL certificates
        catalog_url: Optional pre-resolved catalog URL (from a DNS pointer)
            tried before the well-known patterns.

    Returns:
        List of HttpIndexAgent objects (empty on failure)
    """
    try:
        return await fetch_http_index(domain, timeout, verify_ssl, catalog_url=catalog_url)
    except HttpIndexError:
        return []
    except Exception as e:
        logger.warning(
            "Unexpected error fetching HTTP index",
            domain=domain,
            error=str(e),
        )
        return []


async def fetch_http_index_result_or_empty(
    domain: str,
    timeout: float = DEFAULT_TIMEOUT,
    verify_ssl: bool = True,
    *,
    catalog_url: str | None = None,
) -> HttpIndexResult:
    """Like :func:`fetch_http_index_result` but returns an empty result on failure.

    Never raises — the fallback-friendly form used by the discoverer, which
    needs the served host alongside the agents.
    """
    try:
        return await fetch_http_index_result(domain, timeout, verify_ssl, catalog_url=catalog_url)
    except HttpIndexError:
        return HttpIndexResult(agents=[], served_host=None)
    except Exception as e:  # noqa: BLE001 — one bad index must not abort discovery
        logger.warning(
            "Unexpected error fetching HTTP index",
            domain=domain,
            error=str(e),
        )
        return HttpIndexResult(agents=[], served_host=None)
