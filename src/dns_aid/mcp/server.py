# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
DNS-AID MCP Server.

Provides MCP tools for AI agents to publish and discover other agents via DNS.
Uses the DNS-AID protocol (IETF draft-mozleywilliams-dnsop-dnsaid-02).

Usage:
    # Run with stdio transport (default for MCP)
    python -m dns_aid.mcp.server

    # Run with HTTP transport
    python -m dns_aid.mcp.server --transport http --port 8000

    # Or use the CLI
    dns-aid-mcp

Security Notes:
    - HTTP transport binds to 127.0.0.1 by default (use --host to override)
    - All inputs are validated before processing
    - For production HTTP deployment, use a reverse proxy (nginx, traefik)
"""

from __future__ import annotations

import asyncio
import logging
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Literal

# Configure logging BEFORE importing any dns_aid modules to ensure
# structlog outputs to stderr (not stdout) in MCP stdio mode.
# This prevents corruption of the JSON-RPC protocol.
logging.basicConfig(
    level=logging.WARNING,
    stream=sys.stderr,
    format="%(levelname)s: %(message)s",
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

import structlog  # noqa: E402

structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.dev.ConsoleRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
    cache_logger_on_first_use=True,
)

from mcp.server.fastmcp import FastMCP  # noqa: E402
from mcp.types import ToolAnnotations  # noqa: E402

from dns_aid.utils.validation import (  # noqa: E402
    ValidationError,
    validate_agent_name,
    validate_backend,
    validate_capabilities,
    validate_domain,
    validate_endpoint,
    validate_fqdn,
    validate_port,
    validate_protocol,
    validate_ttl,
    validate_version,
)

# Track server start time for uptime
_start_time = time.time()

# Shared thread pool for async operations (avoids creating pool per call)
_executor: ThreadPoolExecutor | None = None


def _get_executor() -> ThreadPoolExecutor:
    """Get or create shared thread pool executor."""
    global _executor
    if _executor is None:
        _executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="dns-aid-")
    return _executor


import atexit  # noqa: E402


def _shutdown_executor() -> None:
    global _executor
    if _executor is not None:
        _executor.shutdown(wait=False)
        _executor = None


atexit.register(_shutdown_executor)


# Initialize MCP server
mcp = FastMCP(
    "DNS-AID",
    json_response=True,
    instructions="""DNS-AID enables AI agents to discover and connect to other agents using DNS.

Use these tools to:
- Publish your agent to DNS so others can discover it
- Discover other agents at a domain
- Verify that an agent's DNS records are properly configured
- List all agents published at a domain

DNS-AID uses SVCB records (RFC 9460). Under draft-02 an agent's primary
record lives at the flat owner name {agent-name}.{domain}.

Example: chat.example.com""",
)


def _run_async(coro, timeout: float = 120):
    """
    Run async coroutine in sync context.

    When the MCP server runs in stdio transport mode, FastMCP invokes tool
    functions synchronously inside an event loop.  We bridge to async via a
    shared :class:`ThreadPoolExecutor` that runs ``asyncio.run(coro)`` in a
    worker thread.  Each worker gets its own fresh event loop, avoiding
    interference with the server's main loop.

    Args:
        coro: The async coroutine to run.
        timeout: Max seconds to wait for the result. Should match or exceed
                 the timeout passed to the underlying network call so the
                 thread pool does not abandon a still-in-flight request.
    """
    import concurrent.futures

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None:
        # We're in an async context, use the shared thread pool
        executor = _get_executor()
        future = executor.submit(asyncio.run, coro)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            raise TimeoutError(f"Operation did not complete within {timeout:.0f}s") from None
    else:
        return asyncio.run(coro)


def _get_dns_backend(name: str | None = None):
    """Get DNS backend instance by name, env var, or auto-detect.

    Resolution order:
      1. Explicit *name* parameter
      2. ``DNS_AID_BACKEND`` environment variable
      3. Auto-detect from configured credentials
      4. Falls back to mock backend with a warning
    """
    import os

    from dns_aid.backends import VALID_BACKEND_NAMES, create_backend
    from dns_aid.cli.backends import BACKEND_REGISTRY, detect_backend

    # Resolve name
    if not name:
        name = os.environ.get("DNS_AID_BACKEND")
    if not name:
        try:
            name = detect_backend()
        except ValueError:
            name = None
    if not name:
        return create_backend("mock")

    name = name.lower()

    if name not in VALID_BACKEND_NAMES:
        return create_backend("mock")

    info = BACKEND_REGISTRY.get(name)

    try:
        return create_backend(name)
    except ImportError as exc:
        dep = f"dns-aid[{info.optional_dep}]" if info and info.optional_dep else "dns-aid"
        display = info.display_name if info else name
        raise ValueError(
            f"Missing dependency for {display}: {exc}. Install with: pip install '{dep}'"
        ) from exc
    except (ValueError, OSError) as exc:
        setup = " → ".join(info.setup_steps) if info and info.setup_steps else ""
        display = info.display_name if info else name
        raise ValueError(f"Failed to initialize {display}: {exc}. Setup: {setup}") from exc


def _format_validation_error(e: ValidationError) -> dict:
    """Format validation error for API response."""
    return {
        "success": False,
        "error": "validation_error",
        "field": e.field,
        "message": e.message,
        "value": e.value,
    }


@mcp.tool(
    title="Publish Agent to DNS",
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
def publish_agent_to_dns(
    name: str,
    domain: str,
    protocol: Literal["mcp", "a2a"] = "mcp",
    endpoint: str | None = None,
    port: int = 443,
    capabilities: list[str] | None = None,
    version: str = "1.0.0",
    description: str | None = None,
    use_cases: list[str] | None = None,
    category: str | None = None,
    ttl: int = 3600,
    backend: Literal[
        "route53", "cloudflare", "ns1", "infoblox", "nios", "ddns", "mock"
    ] = "route53",
    update_index: bool = True,
    cap_uri: str | None = None,
    cap_sha256: str | None = None,
    well_known_path: str | None = None,
    bap: str | None = None,
    policy_uri: str | None = None,
    realm: str | None = None,
    connect_class: str | None = None,
    connect_meta: str | None = None,
    enroll_uri: str | None = None,
    ipv4_hint: list[str] | None = None,
    ipv6_hint: list[str] | None = None,
    allow_underscore_target: bool = False,
    publish_walkable_alias: bool = False,
) -> dict:
    """
    Publish an AI agent to DNS using DNS-AID protocol.

    Creates SVCB and TXT records that allow other agents to discover this agent.
    The agent will be discoverable at the flat draft-02 FQDN ``{name}.{domain}``
    (with an optional walkable AliasMode at ``{name}._agents.{domain}``).

    By default, also updates the domain's index record (_index._agents.{domain})
    to include this agent for efficient discovery.

    Args:
        name: Agent identifier (e.g., "chat", "network-specialist", "data-cleaner").
              Must be lowercase with hyphens only.
        domain: Domain to publish under (must have DNS control via Route53 or other backend).
        protocol: Communication protocol - "mcp" for Model Context Protocol or "a2a" for Agent-to-Agent.
        endpoint: Hostname where agent is reachable. Defaults to {protocol}.{domain}.
        port: Port number where agent listens (default: 443).
        capabilities: List of agent capabilities (e.g., ["chat", "code-review", "data-analysis"]).
        version: Agent version string (default: "1.0.0").
        description: Human-readable description of the agent.
        use_cases: List of use cases for this agent (e.g., ["Generate invoices", "Process refunds"]).
        category: Agent category (e.g., "network", "security", "finance", "chat").
        ttl: DNS record TTL in seconds (default: 3600).
        backend: DNS backend to use - "route53" for AWS Route53 or "mock" for testing.
        update_index: Whether to update the domain's agent index record (default: True).
        cap_uri: URI to capability document (DNS-AID draft-compliant, e.g.,
            "https://mcp.example.com/.well-known/agent-cap.json"). When set, the
            SVCB record will include a `cap` parameter pointing to a JSON document
            describing the agent's capabilities.
        cap_sha256: Base64url-encoded SHA-256 digest of the capability descriptor
            for integrity checks and cache revalidation. Included in the SVCB record
            as a `cap-sha256` parameter.
        well_known_path: RFC 8615 well-known path suffix (e.g., "agent-card.json")
            for the DNS-AID draft-02 `well-known` SvcParamKey. Independent of
            cap_uri; both may be set. Consumers prefer cap_uri when both are present
            and fall back to reconstructing
            https://<svcb-target>/.well-known/<well_known_path>.
        bap: Optional single versioned agent-protocol identifier (e.g.,
            "mcp=2.1", "a2a=1.0") for the Bulk Agent Protocol SvcParamKey.
            Experimental per draft-02 §FutureWork; alpn remains the canonical
            protocol carrier. Multi-protocol agents publish multiple records
            at the same flat owner, each with its own alpn and (optionally)
            bap — NOT as a list on one record.
        policy_uri: URI to agent policy document. Included in the SVCB record as
            a `policy` parameter.
        realm: Multi-tenant scope identifier (e.g., "production", "staging").
            Included in the SVCB record as a `realm` parameter.
        ipv4_hint: IPv4 address hints for SVCB record (RFC 9460 key 4).
            Eliminates extra A record lookup for the target hostname.
        ipv6_hint: IPv6 address hints for SVCB record (RFC 9460 key 6).
            Eliminates extra AAAA record lookup for the target hostname.
        allow_underscore_target: When True, downgrade a "TargetName contains
            underscored label" violation from an error to a warning. Per
            draft-mozleywilliams-dnsop-dnsaid-02 §3.2 (Known Organization, Unknown Agent), SVCB
            TargetNames reached over TLS with publicly-issued x.509 certs
            MUST NOT contain underscores. Set this only when the target is
            internal-only and will not be reached over public PKI.
        publish_walkable_alias: When True, additionally write the
            optional walkable AliasMode SVCB record at
            ``{name}._agents.{domain}`` pointing at the flat primary
            owner. Default False — the walkable record is an
            enumeration handle (a crawler can walk ``_agents.<zone>``
            and inventory every agent the operator publishes), which
            is undesirable for most deployments. Enable when you
            actively want the agent discoverable via enumeration:
            internal directories, intentional public catalogs, or
            DNS-SD-style consumers.

    Returns:
        dict with:
        - success: Whether publication succeeded
        - fqdn: The fully qualified domain name for the agent record
        - endpoint_url: The URL where the agent can be reached
        - records_created: List of DNS records that were created
        - index_updated: Whether the index record was updated
        - message: Status message
    """
    # Validate all inputs
    try:
        name = validate_agent_name(name)
        domain = validate_domain(domain)
        protocol = validate_protocol(protocol)
        port = validate_port(port)
        capabilities = validate_capabilities(capabilities)
        version = validate_version(version)
        ttl = validate_ttl(ttl)
        validate_backend(backend)

        if endpoint:
            endpoint = validate_endpoint(endpoint)
        else:
            endpoint = f"{protocol}.{domain}"

    except ValidationError as e:
        return _format_validation_error(e)

    from dns_aid.core.publisher import publish

    # Get backend
    dns_backend = _get_dns_backend(backend)

    async def _publish():
        return await publish(
            name=name,
            domain=domain,
            protocol=protocol,
            endpoint=endpoint,
            port=port,
            capabilities=capabilities,
            version=version,
            description=description,
            use_cases=use_cases,
            category=category,
            ttl=ttl,
            backend=dns_backend,
            cap_uri=cap_uri,
            cap_sha256=cap_sha256,
            well_known_path=well_known_path,
            bap=bap,
            policy_uri=policy_uri,
            realm=realm,
            connect_class=connect_class,
            connect_meta=connect_meta,
            enroll_uri=enroll_uri,
            ipv4_hint=ipv4_hint,
            ipv6_hint=ipv6_hint,
            allow_underscore_target=allow_underscore_target,
            publish_walkable_alias=publish_walkable_alias,
        )

    try:
        result = _run_async(_publish())

        index_updated = False
        index_message = None

        # Update index if requested and publish succeeded
        if result.success and update_index:
            from dns_aid.core.indexer import IndexEntry
            from dns_aid.core.indexer import update_index as do_update_index

            async def _update_index():
                return await do_update_index(
                    domain=domain,
                    backend=dns_backend,
                    add=[IndexEntry(name=name, protocol=protocol)],
                    ttl=ttl,
                )

            try:
                index_result = _run_async(_update_index())
                index_updated = index_result.success
                if index_result.success:
                    action = "Created" if index_result.created else "Updated"
                    index_message = f"{action} index with {len(index_result.entries)} agent(s)"
                else:
                    index_message = index_result.message
            except Exception as e:
                index_message = f"Index update failed: {e}"

        return {
            "success": result.success,
            "fqdn": result.agent.fqdn if result.agent else None,
            "endpoint_url": result.agent.endpoint_url if result.agent else None,
            "records_created": result.records_created,
            "index_updated": index_updated,
            "index_message": index_message,
            "message": result.message,
        }
    except Exception as e:
        return {
            "success": False,
            "error": "publish_error",
            "message": str(e),
        }


@mcp.tool(
    title="Discover Agents via DNS",
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
def discover_agents_via_dns(
    domain: str,
    protocol: Literal["mcp", "a2a"] | None = None,
    name: str | None = None,
    use_http_index: bool = False,
    capabilities: list[str] | None = None,
    capabilities_any: list[str] | None = None,
    auth_type: str | None = None,
    intent: Literal["query", "command", "transaction", "subscription"] | None = None,
    transport: str | None = None,
    realm: str | None = None,
    min_dnssec: bool = False,
    text_match: str | None = None,
    require_signed: bool = False,
    require_signature_algorithm: list[str] | None = None,
) -> dict:
    """
    Discover AI agents at any public domain using the DNS-AID protocol (no credentials needed).

    Discovery flow (DNS-only, default):
      1. Query the TXT index record at _index._agents.{domain} to get the list of
         published agent names and their protocols.
      2. For each agent in the index, query the SVCB record at the flat owner
         {name}.{domain} to resolve the target host, port, and ALPN protocol —
         plus DNS-AID custom params (cap, bap, policy, realm).
      3. If the SVCB record contains a `cap` param (URI to capability document),
         fetch the capability document via HTTPS for rich capability metadata.
      4. If the cap URI is missing or the fetch fails, fall back to querying the
         TXT record at the same FQDN for inline capabilities.
      5. Construct the full endpoint URL from the SVCB target and port.

    Discovery flow (HTTP index, when use_http_index=True):
      1. Fetch the agent index from the HTTP endpoint at
         https://index.aiagents.{domain}/index-wellknown (or well-known fallback).
      2. Parse the JSON index for agent names, protocols, and descriptions.
      3. For each agent, attempt a DNS SVCB lookup to resolve the authoritative
         endpoint. If the SVCB record exists, the endpoint is sourced from DNS;
         otherwise, the endpoint falls back to data from the HTTP index.
      4. Return all agents with their resolved endpoints and metadata.

    Args:
        domain: Domain to search for agents (e.g., "example.com", "salesforce.com").
        protocol: Filter by protocol - "mcp" or "a2a". If None, discovers all protocols.
        name: Filter by agent name (e.g., "chat", "network"). If None, discovers all agents.
        use_http_index: If True, fetch agent list from the HTTP index endpoint
            instead of DNS-only discovery. The HTTP index provides richer metadata
            (descriptions, capabilities) upfront. Default False (pure DNS).

    Returns:
        dict with:
        - domain: The domain that was queried
        - query: The DNS query name (e.g., "_index._agents.example.com") or
          HTTP URL that was used for discovery
        - discovery_method: "dns" (pure DNS via TXT+SVCB) or "http_index"
          (HTTP index with optional DNS SVCB enrichment)
        - agents: List of discovered agents, each with:
            - name: Agent identifier (e.g., "booking", "chat")
            - protocol: Communication protocol ("mcp" or "a2a")
            - endpoint: Full URL to reach the agent (e.g., "https://booking.example.com:443")
            - endpoint_source: How the endpoint was resolved:
                "dns_svcb" = from DNS SVCB record (authoritative),
                "http_index_fallback" = from HTTP index (no SVCB record found),
                "constructed" = built from DNS target host and port
            - capabilities: List of agent capabilities (e.g., ["travel", "booking"])
            - capability_source: Where capabilities came from:
                "cap_uri" = fetched from SVCB cap parameter URI,
                "txt_fallback" = parsed from TXT record,
                "none" = no capabilities found
            - cap_uri: URI to capability document (if present in SVCB record)
            - bap: Supported bulk agent protocols (if present in SVCB record)
            - policy_uri: URI to agent policy document (if present in SVCB record)
            - realm: Multi-tenant scope identifier (if present in SVCB record)
            - description: Human-readable agent description (if available)
            - fqdn: Fully qualified DNS name for this agent
              (e.g., "booking.example.com")
        - count: Number of agents found
        - query_time_ms: Total discovery latency in milliseconds
    """
    # Validate inputs
    try:
        domain = validate_domain(domain)
        if protocol:
            protocol = validate_protocol(protocol)
        if name:
            name = validate_agent_name(name)
    except ValidationError as e:
        return _format_validation_error(e)

    from dns_aid.core.discoverer import discover

    async def _discover():
        return await discover(
            domain=domain,
            protocol=protocol,
            name=name,
            use_http_index=use_http_index,
            capabilities=capabilities,
            capabilities_any=capabilities_any,
            auth_type=auth_type,
            intent=intent,
            transport=transport,
            realm=realm,
            min_dnssec=min_dnssec,
            text_match=text_match,
            require_signed=require_signed,
            require_signature_algorithm=require_signature_algorithm,
        )

    try:
        result = _run_async(_discover())

        return {
            "domain": result.domain,
            "query": result.query,
            "discovery_method": "http_index" if use_http_index else "dns",
            "agents": [
                {
                    "name": agent.name,
                    "protocol": agent.protocol.value,
                    "endpoint": agent.endpoint_url,
                    "endpoint_source": agent.endpoint_source,
                    "capabilities": agent.capabilities,
                    "capability_source": agent.capability_source,
                    "cap_uri": agent.cap_uri,
                    "cap_sha256": agent.cap_sha256,
                    "well_known_path": agent.well_known_path,
                    "bap": agent.bap,
                    "policy_uri": agent.policy_uri,
                    "realm": agent.realm,
                    "description": agent.description,
                    "fqdn": agent.fqdn,
                }
                for agent in result.agents
            ],
            "count": result.count,
            "query_time_ms": result.query_time_ms,
        }
    except Exception as e:
        return {
            "success": False,
            "error": "discover_error",
            "message": str(e),
        }


@mcp.tool(
    title="Search Agents via Directory",
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
def search_agents(
    q: str | None = None,
    protocol: Literal["mcp", "a2a", "https"] | None = None,
    domain: str | None = None,
    capabilities: list[str] | None = None,
    min_security_score: int | None = None,
    verified_only: bool = False,
    intent: Literal["query", "command", "transaction", "subscription"] | None = None,
    auth_type: str | None = None,
    transport: str | None = None,
    realm: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> dict:
    """
    Cross-domain agent search via the configured DNS-AID directory backend (Path B).

    Use this tool when:
      - You don't yet know which domain hosts the agent you want.
      - You need to find agents by capability, intent, or auth type across many domains.
      - You want ranked results with pre-computed trust scores so you can decide
        whether to invoke directly or re-verify cryptographically via DNS first.

    Requires the directory backend to be configured server-side
    (``DNS_AID_SDK_DIRECTORY_API_URL``). If not configured, returns a structured
    ``directory_not_configured`` error so the caller can fall back to per-domain
    ``discover_agents_via_dns`` calls.

    Args:
        q: Free-text query (e.g., "payment processing"). Omit to browse with filters only.
        protocol: Restrict to a protocol (``mcp`` / ``a2a`` / ``https``).
        domain: Restrict to a single domain.
        capabilities: All-of capability match — every entry must be present on the agent.
        min_security_score: Minimum security score (0–100). Higher = stricter.
        verified_only: Restrict to DCV-verified domains only.
        intent: Filter by action intent (query / command / transaction / subscription).
        auth_type: Filter by auth type (``oauth2``, ``api_key``, ``bearer``, ``mtls``,
            ``http_msg_sig``, etc.).
        transport: Filter by transport (``streamable-http``, ``https``, ``sse``, ``stdio``).
        realm: Filter by realm (multi-tenant scoping identifier).
        limit: Page size (1–10000). Default 20.
        offset: Pagination offset.

    Returns:
        Success: ``{"success": True, "results": [...], "total": int, "limit": int,
        "offset": int, "has_more": bool}`` where each result carries the agent payload,
        relevance ``score``, ``trust`` attestation (security/trust scores, tier badge,
        sub-scores), and optional ``provenance`` (crawler attribution).

        Failure: ``{"success": False, "error": "<class>", "message": "...", "details": {...}}``
        with structured error class — never raises. Error classes:
          - ``directory_not_configured`` (configuration; not transient)
          - ``directory_unavailable`` (transient; retry with backoff recommended)
          - ``directory_rate_limited`` (transient; honor ``retry_after_seconds``)
          - ``directory_auth_failed`` (auth; review credentials)
          - ``invalid_arguments`` (caller-supplied args failed schema validation)

    Composition pattern (zero-trust):

        1. Call ``search_agents`` for cross-domain candidates.
        2. For each result, call ``discover_agents_via_dns`` with that agent's domain
           and name to re-verify endpoint authority via DNS substrate before invoking.
        3. Use ``call_agent_tool`` only against the verified subset.
    """
    from dns_aid.sdk import (
        AgentClient,
        DirectoryAuthError,
        DirectoryConfigError,
        DirectoryRateLimitedError,
        DirectoryUnavailableError,
    )

    async def _do_search() -> dict:
        async with AgentClient() as client:
            response = await client.search(
                q=q,
                protocol=protocol,
                domain=domain,
                capabilities=capabilities,
                min_security_score=min_security_score,
                verified_only=verified_only,
                intent=intent,
                auth_type=auth_type,
                transport=transport,
                realm=realm,
                limit=limit,
                offset=offset,
            )
            return {
                "success": True,
                "results": [
                    {
                        "agent": r.agent.model_dump(mode="json"),
                        "score": r.score,
                        "trust": r.trust.model_dump(mode="json"),
                        "provenance": r.provenance.model_dump(mode="json")
                        if r.provenance is not None
                        else None,
                    }
                    for r in response.results
                ],
                "total": response.total,
                "limit": response.limit,
                "offset": response.offset,
                "has_more": response.has_more,
            }

    try:
        return _run_async(_do_search())
    except DirectoryConfigError as exc:
        return {
            "success": False,
            "error": "directory_not_configured",
            "message": str(exc),
            "details": exc.details,
            "remediation": "Set DNS_AID_SDK_DIRECTORY_API_URL or configure SDKConfig.directory_api_url.",
        }
    except DirectoryRateLimitedError as exc:
        return {
            "success": False,
            "error": "directory_rate_limited",
            "message": str(exc),
            "details": exc.details,
            "transient": True,
            "retry_recommended": True,
        }
    except DirectoryAuthError as exc:
        return {
            "success": False,
            "error": "directory_auth_failed",
            "message": str(exc),
            "details": exc.details,
            "remediation": "Verify the SDK auth handler configuration for the directory backend.",
        }
    except DirectoryUnavailableError as exc:
        return {
            "success": False,
            "error": "directory_unavailable",
            "message": str(exc),
            "details": exc.details,
            "transient": True,
            "retry_recommended": True,
        }
    except ValidationError as exc:
        return {
            "success": False,
            "error": "invalid_arguments",
            "validation_errors": _format_validation_error(exc),
        }


@mcp.tool(
    title="Call Agent Tool",
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True,
    ),
)
def call_agent_tool(
    endpoint: str,
    tool_name: str,
    arguments: dict | None = None,
    policy_uri: str | None = None,
    auth_type: str | None = None,
    auth_config: dict | None = None,
    credentials: dict | None = None,
) -> dict:
    """
    Call a tool on a discovered MCP agent.

    Use this after discovering agents to invoke their tools. First use
    discover_agents_via_dns to find agents and get their endpoints.

    Args:
        endpoint: The agent's MCP endpoint URL (e.g., "https://booking.example.com/mcp").
        tool_name: Name of the tool to call on the remote agent.
        arguments: Arguments to pass to the tool (as a dictionary).
        policy_uri: The target agent's policy document URL (from discovery).
                    If provided, policy is checked before invocation.
        auth_type: Authentication method required by the agent (from discovery).
                   E.g., "oauth2", "bearer", "api_key", "http_msg_sig".
        auth_config: Authentication configuration from the agent's metadata
                     (token_endpoint, header_name, etc.). From discovery.
        credentials: Caller-supplied secrets (tokens, client_id/secret)
                     for authenticating with the target agent.

    Returns:
        dict with:
        - success: Whether the call succeeded
        - result: The tool's response content
        - telemetry: Invocation telemetry (latency, status) when SDK is available
        - policy: Policy check result when policy_uri is provided
        - error: Error message if failed
    """
    from dns_aid.core.invoke import call_mcp_tool
    from dns_aid.sdk.policy.guard import check_target_policy

    try:
        # Policy guard: check target's policy before invocation
        policy_result = _run_async(
            check_target_policy(
                policy_uri,
                protocol="mcp",
                method=f"tools/call:{tool_name}",
                caller_id="dns-aid-mcp-server",
            ),
            timeout=10,
        )
        if policy_result.denied:
            import os

            mode = os.getenv("DNS_AID_POLICY_MODE", "permissive")
            if mode == "strict":
                return {
                    "success": False,
                    "error": f"Policy denied: {policy_result.reason}",
                    "policy": {
                        "result": "denied",
                        "violations": [
                            {"rule": v.rule, "detail": v.detail} for v in policy_result.violations
                        ],
                    },
                }

        result = _run_async(
            call_mcp_tool(
                endpoint,
                tool_name,
                arguments,
                caller_id="dns-aid-mcp-server",
                credentials=credentials,
                auth_type=auth_type,
                auth_config=auth_config,
                policy_uri=policy_uri,
            ),
            timeout=90,
        )
        response: dict = {"success": result.success}
        if result.success:
            response["result"] = result.data
        else:
            response["error"] = result.error or "Invocation failed"
        if result.telemetry:
            response["telemetry"] = result.telemetry
        if policy_uri:
            response["policy"] = {
                "result": "allowed" if policy_result.allowed else "denied",
            }
        return response
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool(
    title="List Agent Tools",
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
def list_agent_tools(endpoint: str) -> dict:
    """
    List available tools on a discovered MCP agent.

    Use this to see what tools an agent provides before calling them.

    Args:
        endpoint: The agent's MCP endpoint URL (e.g., "https://booking.example.com/mcp").

    Returns:
        dict with:
        - success: Whether the call succeeded
        - tools: List of available tools with name, description, and input schema
        - telemetry: Invocation telemetry (latency, status) when SDK is available
        - error: Error message if failed
    """
    from dns_aid.core.invoke import list_mcp_tools

    try:
        result = _run_async(
            list_mcp_tools(endpoint, caller_id="dns-aid-mcp-server"),
            timeout=60,
        )
        tools = result.data if result.success and isinstance(result.data, list) else []
        response: dict = {
            "success": result.success,
            "tools": tools,
            "count": len(tools),
        }
        if result.telemetry:
            response["telemetry"] = result.telemetry
        if not result.success:
            response["error"] = result.error or "Invocation failed"
        return response
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool(
    title="Verify Agent DNS Records",
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
def verify_agent_dns(fqdn: str) -> dict:
    """
    Verify DNS-AID records for an agent.

    Checks DNS record existence, SVCB validity, DNSSEC validation, DANE/TLSA
    configuration, and endpoint reachability. Returns a security score.

    Args:
        fqdn: Fully qualified domain name of the agent record.
              Under draft-02 this is the flat owner {agent-name}.{domain}.
              Example: "chat.example.com"

    Returns:
        dict with:
        - fqdn: The FQDN that was verified
        - record_exists: Whether the DNS record exists
        - svcb_valid: Whether the SVCB record is properly formatted
        - dnssec_valid: Whether DNSSEC validation passed (None if not checked)
        - dane_valid: Whether DANE/TLSA is configured (None if not checked)
        - endpoint_reachable: Whether the endpoint responds
        - endpoint_latency_ms: Response latency if reachable
        - security_score: Score from 0-100
        - security_rating: Human-readable rating (Excellent, Good, Fair, Poor)
    """
    # Validate inputs
    try:
        fqdn = validate_fqdn(fqdn)
    except ValidationError as e:
        return _format_validation_error(e)

    from dns_aid.core.validator import verify

    async def _verify():
        return await verify(fqdn)

    try:
        result = _run_async(_verify())

        return {
            "fqdn": result.fqdn,
            "record_exists": result.record_exists,
            "svcb_valid": result.svcb_valid,
            "dnssec_valid": result.dnssec_valid,
            "dane_valid": result.dane_valid,
            "endpoint_reachable": result.endpoint_reachable,
            "endpoint_latency_ms": result.endpoint_latency_ms,
            "security_score": result.security_score,
            "security_rating": result.security_rating,
        }
    except Exception as e:
        return {
            "success": False,
            "error": "verify_error",
            "message": str(e),
        }


@mcp.tool(
    title="List Published Agents",
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
def list_published_agents(
    domain: str,
    backend: Literal[
        "route53", "cloudflare", "ns1", "infoblox", "nios", "ddns", "mock"
    ] = "route53",
) -> dict:
    """
    List all agents published at a domain you manage via DNS-AID.

    This tool requires backend API credentials (e.g., AWS keys for Route53,
    API key for Infoblox). Use this only for domains you own and have
    configured backend access for.

    To discover agents at any public domain (no credentials needed), use
    discover_agents_via_dns instead.

    Args:
        domain: Domain you manage (e.g., "example.com").
        backend: DNS backend to use - requires matching API credentials configured.

    Returns:
        dict with:
        - domain: The domain that was queried
        - records: List of DNS-AID records found, each with:
            - fqdn: Full record name
            - type: Record type (SVCB, TXT)
            - ttl: Time-to-live
            - value: Record value
        - count: Number of records found
    """
    # Validate inputs
    try:
        domain = validate_domain(domain)
        validate_backend(backend)
    except ValidationError as e:
        return _format_validation_error(e)

    # Get backend
    dns_backend = _get_dns_backend(backend)

    async def _list():
        if not await dns_backend.zone_exists(domain):
            return None  # sentinel: zone not found
        records = []
        async for record in dns_backend.list_records(domain, name_pattern="_agents"):
            records.append(record)
        return records

    try:
        records = _run_async(_list())

        if records is None:
            return {
                "success": False,
                "error": "zone_not_found",
                "message": f"Zone '{domain}' does not exist or is not accessible",
            }

        formatted_records = []
        for record in records:
            value = record.get("values", [])
            if isinstance(value, list):
                value = value[0] if value else ""
            formatted_records.append(
                {
                    "fqdn": record["fqdn"],
                    "type": record["type"],
                    "ttl": record["ttl"],
                    "value": str(value)[:100] + "..." if len(str(value)) > 100 else str(value),
                }
            )

        return {
            "domain": domain,
            "records": formatted_records,
            "count": len(formatted_records),
        }
    except Exception as e:
        return {
            "success": False,
            "error": "list_error",
            "message": str(e),
        }


@mcp.tool(
    title="Delete Agent from DNS",
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=True,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
def delete_agent_from_dns(
    name: str,
    domain: str,
    protocol: Literal["mcp", "a2a"] = "mcp",
    backend: Literal[
        "route53", "cloudflare", "ns1", "infoblox", "nios", "ddns", "mock"
    ] = "route53",
    update_index: bool = True,
) -> dict:
    """
    Delete an agent from DNS.

    Removes SVCB and TXT records for the specified agent.
    By default, also removes the agent from the domain's index record.

    Args:
        name: Agent identifier to delete.
        domain: Domain where agent is published.
        protocol: Protocol the agent was published with.
        backend: DNS backend to use.
        update_index: Whether to remove agent from domain's index record (default: True).

    Returns:
        dict with:
        - success: Whether deletion succeeded
        - fqdn: The FQDN that was deleted
        - index_updated: Whether the index record was updated
        - message: Status message
    """
    # Validate inputs
    try:
        name = validate_agent_name(name)
        domain = validate_domain(domain)
        protocol = validate_protocol(protocol)
        validate_backend(backend)
    except ValidationError as e:
        return _format_validation_error(e)

    from dns_aid.core.publisher import unpublish

    # Get backend
    dns_backend = _get_dns_backend(backend)

    async def _unpublish():
        return await unpublish(
            name=name,
            domain=domain,
            protocol=protocol,
            backend=dns_backend,
        )

    try:
        result = _run_async(_unpublish())
        fqdn = f"{name}.{domain}"

        index_updated = False
        index_message = None

        # Update index if requested and delete succeeded
        if result and update_index:
            from dns_aid.core.indexer import IndexEntry
            from dns_aid.core.indexer import update_index as do_update_index

            async def _update_index():
                return await do_update_index(
                    domain=domain,
                    backend=dns_backend,
                    remove=[IndexEntry(name=name, protocol=protocol)],
                )

            try:
                index_result = _run_async(_update_index())
                index_updated = index_result.success
                if index_result.success:
                    index_message = f"Updated index: {len(index_result.entries)} agent(s) remaining"
                else:
                    index_message = index_result.message
            except Exception as e:
                index_message = f"Index update failed: {e}"

        return {
            "success": result,
            "fqdn": fqdn,
            "index_updated": index_updated,
            "index_message": index_message,
            "message": "Agent deleted successfully" if result else "No records found to delete",
        }
    except Exception as e:
        return {
            "success": False,
            "error": "delete_error",
            "message": str(e),
        }


@mcp.tool(
    title="List Agent Index",
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
def list_agent_index(
    domain: str,
    backend: Literal[
        "route53", "cloudflare", "ns1", "infoblox", "nios", "ddns", "mock"
    ] = "route53",
) -> dict:
    """
    List agents in a domain's index record.

    Reads the _index._agents.{domain} TXT record and returns all indexed agents.
    This is useful for seeing what agents are published at a domain.

    Args:
        domain: Domain to list index from.
        backend: DNS backend to use.

    Returns:
        dict with:
        - domain: The domain queried
        - agents: List of indexed agents with name and protocol
        - count: Number of agents in the index
        - index_exists: Whether an index record was found
    """
    # Validate inputs
    try:
        domain = validate_domain(domain)
        validate_backend(backend)
    except ValidationError as e:
        return _format_validation_error(e)

    from dns_aid.core.indexer import read_index

    # Get backend
    dns_backend = _get_dns_backend(backend)

    async def _read_index():
        return await read_index(domain, dns_backend)

    try:
        entries = _run_async(_read_index())

        return {
            "domain": domain,
            "agents": [
                {
                    "name": entry.name,
                    "protocol": entry.protocol,
                    "fqdn": f"{entry.name}.{domain}",
                }
                for entry in entries
            ],
            "count": len(entries),
            "index_exists": len(entries) > 0,
        }
    except Exception as e:
        return {
            "success": False,
            "error": "list_index_error",
            "message": str(e),
        }


@mcp.tool(
    title="Sync Agent Index",
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
def sync_agent_index(
    domain: str,
    backend: Literal[
        "route53", "cloudflare", "ns1", "infoblox", "nios", "ddns", "mock"
    ] = "route53",
    ttl: int = 3600,
) -> dict:
    """
    Sync domain's agent index with actual DNS records.

    Scans DNS for all _agents.* SVCB records and updates the index
    to reflect what's actually published.

    Args:
        domain: Domain to sync index for.
        backend: DNS backend to use.
        ttl: TTL for the index record.

    Returns:
        dict with:
        - success: Whether sync succeeded
        - domain: The domain synced
        - agents: List of agents now in the index
        - count: Number of agents found
        - created: Whether the index was newly created
        - message: Status message
    """
    # Validate inputs
    try:
        domain = validate_domain(domain)
        validate_backend(backend)
        ttl = validate_ttl(ttl)
    except ValidationError as e:
        return _format_validation_error(e)

    from dns_aid.core.indexer import sync_index

    # Get backend
    dns_backend = _get_dns_backend(backend)

    async def _sync_index():
        if not await dns_backend.zone_exists(domain):
            return None  # sentinel: zone not found
        return await sync_index(domain, dns_backend, ttl=ttl)

    try:
        result = _run_async(_sync_index())

        if result is None:
            return {
                "success": False,
                "error": "zone_not_found",
                "message": f"Zone '{domain}' does not exist or is not accessible",
            }

        return {
            "success": result.success,
            "domain": domain,
            "agents": [
                {
                    "name": entry.name,
                    "protocol": entry.protocol,
                }
                for entry in result.entries
            ],
            "count": len(result.entries),
            "created": result.created,
            "message": result.message,
        }
    except Exception as e:
        return {
            "success": False,
            "error": "sync_index_error",
            "message": str(e),
        }


# =============================================================================
# POLICY COMPILATION TOOLS
# =============================================================================


@mcp.tool(
    title="Compile Policy to RPZ",
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
def compile_policy_to_rpz(
    policy_json: str,
    format: str = "both",
) -> dict:
    """
    Compile a policy document to RPZ and/or bind-aid zone files.

    Takes a PolicyDocument as JSON and produces DNS zone content that can be
    loaded into RPZ-capable resolvers (standard) or bind-aid (Ingmar's BIND 9
    fork with per-record policy actions).

    Args:
        policy_json: A PolicyDocument as a JSON string. Must include "agent"
            (FQDN) and "rules" with policy rule definitions such as
            blocked_caller_domains, allowed_caller_domains, required_protocols,
            and/or cel_rules.
        format: Output format - "rpz" for standard RPZ only, "bindaid" for
            bind-aid only, or "both" (default) for both formats.

    Returns:
        dict with:
        - success: Whether compilation succeeded
        - rpz_zone: The RPZ zone file content (if format is "rpz" or "both")
        - bindaid_zone: The bind-aid zone file content (if format is "bindaid" or "both")
        - report: Compilation summary with directive counts and skipped rules
        - error: Error message if failed
    """
    import json

    from dns_aid.sdk.policy.bindaid_writer import write_bindaid_zone
    from dns_aid.sdk.policy.compiler import PolicyCompiler
    from dns_aid.sdk.policy.rpz_writer import write_rpz_zone
    from dns_aid.sdk.policy.schema import PolicyDocument

    if format not in ("rpz", "bindaid", "both"):
        return {"success": False, "error": f"Invalid format: {format}. Use rpz, bindaid, or both."}

    try:
        doc = PolicyDocument.model_validate(json.loads(policy_json))
    except Exception as e:
        return {"success": False, "error": f"Failed to parse policy document: {e}"}

    compiler = PolicyCompiler()
    result = compiler.compile(doc)

    response: dict = {"success": True}

    zone_name_base = doc.agent.split(".")[-2] if "." in doc.agent else "policy"

    if format in ("rpz", "both"):
        response["rpz_zone"] = write_rpz_zone(result, f"rpz.{zone_name_base}.policy")
    if format in ("bindaid", "both"):
        response["bindaid_zone"] = write_bindaid_zone(result, f"policy.{zone_name_base}.bindaid")

    response["report"] = {
        "agent_fqdn": result.agent_fqdn,
        "rpz_directives": len(result.rpz_directives),
        "bindaid_directives": len(result.bindaid_directives),
        "skipped": [{"rule": s.rule_name, "reason": s.reason} for s in result.skipped],
        "warnings": result.warnings,
    }

    return response


@mcp.tool(
    title="Publish RPZ Zone",
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
def publish_rpz_zone(
    policy_json: str,
    backend: Literal["route53", "cloudflare", "ns1", "infoblox", "nios", "ddns", "mock"],
    rpz_zone: str,
    td_action: str = "action_block",
    td_policy_id: int | None = None,
) -> dict:
    """
    Compile a policy and push RPZ records to a DNS backend.

    For Infoblox (BloxOne): creates a TD named list, binds it to a security
    policy with the specified action (block, log, allow, redirect).
    For NIOS: creates ``record:rpz:cname`` entries via WAPI.
    For other backends: returns the compiled zone content for manual loading.

    Args:
        policy_json: A PolicyDocument as a JSON string.
        backend: DNS backend — "infoblox" for BloxOne TD (recommended),
            "nios" for on-prem WAPI, others return zone content.
        rpz_zone: Name of the RPZ zone (e.g., "rpz.example.com").
        td_action: TD security policy action — "action_block" (NXDOMAIN),
            "action_log" (monitor only), "action_allow", "action_redirect".
            Only used with "infoblox" backend. Default: "action_block".
        td_policy_id: TD security policy ID to bind to. None = default
            global policy. Only used with "infoblox" backend.

    Returns:
        dict with:
        - success: Whether the operation completed
        - rpz_zone: The zone name
        - backend: The backend used
        - record_count: Number of records pushed
        - td_policy: Security policy binding details (infoblox only)
        - message: Status message
    """
    import json

    from dns_aid.sdk.policy.compiler import PolicyCompiler, RPZAction
    from dns_aid.sdk.policy.rpz_writer import write_rpz_zone
    from dns_aid.sdk.policy.schema import PolicyDocument

    # Validate inputs
    try:
        validate_backend(backend)
    except ValidationError as e:
        return _format_validation_error(e)

    try:
        doc = PolicyDocument.model_validate(json.loads(policy_json))
    except Exception as e:
        return {"success": False, "error": f"Failed to parse policy: {e}"}

    compiler = PolicyCompiler()
    result = compiler.compile(doc)

    if backend == "nios":
        from dns_aid.backends.infoblox.nios import InfobloxNIOSBackend

        async def _push_nios():
            nios = InfobloxNIOSBackend()
            try:
                await nios.ensure_rpz_zone(rpz_zone)
                pushed, errors = 0, []
                for d in result.rpz_directives:
                    try:
                        await nios.create_rpz_cname_record(
                            rpz_zone=rpz_zone,
                            owner=d.owner,
                            action=d.action.value,
                            comment=f"DNS-AID: {d.comment}",
                        )
                        pushed += 1
                    except Exception as exc:
                        errors.append(f"{d.owner}: {exc}")
                return pushed, errors
            finally:
                await nios.close()

        try:
            pushed, errors = _run_async(_push_nios())
            return {
                "success": len(errors) == 0,
                "rpz_zone": rpz_zone,
                "backend": "nios",
                "record_count": pushed,
                "errors": errors,
                "message": f"Pushed {pushed}/{len(result.rpz_directives)} RPZ records to NIOS",
            }
        except Exception as e:
            return {"success": False, "error": f"NIOS push failed: {e}"}

    elif backend == "infoblox":
        from dns_aid.backends.infoblox.bloxone import InfobloxBloxOneBackend

        blocked = [
            d.owner
            for d in result.rpz_directives
            if d.action in (RPZAction.NXDOMAIN, RPZAction.DROP) and d.owner != "*"
        ]
        list_name = f"dns-aid-rpz-{rpz_zone.replace('.', '-')}"

        async def _push_and_bind():
            bx = InfobloxBloxOneBackend()
            try:
                nl_result = await bx.create_or_update_named_list(
                    name=list_name,
                    items=blocked,
                    description=f"DNS-AID RPZ for {doc.agent}",
                )
                bind_result = await bx.bind_named_list_to_policy(
                    named_list_name=list_name,
                    policy_id=td_policy_id,
                    action=td_action,
                )
                return nl_result, bind_result
            finally:
                await bx.close()

        try:
            nl_result, bind_result = _run_async(_push_and_bind())
            nl_action = "Updated" if nl_result.get("updated") else "Created"
            return {
                "success": True,
                "rpz_zone": rpz_zone,
                "backend": "infoblox",
                "record_count": len(blocked),
                "named_list": list_name,
                "td_policy": {
                    "policy_id": bind_result.get("policy_id"),
                    "policy_name": bind_result.get("policy_name"),
                    "action": td_action,
                    "status": bind_result.get("action"),
                },
                "message": (
                    f"{nl_action} TD named list '{list_name}' with {len(blocked)} domains. "
                    f"Bound to policy '{bind_result.get('policy_name')}' as {td_action}."
                ),
            }
        except Exception as e:
            return {"success": False, "error": f"Infoblox push failed: {e}"}

    else:
        zone_content = write_rpz_zone(result, rpz_zone)
        return {
            "success": True,
            "rpz_zone": rpz_zone,
            "backend": backend,
            "record_count": len(result.rpz_directives),
            "zone_content": zone_content,
            "message": (
                f"Backend '{backend}' does not support direct RPZ push. "
                "Zone content returned for manual loading."
            ),
        }


@mcp.tool(
    title="List RPZ Rules",
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
def list_rpz_rules(
    rpz_zone: str,
    backend: Literal[
        "route53", "cloudflare", "ns1", "infoblox", "nios", "ddns", "mock"
    ] = "infoblox",
) -> dict:
    """
    List current RPZ rules from a backend.

    For Infoblox: queries TD named lists and security policies.
    For NIOS: queries ``record:rpz:cname`` via WAPI.

    Args:
        rpz_zone: Name of the RPZ zone to query.
        backend: DNS backend to query (default: infoblox).

    Returns:
        dict with:
        - success: Whether the query succeeded
        - rpz_zone: The zone queried
        - named_lists/rules: The RPZ data found
        - count: Number of items found
    """
    if backend == "nios":
        from dns_aid.backends.infoblox.nios import InfobloxNIOSBackend

        async def _list_nios():
            nios = InfobloxNIOSBackend()
            try:
                return await nios.list_rpz_cname_records(rpz_zone)
            finally:
                await nios.close()

        try:
            rules = _run_async(_list_nios())
            return {
                "success": True,
                "rpz_zone": rpz_zone,
                "rules": rules,
                "count": len(rules),
            }
        except Exception as e:
            return {"success": False, "error": f"NIOS query failed: {e}"}

    elif backend == "infoblox":
        from dns_aid.backends.infoblox.bloxone import InfobloxBloxOneBackend

        async def _list_infoblox():
            bx = InfobloxBloxOneBackend()
            try:
                list_name = f"dns-aid-rpz-{rpz_zone.replace('.', '-')}"
                named_lists = await bx.list_named_lists(name_filter=list_name)
                policies = await bx.list_security_policies()
                return named_lists, policies
            finally:
                await bx.close()

        try:
            named_lists, policies = _run_async(_list_infoblox())
            return {
                "success": True,
                "rpz_zone": rpz_zone,
                "named_lists": named_lists,
                "security_policies": policies,
                "count": len(named_lists),
            }
        except Exception as e:
            return {"success": False, "error": f"Infoblox query failed: {e}"}

    else:
        return {
            "success": False,
            "error": f"Backend '{backend}' does not support RPZ rule listing. Use infoblox or nios.",
        }


@mcp.tool(
    title="List TD Security Policies",
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
def list_td_security_policies() -> dict:
    """
    List all Infoblox Threat Defense security policies.

    Use this to find the policy ID for ``publish_rpz_zone``'s ``td_policy_id``
    parameter when you don't want to use the default global policy.

    Returns:
        dict with:
        - success: Whether the query succeeded
        - policies: List of policies with id, name, description, rule_count, is_default
        - count: Number of policies found
    """
    from dns_aid.backends.infoblox.bloxone import InfobloxBloxOneBackend

    async def _list():
        bx = InfobloxBloxOneBackend()
        try:
            return await bx.list_security_policies()
        finally:
            await bx.close()

    try:
        policies = _run_async(_list())
        return {
            "success": True,
            "policies": policies,
            "count": len(policies),
        }
    except Exception as e:
        return {"success": False, "error": f"Failed to list TD policies: {e}"}


# =============================================================================
# ENVIRONMENT DIAGNOSTICS
# =============================================================================


@mcp.tool(
    title="Diagnose Environment",
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=False,
    ),
)
def diagnose_environment(domain: str | None = None) -> dict:
    """
    Run DNS-AID environment diagnostics.

    Checks Python version, core dependencies, DNS resolution, backend
    credentials, optional features, and .env configuration.  Use this
    before publish/discover operations to verify the environment is
    correctly set up.

    Args:
        domain: Domain to test agent discovery against (optional).
                Falls back to DNS_AID_DOCTOR_DOMAIN env var.
                Discovery check is skipped if neither is set.

    Returns:
        dict with:
        - version: Installed dns-aid version
        - sections: Dict of section name → list of check results
        - pass_count: Number of checks that passed
        - fail_count: Number of checks that failed
        - warn_count: Number of optional/unconfigured warnings
    """
    from dns_aid.doctor import run_checks

    report = run_checks(domain=domain)
    return report.to_dict()


# =============================================================================
# A2A MESSAGING
# =============================================================================


@mcp.tool(
    title="Send A2A Message",
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True,
    ),
)
def send_a2a_message(
    message: str,
    endpoint: str | None = None,
    domain: str | None = None,
    name: str | None = None,
    timeout: float = 60.0,
    policy_uri: str | None = None,
    credentials: dict | None = None,
) -> dict:
    """
    Send a message to an A2A (Agent-to-Agent) agent and get its response.

    Use this to communicate with agents that speak the Google A2A protocol.
    This is the primary tool for agent-to-agent conversation.

    Two ways to specify the agent:

    1. **By domain + name** (recommended — auto-discovers via DNS):
       send_a2a_message(message="Hello", domain="ai.infoblox.com", name="security-analyzer")

    2. **By endpoint URL** (use exactly as returned by discover_agents_via_dns):
       send_a2a_message(message="Hello", endpoint="https://security-analyzer.ai.infoblox.com")

    Before sending, this tool fetches the agent's Agent Card from
    /.well-known/agent-card.json to get the canonical endpoint URL and
    agent metadata (name, description, skills).

    Args:
        message: The text message to send to the agent.
        endpoint: The agent's A2A endpoint URL. Use EXACTLY as returned by
                  discover_agents_via_dns — do not modify the URL.
        domain: Domain to discover the agent on (e.g., "ai.infoblox.com").
                Use with ``name`` for automatic DNS discovery.
        name: Agent name to discover (e.g., "security-analyzer").
              Use with ``domain`` for automatic DNS discovery.
        timeout: Request timeout in seconds (default 30).
        policy_uri: The target agent's policy document URL (from discovery).
                    If provided, policy is checked before invocation.

    Returns:
        dict with:
        - success: Whether the call succeeded
        - response: The agent's text response
        - agent_endpoint: The endpoint that was called
        - agent_info: Agent metadata (name, description, skills, how endpoint was resolved)
        - telemetry: Invocation telemetry (latency, status) when SDK is available
        - policy: Policy check result when policy_uri is provided
        - error: Error message if failed
    """
    from dns_aid.core.invoke import send_a2a_message as _send_a2a
    from dns_aid.sdk.policy.guard import check_target_policy

    if not endpoint and not (domain and name):
        return {
            "success": False,
            "error": "Provide either 'endpoint' URL or both 'domain' and 'name' for DNS discovery.",
        }

    agent_label = endpoint or f"{name}.{domain}" if (name and domain) else endpoint or ""

    try:
        # Policy guard: check target's policy before invocation
        policy_result = _run_async(
            check_target_policy(
                policy_uri,
                protocol="a2a",
                method="message/send",
                caller_id="dns-aid-mcp-server",
            ),
            timeout=10,
        )
        if policy_result.denied:
            import os

            mode = os.getenv("DNS_AID_POLICY_MODE", "permissive")
            if mode == "strict":
                return {
                    "success": False,
                    "error": f"Policy denied: {policy_result.reason}",
                    "agent_endpoint": agent_label,
                    "policy": {
                        "result": "denied",
                        "violations": [
                            {"rule": v.rule, "detail": v.detail} for v in policy_result.violations
                        ],
                    },
                }

        result = _run_async(
            _send_a2a(
                endpoint,
                message,
                domain=domain,
                name=name,
                timeout=timeout,
                caller_id="dns-aid-mcp-server",
                credentials=credentials,
                policy_uri=policy_uri,
            ),
            timeout=timeout + 15,  # allow headroom for DNS resolution + agent card fetch
        )

        # Extract resolved endpoint from agent_info if available
        if isinstance(result.data, dict) and "agent_info" in result.data:
            info = result.data["agent_info"]
            agent_label = info.get("canonical_endpoint", agent_label)
            if agent_label == (endpoint or ""):
                # No canonical override — try the resolved endpoint from discovery
                agent_label = endpoint or info.get("resolved_via", agent_label)

        response: dict = {"success": result.success, "agent_endpoint": agent_label}

        if result.success and isinstance(result.data, dict):
            response["response"] = result.data.get("response_text", str(result.data))
            if "agent_info" in result.data:
                response["agent_info"] = result.data["agent_info"]
        elif result.success:
            response["response"] = str(result.data)
        else:
            error_msg = result.error or "Invocation failed"
            if not error_msg.strip():
                error_msg = "Invocation failed"
            response["error"] = error_msg

        if result.telemetry:
            response["telemetry"] = result.telemetry
        return response
    except Exception as e:
        error_msg = str(e).strip() or "Unknown invocation error"
        return {"success": False, "agent_endpoint": agent_label, "error": error_msg}


# =============================================================================
# HEALTH ENDPOINTS (for HTTP transport)
# =============================================================================

try:
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response

    @mcp.custom_route(path="/health", methods=["GET"])
    async def health_check(request: Request) -> Response:
        """
        Health check endpoint for load balancers and monitoring.
        Returns server status and version information.
        """
        from dns_aid import __version__

        uptime = time.time() - _start_time

        return JSONResponse(
            {
                "status": "healthy",
                "service": "dns-aid-mcp",
                "version": __version__,
                "uptime_seconds": round(uptime, 2),
                "tools": [
                    "publish_agent_to_dns",
                    "discover_agents_via_dns",
                    "verify_agent_dns",
                    "list_published_agents",
                    "delete_agent_from_dns",
                    "list_agent_index",
                    "sync_agent_index",
                    "send_a2a_message",
                    "dcv_issue_challenge",
                    "dcv_place_challenge",
                    "dcv_verify_challenge",
                    "dcv_revoke_challenge",
                ],
            }
        )

    @mcp.custom_route(path="/ready", methods=["GET"])
    async def readiness_check(request: Request) -> Response:
        """
        Readiness check endpoint for Kubernetes and orchestrators.
        Verifies the server can handle requests.
        """
        # Test that we can import core modules
        try:
            from dns_aid.backends.mock import MockBackend  # noqa: F401
            from dns_aid.core.discoverer import discover  # noqa: F401
            from dns_aid.core.publisher import publish  # noqa: F401

            return JSONResponse(
                {
                    "ready": True,
                    "checks": {
                        "publisher": "ok",
                        "discoverer": "ok",
                        "mock_backend": "ok",
                    },
                }
            )
        except ImportError as e:
            return JSONResponse(
                {
                    "ready": False,
                    "error": str(e),
                },
                status_code=503,
            )

    @mcp.custom_route(path="/", methods=["GET"])
    async def root_info(request: Request) -> Response:
        """
        Root endpoint with API information.
        """
        from dns_aid import __version__

        return JSONResponse(
            {
                "service": "DNS-AID MCP Server",
                "version": __version__,
                "description": "DNS-based Agent Identification and Discovery",
                "endpoints": {
                    "/mcp": "MCP protocol endpoint (POST)",
                    "/health": "Health check (GET)",
                    "/ready": "Readiness check (GET)",
                },
                "documentation": "https://github.com/dns-aid/dns-aid-core",
                "specification": "IETF draft-mozleywilliams-dnsop-dnsaid-02",
            }
        )

except ImportError:
    # Starlette not available (stdio-only mode)
    pass


# =============================================================================
# DCV TOOLS
# =============================================================================


def _dcv_safe_error(e: Exception) -> str:
    """
    Return a safe error message for MCP tool responses.

    ValidationError and ValueError carry our own safe messages. Any other
    exception (backend errors, network failures) is logged server-side only;
    the LLM receives a generic message to prevent infra detail leakage.
    """
    from dns_aid.utils.validation import ValidationError as _ValidationError

    if isinstance(e, (_ValidationError, ValueError)):
        return str(e)
    import logging as _logging

    _logging.getLogger(__name__).error("DCV tool unexpected error", exc_info=True)
    return "Operation failed. Check server logs for details."


@mcp.tool(
    title="Issue DCV Challenge",
    annotations=ToolAnnotations(
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=False,  # each call produces a distinct token
        openWorldHint=False,
    ),
)
def dcv_issue_challenge(
    domain: str,
    agent_name: str | None = None,
    issuer_domain: str | None = None,
    ttl_seconds: int = 3600,
) -> dict:
    """
    Generate a DCV challenge token for a domain.

    The challenger calls this and delivers the result out-of-band (via A2A, MCP,
    or any other channel) to the claimant.  Nothing is written to DNS here —
    placement is the claimant's job.

    After a successful dcv_verify_challenge(), call dcv_revoke_challenge()
    immediately to prevent token reuse within the validity window.

    Args:
        domain: Domain the claimant must prove control of.
        agent_name: Optional agent name to scope the bnd-req field
                    (lowercase alphanumeric + hyphens, max 63 chars).
        issuer_domain: Optional issuer domain to scope the bnd-req field.
        ttl_seconds: Challenge validity window in seconds (30–86400, default: 3600).

    Returns:
        dict with success, token, fqdn, txt_value, expiry, and optional bnd_req.
    """
    from dns_aid.core import dcv as _dcv

    try:
        challenge = _dcv.issue(
            domain,
            agent_name=agent_name,
            issuer_domain=issuer_domain,
            ttl_seconds=ttl_seconds,
        )
        result = challenge.model_dump(mode="json")
        result["success"] = True
        return result
    except Exception as e:
        return {"success": False, "error": _dcv_safe_error(e)}


@mcp.tool(
    title="Place DCV Challenge",
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=False,
        idempotentHint=False,  # backend behaviour varies; not guaranteed idempotent
        openWorldHint=True,
    ),
)
def dcv_place_challenge(
    domain: str,
    token: str,
    bnd_req: str | None = None,
    ttl: int = 300,
    expiry_seconds: int = 3600,
) -> dict:
    """
    Write a DCV challenge TXT record to DNS via the configured backend.

    The claimant calls this using their own dns-aid backend credentials,
    proving they have write access to the domain's zone.

    Args:
        domain: Zone to write the challenge into.
        token: Token received from the challenger (32-char base32, from dcv_issue_challenge).
        bnd_req: Binding scope from the challenge (pass through as-is).
        ttl: DNS record TTL in seconds (30–604800, default: 300).
        expiry_seconds: How long the placed record should be valid (30–86400, default: 3600).

    Returns:
        dict with success (bool) and fqdn where the record was placed.
    """
    from dns_aid.core import dcv as _dcv

    try:
        place_result = _run_async(
            _dcv.place(domain, token, bnd_req=bnd_req, ttl=ttl, expiry_seconds=expiry_seconds)
        )
        return {"success": True, "fqdn": place_result.fqdn}
    except Exception as e:
        return {"success": False, "error": _dcv_safe_error(e)}


@mcp.tool(
    title="Verify DCV Challenge",
    annotations=ToolAnnotations(
        readOnlyHint=False,  # sends an active DNS probe to an external resolver
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
def dcv_verify_challenge(
    domain: str,
    token: str,
    expected_bnd_req: str | None = None,
) -> dict:
    """
    Verify that a DCV challenge token is present and unexpired in DNS.

    The challenger calls this after the claimant has placed the record.
    No backend credentials required — pure DNS resolution against the
    system resolver.

    Args:
        domain: Domain to check.
        token: Token originally issued by the challenger.
        expected_bnd_req: When provided, the record's bnd-req field must match
                          exactly (prevents cross-vendor token reuse).

    Returns:
        dict with success (bool), verified (bool), fqdn, expired (bool), and error.
    """
    from dns_aid.core import dcv as _dcv

    try:
        result = _run_async(_dcv.verify(domain, token, expected_bnd_req=expected_bnd_req))
        out = result.model_dump()
        out["success"] = True
        # Do not echo the token back — it is already known to the caller
        out.pop("token", None)
        return out
    except Exception as e:
        return {"success": False, "verified": False, "error": _dcv_safe_error(e)}


@mcp.tool(
    title="Revoke DCV Challenge",
    annotations=ToolAnnotations(
        readOnlyHint=False,
        destructiveHint=True,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
def dcv_revoke_challenge(domain: str, token: str) -> dict:
    """
    Delete the DCV challenge TXT record from DNS.

    Should be called immediately after a successful dcv_verify_challenge()
    to prevent token reuse within the validity window.
    Requires backend credentials for the domain.

    Args:
        domain: Zone to remove the challenge from.
        token:  Token that was placed (must match the record in DNS).

    Returns:
        dict with success (bool) and optional error.
    """
    from dns_aid.core import dcv as _dcv

    try:
        revoke_result = _run_async(_dcv.revoke(domain, token=token))
        return {"success": revoke_result.removed}
    except Exception as e:
        return {"success": False, "error": _dcv_safe_error(e)}


def _cleanup():
    """Cleanup resources on shutdown."""
    global _executor
    if _executor is not None:
        _executor.shutdown(wait=False)
        _executor = None


def main():
    """Run the MCP server."""
    import atexit

    from dotenv import load_dotenv

    load_dotenv()

    # Register cleanup handler
    atexit.register(_cleanup)

    # Logging is already configured at module level (before dns_aid imports)
    # to ensure structlog outputs to stderr in MCP stdio mode.

    transport = "stdio"
    # Security: Default to localhost for HTTP transport
    host = "127.0.0.1"
    port = 8000

    # Simple argument parsing
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--transport":
            transport = args[i + 1]
            i += 2
        elif args[i] == "--port":
            port = int(args[i + 1])
            i += 2
        elif args[i] == "--host":
            host = args[i + 1]
            i += 2
        elif args[i] in ("--help", "-h"):
            print("""DNS-AID MCP Server

Usage: dns-aid-mcp [OPTIONS]

Options:
  --transport <TYPE>   Transport type: stdio (default) or http
  --host <HOST>        Host to bind to (default: 127.0.0.1, http only)
  --port <PORT>        Port to listen on (default: 8000, http only)
  --help, -h           Show this help message

Examples:
  dns-aid-mcp                           # Run with stdio transport
  dns-aid-mcp --transport http          # Run HTTP server on localhost:8000
  dns-aid-mcp --transport http --port 9000  # Run HTTP server on port 9000
  dns-aid-mcp --transport http --host 0.0.0.0  # Bind to all interfaces (use with caution)

HTTP Endpoints:
  /mcp      MCP protocol endpoint
  /health   Health check
  /ready    Readiness check

Security Notes:
  - HTTP transport binds to 127.0.0.1 by default for security
  - For production deployment, use a reverse proxy (nginx, traefik)
  - Use --host 0.0.0.0 only in containerized environments with proper network isolation
""")
            return
        else:
            i += 1

    if transport == "http":
        import uvicorn

        # Security warning for binding to all interfaces
        if host == "0.0.0.0":  # nosec B104 - This is a security check, not a bind
            print("WARNING: Binding to 0.0.0.0 exposes this server to all network interfaces.")
            print("         Ensure proper network isolation or use a reverse proxy.")
            print()

        print(f"Starting DNS-AID MCP server on http://{host}:{port}")
        print(f"  MCP endpoint: http://{host}:{port}/mcp")
        print(f"  Health check: http://{host}:{port}/health")
        print(f"  Ready check:  http://{host}:{port}/ready")
        print()
        uvicorn.run(
            mcp.streamable_http_app(),
            host=host,
            port=port,
            log_level="info",
        )
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
