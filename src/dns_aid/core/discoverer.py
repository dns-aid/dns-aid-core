# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
DNS-AID Discoverer: Query DNS to find AI agents.

This module handles discovering agents via DNS queries for SVCB and TXT
records as specified in IETF draft-mozleywilliams-dnsop-dnsaid-01.
"""

from __future__ import annotations

import asyncio
import base64
import json
import shlex
import time
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import urlparse

import dns.asyncresolver
import dns.rdatatype
import dns.resolver
import structlog

from dns_aid.core._edns_hint_ctx import (
    apply_agent_hint_to_resolver as _apply_agent_hint_to_resolver,
)
from dns_aid.core._edns_hint_ctx import (
    reset_agent_hint as _reset_agent_hint,
)
from dns_aid.core._edns_hint_ctx import (
    set_agent_hint as _set_agent_hint,
)
from dns_aid.core.a2a_card import A2AAgentCard, fetch_agent_card
from dns_aid.core.cap_fetcher import fetch_cap_document
from dns_aid.core.filters import apply_filters
from dns_aid.core.http_index import HttpIndexAgent, fetch_http_index_or_empty
from dns_aid.core.models import AgentRecord, DiscoveryResult, DNSSECError, Protocol

if TYPE_CHECKING:
    from dns_aid.experimental.edns_hint import AgentHint

logger = structlog.get_logger(__name__)


def _normalize_protocol(protocol: str | Protocol | None) -> Protocol | None:
    """Convert string protocol to Protocol enum if needed."""
    if isinstance(protocol, str):
        return Protocol(protocol.lower())
    return protocol


async def _execute_discovery(
    domain: str,
    protocol: Protocol | None,
    name: str | None,
    use_http_index: bool,
    query: str,
) -> list[AgentRecord]:
    """Execute the appropriate discovery strategy and handle DNS errors."""
    try:
        if use_http_index:
            return await _discover_via_http_index(domain, protocol, name)
        elif name and protocol:
            agent = await _query_single_agent(domain, name, protocol)
            return [agent] if agent else []
        else:
            return await _discover_agents_in_zone(domain, protocol)
    except dns.resolver.NXDOMAIN:
        logger.debug("No DNS-AID records found", query=query)
    except dns.resolver.NoAnswer:
        logger.debug("No answer for query", query=query)
    except dns.resolver.NoNameservers:
        logger.error("No nameservers available", domain=domain)
    except Exception as e:
        logger.exception("DNS query failed", error=str(e))
    return []


async def _apply_post_discovery(
    agents: list[AgentRecord],
    require_dnssec: bool,
    enrich_endpoints: bool,
    verify_signatures: bool,
    domain: str,
) -> bool:
    """Apply DNSSEC enforcement, endpoint enrichment, and JWS verification.

    Returns whether DNSSEC was validated.
    """
    dnssec_validated = False

    if agents and require_dnssec:
        from dns_aid.core.validator import _check_dnssec

        dnssec_validated = await _check_dnssec(agents[0].fqdn)
        if not dnssec_validated:
            raise DNSSECError(
                f"DNSSEC validation required but DNS response for "
                f"{agents[0].fqdn} is not authenticated (AD flag not set)"
            )

    if enrich_endpoints and agents:
        try:
            await _enrich_agents_with_endpoint_paths(agents)
        except Exception:
            logger.debug("Endpoint enrichment failed (non-fatal)", exc_info=True)

    if verify_signatures and agents:
        await _verify_agent_signatures(agents, domain, dnssec_validated)

    return dnssec_validated


async def discover(
    domain: str,
    protocol: str | Protocol | None = None,
    name: str | None = None,
    require_dnssec: bool = False,  # Default False for now, True in production
    use_http_index: bool = False,
    enrich_endpoints: bool = True,
    verify_signatures: bool = False,
    *,
    # Path A in-memory filter kwargs (FR-002, FR-021..FR-023). All optional; default
    # behavior is unchanged when none are passed.
    capabilities: list[str] | None = None,
    capabilities_any: list[str] | None = None,
    auth_type: str | None = None,
    intent: str | None = None,
    transport: str | None = None,
    realm: str | None = None,
    min_dnssec: bool = False,
    text_match: str | None = None,
    require_signed: bool = False,
    require_signature_algorithm: list[str] | None = None,
    # Experimental: EDNS(0) agent-hint signaling. See docs/experimental/edns-signaling.md.
    # Accepted unconditionally for forward-compat; only injected on the wire when
    # DNS_AID_EXPERIMENTAL_EDNS_HINTS=1 is set in the environment.
    agent_hint: AgentHint | None = None,
) -> DiscoveryResult:
    """
    Discover AI agents at a domain using DNS-AID protocol.

    Queries DNS for SVCB records under _agents.{domain} and returns discovered agent
    endpoints, optionally filtered by structured kwargs.

    Args:
        domain: Domain to search for agents (e.g., "example.com").
        protocol: Filter by protocol ("a2a", "mcp", or None for all).
        name: Filter by specific agent name (or None for all).
        require_dnssec: Require DNSSEC validation (raises if invalid).
        use_http_index: If True, fetch agent list from HTTP endpoint
            (``/.well-known/agents-index.json``) instead of DNS-only discovery.
        enrich_endpoints: If True (default), fetch ``.well-known/agent-card.json``
            from each discovered agent's host to resolve protocol-specific endpoint paths.
        verify_signatures: If True, verify JWS signatures. Implicit when ``require_signed``
            is set so the trust filter has data to act on.
        capabilities: All-of capability match. Empty list explicitly matches no records.
        capabilities_any: Any-of capability match. Empty list explicitly matches no records.
        auth_type: Case-insensitive exact match against ``agent.auth_type``.
        intent: Match against ``agent.category``; substring fallback against capabilities.
        transport: For Path A this matches ``agent.protocol.value`` (DNS substrate does not
            surface the wire transport binding; use Path B for streamable-http / sse / etc.).
        realm: Exact match against ``agent.realm``.
        min_dnssec: When True, only records with DNSSEC-validated DNS responses pass.
        text_match: Case-insensitive substring across description, use_cases, capabilities.
        require_signed: Only records whose JWS signature verified pass. Auto-enables
            ``verify_signatures``.
        require_signature_algorithm: Restrict ``require_signed`` to records whose verified
            algorithm appears in this allow-list. Requires ``require_signed=True``.

    Returns:
        DiscoveryResult with the post-filter list of agents.

    Raises:
        ValueError: ``text_match`` is the empty string, or
            ``require_signature_algorithm`` is set without ``require_signed=True``.
        DNSSECError: ``require_dnssec=True`` and the response was not authenticated.

    Example:
        >>> result = await discover(
        ...     "example.com",
        ...     protocol="mcp",
        ...     capabilities=["payment-processing"],
        ...     auth_type="oauth2",
        ...     require_signed=True,
        ... )
        >>> for agent in result.agents:
        ...     print(f"{agent.name}: {agent.endpoint_url}")
    """
    if require_signed and not verify_signatures:
        # Implicit upgrade: trust filter needs verification to have run (FR-023).
        verify_signatures = True
        logger.debug("sdk.discover_implicit_verify_signatures", reason="require_signed=True")

    start_time = time.perf_counter()

    # Experimental: stash agent_hint on the contextvar so DNS helpers below can
    # attach it as an EDNS option without threading through every signature.
    # try/finally guarantees the reset even on exception so the contextvar
    # doesn't carry stale state across calls within the same async task.
    _hint_token = _set_agent_hint(agent_hint)
    try:
        return await _discover_body(
            domain,
            protocol,
            name,
            require_dnssec,
            use_http_index,
            enrich_endpoints,
            verify_signatures,
            capabilities,
            capabilities_any,
            auth_type,
            intent,
            transport,
            realm,
            min_dnssec,
            text_match,
            require_signed,
            require_signature_algorithm,
            start_time,
        )
    finally:
        _reset_agent_hint(_hint_token)


async def _discover_body(
    domain: str,
    protocol: str | Protocol | None,
    name: str | None,
    require_dnssec: bool,
    use_http_index: bool,
    enrich_endpoints: bool,
    verify_signatures: bool,
    capabilities: list[str] | None,
    capabilities_any: list[str] | None,
    auth_type: str | None,
    intent: str | None,
    transport: str | None,
    realm: str | None,
    min_dnssec: bool,
    text_match: str | None,
    require_signed: bool,
    require_signature_algorithm: list[str] | None,
    start_time: float,
) -> DiscoveryResult:
    """Body of discover(), extracted so the public surface can wrap it in a
    contextvar try/finally for the experimental agent_hint plumbing."""

    protocol = _normalize_protocol(protocol)

    # Build query based on filters
    if name and protocol:
        query = f"_{name}._{protocol.value}._agents.{domain}"
    elif protocol:
        query = f"_index._{protocol.value}._agents.{domain}"
    else:
        query = f"_index._agents.{domain}"

    if use_http_index:
        query = f"https://_index._aiagents.{domain}/index-wellknown"

    logger.info(
        "Discovering agents via DNS",
        domain=domain,
        protocol=protocol.value if protocol else None,
        name=name,
        query=query,
        use_http_index=use_http_index,
    )

    agents = await _execute_discovery(domain, protocol, name, use_http_index, query)

    # Path A name filter — applied here, *before* enrichment, so we don't fetch
    # cap docs / agent cards / JWKS for agents we're about to discard.
    # ``_execute_discovery`` already short-circuits to a single SVCB query when
    # both ``name`` and ``protocol`` are set; this branch covers the remaining
    # case (name without protocol) where the substrate did a full-zone walk.
    # Comparison is case-insensitive: DNS labels are case-insensitive per
    # RFC 1035, so ``--name Test`` should match a record published as ``test``.
    if name and not (use_http_index or protocol):
        needle = name.lower()
        agents = [a for a in agents if a.name.lower() == needle]

    dnssec_validated = await _apply_post_discovery(
        agents, require_dnssec, enrich_endpoints, verify_signatures, domain
    )

    # Propagate domain-level DNSSEC outcome onto each agent so per-agent trust filters
    # (``min_dnssec``) have a record-level signal to evaluate.
    if dnssec_validated:
        for agent in agents:
            agent.dnssec_validated = True

    # Apply Path A in-memory filters (FR-002, FR-021..FR-023). When no filter kwargs are
    # set, ``apply_filters`` short-circuits and returns the input list unchanged.
    pre_filter_count = len(agents)
    agents = apply_filters(
        agents,
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
    if len(agents) != pre_filter_count:
        active_filters = [
            n
            for n, v in (
                ("capabilities", capabilities),
                ("capabilities_any", capabilities_any),
                ("auth_type", auth_type),
                ("intent", intent),
                ("transport", transport),
                ("realm", realm),
                ("min_dnssec", min_dnssec),
                ("text_match", text_match),
                ("require_signed", require_signed),
                ("require_signature_algorithm", require_signature_algorithm),
            )
            if v
        ]
        logger.debug(
            "sdk.discover_filtered",
            domain=domain,
            pre_filter_count=pre_filter_count,
            post_filter_count=len(agents),
            filters_applied=active_filters,
        )

    elapsed_ms = (time.perf_counter() - start_time) * 1000

    result = DiscoveryResult(
        query=query,
        domain=domain,
        agents=agents,
        dnssec_validated=dnssec_validated,
        cached=False,
        query_time_ms=elapsed_ms,
    )

    logger.info(
        "Discovery complete",
        domain=domain,
        agents_found=result.count,
        time_ms=f"{elapsed_ms:.2f}",
        use_http_index=use_http_index,
    )

    return result


async def _query_single_agent(
    domain: str,
    name: str,
    protocol: Protocol,
) -> AgentRecord | None:
    """Query DNS for a specific agent's SVCB record."""
    fqdn = f"_{name}._{protocol.value}._agents.{domain}"

    try:
        resolver = dns.asyncresolver.Resolver()
        _apply_agent_hint_to_resolver(resolver)

        # Query SVCB record
        # Note: dnspython uses type 64 for SVCB
        try:
            answers = await resolver.resolve(fqdn, "SVCB")
        except dns.resolver.NoAnswer:
            # Try HTTPS record as fallback (type 65)
            try:
                answers = await resolver.resolve(fqdn, "HTTPS")
            except dns.resolver.NoAnswer:
                return None

        for rdata in answers:
            # AliasMode (priority 0): follow alias to canonical name
            # Per RFC 9460 and IETF draft Section 4.4.2, AliasMode maps a
            # friendly name to a canonical SVCB owner name.
            if rdata.priority == 0:
                alias_target = str(rdata.target).rstrip(".")
                if alias_target and alias_target != ".":
                    logger.debug(
                        "Following SVCB AliasMode",
                        fqdn=fqdn,
                        alias_target=alias_target,
                    )
                    try:
                        answers = await resolver.resolve(alias_target, "SVCB")
                        # Recurse into the resolved answers (ServiceMode expected)
                        for alias_rdata in answers:
                            if alias_rdata.priority > 0:
                                rdata = alias_rdata
                                break
                        else:
                            return None  # No ServiceMode record found
                    except Exception:
                        logger.debug("AliasMode resolution failed", alias=alias_target)
                        return None

            # Parse ServiceMode SVCB record
            target = str(rdata.target).rstrip(".")

            # Extract standard parameters
            port = 443
            ipv4_hint = None
            ipv6_hint = None

            if hasattr(rdata, "params") and rdata.params:
                # Port (SvcParamKey 3)
                port_param = rdata.params.get(3)
                if port_param and hasattr(port_param, "port"):
                    port = port_param.port
                # ipv4hint (SvcParamKey 4) — per IETF draft Section 4.4.2,
                # SHOULD be used to reduce follow-up A/AAAA queries
                ipv4_param = rdata.params.get(4)
                if ipv4_param:
                    addrs = getattr(ipv4_param, "addresses", None)
                    if addrs:
                        ipv4_hint = str(addrs[0])
                # ipv6hint (SvcParamKey 6)
                ipv6_param = rdata.params.get(6)
                if ipv6_param:
                    addrs = getattr(ipv6_param, "addresses", None)
                    if addrs:
                        ipv6_hint = str(addrs[0])
            elif hasattr(rdata, "port") and rdata.port:
                port = rdata.port

            # Extract DNS-AID custom params from SVCB presentation format.
            # dnspython stores params as a dict keyed by SvcParamKey integers.
            # Custom/private-use params may appear as string keys in the
            # presentation format. We parse the text representation to extract them.
            svcb_text = str(rdata)
            custom_params = _parse_svcb_custom_params(svcb_text)

            cap_uri = custom_params.get("cap")
            cap_sha256 = custom_params.get("cap-sha256")
            bap_str = custom_params.get("bap", "")
            bap = [b.strip() for b in bap_str.split(",") if b.strip()] if bap_str else []
            policy_uri = custom_params.get("policy")
            realm = custom_params.get("realm")
            connect_class = custom_params.get("connect-class")
            connect_meta = custom_params.get("connect-meta")
            enroll_uri = custom_params.get("enroll-uri")

            # Discovery priority: cap URI first, then TXT fallback
            capabilities: list[str] = []
            capability_source: Literal[
                "cap_uri", "agent_card", "http_index", "txt_fallback", "none"
            ] = "none"
            agent_card = None

            if cap_uri:
                cap_doc = await fetch_cap_document(cap_uri, expected_sha256=cap_sha256)
                if cap_doc and cap_doc.capabilities:
                    capabilities = cap_doc.capabilities
                    capability_source = "cap_uri"
                    logger.debug(
                        "Capabilities fetched from cap URI",
                        fqdn=fqdn,
                        cap_uri=cap_uri,
                        capabilities=capabilities,
                    )

                # Reuse raw data as A2AAgentCard (avoids redundant fetch later)
                if cap_doc and cap_doc.raw_data:
                    try:
                        agent_card = A2AAgentCard.from_dict(cap_doc.raw_data)
                        logger.debug(
                            "Parsed A2A Agent Card from cap URI response",
                            fqdn=fqdn,
                            card_name=agent_card.name,
                            skills_count=len(agent_card.skills),
                        )
                    except Exception:
                        pass  # Not an agent card format — that's fine

            # Tier 2: If cap_uri didn't yield capabilities but we parsed an
            # A2A Agent Card from it, extract skills → capabilities now
            if not capabilities and agent_card and agent_card.skills:
                capabilities = agent_card.to_capabilities()
                capability_source = "agent_card"
                logger.debug(
                    "Capabilities from A2A Agent Card (cap_uri response)",
                    fqdn=fqdn,
                    capabilities=capabilities,
                )

            # Tier 4: TXT record fallback (lowest priority)
            if not capabilities:
                capabilities = await _query_capabilities(fqdn)
                if capabilities:
                    capability_source = "txt_fallback"

            return AgentRecord(
                name=name,
                domain=domain,
                protocol=protocol,
                target_host=target,
                port=port,
                ipv4_hint=ipv4_hint,
                ipv6_hint=ipv6_hint,
                capabilities=capabilities,
                cap_uri=cap_uri,
                cap_sha256=cap_sha256,
                bap=bap,
                policy_uri=policy_uri,
                realm=realm,
                connect_class=connect_class,
                connect_meta=connect_meta,
                enroll_uri=enroll_uri,
                capability_source=capability_source,
                endpoint_source="dns_svcb",  # Endpoint resolved via DNS SVCB lookup
                agent_card=agent_card,
            )

    except Exception as e:
        logger.debug("Failed to query agent", fqdn=fqdn, error=str(e))

    return None


def _parse_svcb_custom_params(svcb_text: str) -> dict[str, str]:
    """
    Parse DNS-AID custom params from SVCB record text representation.

    Accepts both human-readable string names and RFC 9460 keyNNNNN format:
        String form: cap="https://..." bap="mcp,a2a" realm="demo"
        Numeric form: key65400="https://..." key65402="mcp,a2a" key65404="demo"

    Args:
        svcb_text: String representation of an SVCB rdata.

    Returns:
        Dict of custom param names (always string form) to their string values.
    """
    from dns_aid.core.models import DNS_AID_KEY_MAP_REVERSE

    custom_params: dict[str, str] = {}
    dnsaid_keys = {
        "cap",
        "cap-sha256",
        "bap",
        "policy",
        "realm",
        "sig",
        "connect-class",
        "connect-meta",
        "enroll-uri",
    }

    try:
        parts = shlex.split(svcb_text)
    except ValueError:
        return custom_params

    for part in parts:
        if "=" not in part:
            continue
        key, _, value = part.partition("=")
        key = key.strip().lower()

        # Normalize keyNNNNN to string name
        if key in DNS_AID_KEY_MAP_REVERSE:
            key = DNS_AID_KEY_MAP_REVERSE[key]

        if key in dnsaid_keys:
            custom_params[key] = value

    return custom_params


async def _query_capabilities(fqdn: str) -> list[str]:
    """Query TXT record for agent capabilities (fallback only).

    Per DNS-AID draft-01 Section 4.4.3, rich agent metadata (description,
    use_cases, category) is sourced from the **capability document** fetched
    via the ``cap`` SVCB parameter URI, or from the HTTP index
    (``/.well-known/agent-index.json``).

    This TXT parser intentionally extracts only ``capabilities=`` as a
    lightweight fallback when neither cap URI nor HTTP index is available.
    The publisher writes description/use_cases/category to TXT for human
    readability (``dig TXT``), but the discoverer does NOT parse them here —
    that metadata should come from the structured cap document or HTTP index.
    """
    capabilities = []

    try:
        resolver = dns.asyncresolver.Resolver()
        _apply_agent_hint_to_resolver(resolver)
        answers = await resolver.resolve(fqdn, "TXT")

        for rdata in answers:
            # TXT records can have multiple strings
            for txt_string in rdata.strings:
                txt = txt_string.decode("utf-8")
                if txt.startswith("capabilities="):
                    caps = txt[len("capabilities=") :]
                    capabilities.extend(caps.split(","))

    except Exception:
        pass  # TXT record is optional

    return capabilities


def _build_index_tasks(
    index_entries: list[Any],
    protocol: Protocol | None,
    query_fn: Any,
) -> list[Any]:
    """Build async tasks from index entries, filtering by protocol."""
    tasks = []
    for entry in index_entries:
        try:
            entry_protocol = Protocol(entry.protocol.lower())
        except ValueError:
            continue
        if protocol and entry_protocol != protocol:
            continue
        tasks.append(query_fn(entry.name, entry_protocol))
    return tasks


def _collect_agent_results(results: list[Any]) -> list[AgentRecord]:
    """Filter asyncio.gather results for successful AgentRecord instances."""
    return [r for r in results if isinstance(r, AgentRecord)]


async def _discover_agents_in_zone(
    domain: str,
    protocol: Protocol | None = None,
) -> list[AgentRecord]:
    """
    Discover all agents in a domain's _agents zone.

    First tries the TXT index at _index._agents.{domain} via direct DNS query.
    Falls back to probing hardcoded common names if the index is unavailable.
    """
    from dns_aid.core.indexer import read_index_via_dns

    index_entries = await read_index_via_dns(domain)

    sem = asyncio.Semaphore(20)

    async def _query_with_sem(name: str, proto: Protocol) -> AgentRecord | None:
        async with sem:
            return await _query_single_agent(domain, name, proto)

    if index_entries:
        logger.debug(
            "Using TXT index for discovery",
            domain=domain,
            entry_count=len(index_entries),
        )
        tasks = _build_index_tasks(index_entries, protocol, _query_with_sem)
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return _collect_agent_results(results)

    # Fallback: probe hardcoded common names
    logger.debug("No TXT index found, falling back to common name probing", domain=domain)

    common_names = [
        "chat",
        "assistant",
        "network",
        "data-cleaner",
        "index",
        "multiagent",
        "api",
        "help",
        "support",
        "agent",
    ]

    protocols_to_try = [protocol] if protocol else [Protocol.MCP, Protocol.A2A]

    tasks = []
    for proto in protocols_to_try:
        for agent_name in common_names:
            tasks.append(_query_with_sem(agent_name, proto))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    return _collect_agent_results(results)


def _parse_fqdn(fqdn: str) -> tuple[str | None, str | None]:
    """
    Parse agent name and protocol from a DNS-AID FQDN.

    FQDN format: _{name}._{protocol}._agents.{domain}

    Returns:
        (name, protocol_str) or (None, None) if parsing fails.
    """
    if not fqdn or not fqdn.startswith("_"):
        return None, None

    parts = fqdn.split(".")
    if len(parts) < 3:
        return None, None

    name_part = parts[0]  # _name
    protocol_part = parts[1]  # _protocol

    if not name_part.startswith("_") or not protocol_part.startswith("_"):
        return None, None

    return name_part[1:], protocol_part[1:]


def _enrich_from_http_index(agent: AgentRecord, http_agent: HttpIndexAgent) -> None:
    """Merge HTTP index metadata into a DNS-discovered agent record."""
    if http_agent.description:
        agent.description = http_agent.description
    if (
        http_agent.capability
        and http_agent.capability.modality
        and http_agent.capability.modality not in agent.use_cases
    ):
        agent.use_cases.append(f"modality:{http_agent.capability.modality}")

    # Merge HTTP index capabilities (only if agent has none from higher-priority source)
    if not agent.capabilities and http_agent.capability and http_agent.capability.capabilities:
        agent.capabilities = http_agent.capability.capabilities
        agent.capability_source = "http_index"
        logger.debug(
            "Merged HTTP index capabilities",
            agent=agent.name,
            capabilities=agent.capabilities,
        )

    if http_agent.endpoint and not agent.endpoint_override:
        parsed = urlparse(http_agent.endpoint)
        if parsed.path and parsed.path != "/":
            agent.endpoint_override = http_agent.endpoint
            agent.endpoint_source = "http_index"
            logger.debug(
                "Merged HTTP index endpoint path",
                agent=agent.name,
                endpoint=http_agent.endpoint,
            )


async def _process_http_agent(
    http_agent: HttpIndexAgent,
    domain: str,
    protocol: Protocol | None,
    name: str | None,
) -> AgentRecord | None:
    """Process a single HTTP index entry: parse FQDN, filter, resolve via DNS."""
    if name and http_agent.name != name:
        return None

    dns_agent_name, fqdn_protocol_str = _parse_fqdn(http_agent.fqdn)
    if not dns_agent_name or not fqdn_protocol_str:
        logger.debug(
            "Cannot parse FQDN from HTTP index entry",
            agent=http_agent.name,
            fqdn=http_agent.fqdn,
        )
        return None

    try:
        agent_protocol = Protocol(fqdn_protocol_str.lower())
    except ValueError:
        logger.debug(
            "Unknown protocol in FQDN",
            agent=http_agent.name,
            fqdn=http_agent.fqdn,
            protocol=fqdn_protocol_str,
        )
        return None

    if protocol and agent_protocol != protocol:
        return None

    agent = await _query_single_agent(domain, dns_agent_name, agent_protocol)

    if agent:
        _enrich_from_http_index(agent, http_agent)
        return agent

    logger.debug(
        "DNS lookup failed for HTTP index agent, using HTTP data only",
        agent=http_agent.name,
        fqdn=http_agent.fqdn,
    )
    return _http_agent_to_record(http_agent, domain, dns_agent_name, agent_protocol)


async def _discover_via_http_index(
    domain: str,
    protocol: Protocol | None = None,
    name: str | None = None,
) -> list[AgentRecord]:
    """
    Discover agents using HTTP index endpoint.

    Fetches agent list from HTTP and resolves each via DNS SVCB.
    Protocol and agent name are extracted from the FQDN in the HTTP index,
    not from separate fields — the FQDN is the single source of truth.

    Args:
        domain: Domain to fetch HTTP index from
        protocol: Filter by protocol (or None for all)
        name: Filter by specific agent name (or None for all)

    Returns:
        List of AgentRecord objects
    """
    http_agents = await fetch_http_index_or_empty(domain)

    if not http_agents:
        logger.debug("No agents found in HTTP index", domain=domain)
        return []

    logger.debug(
        "HTTP index fetched",
        domain=domain,
        agent_count=len(http_agents),
    )

    # Mirror the DNS-index path's concurrency pattern: cap fan-out with a
    # Semaphore and dispatch via asyncio.gather. Per-agent processing is
    # independent (each call does its own SVCB+cap+TXT chain), so the
    # sequential for-loop here was a real performance asymmetry vs
    # _discover_agents_in_zone — for N agents on cold DNS/HTTPS caches it
    # multiplied latency by ~N. Same Semaphore(20) cap as the DNS path.
    sem = asyncio.Semaphore(20)

    async def _process_with_sem(ha: HttpIndexAgent) -> AgentRecord | None:
        async with sem:
            return await _process_http_agent(ha, domain, protocol, name)

    tasks = [_process_with_sem(ha) for ha in http_agents]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return _collect_agent_results(results)


def _http_agent_to_record(
    http_agent: HttpIndexAgent,
    domain: str,
    dns_name: str | None = None,
    dns_protocol: Protocol | None = None,
) -> AgentRecord | None:
    """
    Convert HttpIndexAgent to AgentRecord.

    Used as fallback when DNS SVCB lookup fails.
    Protocol is extracted from FQDN by the caller; only falls back
    to http_agent.primary_protocol if not provided.
    """
    # Use caller-provided protocol (from FQDN), or fall back to HTTP index field
    if dns_protocol:
        agent_protocol = dns_protocol
    else:
        proto_str = http_agent.primary_protocol
        if not proto_str:
            return None
        try:
            agent_protocol = Protocol(proto_str.lower())
        except ValueError:
            return None

    agent_name = dns_name or http_agent.name

    # Use direct endpoint if provided in HTTP index
    if http_agent.endpoint:
        from urllib.parse import urlparse

        parsed = urlparse(http_agent.endpoint)
        target_host = parsed.netloc.split(":")[0] if parsed.netloc else domain
        port = parsed.port or 443
    else:
        # Default to domain
        target_host = domain
        port = 443

        # If FQDN is a non-standard hostname (not _agents format), use it as target
        if (
            http_agent.fqdn
            and "._agents." not in http_agent.fqdn
            and not http_agent.fqdn.startswith("_")
        ):
            target_host = http_agent.fqdn.rstrip(".")

    # Extract capabilities from HTTP index if available
    http_capabilities: list[str] = []
    cap_source: Literal["cap_uri", "agent_card", "http_index", "txt_fallback", "none"] = "none"
    if http_agent.capability and http_agent.capability.capabilities:
        http_capabilities = http_agent.capability.capabilities
        cap_source = "http_index"

    return AgentRecord(
        name=agent_name,
        domain=domain,
        protocol=agent_protocol,
        target_host=target_host,
        port=port,
        capabilities=http_capabilities,
        capability_source=cap_source,
        description=http_agent.description,
        endpoint_override=http_agent.endpoint,
        endpoint_source="http_index_fallback",
    )


def _apply_agent_card(agent: AgentRecord, card: A2AAgentCard) -> None:
    """Apply A2A Agent Card data to an agent record.

    Stores the card, wires skills → capabilities (if not already set),
    extracts endpoint paths from card metadata, and populates auth
    metadata from the card's authentication field.
    """
    agent.agent_card = card

    # Wire agent card skills → capabilities
    # agent_card is higher priority than txt_fallback and http_index,
    # so override those sources. Only cap_uri takes precedence.
    if card.skills and agent.capability_source not in ("cap_uri",):
        agent.capabilities = card.to_capabilities()
        agent.capability_source = "agent_card"
        logger.debug(
            "Capabilities from A2A Agent Card skills",
            agent=agent.name,
            capabilities=agent.capabilities,
        )

    # Extract endpoint path from card metadata if available
    endpoints = card.metadata.get("endpoints")
    if isinstance(endpoints, dict) and not agent.endpoint_override:
        protocol_key = agent.protocol.value  # "mcp", "a2a", "https"
        path = endpoints.get(protocol_key)
        if path and isinstance(path, str):
            agent.endpoint_override = f"https://{agent.target_host}:{agent.port}{path}"
            agent.endpoint_source = "dns_svcb_enriched"
            logger.debug(
                "Enriched agent endpoint from agent card",
                agent=agent.name,
                endpoint=agent.endpoint_override,
                path=path,
            )

    # Extract auth metadata from card (A2A format)
    # Only populate if not already set (DNS-AID native AuthSpec takes precedence)
    if not agent.auth_type and card.authentication and card.authentication.schemes:
        agent.auth_type = card.authentication.schemes[0]
        agent.auth_config = {"schemes": card.authentication.schemes}
        logger.debug(
            "Auth metadata from A2A Agent Card",
            agent=agent.name,
            auth_type=agent.auth_type,
        )

    # Check if card metadata contains DNS-AID native auth (aid_version present)
    # Some agents serve DNS-AID native format at agent-card.json
    if not agent.auth_type:
        _apply_auth_from_metadata(agent, card.metadata)

    logger.debug(
        "Applied A2A Agent Card to agent",
        agent=agent.name,
        card_name=card.name,
        skills_count=len(card.skills),
    )


def _apply_auth_from_metadata(agent: AgentRecord, metadata: dict) -> None:
    """Extract auth from DNS-AID native metadata (``aid_version`` discriminator).

    DNS-AID native documents embed a full ``auth`` object with ``type``,
    ``location``, ``header_name``, ``oauth_discovery``, etc.  This is
    richer than A2A's ``authentication.schemes`` list and always takes
    precedence when present.
    """
    auth_data = metadata.get("auth")
    if not isinstance(auth_data, dict):
        return

    auth_type = auth_data.get("type")
    if not auth_type or auth_type == "none":
        return

    # Validate against known auth types to prevent malicious metadata
    # from injecting arbitrary auth_type values that would only fail
    # at invocation time with a confusing error.
    from dns_aid.sdk.auth.registry import _REGISTRY, _ZTAIP_ALIASES

    normalized = _ZTAIP_ALIASES.get(str(auth_type), str(auth_type))
    if normalized not in _REGISTRY:
        logger.warning(
            "Unknown auth_type in metadata — skipping",
            agent=agent.name,
            auth_type=auth_type,
            supported=sorted(_REGISTRY.keys()),
        )
        return

    # Build auth_config from all non-type fields, excluding None values
    auth_config = {k: v for k, v in auth_data.items() if k != "type" and v is not None}

    agent.auth_type = str(auth_type)
    agent.auth_config = auth_config if auth_config else None
    logger.debug(
        "Auth metadata from DNS-AID native format",
        agent=agent.name,
        auth_type=agent.auth_type,
        config_keys=list(auth_config.keys()) if auth_config else [],
    )


async def _enrich_agents_with_endpoint_paths(agents: list[AgentRecord]) -> None:
    """
    Enrich discovered agents with data from .well-known/agent-card.json (A2A Agent Card).

    For agents without an endpoint_override, fetches .well-known/agent-card.json
    from their target host and:
    1. Extracts protocol-specific endpoint path (e.g., endpoints.mcp = "/mcp")
    2. Stores the full A2AAgentCard on the agent for skills, auth, etc.

    Modifies agents in place. Failures are silently skipped.
    """
    # Only enrich agents that don't already have an endpoint_override
    agents_to_enrich = [a for a in agents if not a.endpoint_override]
    if not agents_to_enrich:
        return

    # Apply already-fetched agent cards (from cap_uri optimization) to
    # agents that need endpoint enrichment but already have card data
    for agent in agents_to_enrich:
        if agent.agent_card:
            _apply_agent_card(agent, agent.agent_card)

    # Filter to agents still needing a fetch (no agent_card yet)
    agents_needing_fetch = [a for a in agents_to_enrich if not a.agent_card]
    if not agents_needing_fetch:
        return

    # Deduplicate by target_host to avoid redundant fetches
    hosts_to_agents: dict[str, list[AgentRecord]] = {}
    for agent in agents_needing_fetch:
        hosts_to_agents.setdefault(agent.target_host, []).append(agent)

    # Fetch .well-known/agent-card.json concurrently for all unique hosts
    async def _fetch_and_enrich(host: str, host_agents: list[AgentRecord]) -> None:
        # Use typed A2AAgentCard fetcher
        card = await fetch_agent_card(f"https://{host}")
        if card:
            for agent in host_agents:
                _apply_agent_card(agent, card)

        # If auth still not populated, try DNS-AID native .well-known/agent.json
        agents_missing_auth = [a for a in host_agents if not a.auth_type]
        if agents_missing_auth:
            auth_data = await _fetch_agent_json_auth(host)
            if auth_data:
                for agent in agents_missing_auth:
                    _apply_auth_from_metadata(agent, {"auth": auth_data})

    await asyncio.gather(
        *[_fetch_and_enrich(host, host_agents) for host, host_agents in hosts_to_agents.items()],
        return_exceptions=True,
    )


async def _fetch_agent_json_auth(host: str, timeout: float = 5.0) -> dict | None:
    """Fetch auth section from ``/.well-known/agent.json`` (DNS-AID native).

    Returns the ``auth`` dict if the document has ``aid_version`` (DNS-AID
    discriminator), *None* otherwise.  Does NOT parse the full document —
    only extracts the auth section to minimize coupling.
    """
    url = f"https://{host}/.well-known/agent.json"

    try:
        from dns_aid.utils.url_safety import UnsafeURLError, validate_fetch_url

        validate_fetch_url(url)
    except UnsafeURLError:
        return None

    try:
        from dns_aid.utils.url_safety import ResponseTooLargeError, safe_fetch_bytes

        body = await safe_fetch_bytes(url, max_bytes=100_000, timeout=timeout)
        if body is None:
            return None
        import json

        data = json.loads(body)
        if not isinstance(data, dict):
            return None
        # Discriminator: DNS-AID native documents have aid_version
        if "aid_version" not in data:
            return None
        auth = data.get("auth")
        if isinstance(auth, dict) and auth.get("type", "none") != "none":
            logger.debug("Fetched auth from agent.json", host=host, auth_type=auth.get("type"))
            return auth
    except ResponseTooLargeError:
        logger.warning("agent.json response too large — skipping", host=host)
    except Exception:
        pass
    return None


async def discover_at_fqdn(fqdn: str) -> AgentRecord | None:
    """
    Discover agent at a specific FQDN.

    Args:
        fqdn: Full DNS-AID record name (e.g., "_chat._a2a._agents.example.com")

    Returns:
        AgentRecord if found, None otherwise
    """
    # Parse FQDN to extract components
    # Format: _{name}._{protocol}._agents.{domain}
    parts = fqdn.split(".")

    if len(parts) < 4:
        logger.error("Invalid DNS-AID FQDN format", fqdn=fqdn)
        return None

    # Extract components
    name_part = parts[0]  # _name
    protocol_part = parts[1]  # _protocol

    if not name_part.startswith("_") or not protocol_part.startswith("_"):
        logger.error("Invalid DNS-AID FQDN format", fqdn=fqdn)
        return None

    name = name_part[1:]  # Remove leading underscore
    protocol_str = protocol_part[1:]  # Remove leading underscore

    # Find _agents marker to determine domain
    try:
        agents_idx = parts.index("_agents")
        domain = ".".join(parts[agents_idx + 1 :])
    except ValueError:
        logger.error("Missing _agents in FQDN", fqdn=fqdn)
        return None

    try:
        protocol = Protocol(protocol_str)
    except ValueError:
        logger.error("Unknown protocol", protocol=protocol_str)
        return None

    return await _query_single_agent(domain, name, protocol)


async def _verify_agent_signatures(
    agents: list[AgentRecord],
    domain: str,
    dnssec_validated: bool,
) -> None:
    """
    Verify JWS signatures on agents that have sig parameter but no DNSSEC.

    For each agent:
    - If DNSSEC validated: skip (stronger verification already done)
    - If has sig parameter: verify against domain's JWKS
    - Log warnings for invalid/missing signatures but don't remove agents

    Args:
        agents: List of agents to verify (modified in place with verification status)
        domain: Domain to fetch JWKS from
        dnssec_validated: Whether DNSSEC validation passed
    """
    if dnssec_validated:
        logger.debug("DNSSEC validated, skipping JWS verification")
        return

    # Find agents with signatures to verify
    agents_with_sig = [a for a in agents if a.sig]

    if not agents_with_sig:
        logger.debug("No agents with JWS signatures to verify")
        return

    logger.info(
        "Verifying JWS signatures",
        agents_count=len(agents_with_sig),
        domain=domain,
    )

    from dns_aid.core.jwks import verify_record_signature

    for agent in agents_with_sig:
        if agent.sig is None:
            continue
        try:
            is_valid, _payload = await verify_record_signature(domain, agent.sig)
            agent.signature_verified = is_valid
            agent.signature_algorithm = _extract_jws_algorithm(agent.sig) if is_valid else None

            if is_valid:
                logger.info(
                    "JWS signature verified",
                    agent=agent.name,
                    fqdn=agent.fqdn,
                    algorithm=agent.signature_algorithm,
                )
            else:
                logger.warning(
                    "JWS signature verification failed",
                    agent=agent.name,
                    fqdn=agent.fqdn,
                )
        except Exception as e:
            agent.signature_verified = False
            agent.signature_algorithm = None
            logger.warning(
                "JWS verification error",
                agent=agent.name,
                error=str(e),
            )


def _extract_jws_algorithm(jws: str) -> str | None:
    """
    Decode the JWS protected header and return the ``alg`` claim.

    Returns ``None`` when the JWS is malformed or the header lacks an ``alg``. Used by
    the verification path to surface the algorithm onto the AgentRecord so trust filters
    can apply algorithm allow-lists without re-parsing the signature.
    """
    try:
        header_b64 = jws.split(".", 1)[0]
        padding = "=" * (-len(header_b64) % 4)
        header_bytes = base64.urlsafe_b64decode(header_b64 + padding)
        header = json.loads(header_bytes)
    except (ValueError, IndexError, json.JSONDecodeError):
        return None
    alg = header.get("alg")
    if alg is None:
        return None
    return str(alg)
