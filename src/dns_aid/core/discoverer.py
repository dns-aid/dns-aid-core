# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
DNS-AID Discoverer: Query DNS to find AI agents.

This module handles discovering agents via DNS queries for SVCB and TXT
records as specified in IETF draft-mozleywilliams-dnsop-dnsaid-02.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import os
import shlex
import time
from typing import Any, Literal
from urllib.parse import urlparse

import dns.asyncresolver
import dns.rdatatype
import dns.resolver
import structlog

from dns_aid.core.a2a_card import A2AAgentCard, fetch_agent_card
from dns_aid.core.cap_fetcher import fetch_cap_document
from dns_aid.core.filters import apply_filters
from dns_aid.core.http_index import HttpIndexAgent, fetch_http_index_or_empty
from dns_aid.core.models import (
    AgentRecord,
    CapabilitySource,
    DiscoveryResult,
    DNSSECError,
    Protocol,
)

logger = structlog.get_logger(__name__)

# Per-agent total-time budget for descriptor (cap / well-known) fetch.
# Slightly above fetch_cap_document's default 10s HTTP timeout so a
# normal slow response still completes, but bounds pathological cases
# (DNS hangs, TLS handshake stalls, redirect chains). Cross-agent
# bulk discovery would otherwise serialize on the slowest endpoint.
_DESCRIPTOR_FETCH_BUDGET_SECONDS: float = 12.0


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
    *,
    allow_legacy: bool | None = None,
) -> list[AgentRecord]:
    """Execute the appropriate discovery strategy and handle DNS errors."""
    try:
        if use_http_index:
            return await _discover_via_http_index(domain, protocol, name)
        elif name and protocol:
            agent = await _query_single_agent(domain, name, protocol, allow_legacy=allow_legacy)
            return [agent] if agent else []
        else:
            return await _discover_agents_in_zone(domain, protocol, allow_legacy=allow_legacy)
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

    Under draft-02's flat-FQDN model each agent has its own owner name,
    so DNSSEC is checked per agent rather than once for the zone. The
    result-level boolean returned here is True only if every agent's
    fqdn validated; per-agent state lives on ``AgentRecord.dnssec_validated``.

    Returns whether DNSSEC was validated across all agents.
    """
    per_agent_dnssec: dict[str, bool] = {}

    if agents and require_dnssec:
        from dns_aid.core.validator import _check_dnssec

        results = await asyncio.gather(
            *[_check_dnssec(a.fqdn) for a in agents],
            return_exceptions=True,
        )
        for agent, outcome in zip(agents, results, strict=True):
            ok = outcome is True
            per_agent_dnssec[agent.fqdn] = ok
            agent.dnssec_validated = ok

        if not all(per_agent_dnssec.values()):
            failed = sorted(f for f, ok in per_agent_dnssec.items() if not ok)
            raise DNSSECError(
                f"DNSSEC validation required but the following agent "
                f"FQDNs were not authenticated (AD flag not set): {failed}"
            )

    if enrich_endpoints and agents:
        try:
            await _enrich_agents_with_endpoint_paths(agents)
        except Exception:
            logger.debug("Endpoint enrichment failed (non-fatal)", exc_info=True)

    if verify_signatures and agents:
        await _verify_agent_signatures(agents, domain, dnssec_validated=per_agent_dnssec)

    return bool(per_agent_dnssec) and all(per_agent_dnssec.values())


async def discover(
    domain: str,
    protocol: str | Protocol | None = None,
    name: str | None = None,
    # draft-02 §6.2 relaxes DNSSEC to MAY by default; MUST applies only when
    # TLSA / DANE is in use (RFC 6698 §10.1). Default False matches the
    # baseline SVCB-only deployment posture. Opt-in True when the consumer
    # wants AD-flag enforcement or when records carry TLSA hints.
    require_dnssec: bool = False,
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
    allow_legacy: bool | None = None,
) -> DiscoveryResult:
    """
    Discover AI agents at a domain using DNS-AID protocol.

    Queries DNS for SVCB records under _agents.{domain} and returns discovered agent
    endpoints, optionally filtered by structured kwargs.

    Args:
        domain: Domain to search for agents (e.g., "example.com").
        protocol: Filter by protocol ("a2a", "mcp", or None for all).
        name: Filter by specific agent name (or None for all).
        require_dnssec: Require DNSSEC validation (raises if invalid). Per
            draft-02 §6.2 DNSSEC is MAY by default; consumers SHOULD set this
            to True for TLSA/DANE-bound deployments, where unsigned records
            cannot be trusted (RFC 6698 §10.1). SVCB-only deployments may
            leave this False.
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

    protocol = _normalize_protocol(protocol)

    # Build query based on filters. draft-02: the primary owner is a
    # flat FQDN ({name}.{domain}); protocol is no longer in the
    # FQDN — it lives in the bap/alpn SvcParam after resolution. The
    # organization-level index keeps the underscored shape
    # (_index._agents.{domain}) per draft-02 §Known Organization.
    if name and protocol:
        # Known-agent query: flat draft-02 form. Legacy -01 form is
        # tried as a fallback in _query_single_agent when
        # allow_legacy=True (or DNS_AID_LEGACY_01_FALLBACK=1 for
        # callers using the env-flag form). Results that came from the
        # legacy path are stamped legacy_resolved=True on the returned
        # AgentRecord.
        query = f"{name}.{domain}"
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

    agents = await _execute_discovery(
        domain, protocol, name, use_http_index, query, allow_legacy=allow_legacy
    )

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
    # Per-agent `dnssec_validated` is set inside _apply_post_discovery
    # when require_dnssec=True; no need to re-stamp at this level.

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
    *,
    allow_legacy: bool | None = None,
) -> AgentRecord | None:
    """Query DNS for a specific agent's SVCB record.

    draft-02: tries the flat FQDN ({name}.{domain}) first. If that
    returns no answer AND the caller permits legacy fallback, also tries
    the legacy -01 shape (_{name}._{protocol}._agents.{domain}) so
    consumers can still resolve publishers that haven't migrated.

    Legacy fallback is opt-in per call:

    - ``allow_legacy=True`` — fallback enabled for this call.
    - ``allow_legacy=False`` — fallback disabled regardless of env.
    - ``allow_legacy=None`` (default) — defer to the env flag
      ``DNS_AID_LEGACY_01_FALLBACK`` for backwards compatibility with
      existing deployments.

    When the legacy path serves an answer, the returned ``AgentRecord``
    has ``legacy_resolved=True`` and a warning is logged so operators
    can detect publishers that haven't migrated and downstream filters
    can down-weight legacy records.
    """
    fqdn = f"{name}.{domain}"
    legacy_fqdn: str | None = None
    if allow_legacy is True or (
        allow_legacy is None
        and os.environ.get("DNS_AID_LEGACY_01_FALLBACK", "").lower() in ("1", "true", "yes")
    ):
        legacy_fqdn = f"_{name}._{protocol.value}._agents.{domain}"
    resolved_via_legacy = False

    try:
        resolver = dns.asyncresolver.Resolver()

        # Query SVCB record. dnspython uses type 64 for SVCB.
        # draft-02: try the flat FQDN first. On NoAnswer / NXDOMAIN
        # try the legacy -01 shape if the back-compat env flag is set.
        async def _try(name_to_query: str) -> dns.resolver.Answer:
            try:
                return await resolver.resolve(name_to_query, "SVCB")
            except dns.resolver.NoAnswer:
                # HTTPS record (type 65) is the protocol-specific alias
                # of SVCB; some publishers may have used it instead.
                return await resolver.resolve(name_to_query, "HTTPS")

        try:
            answers = await _try(fqdn)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            if legacy_fqdn is None:
                return None
            try:
                logger.warning(
                    "Flat FQDN returned no answer; serving legacy -01 fallback",
                    fqdn=fqdn,
                    legacy_fqdn=legacy_fqdn,
                    note="caller will receive legacy_resolved=True on this record",
                )
                answers = await _try(legacy_fqdn)
                # Hand the legacy FQDN downstream so logging is accurate.
                fqdn = legacy_fqdn
                resolved_via_legacy = True
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
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
            well_known_path = custom_params.get("well-known")
            bap_str = custom_params.get("bap", "")
            bap = [b.strip() for b in bap_str.split(",") if b.strip()] if bap_str else []
            policy_uri = custom_params.get("policy")
            realm = custom_params.get("realm")
            connect_class = custom_params.get("connect-class")
            connect_meta = custom_params.get("connect-meta")
            enroll_uri = custom_params.get("enroll-uri")

            # Descriptor-fetch precedence (local dns-aid-core convention,
            # NOT spec-mandated — draft §6.1 names only well-known as the
            # source). When both `cap` and `well-known` are present we
            # prefer the explicit locator if it's https-fetchable; if it
            # isn't (URN, JSON-Ref, non-https scheme), we fall back to
            # the reconstructed well-known URL rather than treating the
            # non-fetchable `cap` as terminal.
            capabilities: list[str] = []
            capability_source: CapabilitySource = "none"
            agent_card = None
            cap_sha256_applied = False

            effective_descriptor_url: str | None = None
            descriptor_source_label: Literal["cap_uri", "well_known", "none"] = "none"

            # Item 3: only treat `cap` as a descriptor when it's
            # https-fetchable. The fetcher's SSRF guard would reject
            # other schemes anyway, but routing the decision here lets
            # well-known still get a chance.
            cap_is_https = cap_uri is not None and cap_uri.lower().startswith("https://")
            if cap_is_https:
                effective_descriptor_url = cap_uri
                descriptor_source_label = "cap_uri"

            # Item 4 + path validation: well-known accepts a bare RFC
            # 8615 suffix (e.g. ``agent-card.json``) or an absolute
            # origin path (e.g. ``/.well-known/agent-card.json``,
            # ``/not-well-known/other-card.json``, per draft Figure 3).
            # The validator constrains the character class on both
            # shapes so a forged SVCB can't steer the fetch off origin.
            if effective_descriptor_url is None and well_known_path:
                from dns_aid.utils.validation import (
                    ValidationError,
                    validate_well_known_path,
                )

                try:
                    safe_wk = validate_well_known_path(well_known_path)
                except ValidationError as exc:
                    logger.warning(
                        "well-known SvcParamKey rejected — skipping descriptor fetch",
                        fqdn=fqdn,
                        well_known_path=well_known_path,
                        reason=str(exc),
                    )
                    safe_wk = None

                if safe_wk:
                    # SVCB target is the host serving the well-known
                    # path. Strip any trailing dot for URL construction.
                    wk_host = target.rstrip(".")
                    if safe_wk.startswith("/"):
                        # Absolute origin path — use as-is. Draft Figure
                        # 3 includes values outside ``/.well-known/`` so
                        # we don't force a prefix here.
                        effective_descriptor_url = f"https://{wk_host}{safe_wk}"
                    else:
                        effective_descriptor_url = f"https://{wk_host}/.well-known/{safe_wk}"
                    descriptor_source_label = "well_known"

            # Non-https `cap` (URN, JSON-Ref, etc.) with no fetchable
            # well-known is a metadata-only locator: keep it on the
            # record but don't try to fetch it.
            if effective_descriptor_url is None and cap_uri is not None and not cap_is_https:
                logger.debug(
                    "cap is non-https locator and no well-known fallback — "
                    "keeping cap on record but skipping descriptor fetch",
                    fqdn=fqdn,
                    cap_uri=cap_uri,
                )

            if effective_descriptor_url:
                # Per-agent total-time budget on descriptor fetch.
                # fetch_cap_document already times out individual HTTP
                # operations, but a chain of redirects + DNS + TLS can
                # still pile up; cap the whole fetch so one slow agent
                # can't stall a bulk-discovery loop. PR #154 v2 review
                # (Igor) flagged this as a reliability item.
                from dns_aid.core.cap_fetcher import CapDigestMismatchError

                cap_doc = None
                descriptor_reachable = True
                try:
                    cap_doc = await asyncio.wait_for(
                        fetch_cap_document(effective_descriptor_url, expected_sha256=cap_sha256),
                        timeout=_DESCRIPTOR_FETCH_BUDGET_SECONDS,
                    )
                except TimeoutError:
                    descriptor_reachable = False
                    logger.warning(
                        "Descriptor fetch exceeded per-agent budget — "
                        "recording capability_source=descriptor_unreachable",
                        fqdn=fqdn,
                        descriptor_url=effective_descriptor_url,
                        budget_seconds=_DESCRIPTOR_FETCH_BUDGET_SECONDS,
                    )
                except CapDigestMismatchError as exc:
                    # Per draft §6.1: digest mismatch MUST cause us to
                    # refuse the record. Don't fall back to TXT — the
                    # operator pinned a specific document and the host
                    # served something different. Drop the record so
                    # callers don't see an integrity-pinned-looking
                    # AgentRecord whose capabilities came from elsewhere.
                    logger.warning(
                        "cap-sha256 digest mismatch — refusing record",
                        fqdn=fqdn,
                        descriptor_url=effective_descriptor_url,
                        expected=exc.expected,
                        actual=exc.actual,
                    )
                    return None

                # Reachability signal: the operator declared a descriptor
                # locator (cap or well-known) but we couldn't pull bytes
                # off the wire. Distinct from "no descriptor declared",
                # so consumers can tell transient outages from
                # mis-configurations.
                if cap_doc is None and descriptor_reachable:
                    descriptor_reachable = False
                    logger.debug(
                        "Descriptor fetch returned no document",
                        fqdn=fqdn,
                        descriptor_url=effective_descriptor_url,
                    )

                if cap_doc and cap_doc.capabilities:
                    capabilities = cap_doc.capabilities
                    capability_source = descriptor_source_label
                    # If cap_sha256 was supplied AND the fetcher accepted
                    # the bytes (didn't raise CapDigestMismatchError —
                    # see #155 fix), the integrity pin was actually
                    # applied to these bytes. Record that as a separate
                    # boolean so downstream consumers don't have to
                    # guess from the mere presence of cap_sha256.
                    if cap_sha256 is not None:
                        cap_sha256_applied = True
                    logger.debug(
                        "Capabilities fetched from descriptor URL",
                        fqdn=fqdn,
                        descriptor_url=effective_descriptor_url,
                        source=descriptor_source_label,
                        capabilities=capabilities,
                        cap_sha256_applied=cap_sha256_applied,
                    )
                elif not descriptor_reachable:
                    capability_source = "descriptor_unreachable"

                # Reuse raw data as A2AAgentCard (avoids redundant fetch later)
                if cap_doc and cap_doc.raw_data:
                    try:
                        agent_card = A2AAgentCard.from_dict(cap_doc.raw_data)
                        logger.debug(
                            "Parsed A2A Agent Card from descriptor response",
                            fqdn=fqdn,
                            descriptor_source=descriptor_source_label,
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

            # Item 6 (Igor #154 review): dangling cap_sha256. A
            # `cap_sha256` value on the SVCB combined with capabilities
            # that came from TXT or nowhere is a footgun — the pin
            # isn't covering the bytes the caller will see. We keep the
            # SvcParamKey value on the record for transparency (it tells
            # consumers the operator *intended* an integrity pin) but
            # the `cap_sha256_verified` flag clearly marks whether the
            # pin was applied. Surface the dangling case as a warning
            # for log scrapers.
            if cap_sha256 is not None and not cap_sha256_applied:
                logger.warning(
                    "cap_sha256 declared but not applied — record carries the "
                    "SvcParamKey value but the integrity pin did not cover the "
                    "capabilities returned",
                    fqdn=fqdn,
                    declared_cap_sha256=cap_sha256,
                    capability_source=capability_source,
                    warning_class="dns_aid.dangling_cap_sha256",
                )

            return AgentRecord(
                name=name,
                domain=domain,
                protocol=protocol,
                target_host=target,
                port=port,
                ipv4_hint=ipv4_hint,
                ipv6_hint=ipv6_hint,
                capabilities=capabilities,
                legacy_resolved=resolved_via_legacy,
                cap_uri=cap_uri,
                cap_sha256=cap_sha256,
                cap_sha256_verified=cap_sha256_applied,
                well_known_path=well_known_path,
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


# Derive the recognised DNS-AID SvcParamKey name set from the
# single source of truth in models.py so adding a new key in one
# place (DNS_AID_KEY_MAP) automatically updates the parser. Earlier
# this was a literal set hand-maintained here; adding `well-known`
# in #154 needed edits in three different files.
from dns_aid.core.models import DNS_AID_KEY_MAP, DNS_AID_KEY_MAP_REVERSE  # noqa: E402

_DNS_AID_KEY_NAMES: frozenset[str] = frozenset(DNS_AID_KEY_MAP.keys())


def _parse_svcb_custom_params(svcb_text: str) -> dict[str, str]:
    """Parse DNS-AID custom params from an SVCB record's text rendering.

    Accepts both human-readable string names and RFC 9460 keyNNNNN form:

    - String form: ``cap="https://..." bap="mcp,a2a" realm="demo"``
    - Numeric form: ``key65400="https://..." key65402="mcp,a2a"``

    The recognised name set is derived from
    ``dns_aid.core.models.DNS_AID_KEY_MAP`` at module load so this
    stays in lock-step with publishing.
    """
    custom_params: dict[str, str] = {}

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

        if key in _DNS_AID_KEY_NAMES:
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
    *,
    allow_legacy: bool | None = None,
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
            return await _query_single_agent(domain, name, proto, allow_legacy=allow_legacy)

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

    Thin projection over :func:`dns_aid.core.fqdn.parse_dnsaid_fqdn`
    that drops the domain component; callers needing the domain too
    should use the parent function directly.
    """
    from dns_aid.core.fqdn import parse_dnsaid_fqdn

    parsed = parse_dnsaid_fqdn(fqdn)
    if parsed is None:
        return None, None
    return parsed.name, parsed.protocol


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
    cap_source: CapabilitySource = "none"
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

    # Wire agent card skills → capabilities. Preserve higher-trust
    # provenance: cap_uri (draft §6.1 normative locator) and well_known
    # (RFC 8615 locator, also normative in -02) both record the actual
    # descriptor source. Overwriting them with "agent_card" here would
    # erase the fact that the operator declared a specific fetch path —
    # downstream consumers use capability_source for trust/audit calls.
    if card.skills and agent.capability_source not in ("cap_uri", "well_known"):
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

    Accepts any of the three DNS-AID FQDN shapes (draft-02 flat,
    draft-02 walkable, or legacy -01) and resolves the agent at it.
    When the input doesn't carry a protocol (the two draft-02 shapes),
    the discoverer attempts mcp first, then a2a.

    Args:
        fqdn: Full DNS-AID record name. Examples:
            - ``"chat.example.com"`` (draft-02 flat)
            - ``"chat._agents.example.com"`` (draft-02 walkable)
            - ``"_chat._a2a._agents.example.com"`` (legacy -01)

    Returns:
        AgentRecord if found, None otherwise.
    """
    name, protocol_str = _parse_fqdn(fqdn)
    if not name:
        logger.error("Invalid DNS-AID FQDN format", fqdn=fqdn)
        return None

    # Derive domain from the FQDN: everything after the name + any
    # walkable/legacy infix labels.
    if "._agents." in fqdn:
        domain = fqdn.split("._agents.", 1)[1]
    else:
        # Flat shape: domain is everything after the first label.
        domain = fqdn.split(".", 1)[1] if "." in fqdn else ""

    if not domain:
        logger.error("Could not extract domain from FQDN", fqdn=fqdn)
        return None

    # For the legacy form the protocol is in the FQDN; use it directly.
    if protocol_str:
        try:
            protocol = Protocol(protocol_str)
        except ValueError:
            logger.error("Unknown protocol", protocol=protocol_str)
            return None
        return await _query_single_agent(domain, name, protocol)

    # draft-02 shapes don't carry the protocol in the FQDN. The SVCB
    # DNS query is identical regardless of which Protocol we ask for —
    # only the AgentRecord.protocol field gets stamped from it — so we
    # resolve once and then read the actual protocol from the record's
    # `bap` list (preferred per draft-02 §Known Agent) or fall back to
    # the protocol kwarg if neither bap nor alpn names a known value.
    result = await _query_single_agent(domain, name, Protocol.MCP)
    if result is None:
        return None
    # Reconcile the record's protocol with what was actually announced.
    declared = next(
        (p for p in result.bap if p.strip() in {pv.value for pv in Protocol}),
        None,
    )
    if declared is not None:
        # bap may carry a value we don't model (e.g. an extension);
        # in that case leave the default in place rather than refuse
        # the record.
        with contextlib.suppress(ValueError):
            result.protocol = Protocol(declared.strip())
    return result


async def _verify_agent_signatures(
    agents: list[AgentRecord],
    domain: str,
    dnssec_validated: dict[str, bool] | bool,
) -> None:
    """
    Verify JWS signatures on agents that have sig parameter but no DNSSEC.

    Under draft-02 each agent has its own flat fqdn, so DNSSEC validation
    is also per-agent. JWS verification runs as the per-agent fallback:
    if a specific agent's owner-name validated under DNSSEC we skip JWS
    for that agent (stronger guarantee already in place); otherwise we
    fall through to JWS.

    Args:
        agents: List of agents to verify (modified in place with verification status)
        domain: Domain to fetch JWKS from
        dnssec_validated: Either a mapping of ``agent.fqdn → bool``
            (per-agent DNSSEC outcome) or a plain bool treated as a
            uniform answer for every agent. The plain-bool form is kept
            for callers that haven't migrated to the per-agent map yet.
    """
    # Normalize: plain bool → uniform-per-agent dict.
    if isinstance(dnssec_validated, bool):
        uniform = dnssec_validated
        dnssec_validated = {a.fqdn: uniform for a in agents}

    # Find agents with signatures to verify AND no DNSSEC pass.
    agents_with_sig = [a for a in agents if a.sig and not dnssec_validated.get(a.fqdn, False)]

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
            is_valid, payload = await verify_record_signature(domain, agent.sig)

            # A valid signature alone is insufficient. The signed payload
            # binds to a specific (fqdn, target, port, alpn) tuple — we
            # MUST corroborate that the record we're about to trust is
            # the one those bytes describe. Without this check an attacker
            # who lifts a legit `sig` value can paste it onto a spoofed
            # SVCB pointing at their own host and the discoverer would
            # still stamp signature_verified=True.
            #
            # Publisher-side reference: core/publisher.py builds the
            # payload from name+domain (flat fqdn), endpoint (= target_host),
            # port, and protocol.value. Compare to the same fields here.
            payload_matches = (
                is_valid
                and payload is not None
                and payload.fqdn == agent.fqdn
                and payload.target == agent.target_host
                and payload.port == agent.port
                and payload.alpn == agent.protocol.value
            )

            agent.signature_verified = payload_matches
            agent.signature_algorithm = (
                _extract_jws_algorithm(agent.sig) if payload_matches else None
            )

            if payload_matches:
                logger.info(
                    "JWS signature verified",
                    agent=agent.name,
                    fqdn=agent.fqdn,
                    algorithm=agent.signature_algorithm,
                )
            elif is_valid:
                logger.warning(
                    "JWS signature cryptographically valid but does not bind to record",
                    agent=agent.name,
                    fqdn=agent.fqdn,
                    payload_fqdn=getattr(payload, "fqdn", None),
                    payload_target=getattr(payload, "target", None),
                    payload_port=getattr(payload, "port", None),
                    payload_alpn=getattr(payload, "alpn", None),
                    record_target=agent.target_host,
                    record_port=agent.port,
                    record_alpn=agent.protocol.value,
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
