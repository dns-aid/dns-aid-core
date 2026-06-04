# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
DNS-AID Publisher: Create DNS records for AI agent discovery.

This module handles publishing agents to DNS using SVCB and TXT records
as specified in IETF draft-mozleywilliams-dnsop-dnsaid-02.
"""

from __future__ import annotations

import structlog

from dns_aid.backends import VALID_BACKEND_NAMES, create_backend
from dns_aid.backends.base import DNSBackend
from dns_aid.core.models import AgentRecord, Protocol, PublishResult
from dns_aid.utils.validation import (
    _underscore_bypass_env_enabled,
    validate_agent_name,
    validate_no_underscore_in_target,
    validate_well_known_path,
)

logger = structlog.get_logger(__name__)

# Global default backend (can be overridden)
_default_backend: DNSBackend | None = None


def set_default_backend(backend: DNSBackend) -> None:
    """Set the default DNS backend for publish operations."""
    global _default_backend
    _default_backend = backend


def reset_default_backend() -> None:
    """Reset the default backend so it will be re-initialized on next call."""
    global _default_backend
    _default_backend = None


def get_default_backend() -> DNSBackend:
    """Get the default DNS backend based on DNS_AID_BACKEND env var.

    Supported values: route53, cloudflare, ns1, infoblox, nios, ddns, mock

    Raises:
        ValueError: If DNS_AID_BACKEND is not set (no silent fallback to mock).
    """
    import os

    global _default_backend
    if _default_backend is None:
        backend_type = os.environ.get("DNS_AID_BACKEND", "").lower()

        if not backend_type:
            raise ValueError(
                "DNS_AID_BACKEND must be set. "
                f"Supported values: {', '.join(sorted(VALID_BACKEND_NAMES))}"
            )

        _default_backend = create_backend(backend_type)

        logger.info(
            "Initialized default DNS backend",
            backend=backend_type,
            backend_name=_default_backend.name,
        )
    return _default_backend


async def publish(
    name: str,
    domain: str,
    protocol: str | Protocol,
    endpoint: str,
    port: int = 443,
    capabilities: list[str] | None = None,
    version: str = "1.0.0",
    description: str | None = None,
    use_cases: list[str] | None = None,
    category: str | None = None,
    ttl: int = 3600,
    backend: DNSBackend | None = None,
    cap_uri: str | None = None,
    cap_sha256: str | None = None,
    well_known_path: str | None = None,
    bap: str | None = None,
    policy_uri: str | None = None,
    realm: str | None = None,
    connect_class: str | None = None,
    connect_meta: str | None = None,
    enroll_uri: str | None = None,
    ipv4_hint: str | None = None,
    ipv6_hint: str | None = None,
    sign: bool = False,
    private_key_path: str | None = None,
    allow_underscore_target: bool = False,
    publish_walkable_alias: bool = False,
) -> PublishResult:
    """
    Publish an AI agent to DNS using DNS-AID protocol.

    Creates SVCB and TXT records that allow other agents to discover
    this agent via DNS queries.

    Args:
        name: Agent identifier (e.g., "chat", "network-specialist")
        domain: Domain to publish under (e.g., "example.com")
        protocol: Communication protocol ("a2a", "mcp", or Protocol enum)
        endpoint: Hostname where agent is reachable
        port: Port number (default: 443)
        capabilities: List of agent capabilities
        version: Agent version string
        description: Human-readable description
        use_cases: List of use cases for this agent
        category: Agent category (e.g., "network", "security")
        ttl: DNS record TTL in seconds
        backend: DNS backend to use (defaults to global backend)
        cap_uri: URI, URN, or compact JSON-Ref locator for the capability
            descriptor (DNS-AID draft-02 'cap' SvcParamKey)
        cap_sha256: Base64url-encoded SHA-256 digest of the capability descriptor
            (DNS-AID draft-02 'cap-sha256' SvcParamKey)
        well_known_path: RFC 8615 well-known path suffix (e.g., 'agent-card.json')
            for the DNS-AID draft-02 'well-known' SvcParamKey. Independent of
            cap_uri; both may be set. Consumers prefer cap_uri when both are
            present and fall back to reconstructing
            https://<svcb-target>/.well-known/<well_known_path>.
        bap: Optional single versioned agent-protocol identifier (e.g. "mcp=2.1",
            "a2a=1.0") for the Bulk Agent Protocol SvcParamKey. Experimental per
            draft-02 §FutureWork; alpn remains the canonical protocol carrier.
            Multi-protocol agents publish multiple AgentRecord instances at the
            same flat owner name, each with its own alpn and (optionally) bap —
            NOT as a comma-separated list on a single record.
        policy_uri: URI to agent policy document
        realm: Multi-tenant scope identifier (e.g., "production")
        connect_class: Connection mediation class (e.g., "direct", "lattice", "apphub-psc")
        connect_meta: Provider-specific connection metadata (e.g., service ARN)
        enroll_uri: Managed enrollment endpoint required before direct connection
        ipv4_hint: IPv4 address hints for SVCB record (RFC 9460 key 4)
        ipv6_hint: IPv6 address hints for SVCB record (RFC 9460 key 6)
        sign: If True, sign the record with JWS (requires private_key_path)
        private_key_path: Path to EC P-256 private key PEM file for signing
        allow_underscore_target: If True, downgrade a TargetName-contains-
            underscore violation from an error to a warning. Per
            draft-mozleywilliams-dnsop-dnsaid-02 §3.2 (Known Organization, Unknown Agent), SVCB
            TargetNames reached over TLS with publicly-issued x.509 certs
            MUST NOT contain underscores. dns-aid-core enforces this by
            default; set this flag for internal-only deployments where the
            target is not behind public PKI.
        publish_walkable_alias: When True, additionally write the
            optional walkable AliasMode SVCB record at
            ``{name}._agents.{domain}`` pointing at the flat primary
            owner. Per draft-02 §3.1 this record is operator-optional.
            **Default False**: the walkable record is an enumeration
            handle — a crawler that knows the zone can walk
            ``_agents.<zone>`` and inventory every agent the operator
            publishes. For most deployments that's undesirable (see
            ``docs/privacy-considerations.md``). Set True when you
            actively want the agents discoverable by enumeration —
            internal directories, intentional public catalogs, or
            DNS-SD-style consumers.

    Returns:
        PublishResult with created records

    Example:
        >>> result = await publish(
        ...     name="network-specialist",
        ...     domain="example.com",
        ...     protocol="mcp",
        ...     endpoint="mcp.example.com",
        ...     capabilities=["ipam", "dns", "vpn"],
        ...     cap_uri="https://mcp.example.com/.well-known/agent-cap.json",
        ...     realm="production",
        ... )
        >>> print(result.agent.fqdn)
        'network-specialist.example.com'
    """
    # Normalize protocol to enum
    if isinstance(protocol, str):
        protocol = Protocol(protocol.lower())

    # Validate the agent name BEFORE the rest of the pipeline runs.
    # The flat draft-02 FQDN is `{name}.{domain}`, which becomes the
    # x.509 dNSName SAN; CA/Browser Forum + RFC 5280 forbid underscored
    # labels and the validator's lowercase+hyphenated rule lines up with
    # what most CAs and DNS providers will actually accept. Without this
    # check a publisher can land a record whose SAN is unrepresentable.
    name = validate_agent_name(name)

    # Enforce draft-02 §3.2 (Known Organization, Unknown Agent): the
    # SVCB TargetName MUST NOT contain underscores when reached over
    # TLS with a public x.509 cert. Strict-by-default; the
    # allow_underscore_target flag downgrades to a warning for
    # internal-only deployments.
    validate_no_underscore_in_target(endpoint, allow_underscore=allow_underscore_target)

    # Capture whether the bypass actually fired so we can surface it
    # on PublishResult.warnings (caller-visible, log-aggregator
    # parseable). The check is intentionally redundant with the
    # validator's WARN log: PR #154 v2 review (Igor) asked for the
    # signal as structured data, not just a log line.
    publish_warnings: list[str] = []
    if (
        allow_underscore_target
        and _underscore_bypass_env_enabled()
        and any("_" in label for label in endpoint.rstrip(".").split("."))
    ):
        publish_warnings.append("dns_aid.underscore_bypass")

    # Constrain well-known to a safe RFC 8615 single-segment suffix so
    # the publisher can't emit a SvcParamKey value that a consumer would
    # later interpolate into a non-well-known URL. Enforced on both the
    # publish and discover sides so neither end of the pipe is the
    # weakest link.
    if well_known_path is not None:
        well_known_path = validate_well_known_path(well_known_path)

    # Generate JWS signature if requested
    sig = None
    if sign:
        if not private_key_path:
            raise ValueError("private_key_path is required when sign=True")

        from dns_aid.core.jwks import (
            RecordPayload,
            load_private_key_from_pem,
            sign_record,
        )

        logger.info("Signing record with JWS", private_key_path=private_key_path)
        private_key = load_private_key_from_pem(private_key_path)
        # JWS payload binds to the flat draft-02 FQDN ({name}.{domain}).
        # Verifiers reconstruct the same FQDN before validating the signature.
        fqdn = f"{name}.{domain}"
        payload = RecordPayload.from_agent_record(
            fqdn=fqdn,
            target=endpoint,
            port=port,
            protocol=protocol.value,
            ttl_seconds=ttl,
        )
        sig = sign_record(payload, private_key)
        logger.info("Record signed successfully", fqdn=fqdn)

    # Create agent record
    agent = AgentRecord(
        name=name,
        domain=domain,
        protocol=protocol,
        target_host=endpoint,
        port=port,
        capabilities=capabilities or [],
        version=version,
        description=description,
        use_cases=use_cases or [],
        category=category,
        ttl=ttl,
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
        sig=sig,
        publish_walkable_alias=publish_walkable_alias,
    )

    # Get backend
    dns_backend = backend or get_default_backend()

    logger.info(
        "Publishing agent to DNS",
        agent_name=agent.name,
        domain=agent.domain,
        protocol=agent.protocol.value,
        fqdn=agent.fqdn,
        backend=dns_backend.name,
    )

    # Check zone exists
    if not await dns_backend.zone_exists(domain):
        logger.error("Zone does not exist", zone=domain)
        return PublishResult(
            agent=agent,
            records_created=[],
            zone=domain,
            backend=dns_backend.name,
            success=False,
            message=f"Zone '{domain}' does not exist or is not accessible",
            warnings=publish_warnings,
        )

    try:
        # Create DNS records
        records = await dns_backend.publish_agent(agent)

        logger.info(
            "Agent published successfully",
            fqdn=agent.fqdn,
            records=records,
        )

        return PublishResult(
            agent=agent,
            records_created=records,
            zone=domain,
            backend=dns_backend.name,
            success=True,
            message="Agent published successfully",
            warnings=publish_warnings,
        )

    except Exception as e:
        logger.exception("Failed to publish agent", error=str(e))
        return PublishResult(
            agent=agent,
            records_created=[],
            zone=domain,
            backend=dns_backend.name,
            success=False,
            message=f"Failed to publish: {e}",
            warnings=publish_warnings,
        )


async def unpublish(
    name: str,
    domain: str,
    protocol: str | Protocol,
    backend: DNSBackend | None = None,
) -> bool:
    """
    Remove an agent from DNS.

    Deletes both SVCB and TXT records for the agent.

    Args:
        name: Agent identifier
        domain: Domain where agent is published
        protocol: Communication protocol
        backend: DNS backend to use

    Returns:
        True if records were deleted
    """
    # Normalize protocol
    if isinstance(protocol, str):
        protocol = Protocol(protocol.lower())

    dns_backend = backend or get_default_backend()

    # Under draft-02 the agent's primary owner is the flat name; the
    # relative record name under the zone is just the agent name. We
    # also remove the optional walkable AliasMode record at
    # {name}._agents.{domain} if the publisher wrote one. To keep the
    # migration path clean for operators who published under draft-01
    # before upgrading, we additionally remove the legacy
    # _{name}._{protocol}._agents form (silent if absent).
    record_name = name
    walkable_record_name = f"{name}._agents"
    legacy_record_name = f"_{name}._{protocol.value}._agents"

    logger.info(
        "Removing agent from DNS",
        agent_name=name,
        domain=domain,
        record_name=record_name,
        walkable_record_name=walkable_record_name,
        legacy_record_name=legacy_record_name,
    )

    # Check zone exists before attempting deletion
    if not await dns_backend.zone_exists(domain):
        logger.error("Zone does not exist", zone=domain)
        return False

    # Probe the primary records BEFORE deletion so we can later
    # distinguish "primary was already absent" (migration / re-run case
    # — fine) from "primary existed and delete silently returned False"
    # (the masked-failure case Route53 and Cloudflare can produce on
    # API errors). Both look identical from delete_record's return alone,
    # but only the latter is dangerous.
    primary_svcb_existed = (await dns_backend.get_record(domain, record_name, "SVCB")) is not None
    primary_txt_existed = (await dns_backend.get_record(domain, record_name, "TXT")) is not None

    # Delete the primary-owner records (SVCB + companion TXT).
    svcb_deleted = await dns_backend.delete_record(domain, record_name, "SVCB")
    txt_deleted = await dns_backend.delete_record(domain, record_name, "TXT")

    # Delete the walkable AliasMode record if present. Log at debug on
    # failure rather than swallowing silently so backend quirks are
    # diagnosable.
    try:
        walkable_deleted = await dns_backend.delete_record(domain, walkable_record_name, "SVCB")
    except Exception as exc:
        walkable_deleted = False
        logger.debug(
            "Walkable AliasMode delete raised; treating as absent",
            walkable_record_name=walkable_record_name,
            error=str(exc),
        )

    # Also clear any leftover draft-01-shape records so operators
    # upgrading from -01 to -02 can run unpublish() once and have it
    # remove both shapes. No env flag required — the delete is a
    # silent no-op when the records don't exist.
    legacy_svcb_deleted = False
    legacy_txt_deleted = False
    try:
        legacy_svcb_deleted = await dns_backend.delete_record(domain, legacy_record_name, "SVCB")
        legacy_txt_deleted = await dns_backend.delete_record(domain, legacy_record_name, "TXT")
    except Exception as exc:
        logger.debug(
            "Legacy -01 record delete raised; treating as absent",
            legacy_record_name=legacy_record_name,
            error=str(exc),
        )

    # Decide success:
    #
    #   - "Primary deleted" — record existed and delete returned True.
    #     Unambiguous success.
    #   - "Primary already absent" — record didn't exist before the
    #     call. delete_record reported False but that's expected. If any
    #     cleanup (walkable / legacy) ran successfully we treat the
    #     unpublish as a successful migration cleanup; if nothing was
    #     deleted at all we report no-op.
    #   - "Primary masked-fail" — record DID exist before the call but
    #     delete returned False. This is the dangerous case Route53 /
    #     Cloudflare can produce on API errors. We MUST report False so
    #     the MCP server doesn't de-index a still-live agent.
    primary_existed = primary_svcb_existed or primary_txt_existed
    primary_deleted = svcb_deleted or txt_deleted
    cleanup_deleted = walkable_deleted or legacy_svcb_deleted or legacy_txt_deleted

    primary_masked_failure = primary_existed and not primary_deleted

    if primary_masked_failure:
        logger.error(
            "unpublish: primary SVCB/TXT existed but delete returned False — "
            "agent may still resolve in DNS; refusing to report success",
            agent_name=name,
            primary_svcb_existed=primary_svcb_existed,
            primary_txt_existed=primary_txt_existed,
            svcb_deleted=svcb_deleted,
            txt_deleted=txt_deleted,
        )
        return False

    success = primary_deleted or cleanup_deleted

    if success:
        logger.info(
            "Agent removed from DNS",
            agent_name=name,
            primary_deleted=primary_deleted,
            cleanup_deleted=cleanup_deleted,
            svcb_deleted=svcb_deleted,
            txt_deleted=txt_deleted,
            walkable_deleted=walkable_deleted,
            legacy_svcb_deleted=legacy_svcb_deleted,
            legacy_txt_deleted=legacy_txt_deleted,
        )
    else:
        logger.warning("No records found to delete", agent_name=name)

    return success
