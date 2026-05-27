# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Input validation utilities for DNS-AID.

Provides validation and sanitization for domain names, agent names,
and other user inputs. Used to prevent injection attacks and ensure
compliance with DNS naming standards.

Security Note:
    All user-provided inputs should be validated before use in DNS operations.
    This module is designed to pass security scanners (Wiz, SonarQube, Bandit).
"""

from __future__ import annotations

import re
from typing import Literal

# DNS label constraints (RFC 1035)
MAX_LABEL_LENGTH = 63
MAX_DOMAIN_LENGTH = 253
MIN_LABEL_LENGTH = 1

# Agent name pattern: lowercase alphanumeric with hyphens
AGENT_NAME_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

# Domain name pattern (RFC 1035 compliant)
DOMAIN_LABEL_PATTERN = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")

# Safe characters for capabilities
CAPABILITY_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")

# Supported provider mediation classes and their token grammar
CONNECT_CLASS_PATTERN = re.compile(r"^[a-z0-9-]{1,64}$")
KNOWN_CONNECT_CLASSES = frozenset({"direct", "lattice", "apphub-psc"})

# Version pattern (semver-like, supports pre-release and build metadata)
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+([a-zA-Z0-9._+-]*)?$")


class ValidationError(ValueError):
    """Raised when input validation fails."""

    def __init__(self, field: str, message: str, value: str | None = None):
        self.field = field
        self.message = message
        self.value = value
        super().__init__(f"{field}: {message}")


def validate_agent_name(name: str) -> str:
    """
    Validate and normalize an agent name.

    Agent names must be:
    - 1-63 characters long
    - Lowercase alphanumeric with hyphens
    - Cannot start or end with a hyphen

    Args:
        name: The agent name to validate

    Returns:
        Normalized (lowercase) agent name

    Raises:
        ValidationError: If the name is invalid
    """
    if not name:
        raise ValidationError("name", "Agent name cannot be empty")

    # Normalize to lowercase
    name = name.lower().strip()

    if len(name) > MAX_LABEL_LENGTH:
        raise ValidationError(
            "name",
            f"Agent name cannot exceed {MAX_LABEL_LENGTH} characters",
            name,
        )

    if len(name) < MIN_LABEL_LENGTH:
        raise ValidationError("name", "Agent name cannot be empty", name)

    if not AGENT_NAME_PATTERN.match(name):
        raise ValidationError(
            "name",
            "Agent name must be lowercase alphanumeric with hyphens, "
            "cannot start or end with hyphen",
            name,
        )

    return name


def validate_domain(domain: str) -> str:
    """
    Validate and normalize a domain name.

    Domain names must be:
    - Valid DNS domain format (RFC 1035)
    - Each label 1-63 characters
    - Total length <= 253 characters
    - Only alphanumeric and hyphens in labels

    Args:
        domain: The domain name to validate

    Returns:
        Normalized domain name (lowercase, no trailing dot)

    Raises:
        ValidationError: If the domain is invalid
    """
    if not domain:
        raise ValidationError("domain", "Domain cannot be empty")

    # Normalize: lowercase, remove trailing dot
    domain = domain.lower().strip().rstrip(".")

    if len(domain) > MAX_DOMAIN_LENGTH:
        raise ValidationError(
            "domain",
            f"Domain cannot exceed {MAX_DOMAIN_LENGTH} characters",
            domain,
        )

    # Validate each label
    labels = domain.split(".")

    if len(labels) < 2:
        raise ValidationError(
            "domain",
            "Domain must have at least two labels (e.g., example.com)",
            domain,
        )

    for label in labels:
        if not label:
            raise ValidationError("domain", "Domain labels cannot be empty", domain)

        if len(label) > MAX_LABEL_LENGTH:
            raise ValidationError(
                "domain",
                f"Domain label '{label}' exceeds {MAX_LABEL_LENGTH} characters",
                domain,
            )

        if not DOMAIN_LABEL_PATTERN.match(label):
            raise ValidationError(
                "domain",
                f"Invalid domain label '{label}': must be alphanumeric with hyphens, "
                "cannot start or end with hyphen",
                domain,
            )

    return domain


def validate_protocol(protocol: str) -> Literal["mcp", "a2a"]:
    """
    Validate protocol type.

    Args:
        protocol: Protocol string to validate

    Returns:
        Validated protocol literal

    Raises:
        ValidationError: If protocol is invalid
    """
    if not protocol:
        raise ValidationError("protocol", "Protocol cannot be empty")

    protocol = protocol.lower().strip()

    if protocol not in ("mcp", "a2a"):
        raise ValidationError(
            "protocol",
            "Protocol must be 'mcp' or 'a2a'",
            protocol,
        )

    return protocol  # type: ignore


def validate_connect_class(connect_class: str | None) -> str | None:
    """
    Validate and normalize the DNS-AID connect-class token.

    Args:
        connect_class: Connection mediation class or ``None``

    Returns:
        Normalized mediation class or ``None``

    Raises:
        ValidationError: If the token is malformed or unsupported
    """
    if connect_class is None:
        return None

    normalized = connect_class.strip().lower()
    if not normalized:
        return None

    if not CONNECT_CLASS_PATTERN.match(normalized):
        raise ValidationError(
            "connect_class",
            "connect_class must contain only lowercase letters, digits, and hyphens",
            connect_class,
        )

    if normalized not in KNOWN_CONNECT_CLASSES:
        raise ValidationError(
            "connect_class",
            f"connect_class must be one of: {', '.join(sorted(KNOWN_CONNECT_CLASSES))}",
            connect_class,
        )

    return normalized


def validate_endpoint(endpoint: str) -> str:
    """
    Validate endpoint hostname.

    Args:
        endpoint: Hostname where agent is reachable

    Returns:
        Validated endpoint

    Raises:
        ValidationError: If endpoint is invalid
    """
    if not endpoint:
        raise ValidationError("endpoint", "Endpoint cannot be empty")

    endpoint = endpoint.lower().strip().rstrip(".")

    # Endpoint should be a valid hostname (same rules as domain)
    if len(endpoint) > MAX_DOMAIN_LENGTH:
        raise ValidationError(
            "endpoint",
            f"Endpoint cannot exceed {MAX_DOMAIN_LENGTH} characters",
            endpoint,
        )

    labels = endpoint.split(".")

    for label in labels:
        if not label:
            raise ValidationError("endpoint", "Endpoint labels cannot be empty", endpoint)

        if len(label) > MAX_LABEL_LENGTH:
            raise ValidationError(
                "endpoint",
                f"Endpoint label '{label}' exceeds {MAX_LABEL_LENGTH} characters",
                endpoint,
            )

        if not DOMAIN_LABEL_PATTERN.match(label):
            raise ValidationError(
                "endpoint",
                f"Invalid endpoint label '{label}'",
                endpoint,
            )

    return endpoint


def validate_port(port: int) -> int:
    """
    Validate port number.

    Args:
        port: Port number to validate

    Returns:
        Validated port number

    Raises:
        ValidationError: If port is invalid
    """
    if not isinstance(port, int):
        raise ValidationError("port", "Port must be an integer", str(port))

    if port < 1 or port > 65535:
        raise ValidationError(
            "port",
            "Port must be between 1 and 65535",
            str(port),
        )

    return port


def validate_ttl(ttl: int) -> int:
    """
    Validate DNS TTL value.

    Args:
        ttl: TTL value in seconds

    Returns:
        Validated TTL

    Raises:
        ValidationError: If TTL is invalid
    """
    if not isinstance(ttl, int):
        raise ValidationError("ttl", "TTL must be an integer", str(ttl))

    # Minimum 30 seconds, maximum 1 week
    if ttl < 30:
        raise ValidationError("ttl", "TTL must be at least 30 seconds", str(ttl))

    if ttl > 604800:  # 7 days
        raise ValidationError("ttl", "TTL cannot exceed 604800 seconds (7 days)", str(ttl))

    return ttl


def validate_capabilities(capabilities: list[str] | None) -> list[str]:
    """
    Validate list of capabilities.

    Args:
        capabilities: List of capability strings

    Returns:
        Validated list of capabilities

    Raises:
        ValidationError: If any capability is invalid
    """
    if not capabilities:
        return []

    validated = []
    seen = set()

    for cap in capabilities:
        if not cap:
            continue

        cap = cap.strip().lower()

        if not CAPABILITY_PATTERN.match(cap):
            raise ValidationError(
                "capabilities",
                f"Invalid capability '{cap}': must be alphanumeric with hyphens/underscores, "
                "max 64 characters",
                cap,
            )

        if cap not in seen:
            validated.append(cap)
            seen.add(cap)

    return validated


def validate_version(version: str) -> str:
    """
    Validate version string.

    Args:
        version: Version string (semver format)

    Returns:
        Validated version string

    Raises:
        ValidationError: If version is invalid
    """
    if not version:
        raise ValidationError("version", "Version cannot be empty")

    version = version.strip()

    if not VERSION_PATTERN.match(version):
        raise ValidationError(
            "version",
            "Version must be in semver format (e.g., 1.0.0)",
            version,
        )

    return version


def validate_fqdn(fqdn: str) -> str:
    """
    Validate a fully qualified domain name for DNS-AID records.

    DNS-AID FQDNs follow the pattern: _{agent}._{protocol}._agents.{domain}

    Args:
        fqdn: The FQDN to validate

    Returns:
        Normalized FQDN

    Raises:
        ValidationError: If FQDN is invalid
    """
    if not fqdn:
        raise ValidationError("fqdn", "FQDN cannot be empty")

    fqdn = fqdn.lower().strip().rstrip(".")

    if len(fqdn) > MAX_DOMAIN_LENGTH:
        raise ValidationError(
            "fqdn",
            f"FQDN cannot exceed {MAX_DOMAIN_LENGTH} characters",
            fqdn,
        )

    # DNS-AID records should contain _agents
    if "_agents" not in fqdn:
        raise ValidationError(
            "fqdn",
            "Invalid DNS-AID FQDN: must contain '_agents'",
            fqdn,
        )

    return fqdn


def validate_backend(
    backend: str,
) -> str:
    """
    Validate backend type.

    Args:
        backend: Backend string to validate

    Returns:
        Validated backend name

    Raises:
        ValidationError: If backend is invalid
    """
    from dns_aid.backends import VALID_BACKEND_NAMES

    if not backend:
        raise ValidationError("backend", "Backend cannot be empty")

    backend = backend.lower().strip()

    if backend not in VALID_BACKEND_NAMES:
        raise ValidationError(
            "backend",
            f"Backend must be one of: {', '.join(sorted(VALID_BACKEND_NAMES))}",
            backend,
        )

    return backend


def validate_no_underscore_in_target(
    target: str,
    *,
    allow_underscore: bool = False,
) -> str:
    """
    Validate that an SVCB TargetName contains no underscored DNS labels.

    Per draft-mozleywilliams-dnsop-dnsaid-02 §Known Organization, the
    TargetName of an SVCB record that will be reached over TLS with a
    publicly-issued x.509 certificate MUST NOT contain underscores. The
    constraint exists because CA/Browser Forum Baseline Requirements and
    RFC 5280 dNSName SANs both forbid underscored labels.

    dns-aid-core applies this rule to all SVCB TargetNames on its publish
    paths by default. Deployments where the target is internal-only and
    will not be reached via public PKI (for example, a sandbox or
    inside-the-perimeter service identified by a private CA-issued cert)
    can pass ``allow_underscore=True`` to downgrade the failure into a
    warning that is logged but not raised. The validator is still called
    in that case so the log surfaces the deliberate exception.

    Args:
        target: The SVCB TargetName host (e.g. ``"chat.example.com"`` or
            ``"agent-index.example.com."``). Trailing dots are tolerated.
        allow_underscore: When True, downgrade a violation to a warning
            log line and return the (unchanged) target instead of
            raising.

    Returns:
        The target string, unchanged. (Returns rather than mutating so
        callers can chain the call into existing pipelines.)

    Raises:
        ValidationError: If ``target`` contains a label starting with or
            consisting of an underscore and ``allow_underscore`` is
            False.

    Examples:
        >>> validate_no_underscore_in_target("agent-index.example.com")
        'agent-index.example.com'
        >>> validate_no_underscore_in_target("_index.example.com")
        Traceback (most recent call last):
            ...
        ValidationError: ...
        >>> validate_no_underscore_in_target("_index.example.com", allow_underscore=True)
        '_index.example.com'
    """
    if not target:
        raise ValidationError("target", "SVCB TargetName cannot be empty")

    # Strip a trailing dot if present — the constraint applies to labels,
    # not to the FQDN root marker.
    candidate = target.rstrip(".")
    labels = candidate.split(".")
    underscored = [label for label in labels if "_" in label]

    if not underscored:
        return target

    message = (
        f"SVCB TargetName '{target}' contains underscored label(s) "
        f"{underscored!r}. CA/Browser Forum and RFC 5280 dNSName SANs forbid "
        "underscored labels, so a publicly-issued x.509 cert cannot cover "
        "this name. Per draft-mozleywilliams-dnsop-dnsaid-02 §Known "
        "Organization the TargetName MUST NOT contain underscores. Pass "
        "allow_underscore=True if this target is internal-only and will "
        "not be reached via public PKI."
    )

    if allow_underscore:
        import logging

        logging.getLogger(__name__).warning(message)
        return target

    raise ValidationError("target", message, target)
