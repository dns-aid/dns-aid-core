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

import os
import re
from typing import Literal

import structlog

logger = structlog.get_logger(__name__)

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

# DNS label for a DNS-AID FQDN: a normal DNS label with an optional leading
# underscore so DNS-SD/underscore-prefixed forms (``_agents``, ``_index``,
# ``_mcp``) validate alongside the flat draft-02 owner (``chat``).
FQDN_LABEL_PATTERN = re.compile(r"^_?[a-z0-9]([a-z0-9-]*[a-z0-9])?$")


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
    Validate a fully qualified domain name for DNS-AID verification.

    Accepts any well-formed DNS FQDN. Under draft-02 an agent's primary
    record lives at the flat owner ``{name}.{domain}`` (no ``_agents``
    label). The optional walkable AliasMode (``{name}._agents.{domain}``),
    the organization index (``_index._agents.{domain}``), and legacy -01
    records (``_{name}._{protocol}._agents.{domain}``) use underscored
    DNS-SD labels. All of these are valid inputs to ``verify``.

    Args:
        fqdn: The FQDN to validate

    Returns:
        Normalized FQDN (lowercased, trailing dot removed)

    Raises:
        ValidationError: If the FQDN is empty, too long, or not a
            well-formed multi-label DNS name
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

    labels = fqdn.split(".")
    if len(labels) < 2:
        raise ValidationError(
            "fqdn",
            "FQDN must have at least two labels (e.g., chat.example.com)",
            fqdn,
        )
    for label in labels:
        if len(label) > MAX_LABEL_LENGTH:
            raise ValidationError(
                "fqdn",
                f"FQDN label '{label}' exceeds {MAX_LABEL_LENGTH} characters",
                fqdn,
            )
        if not FQDN_LABEL_PATTERN.match(label):
            raise ValidationError(
                "fqdn",
                f"Invalid FQDN label '{label}': must be a DNS label "
                "(alphanumeric with hyphens, optional leading underscore)",
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


# Operator opt-in for the underscore-target bypass. A per-call kwarg /
# MCP tool arg alone would let a calling LLM flip a draft-02 §Known
# Organization MUST to a warning on its own. The env gate moves that
# decision to deployment configuration where humans land it.
_UNDERSCORE_BYPASS_ENV = "DNS_AID_ALLOW_UNDERSCORE_TARGET"


def _underscore_bypass_env_enabled() -> bool:
    return os.environ.get(_UNDERSCORE_BYPASS_ENV, "").lower() in ("1", "true", "yes")


def validate_no_underscore_in_target(
    target: str,
    *,
    allow_underscore: bool = False,
) -> str:
    """Validate that an SVCB TargetName contains no underscored DNS labels.

    Per draft-mozleywilliams-dnsop-dnsaid-02 §3.2 (Known Organization, Unknown Agent), the
    TargetName of an SVCB record reached over TLS with a publicly-issued
    x.509 certificate MUST NOT contain underscores. CA/Browser Forum
    Baseline Requirements and RFC 5280 dNSName SANs forbid underscored
    labels.

    Detects mid-label underscores too (not just leading ones); the public
    PKI rule rejects any underscore anywhere in any label of the SAN.

    The bypass (``allow_underscore=True``) is operator-gated: it only
    takes effect when ``DNS_AID_ALLOW_UNDERSCORE_TARGET`` is also set in
    the environment to a truthy value. Without the env gate the bypass
    is treated as not-allowed and the violation raises — so a calling
    LLM, MCP client, or test harness can't unilaterally downgrade the
    spec MUST. When the env gate is set, the bypass emits a structured
    WARN with ``warning_class="dns_aid.underscore_bypass"`` so log
    aggregators can count and alert on deliberate opt-ins per zone.

    Returns:
        The target string, unchanged.

    Raises:
        ValidationError: when ``target`` contains an underscored label
            and the bypass is not both requested AND env-gated.
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
        "allow_underscore=True AND set "
        f"{_UNDERSCORE_BYPASS_ENV}=1 in the environment for internal-only "
        "deployments not behind public PKI."
    )

    if allow_underscore and _underscore_bypass_env_enabled():
        logger.warning(
            "SVCB TargetName allowed despite underscored labels — "
            "internal-only deployment opt-in (allow_underscore=True + "
            f"{_UNDERSCORE_BYPASS_ENV} set)",
            target=target,
            underscored=underscored,
            cab_forbidden_chars=True,
            spec_section="draft-02 §3.2 (Known Organization, Unknown Agent)",
            warning_class="dns_aid.underscore_bypass",
            env_gate=_UNDERSCORE_BYPASS_ENV,
        )
        return target

    if allow_underscore and not _underscore_bypass_env_enabled():
        # Caller asked for the bypass but the operator hasn't enabled
        # it in the environment. Surface the refusal distinctly so the
        # caller can tell "this is an env-gate issue" from "this is a
        # genuine validation error."
        logger.warning(
            "SVCB TargetName underscore bypass requested but env gate "
            f"({_UNDERSCORE_BYPASS_ENV}) is not set — refusing",
            target=target,
            underscored=underscored,
            env_gate=_UNDERSCORE_BYPASS_ENV,
            warning_class="dns_aid.underscore_bypass_env_missing",
        )

    raise ValidationError("target", message, target)


# RFC 8615 well-known URI names are a single path segment under
# /.well-known/<name>. The IANA registry shows examples like
# ``agent-card.json``, ``oauth-authorization-server``,
# ``did-configuration``, ``change-password`` — short, ASCII-safe,
# unambiguous strings. We constrain to that class to prevent path
# traversal (`..`), query-string injection (`?`), fragment injection
# (`#`), embedded slashes, percent-encoded escapes, and any other
# character that would let an attacker steer the reconstructed URL
# off of the SVCB target host's `/.well-known/` namespace.
_WELL_KNOWN_PATH_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")
_WELL_KNOWN_PATH_MAX_LEN = 128


def validate_well_known_path(path: str) -> str:
    """Validate a `well-known` SvcParamKey value.

    Two value shapes are accepted, matching draft Figure 3:

    1. **Bare suffix** — ``agent-card.json`` →
       reconstructed as ``https://<target>/.well-known/<value>``.
       Constrained to RFC 8615 single-segment form.

    2. **Absolute origin path** — ``/.well-known/agent-card.json`` or
       ``/not-well-known/other-card.json`` →
       used as-is: ``https://<target><value>``. Each path segment is
       constrained to the same character class as the bare-suffix form;
       no ``..`` traversal, no empty segments (no ``//``), no query
       string / fragment / control characters / percent-encoded
       escapes.

    The discoverer reconstructs the descriptor URL by interpolating the
    value into a fetched URL. Without validation a publisher (or a
    SVCB-record forger if DNSSEC isn't enforced) could supply a value
    containing ``..``, ``?``, ``#``, or backslash and steer the fetch
    away from the operator's intended location. ``validate_fetch_url``
    pins the host but doesn't constrain the path.

    Allowed character class per segment: ``[A-Za-z0-9._-]``. Total
    length 1..128.

    Returns:
        The validated path (unchanged on success).

    Raises:
        ValidationError: On empty, oversize, or pattern-mismatched input.
    """
    if not isinstance(path, str) or not path:
        raise ValidationError(
            "well_known_path",
            "well-known path must be a non-empty string",
            path,
        )
    if len(path) > _WELL_KNOWN_PATH_MAX_LEN:
        raise ValidationError(
            "well_known_path",
            f"well-known path exceeds {_WELL_KNOWN_PATH_MAX_LEN} characters",
            path,
        )

    # Reject any control / URL-special character before we branch on
    # absolute vs. suffix. These are the characters that could shape
    # the reconstructed URL into something other than a path lookup
    # under the SVCB target's origin.
    for forbidden in ("?", "#", "\\", "%", " ", "\t", "\r", "\n"):
        if forbidden in path:
            raise ValidationError(
                "well_known_path",
                (
                    "well-known path must not contain URL control "
                    f"characters (found {forbidden!r}); reject any "
                    "embedded slash, '?', '#', percent-encoded "
                    "escape, or whitespace"
                ),
                path,
            )

    if path.startswith("/"):
        # Absolute origin path form. Each segment must be a clean
        # single-segment token; no ``..``, no empty segments (which
        # would produce ``//`` in the URL).
        segments = path[1:].split("/")
        if not segments or not all(segments):
            raise ValidationError(
                "well_known_path",
                "absolute well-known path must not contain empty segments",
                path,
            )
        for seg in segments:
            if seg == "..":
                raise ValidationError(
                    "well_known_path",
                    "absolute well-known path must not contain '..' (traversal)",
                    path,
                )
            if not _WELL_KNOWN_PATH_PATTERN.match(seg):
                raise ValidationError(
                    "well_known_path",
                    (
                        f"absolute well-known path segment {seg!r} must "
                        "match RFC 8615 single-segment form "
                        "(allowed: A-Z a-z 0-9 . _ - )"
                    ),
                    path,
                )
        if not any(c.isalnum() for c in path):
            raise ValidationError(
                "well_known_path",
                "well-known path must contain at least one alphanumeric character",
                path,
            )
        return path

    # Bare-suffix form.
    if not _WELL_KNOWN_PATH_PATTERN.match(path):
        raise ValidationError(
            "well_known_path",
            (
                "well-known suffix must match RFC 8615 single-segment "
                "form (allowed: A-Z a-z 0-9 . _ - ); use an absolute "
                "path starting with '/' if you need a multi-segment "
                "origin-relative value"
            ),
            path,
        )
    # `.` is in the allowed character class (needed for names like
    # `agent-card.json`), but two consecutive dots produce a path
    # traversal token. Reject explicitly. A path made entirely of
    # dots / underscores / hyphens with no alphanumeric content is
    # also nonsense and we refuse it.
    if ".." in path:
        raise ValidationError(
            "well_known_path",
            "well-known path must not contain '..' (path traversal)",
            path,
        )
    if not any(c.isalnum() for c in path):
        raise ValidationError(
            "well_known_path",
            "well-known path must contain at least one alphanumeric character",
            path,
        )
    return path


# Free-form SVCB SvcParam string fields that lack a stricter validator of
# their own: cap / cap-sha256 / policy / realm / sig / connect-meta /
# enroll-uri. The presentation-format backends emit each as key="<value>"
# verbatim, so a double quote, backslash, or control character in the value
# could break out of the quoting and inject an attacker-controlled sibling
# SvcParamKey into the authoritative record. These fields are free-form
# URIs / digests / opaque strings, so (unlike `bap`) we don't pin a shape —
# we reject only the quote-breakout character class.
_SVCPARAM_FORBIDDEN = re.compile(r'["\\\x00-\x1f\x7f]')
_SVCPARAM_MAX_LEN = 2048


def validate_svcparam_value(value: str, *, field: str = "svcparam") -> str:
    """Reject characters that could break SVCB SvcParam quoting.

    Applied to the free-form SvcParam string fields (cap, cap-sha256,
    policy, realm, sig, connect-meta, enroll-uri) that have no stricter
    validator. The backends serialize each as ``key="<value>"``, so a
    double quote, backslash, or control character could break out of the
    quoting and inject an attacker-controlled sibling SvcParamKey — the
    same server-side parameter injection that :func:`validate_bap` closes
    for ``bap``. Enforced at the model boundary so it fires on every
    construction path (publish, ``to_svcb_record()``, and discovery, where
    it also drops a forged inbound record).

    Returns the value unchanged on success.

    Raises:
        ValidationError: on a non-string, oversize, or forbidden-character
            value.
    """
    if not isinstance(value, str):
        raise ValidationError(field, f"{field} must be a string", value)
    if len(value) > _SVCPARAM_MAX_LEN:
        raise ValidationError(field, f"{field} exceeds {_SVCPARAM_MAX_LEN} characters", value)
    match = _SVCPARAM_FORBIDDEN.search(value)
    if match:
        raise ValidationError(
            field,
            (
                f"{field} contains a character that could break SVCB SvcParam "
                f"quoting ({match.group()!r}); reject double quotes, backslashes, "
                "and control characters"
            ),
            value,
        )
    return value
