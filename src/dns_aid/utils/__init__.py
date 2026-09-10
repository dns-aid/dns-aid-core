# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Utility functions: logging, config, helpers, validation."""

from dns_aid.utils.validation import (
    ValidationError,
    sanitize_discovered_capabilities,
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

__all__ = [
    "ValidationError",
    "sanitize_discovered_capabilities",
    "validate_agent_name",
    "validate_backend",
    "validate_capabilities",
    "validate_domain",
    "validate_endpoint",
    "validate_fqdn",
    "validate_port",
    "validate_protocol",
    "validate_ttl",
    "validate_version",
]
