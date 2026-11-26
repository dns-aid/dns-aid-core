# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""DNS backend implementations: Route53, Cloudflare, Cloud DNS, NS1, Infoblox BloxOne, Akamai EdgeDNS, DDNS, Mock."""

from __future__ import annotations

import importlib

from dns_aid.backends.base import DNSBackend
from dns_aid.backends.mock import MockBackend

__all__ = ["DNSBackend", "MockBackend", "create_backend", "VALID_BACKEND_NAMES"]

# ── Backend class registry (lazy imports) ───────────────────────────────
# Maps backend name → (module_path, class_name).
# Only the requested backend is imported, so optional deps (e.g. boto3)
# don't cause failures for users who never use that backend.
_BACKEND_CLASSES: dict[str, tuple[str, str]] = {
    "route53": ("dns_aid.backends.route53", "Route53Backend"),
    "cloudflare": ("dns_aid.backends.cloudflare", "CloudflareBackend"),
    "cloud-dns": ("dns_aid.backends.cloud_dns", "CloudDNSBackend"),
    "ns1": ("dns_aid.backends.ns1", "NS1Backend"),
    "infoblox": ("dns_aid.backends.infoblox", "InfobloxBackend"),
    "nios": ("dns_aid.backends.infoblox.nios", "InfobloxNIOSBackend"),
    "akamai-edgedns": ("dns_aid.backends.akamai_edgedns", "AkamaiEdgeDNSBackend"),
    "ddns": ("dns_aid.backends.ddns", "DDNSBackend"),
    "mock": ("dns_aid.backends.mock", "MockBackend"),
}

VALID_BACKEND_NAMES: frozenset[str] = frozenset(_BACKEND_CLASSES)
"""All recognised backend identifiers."""


def create_backend(name: str) -> DNSBackend:
    """Instantiate a DNS backend by name.

    This is the single source of truth for backend name → class mapping.
    All consumers (publisher, CLI, MCP server) should delegate here.

    Args:
        name: One of the keys in ``VALID_BACKEND_NAMES``.

    Returns:
        A ready-to-use :class:`DNSBackend` instance.

    Raises:
        ValueError: If *name* is not a known backend.
        ImportError: If the backend's optional dependency is missing.
    """
    name = name.lower().strip()
    if name not in _BACKEND_CLASSES:
        raise ValueError(
            f"Unknown backend: '{name}'. Valid backends: {', '.join(sorted(VALID_BACKEND_NAMES))}"
        )
    module_path, class_name = _BACKEND_CLASSES[name]
    module = importlib.import_module(module_path)
    cls = getattr(module, class_name)
    return cls()


# ── Eager convenience re-exports (optional deps swallowed) ──────────────

# Route53 is optional - requires boto3
try:
    from dns_aid.backends.route53 import Route53Backend  # noqa: F401

    __all__.append("Route53Backend")
except ImportError:
    pass

# Infoblox backends are optional - use httpx (already a core dep)
try:
    from dns_aid.backends.infoblox import (  # noqa: F401
        InfobloxBackend,
        InfobloxBloxOneBackend,
        InfobloxNIOSBackend,
    )

    __all__.extend(["InfobloxBackend", "InfobloxBloxOneBackend", "InfobloxNIOSBackend"])
except ImportError:
    pass

# DDNS backend - uses dnspython (already a core dep)
try:
    from dns_aid.backends.ddns import DDNSBackend  # noqa: F401

    __all__.append("DDNSBackend")
except ImportError:
    pass

# Cloudflare backend - uses httpx (already a core dep)
try:
    from dns_aid.backends.cloudflare import CloudflareBackend  # noqa: F401

    __all__.append("CloudflareBackend")
except ImportError:
    pass

# Cloud DNS backend - uses httpx + google-auth (optional)
try:
    from dns_aid.backends.cloud_dns import CloudDNSBackend  # noqa: F401

    __all__.append("CloudDNSBackend")
except ImportError:
    pass

# NS1 backend - uses httpx (already a core dep)
try:
    from dns_aid.backends.ns1 import NS1Backend  # noqa: F401

    __all__.append("NS1Backend")
except ImportError:
    pass

# Akamai Edge DNS backend - uses edgegrid-python (optional dep)
try:
    from dns_aid.backends.akamai_edgedns import AkamaiEdgeDNSBackend  # noqa: F401

    __all__.append("AkamaiEdgeDNSBackend")
except ImportError:
    pass
