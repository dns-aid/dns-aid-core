# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
ARD catalog DNS pointer — publish and resolve.

This implements the DNS discovery channel for an ARD ai-catalog
(https://agenticresourcediscovery.org/spec/ §6.1) in DNS-AID's own terms.
A domain advertises *where* its agent catalog lives via SVCB records under
two DNS-SD labels:

- ``_index._agents.{domain}`` — DNS-AID's own organizational-index pointer
  (draft-mozleywilliams-dnsop-dnsaid-02 §3.2 "Known Organization"), whose
  index *format* the draft leaves out of scope — an ARD catalog is one valid
  payload.
- ``_catalog._agents.{domain}`` — ARD §6.1's catalog pointer label.

Publishing both ("dual") makes the catalog discoverable to DNS-AID clients
(which probe ``_index._agents``) and to ARD-native clients (which probe
``_catalog._agents``) from a single DNS lookup.

The SVCB target is the catalog host (underscore-free, carries a public
x.509 cert, TLSA-pinnable per draft-02 §Known Organization). The catalog
path defaults to ARD's fixed well-known location
``/.well-known/ai-catalog.json``; a non-default filename may be carried in
the DNS-AID ``well-known`` SvcParamKey (key65409).

Resolution is authoritative for *location only*: it returns a catalog URL
which the caller fetches and parses (:func:`dns_aid.core.http_index.parse_http_index`
auto-detects the ARD format). No catalog content is trusted here.
"""

from __future__ import annotations

import asyncio
import ipaddress

import dns.asyncresolver
import dns.resolver
import structlog

from dns_aid.backends.base import DNSBackend
from dns_aid.core.models import SVCB_SERVICE_MODE
from dns_aid.core.publisher import get_default_backend
from dns_aid.utils.url_safety import UnsafeURLError, validate_fetch_url
from dns_aid.utils.validation import (
    validate_no_underscore_in_target,
    validate_svcparam_value,
    validate_well_known_path,
)

logger = structlog.get_logger(__name__)

# DNS-SD labels probed for a catalog pointer, in resolution precedence order.
# ``_catalog`` (ARD-specific, unambiguous) is tried before ``_index``
# (DNS-AID's generic org-index slot, which may point at a non-ARD index).
CATALOG_POINTER_LABELS: tuple[str, ...] = ("_catalog._agents", "_index._agents")

# ARD's fixed well-known catalog location (the filename under /.well-known/).
DEFAULT_CATALOG_FILENAME = "ai-catalog.json"

# DNS-AID ``well-known`` SvcParamKey (numeric wire form; see DNS_AID_KEY_MAP).
_WELL_KNOWN_KEY = 65409

DEFAULT_RESOLVE_TIMEOUT = 5.0

# Cap SVCB records inspected per resolution (across both labels). An attacker
# who controls a domain's DNS could publish a large SVCB RRset; each record
# otherwise triggers a (DNS-resolving) SSRF validation, so bound the work.
_MAX_POINTER_RECORDS = 4

# Per-URL SSRF-validation budget. validate_fetch_url does a blocking
# getaddrinfo with no timeout of its own; bound it so a slow/blackholed
# authoritative server for the target host can't stall discovery.
_VALIDATE_TIMEOUT = 3.0


async def _resolve_svcb(
    resolver: dns.asyncresolver.Resolver, fqdn: str
) -> dns.resolver.Answer | None:
    """Resolve a SVCB record (with HTTPS/type-65 fallback), None if absent."""
    try:
        return await resolver.resolve(fqdn, "SVCB")
    except dns.resolver.NoAnswer:
        try:
            return await resolver.resolve(fqdn, "HTTPS")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return None
    except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
        return None


def _read_wellknown_filename(rdata: object) -> str | None:
    """Read an optional catalog-filename override from the well-known SvcParam.

    Runs the decoded value through the SAME validator the publish side uses
    (``validate_well_known_path`` — RFC 8615 single-segment, length-bounded,
    control-char / separator / traversal rejecting) so a forged inbound SVCB
    can't push an oversized or control-laden path into the URL. Returns None
    (→ caller uses the default filename) on any non-conforming value.
    """
    params = getattr(rdata, "params", None) or {}
    param = params.get(_WELL_KNOWN_KEY)
    if param is None:
        return None
    value = getattr(param, "value", param)
    if isinstance(value, (bytes, bytearray)):
        try:
            text = value.decode("utf-8", "strict")
        except UnicodeDecodeError:
            return None
    else:
        text = str(value)
    try:
        return validate_well_known_path(text.strip().lstrip("/"))
    except Exception:  # noqa: BLE001 — any invalid value → fall back to default
        return None


async def resolve_catalog_pointer(
    domain: str, *, timeout: float = DEFAULT_RESOLVE_TIMEOUT
) -> str | None:
    """Resolve a domain's ARD catalog URL from its DNS pointer records.

    Tries ``_catalog._agents.{domain}`` then ``_index._agents.{domain}``
    SVCB and, on the first ServiceMode answer with a usable target, returns
    ``https://{target}/.well-known/{filename}``. Returns ``None`` when no
    pointer is published (the caller then falls back to well-known probing).

    Location discovery only — the returned URL is fetched and format-detected
    by the caller; nothing about the catalog's contents is trusted here.
    """
    domain = domain.lower().rstrip(".")
    resolver = dns.asyncresolver.Resolver()
    resolver.lifetime = timeout
    records_seen = 0

    for label in CATALOG_POINTER_LABELS:
        fqdn = f"{label}.{domain}"
        try:
            answers = await _resolve_svcb(resolver, fqdn)
        except Exception as e:  # noqa: BLE001 — resolution must never break discovery
            logger.debug("catalog_pointer.resolve_error", fqdn=fqdn, error=str(e))
            continue
        if answers is None:
            continue
        for rdata in answers:
            # Bound total records inspected — a hostile large SVCB RRset must
            # not fan out into unbounded SSRF-validation work.
            if records_seen >= _MAX_POINTER_RECORDS:
                logger.warning(
                    "catalog_pointer.records_capped", domain=domain, cap=_MAX_POINTER_RECORDS
                )
                return None
            records_seen += 1

            # AliasMode (priority 0) does not carry a target endpoint here.
            if getattr(rdata, "priority", SVCB_SERVICE_MODE) == 0:
                continue
            target = str(getattr(rdata, "target", "")).rstrip(".")
            if not target or target == ".":
                continue
            filename = _read_wellknown_filename(rdata) or DEFAULT_CATALOG_FILENAME
            url = f"https://{target}/.well-known/{filename}"
            # SSRF guard: a pointer targets an arbitrary host (host-anywhere),
            # so reject one that resolves to a private/loopback/link-local/
            # reserved address before we fetch it. On rejection (or any
            # validation error — getaddrinfo can raise beyond gaierror), skip
            # this pointer and fall through to the queried domain's well-known
            # paths (inherently safe). Runs off-loop under a time budget so a
            # slow authoritative server for the target can't stall discovery.
            # NOTE: this validates the host's CURRENT resolution; a DNS-rebinding
            # attacker (TTL 0) could still return a different IP at httpx connect
            # time — a limitation shared with all validate_fetch_url callers, to
            # be closed globally by a pinned-IP transport.
            try:
                await asyncio.wait_for(
                    asyncio.to_thread(validate_fetch_url, url), timeout=_VALIDATE_TIMEOUT
                )
            except UnsafeURLError as e:
                logger.warning(
                    "catalog_pointer.unsafe_target",
                    domain=domain,
                    label=label,
                    url=url,
                    error=str(e),
                )
                continue
            except Exception as e:  # noqa: BLE001 — never break discovery on validation error
                logger.warning(
                    "catalog_pointer.validation_error",
                    domain=domain,
                    label=label,
                    url=url,
                    error=str(e),
                )
                continue
            logger.info("catalog_pointer.resolved", domain=domain, label=label, url=url)
            return url
    return None


async def _existing_svcb_target(backend: DNSBackend, zone: str, name: str) -> str | None:
    """Return the current SVCB target host at ``name`` in ``zone``, or None.

    Used to avoid clobbering an existing org-index pointer. Best-effort:
    on any backend error, returns None (treated as "no existing record").
    """
    try:
        record = await backend.get_record(zone, name, "SVCB")
    except Exception as e:  # noqa: BLE001 — a read failure must not block publish
        logger.debug("catalog_pointer.existing_read_error", zone=zone, name=name, error=str(e))
        return None
    if not record:
        return None
    values = record.get("values") or []
    if not values:
        return None
    # SVCB presentation: "<priority> <target> [params...]" — target is token 1.
    tokens = str(values[0]).split()
    if len(tokens) < 2:
        return None
    return tokens[1].rstrip(".").lower()


async def publish_catalog_pointer(
    domain: str,
    catalog_host: str,
    *,
    filename: str = DEFAULT_CATALOG_FILENAME,
    labels: tuple[str, ...] = CATALOG_POINTER_LABELS,
    backend: DNSBackend | None = None,
    ttl: int = 3600,
    port: int = 443,
    alpn: str = "h2",
    ipv4_hint: str | None = None,
    ipv6_hint: str | None = None,
    force_index: bool = False,
) -> list[str]:
    """Publish ARD catalog pointer SVCB records for a domain.

    Writes a ServiceMode SVCB record under each label in ``labels`` (default
    both ``_catalog._agents`` and ``_index._agents``) pointing at
    ``catalog_host``. The catalog path is ARD's fixed
    ``/.well-known/ai-catalog.json`` unless ``filename`` overrides it, in
    which case the filename is carried in the ``well-known`` SvcParamKey.

    ``ipv4_hint``/``ipv6_hint`` add RFC 9460 address hints — a per-request
    latency optimization that pins the catalog host's IPs in DNS. Only safe
    for a fixed-IP origin; OMIT for CDN-fronted catalogs (e.g. CloudFront),
    whose edge IPs rotate and would make the hint stale. Default off.

    Note: ``_index._agents`` is DNS-AID's generic org-index pointer; it may
    already be owned by the domain's indexer. To avoid silently repointing an
    existing org index, this refuses to overwrite an ``_index._agents`` SVCB
    that already points at a DIFFERENT target — it logs a warning and skips
    that label (still publishing ``_catalog._agents``). Pass
    ``force_index=True`` to replace it anyway, or ``labels=("_catalog._agents",)``
    to publish only the ARD-specific label.

    Returns the list of created FQDNs. Raises ValueError if the zone does
    not exist or an address hint is malformed; the catalog host must not
    contain underscored labels (it carries a public x.509 cert, per
    draft-02 §Known Organization).
    """
    domain = domain.lower().rstrip(".")
    validate_no_underscore_in_target(catalog_host)
    filename = validate_well_known_path(filename)
    # SvcParam quote-breakout guard — alpn is otherwise emitted verbatim as
    # key="value" by the backend, so a value with a quote could inject a
    # sibling SvcParamKey into the authoritative record.
    alpn = validate_svcparam_value(alpn, field="alpn")

    dns_backend = backend or get_default_backend()
    if not await dns_backend.zone_exists(domain):
        raise ValueError(f"Zone '{domain}' does not exist")

    target = catalog_host if catalog_host.endswith(".") else f"{catalog_host}."
    params: dict[str, str] = {"alpn": alpn, "port": str(port)}
    if ipv4_hint is not None:
        if ipaddress.ip_address(ipv4_hint).version != 4:
            raise ValueError(f"ipv4_hint is not an IPv4 address: {ipv4_hint}")
        params["ipv4hint"] = ipv4_hint
    if ipv6_hint is not None:
        if ipaddress.ip_address(ipv6_hint).version != 6:
            raise ValueError(f"ipv6_hint is not an IPv6 address: {ipv6_hint}")
        params["ipv6hint"] = ipv6_hint
    if filename != DEFAULT_CATALOG_FILENAME:
        # Numeric key form for backends that don't take private-use string keys.
        params[f"key{_WELL_KNOWN_KEY}"] = filename

    written: list[str] = []
    for label in labels:
        # Anti-clobber: never silently replace an existing _index._agents
        # pointer that targets a different host (it may be a live org index).
        if label == "_index._agents" and not force_index:
            existing = await _existing_svcb_target(dns_backend, domain, label)
            if existing is not None and existing != target.rstrip("."):
                logger.warning(
                    "catalog_pointer.index_pointer_preserved",
                    domain=domain,
                    existing_target=existing,
                    would_be_target=target.rstrip("."),
                    hint="pass force_index=True to replace, or ignore to keep the existing index",
                )
                continue

        fqdn = await dns_backend.create_svcb_record(
            zone=domain,
            name=label,
            priority=SVCB_SERVICE_MODE,
            target=target,
            params=dict(params),
            ttl=ttl,
        )
        written.append(fqdn)
        logger.info(
            "catalog_pointer.published",
            domain=domain,
            label=label,
            target=target,
            filename=filename,
        )
    return written
