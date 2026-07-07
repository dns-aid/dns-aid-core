# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Pure-function filter primitives for Path A discovery.

Functions in this module operate on already-enriched :class:`AgentRecord` lists returned
from DNS-substrate discovery. All filters are *post-discovery* — they run after the
discoverer has fetched cap documents, agent cards, JWKS, and verified signatures, so
predicates have access to the fully populated record.

The module is intentionally a flat collection of small functions rather than a class
hierarchy or DSL: filtering a small in-memory list is a query, not a domain object, and
list comprehensions remain the most readable expression of "select records matching X".
"""

from __future__ import annotations

from dns_aid.core.models import CATALOG_ENDPOINT_SOURCES, AgentRecord


def apply_filters(
    records: list[AgentRecord],
    *,
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
) -> list[AgentRecord]:
    """
    Return the subset of ``records`` matching every filter that is set.

    All keyword arguments are independently optional. ``None`` (or ``False`` for boolean
    filters) means "no constraint". When every filter is unset, the input list is returned
    unchanged with no allocation — the no-op fast path keeps existing callers free of
    overhead.

    Filter semantics:

    * ``capabilities`` — all-of match. Empty list matches **no** records (caller asked for
      "every capability in an empty set"; the empty constraint is treated as "explicit
      no-match" rather than vacuously true, matching the spec's edge-case guidance).
    * ``capabilities_any`` — any-of match. Empty list matches **no** records.
    * ``auth_type`` — case-insensitive exact match against ``agent.auth_type``.
    * ``intent`` — exact match against ``agent.category``; falls back to substring match
      against capabilities when ``category`` is unset.
    * ``transport`` — exact match against the agent's protocol identifier (Path A surfaces
      the agent protocol, not the underlying wire transport; see :func:`_matches_transport`).
    * ``realm`` — exact match against ``agent.realm``.
    * ``min_dnssec`` — when ``True``, a record passes only if its
      ``agent.dnssec_validated`` is True. HTTP-catalog / ARD records
      (``endpoint_source`` in ``CATALOG_ENDPOINT_SOURCES``) are exempt — they have no
      DNS SVCB record to validate (their trust is ``catalog_trust``) — so they pass
      through rather than being silently dropped.
    * ``text_match`` — case-insensitive substring match across ``description``, ``use_cases``,
      and ``capabilities``. Empty string is a programming error and raises ``ValueError``.
    * ``require_signed`` — when ``True``, only records whose JWS signature verified pass.
    * ``require_signature_algorithm`` — restrict ``require_signed`` matches to records whose
      verified signature algorithm appears in this list.

    Args:
        records: Already-enriched records returned by the discoverer.

    Returns:
        A new list containing the subset of ``records`` matching every active filter, or
        the original list if no filters are set.

    Raises:
        ValueError: ``text_match`` is the empty string, or ``require_signature_algorithm``
            is set but ``require_signed`` is False.
    """
    if text_match is not None and text_match == "":
        raise ValueError("text_match cannot be empty; use None to skip the filter")
    if require_signature_algorithm and not require_signed:
        raise ValueError("require_signature_algorithm requires require_signed=True to take effect")

    no_constraints = (
        capabilities is None
        and capabilities_any is None
        and auth_type is None
        and intent is None
        and transport is None
        and realm is None
        and not min_dnssec
        and text_match is None
        and not require_signed
        and not require_signature_algorithm
    )
    if no_constraints:
        return records

    return [
        record
        for record in records
        if _matches_capabilities_all(record, capabilities)
        and _matches_capabilities_any(record, capabilities_any)
        and _matches_auth_type(record, auth_type)
        and _matches_intent(record, intent)
        and _matches_transport(record, transport)
        and _matches_realm(record, realm)
        and _matches_min_dnssec(record, min_dnssec)
        and _matches_text(record, text_match)
        and _matches_signed(record, require_signed, require_signature_algorithm)
    ]


def _matches_capabilities_all(record: AgentRecord, required: list[str] | None) -> bool:
    if required is None:
        return True
    if not required:
        # Empty list means "explicit no-match" per spec (distinct from None = no constraint).
        return False
    record_caps = {c.lower() for c in record.capabilities}
    return all(item.lower() in record_caps for item in required)


def _matches_capabilities_any(record: AgentRecord, required_any: list[str] | None) -> bool:
    if required_any is None:
        return True
    if not required_any:
        return False
    record_caps = {c.lower() for c in record.capabilities}
    return any(item.lower() in record_caps for item in required_any)


def _matches_auth_type(record: AgentRecord, expected: str | None) -> bool:
    if expected is None:
        return True
    if record.auth_type is None:
        return False
    return record.auth_type.lower() == expected.lower()


def _matches_intent(record: AgentRecord, expected: str | None) -> bool:
    if expected is None:
        return True
    needle = expected.lower()
    if record.category and record.category.lower() == needle:
        return True
    return any(needle in cap.lower() for cap in record.capabilities)


def _matches_transport(record: AgentRecord, expected: str | None) -> bool:
    """
    Transport filter for Path A.

    Path A's ``AgentRecord`` does not surface a discrete transport field — DNS substrate
    discovery exposes the agent protocol (mcp / a2a / https), not the underlying transport
    binding (streamable-http / stdio / sse / etc.). For Path A, transport falls back to
    the protocol identifier so the same query string used in Path B (where the directory
    has full transport metadata) still semantically matches at the protocol level.
    """
    if expected is None:
        return True
    return record.protocol.value.lower() == expected.lower()


def _matches_realm(record: AgentRecord, expected: str | None) -> bool:
    if expected is None:
        return True
    return record.realm == expected


def _matches_min_dnssec(record: AgentRecord, required: bool) -> bool:
    if not required:
        return True
    # HTTP-catalog / ARD agents have no DNS SVCB owner name to validate (their trust
    # is ``catalog_trust``), so they are exempt from this filter rather than silently
    # dropped. Everything else — including unknown-provenance records — must still
    # present a DNSSEC-validated response (fail-safe).
    if record.endpoint_source in CATALOG_ENDPOINT_SOURCES:
        return True
    return record.dnssec_validated


def _matches_text(record: AgentRecord, query: str | None) -> bool:
    if query is None:
        return True
    needle = query.lower()
    haystack_parts: list[str] = []
    if record.description:
        haystack_parts.append(record.description)
    haystack_parts.extend(record.use_cases)
    haystack_parts.extend(record.capabilities)
    return any(needle in part.lower() for part in haystack_parts)


def _matches_signed(
    record: AgentRecord,
    require: bool,
    allowed_algorithms: list[str] | None,
) -> bool:
    """
    Trust gate: pass only records whose JWS signature actually verified.

    Records without a ``sig`` parameter, with a ``sig`` that did not verify, or with a
    verified algorithm not in the optional ``allowed_algorithms`` list are excluded.
    Records where verification was never attempted (``signature_verified is None``) are
    also excluded — the filter requires positive verification, not the absence of
    rejection.
    """
    if not require:
        return True
    if record.signature_verified is not True:
        return False
    if record.signature_algorithm is None:
        return False
    if allowed_algorithms:
        allowed = {algo.lower() for algo in allowed_algorithms}
        return record.signature_algorithm.lower() in allowed
    return True
