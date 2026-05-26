# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Path A filter robustness tests — every filter must survive a minimally-populated
``AgentRecord`` without crashing.

Path A search runs in pure Python over already-fetched DNS substrate data. Some
agents in real DNS zones will have only the bare minimum fields the discoverer
could resolve (no description, no use_cases, no realm, no auth_type, no JWS).
The filter pipeline has to:

1. Never raise on a sparse record — at worst, it filters the record out.
2. Treat absent fields the same as ``None`` (no constraint match) for filter
   purposes — never as truthy / matching.
3. Compose filters with logical AND — a sparse record matches a filter only
   when *that filter's* condition is met, never by accident through other
   missing fields.

These tests are independent of any network/DNS — they exercise the pure
:func:`dns_aid.core.filters.apply_filters` over hand-built records.
"""

from __future__ import annotations

import pytest

from dns_aid.core.filters import apply_filters
from dns_aid.core.models import AgentRecord, Protocol


def _minimal_agent(name: str = "minimal") -> AgentRecord:
    """An agent with only the four required AgentRecord fields. Everything else
    falls to its declared default (None / [] / False / 443)."""
    return AgentRecord(
        name=name,
        domain="example.com",
        protocol=Protocol.MCP,
        target_host=f"{name}.example.com",
    )


def _full_agent() -> AgentRecord:
    """Agent with every filterable field populated."""
    return AgentRecord(
        name="full",
        domain="example.com",
        protocol=Protocol.MCP,
        target_host="full.example.com",
        capabilities=["payment-processing", "fraud-detection"],
        description="Process card payments and fraud heuristics.",
        use_cases=["B2B payments", "Subscription billing"],
        category="finance",
        auth_type="oauth2",
        realm="prod",
        sig="hdr.payload.sig",
        signature_verified=True,
        signature_algorithm="ES256",
        dnssec_validated=True,
    )


class TestEveryFilterSurvivesMinimalAgent:
    """Exercise every public filter against a sparse record — none must raise."""

    def test_capabilities_all_against_empty_capabilities(self) -> None:
        result = apply_filters([_minimal_agent()], capabilities=["payment-processing"])
        assert result == []  # required cap absent → filtered out, not crashed

    def test_capabilities_any_against_empty_capabilities(self) -> None:
        result = apply_filters([_minimal_agent()], capabilities_any=["search"])
        assert result == []

    def test_auth_type_against_none(self) -> None:
        result = apply_filters([_minimal_agent()], auth_type="oauth2")
        assert result == []

    def test_intent_against_none_category(self) -> None:
        # Sparse agent has no category and no capabilities — substring scan
        # over an empty list correctly returns False.
        result = apply_filters([_minimal_agent()], intent="transaction")
        assert result == []

    def test_realm_against_none(self) -> None:
        result = apply_filters([_minimal_agent()], realm="prod")
        assert result == []

    def test_min_dnssec_against_default_false(self) -> None:
        # ``dnssec_validated`` defaults to False; min_dnssec=True excludes.
        result = apply_filters([_minimal_agent()], min_dnssec=True)
        assert result == []

    def test_text_match_against_none_description(self) -> None:
        # Description is None, use_cases empty, capabilities empty → no
        # haystack to scan; returns False without raising.
        result = apply_filters([_minimal_agent()], text_match="payment")
        assert result == []

    def test_require_signed_against_unsigned(self) -> None:
        # No sig field at all → signature_verified is None → filter excludes.
        result = apply_filters([_minimal_agent()], require_signed=True)
        assert result == []

    def test_require_signature_algorithm_requires_require_signed(self) -> None:
        with pytest.raises(ValueError, match="require_signed=True"):
            apply_filters([_minimal_agent()], require_signature_algorithm=["ES256"])

    def test_no_filters_returns_input_unchanged(self) -> None:
        # Sparse agent + no constraints = passthrough.
        agents = [_minimal_agent()]
        assert apply_filters(agents) is agents


class TestSparseAndFullCompose:
    """Mixed lists: sparse agents shouldn't 'leak' through filters meant to
    select on populated metadata, and full agents shouldn't be filtered out
    by accident due to None handling on adjacent records.
    """

    def test_filter_targeting_full_excludes_sparse(self) -> None:
        result = apply_filters(
            [_minimal_agent(), _full_agent()],
            capabilities=["payment-processing"],
        )
        assert [a.name for a in result] == ["full"]

    def test_filter_targeting_sparse_traits_excludes_full(self) -> None:
        # ``realm=None`` doesn't have a way to filter for "no realm" — there's
        # no inverse filter — so this just confirms ``realm="prod"`` selects
        # only the full agent and doesn't accidentally match the sparse one.
        result = apply_filters([_minimal_agent(), _full_agent()], realm="prod")
        assert [a.name for a in result] == ["full"]

    def test_compound_filter_requires_all_conditions(self) -> None:
        # AND semantics: full agent passes; sparse fails on every condition.
        result = apply_filters(
            [_minimal_agent(), _full_agent()],
            auth_type="oauth2",
            realm="prod",
            require_signed=True,
            require_signature_algorithm=["ES256"],
        )
        assert [a.name for a in result] == ["full"]


class TestEdgeCaseInputs:
    def test_empty_record_list_returns_empty(self) -> None:
        assert apply_filters([], capabilities=["x"]) == []
        assert apply_filters([]) == []

    def test_text_match_empty_string_raises(self) -> None:
        with pytest.raises(ValueError, match="text_match cannot be empty"):
            apply_filters([_minimal_agent()], text_match="")

    def test_capabilities_empty_list_means_explicit_no_match(self) -> None:
        # Per spec: empty list ≠ None. None means "no constraint" (passthrough);
        # empty list means "every cap in an empty set" which is vacuously true
        # in math but explicitly defined as no-match in our contract. Confirms
        # the filter doesn't fall back to vacuous-true semantics.
        result = apply_filters([_full_agent()], capabilities=[])
        assert result == []

    def test_capabilities_any_empty_list_means_explicit_no_match(self) -> None:
        result = apply_filters([_full_agent()], capabilities_any=[])
        assert result == []

    def test_case_insensitive_matching_across_filters(self) -> None:
        # capabilities, auth_type, intent, text_match all do case-insensitive
        # comparisons — verify with mixed-case query inputs.
        result = apply_filters(
            [_full_agent()],
            capabilities=["Payment-Processing"],
            auth_type="OAuth2",
            text_match="FRAUD",
        )
        assert [a.name for a in result] == ["full"]
