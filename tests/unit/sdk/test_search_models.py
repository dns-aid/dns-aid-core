# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Tests for the typed Path B result models.

The model shapes mirror the directory's ``AgentResponse`` /
``SearchResultItem`` / ``SearchResponse`` contract. These tests pin three things:

1. **Bounds enforcement** on every score (0..100 ints) and tier (0..3).
2. **Defaults are sensible** so sparse directory output (a freshly indexed agent)
   still produces a valid model.
3. **Forward compatibility** (``extra="ignore"``) — directory schema additions
   don't break the SDK.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from dns_aid.core.models import AgentRecord, Protocol
from dns_aid.sdk.search import (
    Provenance,
    SearchResponse,
    SearchResult,
    TrustAttestation,
)


def _make_agent(name: str = "payments", domain: str = "example.com") -> AgentRecord:
    return AgentRecord(
        name=name,
        domain=domain,
        protocol=Protocol.MCP,
        target_host=f"{name}.{domain}",
        port=443,
    )


class TestTrustAttestationDefaults:
    """A freshly indexed agent (no crawl yet) must produce a valid TrustAttestation."""

    def test_constructable_with_no_args(self) -> None:
        attestation = TrustAttestation()
        assert attestation.security_score == 0
        assert attestation.trust_score == 0
        assert attestation.popularity_score == 0
        assert attestation.trust_tier == 0
        assert attestation.safety_status == "active"
        assert attestation.dnssec_valid is None
        assert attestation.dane_valid is None
        assert attestation.svcb_valid is None
        assert attestation.endpoint_reachable is None
        assert attestation.protocol_verified is None
        assert attestation.threat_flags == {}
        assert attestation.breakdown is None
        assert attestation.badges is None

    def test_full_construction(self) -> None:
        attestation = TrustAttestation(
            security_score=88,
            trust_score=91,
            popularity_score=72,
            trust_tier=2,
            safety_status="active",
            dnssec_valid=True,
            dane_valid=False,
            svcb_valid=True,
            endpoint_reachable=True,
            protocol_verified=True,
            threat_flags={"phishing": False},
            breakdown={"dnssec": 1.0, "tls_strength": 0.9},
            badges=["Verified", "DNSSEC"],
        )
        assert attestation.popularity_score == 72
        assert attestation.dane_valid is False
        assert attestation.threat_flags == {"phishing": False}
        assert attestation.badges == ["Verified", "DNSSEC"]


class TestTrustAttestationBounds:
    @pytest.mark.parametrize("score", [-1, 101, 200])
    def test_security_score_bounds(self, score: int) -> None:
        with pytest.raises(ValidationError):
            TrustAttestation(security_score=score)

    @pytest.mark.parametrize("score", [-1, 101])
    def test_trust_score_bounds(self, score: int) -> None:
        with pytest.raises(ValidationError):
            TrustAttestation(trust_score=score)

    @pytest.mark.parametrize("score", [-1, 101])
    def test_popularity_score_bounds(self, score: int) -> None:
        with pytest.raises(ValidationError):
            TrustAttestation(popularity_score=score)

    @pytest.mark.parametrize("tier", [-1, 4, 5])
    def test_trust_tier_bounds(self, tier: int) -> None:
        with pytest.raises(ValidationError):
            TrustAttestation(trust_tier=tier)

    def test_safety_status_literal_enforced(self) -> None:
        # Allowed values
        TrustAttestation(safety_status="active")
        TrustAttestation(safety_status="blocked")
        # Disallowed value
        with pytest.raises(ValidationError):
            TrustAttestation(safety_status="quarantined")  # type: ignore[arg-type]


class TestTrustAttestationImmutabilityAndForwardCompat:
    def test_immutability(self) -> None:
        attestation = TrustAttestation(security_score=80)
        with pytest.raises(ValidationError):
            attestation.security_score = 99  # type: ignore[misc]

    def test_extra_fields_ignored(self) -> None:
        # Forward compatibility: directory may add fields the SDK doesn't know about.
        attestation = TrustAttestation.model_validate(
            {
                "security_score": 80,
                "trust_score": 75,
                "popularity_score": 60,
                "trust_tier": 2,
                "safety_status": "active",
                "future_signal": "directory-side feature we don't surface yet",
            }
        )
        assert attestation.security_score == 80


class TestProvenance:
    def test_valid_construction(self) -> None:
        now = datetime.now(UTC)
        prov = Provenance(
            discovery_level=2,
            first_seen=now,
            last_seen=now,
        )
        assert prov.discovery_level == 2
        assert prov.last_verified is None
        assert prov.company is None

    def test_first_seen_and_last_seen_required(self) -> None:
        with pytest.raises(ValidationError):
            Provenance(discovery_level=1)  # type: ignore[call-arg]

    def test_discovery_level_bounds(self) -> None:
        now = datetime.now(UTC)
        with pytest.raises(ValidationError):
            Provenance(discovery_level=4, first_seen=now, last_seen=now)

    def test_company_pass_through(self) -> None:
        now = datetime.now(UTC)
        prov = Provenance(
            discovery_level=0,
            first_seen=now,
            last_seen=now,
            company={"name": "Acme", "domain": "acme.com"},
        )
        assert prov.company == {"name": "Acme", "domain": "acme.com"}


class TestSearchResult:
    def test_default_trust_attached(self) -> None:
        # No trust block supplied — model fills in a default-constructed
        # TrustAttestation rather than failing validation.
        result = SearchResult(agent=_make_agent(), score=39.2)
        assert isinstance(result.trust, TrustAttestation)
        assert result.trust.security_score == 0
        assert result.provenance is None

    def test_score_negative_rejected(self) -> None:
        with pytest.raises(ValidationError):
            SearchResult(agent=_make_agent(), score=-0.01)

    def test_raw_score_above_one_accepted(self) -> None:
        # Directory uses raw scores; we removed the <=1.0 ceiling so 39.2 is fine.
        result = SearchResult(agent=_make_agent(), score=39.2)
        assert result.score == 39.2


class TestSearchResponse:
    def _response(
        self,
        results: list[SearchResult],
        total: int,
        offset: int = 0,
        query: str | None = "payments",
    ) -> SearchResponse:
        return SearchResponse(
            query=query,
            results=results,
            total=total,
            limit=20,
            offset=offset,
        )

    def test_has_more_true_when_more_results_exist(self) -> None:
        results = [SearchResult(agent=_make_agent(name=f"a{i}"), score=0.5) for i in range(20)]
        response = self._response(results, total=50, offset=0)
        assert response.has_more is True
        assert response.next_offset == 20

    def test_has_more_false_at_last_page(self) -> None:
        results = [SearchResult(agent=_make_agent(name=f"a{i}"), score=0.5) for i in range(7)]
        response = self._response(results, total=27, offset=20)
        assert response.has_more is False
        assert response.next_offset is None

    def test_empty_results_with_zero_total(self) -> None:
        response = self._response([], total=0)
        assert response.has_more is False
        assert response.next_offset is None

    def test_query_echo_is_optional(self) -> None:
        # Some directories may not echo the query — None is allowed.
        response = self._response([], total=0, query=None)
        assert response.query is None

    def test_extra_response_fields_ignored(self) -> None:
        # Forward compatibility for the response envelope.
        response = SearchResponse.model_validate(
            {
                "query": "x",
                "results": [],
                "total": 0,
                "limit": 20,
                "offset": 0,
                "future_envelope_field": ["a", "b"],
            }
        )
        assert response.total == 0
        assert response.query == "x"
