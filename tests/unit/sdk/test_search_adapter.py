# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Tests for ``_adapt_search_payload`` — the wire-shape adapter that bridges the
directory's flat ``AgentResponse`` to the SDK's typed ``SearchResult.trust`` /
``SearchResult.provenance`` nested objects, plus the small AgentRecord shape
quirks (``target_host`` from ``endpoint_url``, legacy comma-separated or
list-shaped ``bap`` values collapsed to the draft-02 scalar form).

The adapter is the *only* place in the SDK that knows about the directory's
wire shape. If the directory schema drifts, every other piece of SDK code
should keep working as long as this adapter and the typed models stay in sync.
That makes the adapter a load-bearing piece worth testing in isolation.
"""

from __future__ import annotations

from typing import Any

from dns_aid.sdk.client import _adapt_search_payload
from dns_aid.sdk.search import SearchResponse


def _directory_agent(**overrides: Any) -> dict[str, Any]:
    """Minimal directory-shaped agent payload with all required-ish identity fields."""
    base: dict[str, Any] = {
        "fqdn": "_payments._mcp._agents.example.com",
        "name": "payments",
        "domain": "example.com",
        "protocol": "mcp",
        "endpoint_url": "https://payments.example.com",
        "port": 443,
        "first_seen": "2026-04-01T00:00:00Z",
        "last_seen": "2026-05-01T00:00:00Z",
    }
    base.update(overrides)
    return base


def _directory_response(agent: dict[str, Any], score: float = 39.2) -> dict[str, Any]:
    return {
        "query": "payments",
        "results": [{"agent": agent, "score": score}],
        "total": 1,
        "limit": 20,
        "offset": 0,
    }


class TestTrustSignalLifting:
    def test_full_trust_block_is_lifted(self) -> None:
        agent = _directory_agent(
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
            trust_breakdown={"dnssec": 1.0},
            trust_badges=["Verified"],
        )
        payload = _adapt_search_payload(_directory_response(agent))

        result = payload["results"][0]
        assert "security_score" not in result["agent"]
        assert "trust_breakdown" not in result["agent"]
        trust = result["trust"]
        assert trust["security_score"] == 88
        assert trust["trust_score"] == 91
        assert trust["popularity_score"] == 72
        assert trust["trust_tier"] == 2
        assert trust["safety_status"] == "active"
        assert trust["dnssec_valid"] is True
        assert trust["dane_valid"] is False
        assert trust["threat_flags"] == {"phishing": False}
        # Renamed: ``trust_breakdown`` (directory) → ``breakdown`` (SDK).
        assert trust["breakdown"] == {"dnssec": 1.0}
        # Renamed: ``trust_badges`` (directory) → ``badges`` (SDK).
        assert trust["badges"] == ["Verified"]

    def test_sparse_agent_uses_defaults(self) -> None:
        # Directory may return an agent with no trust signals computed yet.
        agent = _directory_agent()
        payload = _adapt_search_payload(_directory_response(agent))
        trust = payload["results"][0]["trust"]
        assert trust["security_score"] == 0
        assert trust["trust_score"] == 0
        assert trust["popularity_score"] == 0
        assert trust["trust_tier"] == 0
        assert trust["safety_status"] == "active"
        assert trust["dnssec_valid"] is None

    def test_pre_existing_trust_block_is_preserved(self) -> None:
        # If a caller (e.g. a test) supplies a pre-built trust block, the
        # adapter must NOT clobber it. ``setdefault`` semantics.
        body = _directory_response(_directory_agent(security_score=99))
        body["results"][0]["trust"] = {
            "security_score": 50,
            "trust_score": 50,
            "popularity_score": 50,
        }
        payload = _adapt_search_payload(body)
        # Caller-supplied block wins; agent-side ``security_score=99`` ignored.
        assert payload["results"][0]["trust"]["security_score"] == 50


class TestProvenanceLifting:
    def test_provenance_lifted_when_first_seen_present(self) -> None:
        agent = _directory_agent(
            discovery_level=2,
            last_verified="2026-04-30T00:00:00Z",
            company={"name": "Acme"},
        )
        payload = _adapt_search_payload(_directory_response(agent))
        prov = payload["results"][0]["provenance"]
        assert prov["discovery_level"] == 2
        assert prov["first_seen"] == "2026-04-01T00:00:00Z"
        assert prov["last_seen"] == "2026-05-01T00:00:00Z"
        assert prov["last_verified"] == "2026-04-30T00:00:00Z"
        assert prov["company"] == {"name": "Acme"}

    def test_provenance_skipped_when_neither_timestamp_present(self) -> None:
        # An agent with no ``first_seen``/``last_seen`` is malformed by directory
        # contract — but the adapter should refuse to fabricate provenance for
        # it rather than producing a zero-value Provenance object.
        agent = {
            "fqdn": "_x._mcp._agents.example.com",
            "name": "x",
            "domain": "example.com",
            "protocol": "mcp",
            "endpoint_url": "https://x.example.com",
            "port": 443,
        }
        payload = _adapt_search_payload(_directory_response(agent))
        assert "provenance" not in payload["results"][0]


class TestAgentShapeQuirks:
    def test_target_host_derived_from_endpoint_url(self) -> None:
        agent = _directory_agent(endpoint_url="https://flex.twilio.com:8443/path")
        payload = _adapt_search_payload(_directory_response(agent))
        assert payload["results"][0]["agent"]["target_host"] == "flex.twilio.com"

    def test_target_host_unchanged_if_already_set(self) -> None:
        # If an upstream caller (or a future directory version) supplies
        # ``target_host`` directly, the adapter must not overwrite it.
        agent = _directory_agent(target_host="explicit.example.com")
        payload = _adapt_search_payload(_directory_response(agent))
        assert payload["results"][0]["agent"]["target_host"] == "explicit.example.com"

    def test_record_dropped_when_endpoint_url_missing(self) -> None:
        # When the directory has neither ``target_host`` nor a parseable
        # ``endpoint_url``, the record is DROPPED rather than fabricated. The
        # SDK never invents an endpoint a caller might invoke. ``total`` is
        # adjusted so pagination stays consistent.
        agent = _directory_agent(endpoint_url=None)
        body = _directory_response(agent)
        original_total = body["total"]
        payload = _adapt_search_payload(body)
        assert payload["results"] == []
        assert payload["total"] == max(0, original_total - 1)

    def test_record_dropped_when_endpoint_url_unparseable(self) -> None:
        # Garbage ``endpoint_url`` (no scheme, no hostname) → no derivable host
        # → record dropped.
        agent = _directory_agent(endpoint_url="not-a-url")
        body = _directory_response(agent)
        payload = _adapt_search_payload(body)
        assert payload["results"] == []

    def test_drop_logs_warning_with_agent_identity(self) -> None:
        from structlog.testing import capture_logs

        agent = _directory_agent(endpoint_url=None)
        with capture_logs() as cap:
            _adapt_search_payload(_directory_response(agent))

        # The WARN must carry enough identity so an operator can correlate the
        # drop back to a specific directory record. ``fqdn`` + ``name`` + ``domain``
        # are all present on every directory agent, so we assert all three made it
        # into the log event.
        skip_events = [e for e in cap if e.get("event") == "sdk.search_record_skipped"]
        assert len(skip_events) == 1
        event = skip_events[0]
        assert event["log_level"] == "warning"
        assert event["fqdn"] == "_payments._mcp._agents.example.com"
        assert event["name"] == "payments"
        assert event["domain"] == "example.com"
        assert event["reason"] == "no_derivable_target_host"

    def test_bap_comma_separated_collapsed_to_first(self) -> None:
        """Pre-draft-02 directory rows may serialize bap as a comma-separated
        string. The adapter collapses to the first (versioned) protocol per
        draft-02 §FutureWork (Bulk Agent Protocol) — bap is scalar."""
        agent = _directory_agent(bap="mcp/1, a2a/1 ,https/1")
        payload = _adapt_search_payload(_directory_response(agent))
        assert payload["results"][0]["agent"]["bap"] == "mcp/1"

    def test_bap_scalar_passes_through_unchanged(self) -> None:
        """A scalar bap string (the draft-02 shape) passes through unchanged."""
        agent = _directory_agent(bap="mcp2.1")
        payload = _adapt_search_payload(_directory_response(agent))
        assert payload["results"][0]["agent"]["bap"] == "mcp2.1"

    def test_bap_legacy_list_collapsed_to_first(self) -> None:
        """A legacy directory row that serializes bap as a list also collapses."""
        agent = _directory_agent(bap=["mcp/1", "a2a/1"])
        payload = _adapt_search_payload(_directory_response(agent))
        assert payload["results"][0]["agent"]["bap"] == "mcp/1"


class TestExplicitNullStripping:
    """The directory writes ``null`` for some fields the SDK types as non-Optional.

    Stripping the key lets Pydantic apply the field's declared default (e.g.
    ``capabilities: list = []``, ``version: str = "1.0.0"``). Without this
    coercion, a real-world agent record with ``"capabilities": null`` would fail
    validation and abort the entire search response.
    """

    def test_null_capabilities_stripped(self) -> None:
        agent = _directory_agent(capabilities=None)
        payload = _adapt_search_payload(_directory_response(agent))
        assert "capabilities" not in payload["results"][0]["agent"]

    def test_null_version_stripped(self) -> None:
        agent = _directory_agent(version=None)
        payload = _adapt_search_payload(_directory_response(agent))
        assert "version" not in payload["results"][0]["agent"]

    def test_null_bap_stripped(self) -> None:
        agent = _directory_agent(bap=None)
        payload = _adapt_search_payload(_directory_response(agent))
        assert "bap" not in payload["results"][0]["agent"]

    def test_null_use_cases_stripped(self) -> None:
        agent = _directory_agent(use_cases=None)
        payload = _adapt_search_payload(_directory_response(agent))
        assert "use_cases" not in payload["results"][0]["agent"]

    def test_non_null_values_preserved(self) -> None:
        agent = _directory_agent(
            capabilities=["a", "b"],
            version="2.0",
            bap="mcp/1",
            use_cases=["x"],
        )
        payload = _adapt_search_payload(_directory_response(agent))
        result_agent = payload["results"][0]["agent"]
        assert result_agent["capabilities"] == ["a", "b"]
        assert result_agent["version"] == "2.0"
        # bap is scalar under draft-02 §FutureWork; the adapter passes a
        # bare string through unchanged.
        assert result_agent["bap"] == "mcp/1"
        assert result_agent["use_cases"] == ["x"]


class TestEndToEndValidation:
    """The adapter output must be parseable by SearchResponse end-to-end."""

    def test_full_directory_response_parses_to_typed_search_response(self) -> None:
        agent = _directory_agent(
            security_score=97,
            trust_score=75,
            popularity_score=99,
            trust_tier=2,
            bap="mcp/1,a2a/1",
            trust_badges=["Verified"],
            discovery_level=2,
        )
        payload = _adapt_search_payload(_directory_response(agent, score=39.2))
        response = SearchResponse.model_validate(payload)

        assert response.query == "payments"
        assert response.total == 1
        assert len(response.results) == 1
        result = response.results[0]
        assert result.agent.target_host == "payments.example.com"
        # bap=`mcp/1,a2a/1` is the legacy directory shape; the adapter
        # collapses to the first value under draft-02 §FutureWork.
        assert result.agent.bap == "mcp/1"
        assert result.score == 39.2
        assert result.trust.security_score == 97
        assert result.trust.popularity_score == 99
        assert result.trust.badges == ["Verified"]
        assert result.provenance is not None
        assert result.provenance.discovery_level == 2

    def test_empty_results_array_returns_unchanged(self) -> None:
        body = {"query": "x", "results": [], "total": 0, "limit": 20, "offset": 0}
        payload = _adapt_search_payload(body)
        response = SearchResponse.model_validate(payload)
        assert response.results == []

    def test_malformed_results_field_is_left_alone(self) -> None:
        # If ``results`` is not a list (e.g. directory broken / proxy ate the
        # body), the adapter must not crash — it returns the payload as-is so
        # the typed validator can raise the proper structured error.
        body = {"query": "x", "results": "not-a-list"}
        payload = _adapt_search_payload(body)
        assert payload["results"] == "not-a-list"


class TestSearchResilience:
    """The adapter must NOT break when the directory returns sparse records.

    A freshly indexed agent (just observed, no crawl yet) might have only
    name / domain / protocol / endpoint_url / first_seen / last_seen — and
    nothing else. The SDK's job is to surface what's there, not insist on
    a fully populated record.
    """

    def test_minimal_record_parses_to_valid_search_result(self) -> None:
        # Directory contract: only fqdn, name, domain, protocol, first_seen,
        # last_seen are required. ``endpoint_url`` is optional but we need it
        # (or target_host) to construct an AgentRecord.
        minimal_agent = {
            "fqdn": "_minimal._mcp._agents.example.com",
            "name": "minimal",
            "domain": "example.com",
            "protocol": "mcp",
            "endpoint_url": "https://minimal.example.com",
            "first_seen": "2026-04-01T00:00:00Z",
            "last_seen": "2026-05-01T00:00:00Z",
        }
        body = {
            "query": "minimal",
            "results": [{"agent": minimal_agent, "score": 1.0}],
            "total": 1,
            "limit": 20,
            "offset": 0,
        }
        payload = _adapt_search_payload(body)
        response = SearchResponse.model_validate(payload)

        assert len(response.results) == 1
        result = response.results[0]
        # Identity preserved.
        assert result.agent.name == "minimal"
        assert result.agent.target_host == "minimal.example.com"
        # Everything else fell back to defaults — no crash.
        assert result.agent.capabilities == []
        assert result.agent.bap is None
        assert result.agent.description is None
        # Trust attestation built from defaults.
        assert result.trust.security_score == 0
        assert result.trust.trust_score == 0
        assert result.trust.dnssec_valid is None
        # Provenance built from required first_seen / last_seen.
        assert result.provenance is not None
        assert result.provenance.discovery_level == 0

    def test_mixed_complete_and_incomplete_records(self) -> None:
        # The directory returns 3 agents: two complete, one missing endpoint_url.
        # The adapter must keep the two and drop the third — total adjusted.
        complete_a = _directory_agent(name="a", endpoint_url="https://a.example.com")
        complete_b = _directory_agent(name="b", endpoint_url="https://b.example.com")
        incomplete = _directory_agent(name="c", endpoint_url=None)
        body = {
            "query": "x",
            "results": [
                {"agent": complete_a, "score": 1.0},
                {"agent": incomplete, "score": 0.9},
                {"agent": complete_b, "score": 0.8},
            ],
            "total": 3,
            "limit": 20,
            "offset": 0,
        }
        payload = _adapt_search_payload(body)
        response = SearchResponse.model_validate(payload)

        assert [r.agent.name for r in response.results] == ["a", "b"]
        # ``total`` reduced by the number dropped — pagination stays honest.
        assert response.total == 2

    def test_field_with_value_zero_is_not_stripped(self) -> None:
        # ``0`` is falsy but it's a meaningful default for score fields. Make
        # sure the null-stripping pass distinguishes ``None`` from ``0`` /
        # ``""`` / ``[]``.
        agent = _directory_agent(security_score=0, trust_score=0, popularity_score=0)
        payload = _adapt_search_payload(_directory_response(agent))
        trust = payload["results"][0]["trust"]
        assert trust["security_score"] == 0
        assert trust["trust_score"] == 0
        assert trust["popularity_score"] == 0
