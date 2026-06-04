# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for the IETF Datatracker draft-state watcher.

The watcher script lives outside the package at ``scripts/check_draft_status.py``
because it's a CI helper, not part of the shipped library. These tests
import it via importlib + path so we don't have to make ``scripts/`` a
package.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any
from unittest.mock import patch

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT_PATH = _REPO_ROOT / "scripts" / "check_draft_status.py"


def _load_watcher_module():
    spec = importlib.util.spec_from_file_location("check_draft_status", _SCRIPT_PATH)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    # Register before exec so @dataclass et al can find the module by name.
    sys.modules["check_draft_status"] = module
    spec.loader.exec_module(module)
    return module


watcher = _load_watcher_module()


# ── Fixtures: canned Datatracker responses ──────────────────────────────


def _related_doc_response(successor_slug: str | None) -> dict[str, Any]:
    """Build a /api/v1/doc/relateddocument/?target=... response."""
    if successor_slug is None:
        return {"meta": {"total_count": 0}, "objects": []}
    return {
        "meta": {"total_count": 1},
        "objects": [
            {
                "source": f"/api/v1/doc/document/{successor_slug}/",
                "target": "/api/v1/doc/document/anything/",
                "relationship": "/api/v1/name/docrelationshipname/replaces/",
            }
        ],
    }


def _doc_response(slug: str, rev: str, state_uri: str) -> dict[str, Any]:
    return {
        "objects": [
            {
                "name": slug,
                "rev": rev,
                "states": [state_uri],
                "title": "Some draft",
            }
        ]
    }


def _state_response(slug: str) -> dict[str, Any]:
    return {"slug": slug}


# ── resolve_current_slug ────────────────────────────────────────────────


def test_resolve_no_rename_returns_input():
    """If the pinned slug has no successor, resolver returns it unchanged."""
    with patch.object(
        watcher,
        "_api_get",
        return_value=_related_doc_response(successor_slug=None),
    ):
        assert (
            watcher.resolve_current_slug("draft-mozleywilliams-dnsop-dnsaid")
            == "draft-mozleywilliams-dnsop-dnsaid"
        )


def test_resolve_single_hop_rename():
    """Real-world case: bandaid → dnsaid (one replaces row, then nothing)."""
    responses = [
        _related_doc_response(successor_slug="draft-mozleywilliams-dnsop-dnsaid"),
        _related_doc_response(successor_slug=None),
    ]
    with patch.object(watcher, "_api_get", side_effect=responses):
        assert (
            watcher.resolve_current_slug("draft-mozleywilliams-dnsop-bandaid")
            == "draft-mozleywilliams-dnsop-dnsaid"
        )


def test_resolve_multi_hop_chain():
    """Real-world shape: cavage → ietf-httpbis-message-signatures →
    nothing (the WG draft is the head until it progresses to RFC,
    after which the chain still ends at the WG slug because RFCs are
    referenced by number, not by replaces)."""
    responses = [
        _related_doc_response(successor_slug="draft-ietf-httpbis-message-signatures"),
        _related_doc_response(successor_slug=None),
    ]
    with patch.object(watcher, "_api_get", side_effect=responses):
        assert (
            watcher.resolve_current_slug("draft-cavage-http-signatures")
            == "draft-ietf-httpbis-message-signatures"
        )


def test_resolve_cycle_guard():
    """Defensive: if datatracker ever returns a cycle, don't loop."""
    responses = [
        _related_doc_response(successor_slug="draft-b"),
        _related_doc_response(successor_slug="draft-a"),  # back to start
    ]
    with patch.object(watcher, "_api_get", side_effect=responses):
        # Should return without infinite loop. Whichever slug it returns
        # is acceptable; the goal is termination.
        result = watcher.resolve_current_slug("draft-a")
        assert result in {"draft-a", "draft-b"}


# ── DocState signature ──────────────────────────────────────────────────


def test_signature_is_deterministic():
    s1 = watcher.DocState(slug="foo", rev="01", state_slug="active")
    s2 = watcher.DocState(slug="foo", rev="01", state_slug="active")
    assert s1.signature() == s2.signature()


def test_signature_changes_on_any_field():
    base = watcher.DocState(slug="foo", rev="01", state_slug="active")
    rev_bump = watcher.DocState(slug="foo", rev="02", state_slug="active")
    rename = watcher.DocState(slug="bar", rev="01", state_slug="active")
    state_tx = watcher.DocState(slug="foo", rev="01", state_slug="rfc")
    assert base.signature() != rev_bump.signature()
    assert base.signature() != rename.signature()
    assert base.signature() != state_tx.signature()


# ── diff_summary ────────────────────────────────────────────────────────


def test_diff_summary_quiet_when_state_matches_pin():
    state = watcher.DocState(slug="foo", rev="01", state_slug="active")
    assert watcher.diff_summary("foo", "01", state) == []


def test_diff_summary_reports_rev_bump():
    state = watcher.DocState(slug="foo", rev="02", state_slug="active")
    notes = watcher.diff_summary("foo", "01", state)
    assert any("revision" in n.lower() and "02" in n for n in notes)


def test_diff_summary_reports_rename():
    state = watcher.DocState(slug="bar", rev="01", state_slug="active")
    notes = watcher.diff_summary("foo", "01", state)
    assert any("renamed" in n.lower() and "`bar`" in n for n in notes)


def test_diff_summary_reports_state_transition_to_rfc():
    state = watcher.DocState(slug="foo", rev="01", state_slug="rfc")
    notes = watcher.diff_summary("foo", "01", state)
    assert any("state transition" in n.lower() and "rfc" in n for n in notes)


# ── render_issue_body + signature_from_body round-trip ──────────────────


def test_issue_body_contains_signature_marker():
    state = watcher.DocState(slug="foo", rev="01", state_slug="active")
    body = watcher.render_issue_body(state, "foo", "01", keyword_findings=[])
    assert state.signature() in body
    assert watcher.signature_from_body(body) == state.signature()


def test_issue_body_includes_keyword_findings_when_present():
    state = watcher.DocState(slug="foo", rev="01", state_slug="active")
    body = watcher.render_issue_body(
        state,
        "foo",
        "01",
        keyword_findings=[("draft-someone-newthing", "A New Thing About DNS-AID")],
    )
    assert "draft-someone-newthing" in body
    assert "A New Thing About DNS-AID" in body
    assert "Possible related drafts" in body


def test_signature_from_body_returns_none_when_marker_missing():
    assert watcher.signature_from_body("no marker here") is None


# ── fetch_doc_state state classification ────────────────────────────────


def test_fetch_doc_state_picks_highest_priority_state():
    """If a doc carries both 'active' and 'rfc' state URIs, prefer 'rfc'."""
    doc_payload = _doc_response(
        slug="foo",
        rev="03",
        state_uri="/api/v1/doc/state/1/",
    )
    doc_payload["objects"][0]["states"] = [
        "/api/v1/doc/state/1/",
        "/api/v1/doc/state/2/",
    ]
    responses = [
        doc_payload,
        _state_response("active"),
        _state_response("rfc"),
    ]
    with patch.object(watcher, "_api_get", side_effect=responses):
        state = watcher.fetch_doc_state("foo")
    assert state.state_slug == "rfc"
    assert state.rev == "03"
