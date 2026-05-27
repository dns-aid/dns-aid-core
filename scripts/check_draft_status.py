#!/usr/bin/env python3
# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0
"""IETF Datatracker draft-state watcher for dns-aid-core.

Queries the public Datatracker API for the slug pinned in
``.github/draft-tracking.json``, follows any ``replaces`` chain forward
to the current head slug, compares revision / state / slug against the
pinned values, and (when run with ``--manage-issue``) maintains a single
canonical GitHub tracking issue via the ``gh`` CLI.

Pure stdlib. Designed to be called from a PR-triggered workflow that
never blocks merge — the script always exits 0; the durable signal lives
in the tracking issue.

Local smoke test:

    python3 scripts/check_draft_status.py --smoke-test

That mode prints the resolved current state without performing any
issue operations and exits 0 regardless of findings.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DATATRACKER_BASE = "https://datatracker.ietf.org"
DEFAULT_CONFIG_PATH = Path(".github/draft-tracking.json")
DEFAULT_ISSUE_TITLE = "[draft-watch] IETF DNS-AID draft state"
SIGNATURE_MARKER_PREFIX = "<!-- draft-watch:signature="
SIGNATURE_MARKER_SUFFIX = " -->"


@dataclass(frozen=True)
class DocState:
    slug: str
    rev: str
    state_slug: str  # e.g. "active", "rfc", "expired", "replaced"

    def signature(self) -> str:
        raw = f"{self.slug}|{self.rev}|{self.state_slug}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


def _api_get(path: str) -> dict[str, Any]:
    """GET a Datatracker API path; return parsed JSON.

    Raises on non-2xx. Path must start with ``/api/v1/`` or be an absolute
    URL. The endpoint is public so no auth is needed.
    """
    if path.startswith("/"):
        url = DATATRACKER_BASE + path
    else:
        url = path
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 — public API
        return json.loads(resp.read().decode("utf-8"))


def resolve_current_slug(starting_slug: str, max_hops: int = 10) -> str:
    """Walk the ``replaces`` chain forward from ``starting_slug``.

    Returns the head slug (the one not replaced by anything else). The
    relationship is filed on the successor side per Datatracker's data
    model — query ``target__name=<current>`` and look for the row whose
    ``source`` points at the successor.
    """
    current = starting_slug
    seen: set[str] = {current}
    for _ in range(max_hops):
        params = urllib.parse.urlencode(
            {
                "target__name": current,
                "relationship__slug": "replaces",
                "format": "json",
            }
        )
        data = _api_get(f"/api/v1/doc/relateddocument/?{params}")
        objects = data.get("objects", [])
        if not objects:
            return current
        # source is a URI like /api/v1/doc/document/<slug>/
        successor_uri: str = objects[0]["source"]
        successor = successor_uri.rstrip("/").rsplit("/", 1)[-1]
        if successor in seen:
            # Cycle guard — would only happen if datatracker data is
            # malformed; return what we have and let the human review.
            return current
        seen.add(successor)
        current = successor
    return current


def fetch_doc_state(slug: str) -> DocState:
    """Fetch ``rev`` and a primary ``state_slug`` for ``slug``.

    Datatracker documents carry multiple state URIs (one per state-type).
    For Internet-Drafts the relevant one is type=draft. We pick the most
    specific state slug we recognize; fall back to "unknown".
    """
    params = urllib.parse.urlencode({"name": slug, "format": "json"})
    data = _api_get(f"/api/v1/doc/document/?{params}")
    objects = data.get("objects", [])
    if not objects:
        raise RuntimeError(f"Datatracker has no document named {slug!r}")
    doc = objects[0]
    rev = str(doc.get("rev") or "")
    state_uris: list[str] = doc.get("states") or []
    state_slug = _classify_state(state_uris)
    return DocState(slug=slug, rev=rev, state_slug=state_slug)


_STATE_PRIORITY = ("rfc", "replaced", "expired", "active", "withdrawn")


def _classify_state(state_uris: list[str]) -> str:
    """Pick the most-meaningful state slug from a list of state URIs.

    Datatracker state URIs look like ``/api/v1/doc/state/<id>/``. We hit
    each one once and read its ``slug`` field. Then pick by priority so
    "rfc" wins over "active" if a doc carries both.
    """
    found: set[str] = set()
    for uri in state_uris:
        try:
            data = _api_get(uri)
            slug = str(data.get("slug") or "").lower()
            if slug:
                found.add(slug)
        except urllib.error.URLError:
            continue
    for candidate in _STATE_PRIORITY:
        if candidate in found:
            return candidate
    return next(iter(found), "unknown")


def keyword_sweep(
    author_person_id: int, keywords: list[str], exclude_slug: str
) -> list[tuple[str, str]]:
    """Return (slug, title) tuples for active drafts authored by the
    given Datatracker Person ID whose title matches any keyword and
    whose slug is not ``exclude_slug``.

    Safety net for the case where a successor was filed without a
    ``replaces`` relationship.
    """
    params = urllib.parse.urlencode(
        {
            "person": author_person_id,
            "document__type": "draft",
            "format": "json",
            "limit": 100,
        }
    )
    data = _api_get(f"/api/v1/doc/documentauthor/?{params}")
    findings: list[tuple[str, str]] = []
    lower_keywords = [k.lower() for k in keywords]
    for entry in data.get("objects", []):
        doc_uri: str = entry["document"]
        # doc_uri is /api/v1/doc/document/<slug>/
        slug = doc_uri.rstrip("/").rsplit("/", 1)[-1]
        if slug == exclude_slug:
            continue
        try:
            doc = _api_get(doc_uri)
        except urllib.error.URLError:
            continue
        # Only consider active drafts; skip expired/replaced/rfc ones for
        # this sweep — they're noise.
        state_slug = _classify_state(doc.get("states") or [])
        if state_slug != "active":
            continue
        title = str(doc.get("title") or "")
        lower_title = title.lower()
        if any(kw in lower_title for kw in lower_keywords):
            findings.append((slug, title))
    return findings


# ── Issue management via gh CLI ─────────────────────────────────────────


def _gh(args: list[str], *, repo: str | None = None) -> str:
    cmd = ["gh"]
    if repo:
        cmd += ["--repo", repo]
    cmd += args
    result = subprocess.run(  # noqa: S603 — controlled args
        cmd, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def _gh_safe(args: list[str], *, repo: str | None = None) -> str | None:
    """Best-effort ``gh`` invocation for issue operations.

    Returns stdout on success, or ``None`` if the call fails for any
    reason — including the common case of a fork-PR running with a
    read-only ``GITHUB_TOKEN`` (where ``gh issue create/edit/comment``
    will be rejected with HTTP 403 regardless of declared
    ``permissions:``). The watcher is designed to be informational and
    must never block merge, so all failures are logged and swallowed.
    """
    try:
        return _gh(args, repo=repo)
    except (RuntimeError, FileNotFoundError, OSError) as exc:
        print(f"[draft-watch] gh {' '.join(args[:2])} skipped: {exc}")
        return None


def find_tracking_issue(title: str, repo: str | None = None) -> dict[str, Any] | None:
    """Return the latest issue matching ``title`` exactly (open or
    closed), or None. Uses ``gh issue list`` with a state=all filter.
    """
    out = _gh_safe(
        [
            "issue",
            "list",
            "--state",
            "all",
            "--search",
            f'in:title "{title}"',
            "--json",
            "number,title,state,body",
            "--limit",
            "10",
        ],
        repo=repo,
    )
    if out is None:
        return None
    candidates: list[dict[str, Any]] = json.loads(out)
    for issue in candidates:
        if issue.get("title") == title:
            return issue
    return None


def signature_from_body(body: str) -> str | None:
    marker_start = body.find(SIGNATURE_MARKER_PREFIX)
    if marker_start == -1:
        return None
    after = body[marker_start + len(SIGNATURE_MARKER_PREFIX) :]
    marker_end = after.find(SIGNATURE_MARKER_SUFFIX)
    if marker_end == -1:
        return None
    return after[:marker_end].strip()


def render_issue_body(
    state: DocState,
    pin_slug: str,
    pin_rev: str,
    keyword_findings: list[tuple[str, str]],
) -> str:
    sig = state.signature()
    lines = [
        f"{SIGNATURE_MARKER_PREFIX}{sig}{SIGNATURE_MARKER_SUFFIX}",
        "",
        "## Current Datatracker state",
        "",
        f"- **Slug**: `{state.slug}`",
        f"- **Revision**: `{state.rev}`",
        f"- **State**: `{state.state_slug}`",
        f"- **Datatracker**: https://datatracker.ietf.org/doc/{state.slug}/",
        "",
        "## Pin in this repo",
        "",
        f"- **Pinned slug**: `{pin_slug}`",
        f"- **Pinned revision**: `{pin_rev}`",
        "",
        "Pin lives at `.github/draft-tracking.json`. Bump it (and close",
        "this issue's current comment thread) once the codebase has",
        "actually synchronized to the new state. See the IETF migration",
        "plan for the procedure.",
    ]
    if keyword_findings:
        lines += [
            "",
            "## Possible related drafts (keyword fallback)",
            "",
            "These are other active drafts authored by the tracked person",
            "whose title matches a watched keyword. They may be a",
            "successor that hasn't been filed with a `replaces`",
            "relationship yet, or unrelated parallel work. Human review",
            "required.",
            "",
        ]
        for slug, title in keyword_findings:
            lines.append(f"- `{slug}` — {title}")
    return "\n".join(lines) + "\n"


def diff_summary(
    pin_slug: str,
    pin_rev: str,
    state: DocState,
) -> list[str]:
    """Human-readable bullets describing what changed since the pin."""
    notes: list[str] = []
    if state.slug != pin_slug:
        notes.append(f"Draft **renamed**: pinned slug `{pin_slug}` was replaced by `{state.slug}`.")
    if state.rev != pin_rev:
        notes.append(f"New **revision** `{state.rev}` published (pinned at `{pin_rev}`).")
    if state.state_slug in {"rfc", "replaced", "expired", "withdrawn"}:
        notes.append(f"Draft **state transition**: now `{state.state_slug}`.")
    return notes


# ── Orchestrator ────────────────────────────────────────────────────────


def load_config(path: Path) -> dict[str, Any]:
    with path.open() as fh:
        return json.load(fh)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Watch IETF Datatracker for state changes on the "
        "pinned dns-aid-core draft. Always exits 0."
    )
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG_PATH),
        help="Path to draft-tracking.json (default: %(default)s)",
    )
    parser.add_argument(
        "--issue-title",
        default=DEFAULT_ISSUE_TITLE,
        help="Title of the canonical tracking issue (default: %(default)s)",
    )
    parser.add_argument(
        "--tag-user",
        default="",
        help="GitHub @user to ping on state change (e.g. nicknacnic)",
    )
    parser.add_argument(
        "--repo",
        default=None,
        help="owner/repo for gh CLI (default: gh's autodetect)",
    )
    parser.add_argument(
        "--manage-issue",
        action="store_true",
        help="Actually create/update the tracking issue via gh. Off by "
        "default so local invocations are read-only.",
    )
    parser.add_argument(
        "--smoke-test",
        action="store_true",
        help="Print resolved state and findings, then exit 0. Implies "
        "--manage-issue is OFF regardless of other flags.",
    )
    args = parser.parse_args(argv)

    config = load_config(Path(args.config))
    pin_slug: str = config["slug"]
    pin_rev: str = config["known_rev"]
    author_id: int = int(config["author_person_id"])
    keywords: list[str] = list(config["watched_keywords"])

    print(f"[draft-watch] Pin: slug={pin_slug} rev={pin_rev}")
    resolved_slug = resolve_current_slug(pin_slug)
    print(f"[draft-watch] Resolved current slug: {resolved_slug}")
    state = fetch_doc_state(resolved_slug)
    print(
        f"[draft-watch] State: rev={state.rev} state={state.state_slug} "
        f"signature={state.signature()}"
    )
    findings = keyword_sweep(author_id, keywords, exclude_slug=resolved_slug)
    if findings:
        print(f"[draft-watch] Keyword fallback found {len(findings)} candidate(s):")
        for slug, title in findings:
            print(f"  - {slug}: {title}")
    else:
        print("[draft-watch] Keyword fallback: no candidates.")

    notes = diff_summary(pin_slug, pin_rev, state)
    if not notes:
        print("[draft-watch] All quiet — pin matches current state.")
    else:
        print("[draft-watch] State change(s):")
        for note in notes:
            print(f"  - {note}")

    if args.smoke_test:
        print("[draft-watch] Smoke test mode — no issue ops performed.")
        return 0

    if not args.manage_issue:
        return 0

    # Issue management path.
    existing = find_tracking_issue(args.issue_title, repo=args.repo)
    body = render_issue_body(state, pin_slug, pin_rev, findings)
    new_signature = state.signature()
    pin_matches_current = state.slug == pin_slug and state.rev == pin_rev

    if existing is None:
        if pin_matches_current and not notes:
            print(
                "[draft-watch] No existing issue and state is at-pin; "
                "skipping issue creation on first install."
            )
            return 0
        # Open a fresh issue.
        print(f"[draft-watch] Opening tracking issue: {args.issue_title!r}")
        _gh_safe(
            [
                "issue",
                "create",
                "--title",
                args.issue_title,
                "--body",
                body,
            ],
            repo=args.repo,
        )
        if notes:
            ping = f"@{args.tag_user.lstrip('@')}" if args.tag_user else ""
            comment = (
                "Initial state observed:\n\n"
                + "\n".join(f"- {n}" for n in notes)
                + (f"\n\n{ping}" if ping else "")
            )
            # Re-fetch the just-created issue to comment on it.
            created = find_tracking_issue(args.issue_title, repo=args.repo)
            if created is not None:
                _gh_safe(
                    [
                        "issue",
                        "comment",
                        str(created["number"]),
                        "--body",
                        comment,
                    ],
                    repo=args.repo,
                )
        return 0

    existing_signature = signature_from_body(existing.get("body") or "")
    if existing_signature == new_signature:
        print("[draft-watch] Existing issue signature matches current state. No-op.")
        return 0

    # Signature changed — update body, add a diff comment, reopen if closed.
    print(
        f"[draft-watch] Signature changed "
        f"({existing_signature!r} -> {new_signature!r}). "
        "Updating issue."
    )
    _gh_safe(
        [
            "issue",
            "edit",
            str(existing["number"]),
            "--body",
            body,
        ],
        repo=args.repo,
    )
    if (existing.get("state") or "").upper() == "CLOSED":
        _gh_safe(
            ["issue", "reopen", str(existing["number"])],
            repo=args.repo,
        )
    ping = f"@{args.tag_user.lstrip('@')}" if args.tag_user else ""
    comment_lines = ["State changed:"]
    comment_lines.extend(f"- {n}" for n in (notes or ["(signature changed)"]))
    if ping:
        comment_lines.append("")
        comment_lines.append(ping)
    _gh_safe(
        [
            "issue",
            "comment",
            str(existing["number"]),
            "--body",
            "\n".join(comment_lines),
        ],
        repo=args.repo,
    )
    return 0


if __name__ == "__main__":
    # Honour Actions environment if present (for nicer log grouping); not
    # strictly necessary.
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print("::group::draft-watch")
    try:
        sys.exit(main())
    finally:
        if os.environ.get("GITHUB_ACTIONS") == "true":
            print("::endgroup::")
