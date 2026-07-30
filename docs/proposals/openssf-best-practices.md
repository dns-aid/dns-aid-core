# Proposal: OpenSSF Best Practices — Silver badge, Scorecard fixes, and the road to Gold

- **Status:** Proposed (decisions on review policy, coverage pacing, fuzzing scope,
  security-review route, and timeline recorded 2026-07-29 — see §Decisions)
- **Date:** 2026-07-29
- **Scope:** [OpenSSF Best Practices badge](https://www.bestpractices.dev/projects/12651) (Silver/Gold levels), [OpenSSF Scorecard](https://scorecard.dev/viewer/?uri=github.com/dns-aid/dns-aid-core), and the OSPS Security Baseline questionnaire

## Summary

DNS-AID earned the **Passing** badge (100%) on 2026-04-25 and has not touched the
badge entry since. The Silver questionnaire sits at 15% and Gold at 22% — almost
entirely because the questions are **unanswered**, not because the practices are
missing. An audit of the badge API against the current repository shows that the
large majority of Silver criteria are already satisfied by existing files, CI
workflows, and release automation; a handful need small, well-scoped changes.

Separately, the badge entry still points at the pre-rename
`github.com/infobloxopen/dns-aid-core` URL, which is why OpenSSF Scorecard's
`CII-Best-Practices` check scores **0/10** ("no effort to earn a badge detected")
despite the achieved badge. Fixing that one URL raises the overall Scorecard
score at zero engineering cost.

This proposal sequences the work into four phases: an immediate metadata fix,
documentation PRs, CI/process hardening, and a Gold execution plan targeting
**Gold-ready within 1–2 release cycles**, with `contributors_unassociated` as
the sole criterion gated on ecosystem growth.

## Decisions (2026-07-29)

Recorded from maintainer review of the draft; facts verified against the GitHub
API the same day.

| Topic | Decision / fact |
| --- | --- |
| Badge entry access | Held by @iracic82 only; questionnaire edits are coordinated with him (or he adds a co-owner login on the entry) |
| Org admin | @ivanglabbeek is a dns-aid org owner — settings changes are direct actions, not requests |
| Org 2FA status | **0 members have 2FA disabled** (verified via API) — `require_2FA` can be enforced with no member ejections |
| Branch protection on `main` | Already requires 1 approving review with stale-review dismissal + 8 required status checks (strict). Gaps: `enforce_admins` off, last-push approval off |
| Review policy | 1 approval on **all** PRs (already configured); add `enforce_admins` so it binds admins too |
| Coverage pacing | **Dedicated push now** to 90% statement / 80% branch, not a slow ratchet |
| Fuzzing & builds | All three: reproducible-build CI job, Atheris harness in CI, OSS-Fuzz application |
| Security review | Infoblox internal security team (reviewers independent of the dev team), written report |
| External contributors | Candidates in pipeline (IETF/ecosystem); tracked as the one open Gold blocker |
| Timeline | Gold-ready in the next 1–2 release cycles |

## Current state

| Metric | Value | Source |
| --- | --- | --- |
| Best Practices — Passing | **100% (achieved 2026-04-25)** | bestpractices.dev project 12651 |
| Best Practices — Silver | 15% (criteria unanswered) | same |
| Best Practices — Gold | 22% (criteria unanswered) | same |
| OSPS Security Baseline (tiered) | unanswered | same |
| Scorecard (aggregate) | 8.0 / 10 | api.securityscorecards.dev |
| Unit-test coverage | 79% combined statement+branch; ≈81% statement-only (measured 2026-07-29, 2142 tests) | local run of `tests/unit/` |

Scorecard checks below 10: `CII-Best-Practices` 0, `Fuzzing` 0, `Code-Review` 2,
`Branch-Protection` 4, `Pinned-Dependencies` 8, `Signed-Releases` 8,
`Token-Permissions` 9.

## Phase 0 — Immediate metadata fix (no code)

1. **Update the badge entry URLs.** The bestpractices.dev entry's `repo_url` and
   `homepage_url` still read `https://github.com/infobloxopen/dns-aid-core`.
   Update both to `https://github.com/dns-aid/dns-aid-core` (badge-entry owner
   action; bestpractices.dev supports repo URL changes with a rename note).
   This alone should move Scorecard `CII-Best-Practices` from 0 to 5 (passing
   badge detected), and to 7 once Silver is achieved.

## Phase 1 — Silver: answer what is already true

These criteria are already satisfied; the work is filling in the questionnaire
with evidence links. No repository changes required.

| Criterion | Evidence already in the repo |
| --- | --- |
| `dco` | [DCO](../../DCO) file; `dco.yml` workflow enforces sign-off on every PR |
| `governance` | [GOVERNANCE.md](../../GOVERNANCE.md) (roles, lazy consensus, voting) |
| `code_of_conduct` | [CODE_OF_CONDUCT.md](../../CODE_OF_CONDUCT.md) |
| `roles_responsibilities` | GOVERNANCE.md §Roles; [MAINTAINERS.md](../../MAINTAINERS.md) role table |
| `bus_factor` | Three maintainers listed in MAINTAINERS.md (≥2 required) |
| `documentation_architecture` | [docs/architecture.md](../architecture.md) |
| `documentation_quick_start` | [docs/getting-started.md](../getting-started.md) |
| `documentation_current` | Docs updated in lockstep with releases (CHANGELOG discipline) |
| `documentation_achievements` | Badge row in README |
| `coding_standards` / `coding_standards_enforced` | CONTRIBUTING.md; ruff + mypy jobs are required CI |
| `maintenance_or_update` | SECURITY.md supported-versions table; SUPPORT.md |
| `vulnerability_response_process` | SECURITY.md response timeline (48h / 7d / 30d) |
| `external_dependencies` | pyproject.toml + uv.lock enumerate all dependencies |
| `dependency_monitoring` | Dependabot + nightly `pip-audit` in security.yml |
| `updateable_reused_components` | All deps from PyPI, floor-pinned, lockfile-managed |
| `interfaces_current` | [docs/api-reference.md](../api-reference.md) |
| `automated_integration_testing` | `integration` job in ci.yml (mock integration suite) |
| `regression_tests_added50` | Bug-fix PRs ship regression tests (see recent history, e.g. #201) |
| `test_policy_mandated` | CONTRIBUTING.md "Tests (required)" checklist |
| `installation_common` / `installation_development_quick` | `pip install dns-aid`; CONTRIBUTING dev setup |
| `signed_releases` | Sigstore/cosign signatures (`.sig`/`.pem`) on every release artifact + SBOM |
| `implement_secure_design` / `input_validation` | SECURITY.md (SSRF protections, input validation rules, cap-sha256 integrity) |
| `crypto_*` (agility, certificate verification, TLS ≥1.2, network crypto) | httpx/TLS defaults; DANE/TLSA and DNSSEC handling documented in SECURITY.md |
| `hardening` | SSRF allowlist-deny-by-default, HTTPS-only fetches, localhost-bound MCP transport |
| `build_*` (repeatable, non-recursive, standard variables) | hatchling + uv.lock; pure-Python build (several N/A with justification) |
| `accessibility_best_practices`, `internationalization`, `sites_password_security` | N/A with justification (library/CLI; no UI, no password-accepting site) |

## Phase 2 — Silver: small, concrete repo changes

Each item below is a small PR; together they close every remaining Silver MUST.

1. **`documentation_roadmap` — add `docs/roadmap.md`.** The only Silver MUST with
   no existing artifact. One page: near-term (IETF draft tracking, backend
   parity), mid-term (LF onboarding goals from MAINTAINERS.md), and a pointer to
   the issue tracker as the source of truth. Link it from README.

2. **`vulnerability_report_credit` — one paragraph in SECURITY.md** committing to
   credit reporters in release notes/advisories unless they request anonymity
   (the practice already happens; it just isn't written down).

3. **`assurance_case` — add `docs/security/assurance-case.md`.** A structured
   argument mapping threats → mitigations. Most content already exists in
   SECURITY.md (SSRF, DNSSEC/AD-flag trust model, DANE modes, cap-sha256
   integrity, input validation) and docs/rfc/security-considerations.md; this
   document arranges it as claim → argument → evidence, adds a trust-boundary
   diagram, and states what is explicitly out of scope (resolver compromise).

4. **`test_statement_coverage80` — enforce coverage in CI.** Coverage is already
   measured but not gated, and the criterion is already met on the measure it
   uses: statement-only coverage is ≈81% (the 79% figure in CI reports includes
   branch coverage, which is stricter). Add `--cov-fail-under=79` to the ci.yml
   coverage step immediately so the achieved level cannot regress while the
   Gold coverage push (G3 below) is underway; the gate rises with the push and
   is never lowered without a recorded decision.

5. **`version_tags_signed` — sign release tags.** Release *artifacts* are already
   Sigstore-signed; the git tags themselves are not. Update RELEASE.md to require
   `git tag -s` (maintainer GPG/SSH key) or gitsign for `v*` tags.

6. **`access_continuity` — one paragraph in GOVERNANCE.md** documenting that at
   least two people hold org-owner/admin access and that the Project Lead role
   has a succession process (currently only implied by the election clause).

## Phase 3 — Scorecard hardening (parallel to Phase 2)

These raise the Scorecard score and simultaneously pre-answer Gold and OSPS
Baseline questions:

1. **Branch protection (currently 4/10) + Code-Review (currently 2/10).**
   Verified 2026-07-29: `main` already requires 1 approving review with
   stale-review dismissal and 8 strict status checks. The remaining gaps are
   `enforce_admins` (off — admins can currently merge without review, which is
   also why the Code-Review score is low: 5/21 recent changesets carried
   approvals) and optionally require-last-push-approval. Action: enable
   `enforce_admins`; the Code-Review score then recovers on its own as the
   trailing 30-changeset window fills with reviewed merges.
2. **Token-Permissions (9/10).** Audit workflows for job-level `permissions`
   blocks (likely one workflow missing an explicit top-level `permissions:
   contents: read`).
3. **Fuzzing (0/10).** Two tracks (decided): a small
   [Atheris](https://github.com/google/atheris) harness fuzzing the SVCB
   wire-format parser and record deserializers (the highest-value
   untrusted-input surface) on a weekly CI schedule, **and** an OSS-Fuzz
   application once the harness runs clean for a couple of weeks (needs a
   maintainer contact email and an `oss-fuzz` project directory PR).
4. **Pinned-Dependencies (8/10).** Workflows already pin actions by SHA; the
   residual findings are `pip install` steps in release.yml — pin
   `build`/`cyclonedx-bom` versions with hashes.

## Phase 4 — Gold execution plan

Target: **Gold-ready within 1–2 release cycles**, meaning every Gold criterion
is Met except `contributors_unassociated`, which is tracked as the single open
blocker and worked via the contributor pipeline.

Already met — answer on the form with evidence, no work:

- `copyright_per_file` / `license_per_file` — all 86 source files carry SPDX +
  copyright headers.
- `repo_distributed`, `test_invocation`, `test_continuous_integration` — carried
  over from Passing.
- `crypto_used_network` / `crypto_tls12` / `hardened_site` / `hardening` —
  HTTPS-only fetches (TLS ≥1.2 via httpx defaults), GitHub-hosted site with
  HSTS, SSRF/input-validation hardening per SECURITY.md.
- `dynamic_analysis` — already answered Met at Passing.

Work items:

- **G1 — Org settings (owner: @ivanglabbeek, immediate).** Enable "Require
  two-factor authentication" on the dns-aid org (`require_2FA`; verified safe —
  0 members lack 2FA, so nobody gets ejected). GitHub requires TOTP/security
  keys rather than SMS-only for org enforcement, covering `secure_2FA`. Enable
  `enforce_admins` on main's branch protection (see Phase 3.1).
- **G2 — Review standards (1 small PR).** Add a "Code review" section to
  CONTRIBUTING.md: what reviewers check (correctness, tests, security-sensitive
  paths, DCO), who may approve, and the rule that no change merges without a
  non-author approval (`code_review_standards`). `two_person_review` (≥50% of
  changes reviewed by a non-author) is then enforced mechanically by G1 +
  existing branch protection; the criterion evaluates recent history, so it
  becomes claimable roughly one release cycle after enforcement.
- **G3 — Coverage push (the main engineering item, this cycle).** Dedicated
  test-writing effort to reach 90% statement / 80% branch (currently ≈81%
  statement). The gap is concentrated: `cli/main.py` (443 uncovered statements,
  50%) and `mcp/server.py` (394, 30%) hold ~41% of all uncovered statements,
  followed by `backends/infoblox/bloxone.py` (137, 53%), `core/invoke.py`
  (103, 55%), `backends/infoblox/nios.py` (102, 70%), and
  `backends/cloud_dns.py` (65, 53%). Approach: typer `CliRunner` tests for the
  CLI command surface, MCP tool-handler tests against the mock backend, and
  mocked-HTTP tests for the two Infoblox backends and Cloud DNS (the
  `test_cloudflare_backend.py` pattern already exists). Raise the
  `--cov-fail-under` gate as each tranche lands.
- **G4 — Reproducible builds (1 PR).** CI job that builds the wheel/sdist twice
  with `SOURCE_DATE_EPOCH` pinned and fails on binary diff
  (`build_reproducible`; hatchling is reproducible by default, so this is
  expected to pass immediately and serve as the criterion's evidence URL).
- **G5 — Fuzzing (1 PR + application).** Atheris harness in weekly CI, then the
  OSS-Fuzz application (Phase 3.3). Not a Gold criterion, but scheduled here
  because the harness reuses G3's test fixtures.
- **G6 — Security review (owner: @ivanglabbeek, external ask).** Request a
  review from the Infoblox product-security team — reviewers must be
  independent of the dev team for `security_review` to count. Scope: the
  assurance case (Phase 2.3), SSRF/input-validation paths, DNSSEC/DANE trust
  handling, and release pipeline. Deliverable: a written report linked from
  SECURITY.md, with findings triaged as issues.
- **G7 — Starter tasks (ongoing).** Label `good first issue` tasks
  (`small_tasks`) — also feeds the contributor pipeline that G8 depends on.
- **G8 — Unassociated contributors (open blocker).** Candidates exist in the
  pipeline (IETF draft co-authors, ARD-ecosystem developers). The criterion
  needs two *significant* contributors not associated with Infoblox — track
  candidate progress in the LF-graduation issue and revisit at each release.
  Everything else in this plan proceeds independently.

## OSPS Security Baseline

The badge entry also carries the OSPS Baseline questionnaire (`OSPS-*` criteria,
all unanswered). Nearly every control maps to evidence produced by Phases 0–3
(MFA, branch protection, SAST, dependency policy, release signing, vuln
process). Fill it in **after** Phase 3 lands so the answers are all "Met" on
first submission.

## Sequencing and ownership

| When | Items | Owner |
| --- | --- | --- |
| Now (settings, no PR) | G1: org require-2FA, `enforce_admins`; Phase 0 badge-URL fix | @ivanglabbeek; @iracic82 for the badge entry |
| Release cycle 1 | Phase 2 PRs (roadmap, assurance case, SECURITY/GOVERNANCE paragraphs, `--cov-fail-under=79`, signed tags); G2 review standards; G4 repro-build job; Phase 3 token-perms + pip pins; Silver questionnaire pass | maintainers; @iracic82 for the questionnaire |
| Release cycle 1–2 | G3 coverage push to 90/80 (CLI → MCP server → Infoblox/Cloud DNS backends); G5 fuzz harness + OSS-Fuzz application; G6 security review request → report | maintainers; Infoblox security team for G6 |
| After cycle 2 | Claim `two_person_review` (needs a cycle of enforced history); Gold questionnaire pass; OSPS Baseline pass | @iracic82 (form), maintainers (evidence) |
| Unscheduled | G8 `contributors_unassociated` — pipeline candidates tracked per release | project lead |

Silver is achievable within release cycle 1. Every Gold criterion except
`contributors_unassociated` is scheduled above; that criterion aligns exactly
with the existing LF-graduation recruiting goals in MAINTAINERS.md, so no new
organizational commitments are introduced by this proposal.
