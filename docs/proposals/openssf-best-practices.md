# Proposal: OpenSSF Best Practices — Silver badge, Scorecard fixes, and the road to Gold

- **Status:** Proposed
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
documentation PRs, CI/process hardening, and Gold-level items that are gated on
organizational growth rather than engineering.

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
   coverage step so the achieved level cannot silently regress, with a ratchet
   policy: raise the floor as coverage rises, never lower it without a recorded
   decision. This same gate is the runway for Gold's 90%/80% targets (Phase 4).

5. **`version_tags_signed` — sign release tags.** Release *artifacts* are already
   Sigstore-signed; the git tags themselves are not. Update RELEASE.md to require
   `git tag -s` (maintainer GPG/SSH key) or gitsign for `v*` tags.

6. **`access_continuity` — one paragraph in GOVERNANCE.md** documenting that at
   least two people hold org-owner/admin access and that the Project Lead role
   has a succession process (currently only implied by the election clause).

## Phase 3 — Scorecard hardening (parallel to Phase 2)

These raise the Scorecard score and simultaneously pre-answer Gold and OSPS
Baseline questions:

1. **Branch protection (currently 4/10) + Code-Review (currently 2/10).** Enable
   on `main`: require ≥1 approving review, dismiss stale approvals, require
   status checks (test, lint, typecheck, integration, DCO), and block force
   pushes. Note: 5/21 recent changesets had approvals — with three maintainers
   this is now sustainable where it wasn't with one.
2. **Token-Permissions (9/10).** Audit workflows for job-level `permissions`
   blocks (likely one workflow missing an explicit top-level `permissions:
   contents: read`).
3. **Fuzzing (0/10).** Add a small [Atheris](https://github.com/google/atheris)
   harness fuzzing the SVCB wire-format parser and record deserializers (the
   highest-value untrusted-input surface), run weekly in CI. Apply to OSS-Fuzz
   once the harness is stable.
4. **Pinned-Dependencies (8/10).** Workflows already pin actions by SHA; the
   residual findings are `pip install` steps in release.yml — pin
   `build`/`cyclonedx-bom` versions with hashes.

## Phase 4 — Gold: what's achievable now vs. gated

Already met (answer with evidence): `copyright_per_file` / `license_per_file`
(all 86 source files carry SPDX + copyright headers), signed releases,
`dco`-adjacent provenance.

Achievable with settings/process:

- `require_2FA` / `secure_2FA` — enable "Require two-factor authentication" on
  the `dns-aid` GitHub org.
- `code_review_standards` / `two_person_review` — document review standards in
  CONTRIBUTING.md; require 2 approvals for changes touching crypto/validation
  paths (CODEOWNERS already routes these).
- `small_tasks` — label starter issues (`good first issue`) as part of the
  LF-graduation contributor-growth push.
- `build_reproducible` — hatchling builds are reproducible given
  `SOURCE_DATE_EPOCH`; add a CI job that builds twice and diffs the wheels.
- `test_statement_coverage90` / `test_branch_coverage80` — continuation of the
  Phase 2 ratchet.

Gated on ecosystem growth (not engineering): `contributors_unassociated`
(requires significant contributors from ≥2 organizations — this is the same
top-priority goal MAINTAINERS.md already sets for LF graduation) and
`security_review` (independent security review; candidate for an LF/OSTIF
review request once onboarded).

## OSPS Security Baseline

The badge entry also carries the OSPS Baseline questionnaire (`OSPS-*` criteria,
all unanswered). Nearly every control maps to evidence produced by Phases 0–3
(MFA, branch protection, SAST, dependency policy, release signing, vuln
process). Fill it in **after** Phase 3 lands so the answers are all "Met" on
first submission.

## Sequencing and ownership

| Phase | Items | Effort | Blocked on |
| --- | --- | --- | --- |
| 0 | Badge entry URL fix | minutes | badge-entry owner (@iracic82) |
| 1 | Silver questionnaire pass | ~2h form work | badge-entry edit access |
| 2 | Roadmap, SECURITY/GOVERNANCE paragraphs, assurance case, coverage gate, signed tags | 3–4 small PRs | — |
| 3 | Branch protection, token perms, fuzz harness, pip pinning | 2 PRs + org settings | org admin |
| 4 | Gold: 2FA org setting, review standards, reproducible-build check | 1–2 PRs + org settings | Phase 2–3; external contributors for the gated items |

Silver is achievable within one release cycle. Gold's engineering items are all
tractable; its two gated criteria align exactly with the existing LF-graduation
goals in MAINTAINERS.md, so no new organizational commitments are introduced by
this proposal.
