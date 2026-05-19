# Experimental DNS-AID features

This directory holds design proposals and rationale documents for **experimental** features that ship in the `dns_aid.experimental` Python subpackage.

## ⚠ Stability

APIs and wire formats described in this directory are **unstable**. They are NOT covered by the semver guarantees that apply to `dns_aid.core` and `dns_aid.sdk`. They may change shape, change behaviour, or be removed entirely in any release — including patch versions.

If you build on an experimental feature, pin the patch version of `dns-aid` and watch the CHANGELOG.

## Conventions

Every experimental feature follows the same shape:

| Aspect | Where it lives |
|---|---|
| Code | `src/dns_aid/experimental/<feature>.py` |
| Public symbols | Imported explicitly: `from dns_aid.experimental import X`. Never re-exported from `dns_aid/__init__.py`. |
| Runtime gate | A per-feature environment variable, e.g. `DNS_AID_EXPERIMENTAL_<FEATURE>=1`. Without the flag set, related code paths stay dormant. |
| CLI surface | Commands print `[experimental]` to stderr on every invocation. |
| Tests | `tests/unit/test_<feature>.py` is required. |
| Design doc | `docs/experimental/<feature>.md` (this directory). Section headers should map cleanly to future RFC structure so content lifts into a draft when an LF spec home arrives. |
| ABNF / wire format | `docs/experimental/<feature>.abnf` (kept separate from `docs/rfc/wire-format.abnf` so the experimental status is unambiguous). |

## Current proposals

- **[EDNS(0) agent-hint signaling](edns-signaling.md)** — client signals selector filters to a hint-aware DNS hop (resolver, forwarder, or authoritative) to enable per-query response narrowing and warm-cache short-circuits. Wire format: option code 65430 (private use). Reference programmable hop: in-process `EdnsAwareResolver`. Status: design + client-side spike.

## Migrating an experimental feature to stable

When a feature graduates to stable:

1. Move the design doc from `docs/experimental/` to `docs/rfc/` (rename to a `-stable` suffix or whatever fits the section).
2. Move the code from `src/dns_aid/experimental/` to its proper tier (`core/`, `sdk/`, or backends).
3. Re-export public symbols from `dns_aid/__init__.py` if appropriate.
4. Drop the env-flag gate; the feature is on by default.
5. Update `CHANGELOG.md` with a `BREAKING:` line if the public surface changed during the experimental phase.
6. Update `docs/api-reference.md` to remove the "Experimental" marking.
