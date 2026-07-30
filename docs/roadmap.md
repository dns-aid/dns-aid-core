# DNS-AID Roadmap

This page describes where the project is headed. The
[issue tracker](https://github.com/dns-aid/dns-aid-core/issues) is the source
of truth for individual work items; this document explains priorities and
direction. It is reviewed at each minor release and at governance changes.

The DNS-AID *protocol* is specified in the IETF
([draft-mozleywilliams-dnsop-dnsaid](https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-dnsaid/));
protocol-level changes happen there, not here. This roadmap covers the
reference implementation only.

## Near term (next 1–2 releases)

- **Track the IETF draft.** Keep the implementation aligned with each draft
  revision (the `draft-watch` workflow flags new revisions automatically);
  implement wire-format and behavior changes as they land.
- **OpenSSF Best Practices Silver → Gold.** Execute the
  [OpenSSF proposal](proposals/openssf-best-practices.md): assurance case,
  coverage push to 90% statement / 80% branch, reproducible-build check,
  fuzzing, independent security review.
- **Backend parity.** Bring all DNS provider backends (Route 53, Cloudflare,
  NS1, Cloud DNS, Infoblox BloxOne/NIOS, Akamai EdgeDNS, DDNS) to the same
  feature and test level, including native private-use SVCB keys and uniform
  error propagation.

## Medium term

- **Linux Foundation onboarding.** Complete the sustainability goals in
  [MAINTAINERS.md](../MAINTAINERS.md): a maintainer from a second
  organization, documented project-lead succession, and an external committer
  with merge rights on at least one subsystem.
- **IANA registration.** Move the private-use SVCB SvcParamKeys
  (key65400–65405) to permanently registered keys as the draft progresses,
  with a migration path for published records.
- **Ecosystem interoperability.** Continue ARD ai-catalog interop and keep the
  indexer/telemetry interfaces provider-neutral so independent directories can
  build on the same records.

## Long term

- **1.0 release** once the IETF draft reaches a stable state (working-group
  adoption and wire-format stability), with semantic-versioning guarantees for
  the public Python API and CLI.
- **Post-quantum readiness.** Mature the ML-DSA-65 HTTP Message Signatures
  support (`pqc` extra) from experimental to supported as standards settle.

## Non-goals

- Defining protocol behavior (IETF territory).
- Canonicalizing a single directory/indexer service; DNS-AID stays a substrate
  that any directory can build on.
