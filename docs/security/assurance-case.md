# DNS-AID Security Assurance Case

This document argues, with evidence, that the DNS-AID reference implementation
meets its security requirements. It follows the claim → argument → evidence
structure suggested by the
[OpenSSF Best Practices `assurance_case` criterion](https://www.bestpractices.dev/en/criteria/1#1.assurance_case).
Normative security requirements for the *protocol* live in the IETF draft
([Security Considerations](../rfc/security-considerations.md)); this document
covers the implementation.

## Top-level claim

> The DNS-AID library, CLI, and MCP server preserve the integrity and
> authenticity guarantees of the DNS records they publish and consume, and do
> not extend the attacker capabilities of the environment they run in.

The claim decomposes along the trust boundaries below.

## Trust boundaries

```text
                 ┌────────────────────────────────────────────┐
                 │            Operator environment            │
                 │  ┌──────────┐   ┌──────────┐  ┌─────────┐  │
   DNS zone  ◄───┼──┤ publisher│   │discoverer│  │   MCP   │◄─┼── MCP client
  (provider API) │  └──────────┘   └────┬─────┘  │ server  │  │   (localhost)
                 │   credentials        │        └─────────┘  │
                 └──────────────────────┼─────────────────────┘
                                        │ untrusted inputs
                          ┌─────────────┴──────────────┐
                          │  DNS responses (resolver)  │
                          │  capability documents      │
                          │  A2A agent cards (HTTPS)   │
                          └────────────────────────────┘
```

Untrusted inputs: DNS responses, fetched capability documents and agent cards,
and all user-supplied names/domains/parameters. Trusted-but-guarded: DNS
provider credentials and the upstream resolver.

## Sub-claim 1 — Untrusted network input cannot corrupt discovery results

**Argument.** All discovery inputs are parsed defensively, validated against
strict schemas, and integrity-checked where the protocol provides a mechanism.

**Evidence.**

- Input validation: agent names, domains, ports, and TTLs are validated before
  use (`src/dns_aid/utils/validation.py`; rules documented in
  [SECURITY.md §Input Validation](../../SECURITY.md#input-validation)).
- Record models are pydantic-typed; malformed SVCB/TXT data fails parsing
  rather than propagating (`src/dns_aid/core/models.py`).
- Capability documents are integrity-verified against the `cap-sha256`
  SVCB parameter when present; digest mismatch rejects the document
  ([SECURITY.md §Capability Document Integrity](../../SECURITY.md#capability-document-integrity-cap_sha256)).
- DNSSEC status is surfaced via the resolver AD flag and DANE/TLSA
  verification supports full certificate matching
  ([SECURITY.md §Security Architecture](../../SECURITY.md#security-architecture));
  the residual trust in the upstream resolver is documented as an explicit
  limitation rather than hidden.
- Adversarial parsing is exercised by unit tests and a fuzzing harness over
  the SVCB parameter parser, FQDN parser, and index/TXT parsers.

## Sub-claim 2 — Outbound fetches cannot be abused for SSRF

**Argument.** Every outbound HTTP fetch initiated from untrusted data (capability
URIs, agent-card URLs) goes through a hardened fetch path.

**Evidence.** HTTPS-only scheme enforcement, pre-connection DNS resolution
checks blocking RFC 1918/loopback/link-local targets, a redirect cap of 3, and
an explicit allowlist escape hatch for testing only
(`src/dns_aid/utils/url_safety.py`;
[SECURITY.md §SSRF Protection](../../SECURITY.md#ssrf-protection)).

## Sub-claim 3 — Credentials are confined

**Argument.** Provider credentials are used only to authenticate to the
operator's own DNS provider and never leave the process by another path.

**Evidence.** Credentials are read from environment/config, never logged
(structlog processors exclude them; `scripts/audit_credential_handling.py`
audits the handling paths); backends send them only to their provider
endpoints over TLS; the MCP HTTP transport binds to 127.0.0.1 by default so
the tool surface is not network-exposed
([SECURITY.md §Network Security](../../SECURITY.md#network-security)).

## Sub-claim 4 — The supply chain from source to artifact is verifiable

**Argument.** A consumer can verify that a released artifact corresponds to the
reviewed source.

**Evidence.** Branch protection with required review and status checks
(including admins); DCO sign-off on every commit; CI runs SAST (CodeQL,
Bandit), dependency audit (pip-audit, Dependabot), and the full test matrix;
releases are built in CI from the tag, signed with Sigstore keyless signing,
shipped with a CycloneDX SBOM, and published to PyPI via OIDC trusted
publishing (no long-lived tokens) — see
`.github/workflows/release.yml` and [RELEASE.md](../../RELEASE.md).

## Sub-claim 5 — Secure-design principles are applied

**Argument.** The implementation follows economy of mechanism, fail-safe
defaults, complete mediation, and least privilege.

**Evidence.** Deliberately small dependency set (stdlib + dnspython, httpx,
pydantic, cryptography); fail-closed defaults (HTTPS-only, advisory DANE warns
and full matching rejects on mismatch, integrity mismatch treated as fetch
failure, backend `get_record` errors propagate instead of masking as
not-found); every untrusted input crosses a validation layer; CI workflow
tokens default to `contents: read` with per-job escalation.

## Known limitations (accepted, documented)

- DNSSEC validation trusts the upstream resolver's AD flag; no independent
  chain validation. Operators must run a validating resolver.
- DANE defaults to advisory mode; full certificate matching is opt-in.
- The mock backend is for testing only.
- SVCB keys 65400–65405 are in the private-use range pending IANA
  registration.

These are stated in [SECURITY.md](../../SECURITY.md#known-security-limitations)
and in user-facing docs rather than silently assumed.

## Maintenance

This assurance case is reviewed when a new attack surface is added (new
backend, new network fetch path, new transport), when the IETF draft changes
security-relevant behavior, and at least once per minor release. Material
changes to the argument require review by a maintainer other than the author.
