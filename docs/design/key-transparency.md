# Key transparency for DNS-AID agent signatures

Status: proposal, for the IETF draft. Not implemented.

## The problem this exists to solve

DNS-AID authenticates a record two ways. DNSSEC proves *the zone published this*.
A JWS in the `sig` SvcParam proves *the agent owner authorized this binding*.
Those are different parties, and that difference is the whole value of the JWS
path — a registrar compromise, a DNS-provider insider, or a stolen console
credential defeats DNSSEC completely and cannot forge a signature by a key the
agent operator holds.

But the JWS path has a bootstrapping problem that cannot be solved at its own
layer. The key document lives at `dns-aid.<zone>/.well-known/dns-aid-jwks.json`,
fetched over HTTPS. Its authenticity therefore rests on WebPKI for a name inside
the zone the fallback exists to protect. An attacker with zone-level DNS control
can satisfy an ACME challenge for that name, obtain a DV certificate, and serve
their own keys.

Moving the anchor does not help. A key fingerprint carried in the SVCB record is
forged alongside the record. A TLSA record for the JWKS host requires DNSSEC,
which is the thing the JWS path exists to substitute for. **You cannot bootstrap
trust from inside a zone the attacker controls.** That is a property of the
layer, not a defect to patch.

## The reframe

Stop trying to prevent the substitution. Make it undeniable.

An attacker who swaps the key document must swap the key, and a key change is
observable. The reachable goal is **detectability**, and detectability is a
solved problem: Certificate Transparency solved exactly this shape for WebPKI.
It does not stop a CA from mis-issuing; it makes mis-issuance permanent, public,
and attributable.

`dns_aid.core.jwks.observe_key_set` is the local half of this, shipped today:
trust-on-first-use with change alerting, per zone, advisory only. It catches an
attacker who substitutes keys for *one observer who has seen the zone before*. It
cannot catch a substitution targeted at a first-time observer, and it cannot
distinguish "the publisher rotated" from "someone else rotated for them".

A log closes both gaps.

## Sketch

A publisher submits its key set to one or more append-only logs and receives a
signed inclusion promise. The promise is small enough to carry in the record, in
a new SvcParam alongside `sig`.

A consumer verifying a signature checks that the key it verified against is
present in a log it trusts. A key that verifies but is absent from any log is
reported, not refused — the same tri-state discipline the rest of the library
uses, where unverifiable never reads as forged.

Three properties follow, and they are the argument:

1. **A substituted key must be logged to be accepted**, so the substitution is
   public and permanent.
2. **A publisher can audit their own zone** — any key claiming to be theirs that
   they did not submit is visible to them, without anyone's cooperation.
3. **Nobody grants permission.** A log accepts every submission; it only refuses
   to forget.

## Why this fits DNS-AID specifically

The project's differentiator against ANS and AgentDNS is that no gatekeeper
decides who may publish an agent. A transparency log is the opposite of a
gatekeeper: it is an auditable public record that grants nobody authority and
denies nobody entry.

**"Anyone can publish, and nobody can publish quietly"** is a defensible position
at IETF in a way that "we rely on WebPKI" is not, and it is a genuinely novel one
in agent discovery.

## Open questions for the draft

- Log operator model. Federated, as CT is, or a single community log to start.
- Whether the inclusion promise is carried in the record or fetched alongside the
  JWKS. In-record costs SVCB space; fetched costs a round trip.
- Failure posture for a consumer that cannot reach any log. Almost certainly
  report-only; refusing would make log availability a dependency of discovery,
  which reintroduces a gatekeeper by the back door.
- Whether logging is per key set or per record. Per key set is far smaller and
  is what the substitution attack actually turns on.

## Relationship to what is implemented

| Layer | Status | Catches |
|---|---|---|
| `svcb` claim over the full parameter set | shipped | replay onto a record with swapped parameters |
| `observe_key_set` continuity | shipped | substitution seen by a returning observer |
| DNSSEC chain validation to the root anchor | shipped, opt-in | forged records in a signed zone |
| Key transparency | this proposal | substitution against any observer, including a first-time one |
