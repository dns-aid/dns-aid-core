# Privacy Considerations

DNS-AID publishes service-discovery records in DNS. By design, DNS is a
public namespace — any client that can resolve names in your zone can
read what you publish. This document describes the privacy trade-offs
baked into each record type so operators can choose the right defaults
for their deployment.

## Enumeration vs. Discovery

There's a distinction worth naming up front:

- **Discovery** is the case where a caller already knows the agent name
  it wants and resolves a specific FQDN — `chat.example.com`,
  `pharmacy-delivery.acmehealth.com`. This is the everyday flow and is
  fundamentally what DNS is for.
- **Enumeration** is the case where a caller doesn't know the agent
  names in advance and discovers them by walking the zone. DNS-AID
  optionally supports this via DNS-SD-style records, but it's a
  different privacy posture: enumeration lets *anyone* inventory the
  agents an operator has published.

Most operators want discovery without enumeration. Some — operators
running intentional public directories, internal indexes, or
DNS-SD-style consumers — want both. The defaults in dns-aid-core
reflect "discovery on, enumeration off" and the per-record knobs let
you opt into enumeration deliberately.

## The Walkable AliasMode Record

Under draft-mozleywilliams-dnsop-dnsaid-02 §3.1, publishers MAY emit a
walkable AliasMode SVCB record at `{name}._agents.{domain}` pointing at
the flat primary owner `{name}.{domain}`. This record exists so
DNS-SD-style consumers and crawlers can enumerate an operator's agents
by walking `_agents.{domain}` and following each AliasMode to the
canonical owner.

**dns-aid-core publishes this record only when explicitly enabled.**
The default is `publish_walkable_alias=False` (SDK), `--walkable`
(CLI flag, opt-in), and `publish_walkable_alias=False` (MCP tool).

### Why off by default

The walkable record is, by construction, an enumeration handle. With
the walkable record present, a caller that knows your zone name can:

1. Query `_agents.{zone}` for SVCB records, or zone-walk the
   `_agents.{zone}` namespace under DNSSEC's NSEC/NSEC3 records.
2. Receive a list of every `{name}._agents.{zone}` your operator
   publishes.
3. Follow the AliasMode for each one to learn the canonical owner
   `{name}.{zone}`.

Net effect: complete inventory of your agents from the zone name
alone. For a public commercial service that wants to be discoverable,
this is exactly the desired behaviour. For a healthcare operator with
internal-only agents whose names indirectly reveal sensitive workflows
(`oncology-triage`, `crisis-helpline`), it's the wrong default.

Erring on the side of less information leakage matches the privacy
posture of the rest of the stack: DNSSEC zone-walking has been a
known privacy issue since RFC 5155, and NSEC3-opt-out exists to limit
exactly this kind of enumeration.

### When to enable

Set `publish_walkable_alias=True` (or pass `--walkable` to the CLI)
when:

- **You're running a public agent directory** — a curated catalog of
  agents intentionally meant to be discovered by anyone. The walkable
  shape is the most standard way to expose that.
- **You're running an internal directory or DNS-SD-style index** —
  on private networks where enumeration by callers inside your
  perimeter is desirable and the records aren't reachable from
  outside.
- **You're publishing a DNS-SD-bridged service** — interop with
  consumers that already speak the DNS-SD enumeration shape.
- **You want crawler discoverability** for an agent-catalog project
  (e.g. dns-aid.org's spider) and are okay with the enumeration
  surface that implies.

For any of those cases, the walkable record is doing useful work and
the privacy cost is acceptable.

### When to leave it off

Leave the default in place when:

- **The agent's existence or name is sensitive** — anything where the
  name itself signals workflow detail you don't want indexed by
  third-party DNS scanners.
- **You have a small, fixed set of consumers** who already know the
  agent FQDNs they need (out-of-band exchange, configuration, or
  partner agreements).
- **You publish a large number of agents in one zone** — even if no
  individual name is sensitive, the aggregate inventory may reveal
  operational scale you'd rather keep private.

### What discovery still works without the walkable record

Without the walkable record, a caller can still:

- Resolve a specific known agent by querying `{name}.{domain}`
  directly. This is unaffected.
- Find agents through an organisation index at
  `_index._agents.{domain}` — which is a separate, intentionally
  publishable list of names the operator chose to include. Operators
  curate this list; the walkable record is opt-out-of-curation.

So the choice "walkable off, organisation index on" gives consumers a
discovery list the operator controls while denying random crawlers an
inventory handle.

## Other Records Worth Noting

- **The organisation index** (`_index._agents.{domain}`) is explicitly
  a curated list — operators choose what to put there. There's no
  privacy hazard beyond what the operator has already decided to
  publish.
- **TLSA records** (`_443._tcp.{name}.{domain}`) pin certificates to
  DNS-anchored trust. They reveal that the agent uses TLS at a given
  port and bind it to a cert chain; they don't reveal the agent's
  capabilities or activity.
- **Capability descriptors** referenced by `cap` or `well-known` are
  fetched over HTTPS to the SVCB target. Their content is whatever
  the operator chose to publish there — typically a capability list,
  schema URIs, and contact info. Operators concerned about leaking
  capability detail can put a minimal pointer behind authentication
  on the descriptor URL itself.

## Summary

Default off for the walkable record. Default on for the flat primary
owner. Explicit opt-in for any record whose primary purpose is
enumeration. Operators who want their agents indexed turn enumeration
on deliberately; operators who don't, get the privacy-preserving
shape by default.
