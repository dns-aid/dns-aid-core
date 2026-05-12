# Experimental: EDNS(0) `agent-hint` signaling for DNS-AID

**Status:** Experimental. APIs and wire format are unstable.
**Module:** `dns_aid.experimental` (`AgentHint`, `AgentHintEcho`, `EdnsSignalingAdvertisement`, `EdnsAwareResolver`)
**Runtime gate:** `DNS_AID_EXPERIMENTAL_EDNS_HINTS=1`

---

## 1. Overview

DNS-AID today is a one-shot lookup protocol: a client knows what to ask, sends an SVCB query, and gets back an endpoint. The protocol works well when the client already knows the agent name and the publisher's domain, but it offers no mechanism for the client to communicate **what kind of agent it's looking for** while resolution is in progress. Any pre-filtering must happen client-side, after the full record set has been fetched.

This document proposes an experimental EDNS(0) option — `agent-hint` — that lets the client attach a compact set of selector filters to its outgoing DNS query. Any hop on the resolution path that understands the option can use the hint to narrow the response, return a cached pre-filtered answer, or short-circuit the query entirely. Hops that don't understand the option treat it as inert, per RFC 6891 §6.1.1, and the query proceeds normally — the option degrades gracefully.

The goal is not to change DNS. The goal is to give the agent-discovery flow a substrate-level signal mechanism that mirrors the way DNS recursion itself amortizes cost: expensive at the cold edge, cheap when a downstream cache has the answer. For agent discovery the equivalent of "the answer is cached at my local resolver" is "a hint-aware hop on this resolution path has a recent matching SVCB record and can hand it back without an upstream walk."

## 2. Motivation

Consider the three discovery scenarios from `draft-mozleywilliams-dnsop-dnsaid-01` §3:

1. **Known endpoint and domain** — direct SVCB lookup. Already cheap.
2. **Known domain, unknown service** — query `_index._agents.{domain}`, then walk the named entries. Multiple round trips; the index tells you names but not metadata.
3. **Unknown / wildcard** — search provider or federated registry. Most expensive.

Scenarios 2 and 3 commonly produce *N* candidates of which the client only wants a handful that match its needs — capabilities, intent, transport, auth posture. Today the client filters all *N* locally after fetching, often after also fetching enrichment metadata (cap docs, agent cards) for records it will discard.

The `agent-hint` option moves the filter description to the query itself. If any hop along the path understands the option, that hop can:

- Return only the subset that matches (a hint-aware authoritative)
- Serve a cached pre-filtered answer (a hint-aware recursive resolver or forwarder)
- Short-circuit the query entirely (the client's own resolver wrapper, when the hint matches a recent cache entry)

Cost decays across three states:

- **Cold** — no caches anywhere. Client falls back to search/registry. Expensive.
- **Warm** — at least one hop is hint-aware and has a fresh matching record. No expensive search, possibly no DNS round-trip at all.
- **Hot** — the client itself has already parsed and stored an SVCB record as a long-lived "skill" reference. No query at all until the record is invalidated (failed invoke, scheduled re-verification, manual flush).

The hint is most useful at the **warm** state. At hot, it is bypassed. At cold, Path B search/registry is the right answer.

## 3. Conceptual model

The hint flows from the client toward the authoritative server. Any hop that understands the option may act on it. Hops that don't simply forward the option per RFC 6891 (commodity authoritative servers serve the same records they would have served without the option):

```
                          query + agent-hint EDNS opt
   ┌─────────────┐ ─────────────────────────────────────▶ ┌──────────────┐
   │  Agent      │                                         │ Forwarder /  │
   │  runtime    │                                         │ recursive    │  (Locus 2 — optional)
   │  (Locus 1)  │ ◀──── narrowed/cached response  ────── │ (hint-aware  │
   └─────────────┘                                         │  if running  │
          │                                                │  extension)  │
          │                                                └──────┬───────┘
          │                                                       │
          │                                                       ▼
          │                                              ┌──────────────────┐
          │                                              │  Authoritative   │
          │  reads edns_signaling advertisement          │  DNS server      │  (Locus 3 — optional)
          │  from cap-doc / agent-card JSON              │  (hint-aware     │
          │  AND/OR honored_selectors echoed in OPT      │   if running     │
          │  response from hint-aware authoritative      │   extension)     │
          └─────────────────────────────────────────────▶│   OR             │
                                                         │   stock BIND /   │
                                                         │   Route53 / CF   │
                                                         │   (inert, ignores│
                                                         │    the option)   │
                                                         └──────────────────┘
```

**Locus 1 — in-process client cache.** The agent's own resolver wrapper reads the hint, checks a local cache keyed by `(qname, qtype, hint_signature)`. Cache hit short-circuits the query. The reference implementation, `EdnsAwareResolver`, ships with this PR. Always usable; no infrastructure required.

**Locus 2 — hint-aware forwarder / recursive resolver.** A corporate gateway or shared resolver that understands the hint, serves cached pre-filtered responses, or rewrites the query before forwarding. Out of scope for this PR; valid future deployment.

**Locus 3 — hint-aware authoritative server.** A DNS server implementation that inspects the hint on incoming queries and narrows the response set to records matching the selectors. For example: a domain publishes 50 agents, the client queries with `capabilities=chat & intent=summarize`, the authoritative returns just the 2 records that match. Out of scope for this PR's reference implementation; the wire format and advertisement schema are designed to support this hop without modification.

Commodity authoritative servers (stock BIND, Route53, Cloudflare) are inert to unknown options per RFC 6891. They will respond identically with or without the option. That is a valid, lowest-common-denominator deployment — the client-side cache at Locus 1 still provides value.

## 4. Wire format

### 4.1 Request

EDNS(0) option-code **65430** (private use, RFC 6891 §6.1.1, range 65001–65534).

```
+------+------+------+------+------+------+
| OPTION-CODE = 65430  | OPTION-LENGTH    |
+----------------------+------------------+
| VERSION (1B)  | SELECTOR-COUNT (1B)     |
+---------------+-------------------------+
| selector-code (1B) | selector-length (1B) | selector-value (N B UTF-8) |
+--------------------+----------------------+----------------------------+
                    ...
```

- **VERSION** — `0x00` for the current version. The high bit (`0x80`) is reserved for the response-side echo (see §4.2).
- **SELECTOR-COUNT** — number of selectors that follow. May be zero.
- Each selector is a 1-byte type code, a 1-byte length, and a length-prefixed UTF-8 value (≤ 255 bytes).
- Total option payload SHOULD NOT exceed 512 bytes (soft cap to keep EDNS budget reasonable).

Consumers MUST ignore selector codes they don't recognise rather than reject the whole option.

### 4.2 Response echo

A hint-aware hop MAY include an `agent-hint` option in its response with the VERSION byte's high bit set (`0x80`) to indicate "this is an echo, not a request." The payload lists the selector codes the responder actually honoured:

```
+------+------+------+------+------+------+
| OPTION-CODE = 65430  | OPTION-LENGTH    |
+----------------------+------------------+
| VERSION (0x80) | APPLIED-COUNT (1B)     |
+----------------+------------------------+
| selector-code (1B) | selector-code (1B) | ...                          |
+--------------------+----------------------+------------------------+
```

Absence of an echo on a response is meaningful — it tells the client no upstream filtering happened, and the client should fall back to local filtering against the returned record set. This mirrors RFC 8914 (Extended DNS Errors) in pattern: response-only, non-mandatory, additive context.

### 4.3 Selectors v0

| Code | Name | Value format | Example |
|------|------|--------------|---------|
| 0x01 | `capabilities` | Comma-separated UTF-8 list | `"chat,code-review"` |
| 0x02 | `intent` | Single UTF-8 tag | `"summarize"` |
| 0x03 | `transport` | `"mcp"` \| `"a2a"` \| `"https"` | `"mcp"` |
| 0x04 | `auth_type` | `"none"` \| `"bearer"` \| `"oauth2"` \| `"mtls"` | `"bearer"` |

Codes `0x05` through `0xFF` are reserved for future selectors. The taxonomy intentionally matches the existing Path A filter kwargs on `dns_aid.discover()`.

### 4.4 Worked example

A client looking for an MCP-transport, bearer-auth chat agent emits an option payload of:

```
version=0x00  count=0x04
0x01 0x04 "chat"
0x02 0x09 "summarize"
0x03 0x03 "mcp"
0x04 0x06 "bearer"
```

Bytes on the wire: `00 04 01 04 63 68 61 74 02 09 73 75 6d 6d 61 72 69 7a 65 03 03 6d 63 70 04 06 62 65 61 72 65 72` (32 bytes payload, well under the 512-byte cap).

A hint-aware authoritative that applied both `capabilities` and `transport` (but not `intent` or `auth_type`) would echo:

```
version=0x80  count=0x02
0x01 0x03
```

Bytes: `80 02 01 03` (4 bytes payload).

## 5. Publisher advertisement

A hint-aware deployment advertises across two complementary channels.

### 5.1 Channel 1 — well-known JSON

Every publisher (hint-aware or not) MAY include an `edns_signaling` block in their `cap-doc`, `agent-card`, or `agents-index.json`:

```json
{
  "name": "chat-agent",
  ...
  "edns_signaling": {
    "version": 0,
    "honored_selectors": ["capabilities", "intent", "transport"],
    "note": "Recommends client-side pre-filtering with these selectors."
  }
}
```

This tells the client which selectors are *meaningful* for this publisher's agents — i.e. the publisher has populated the matching metadata fields so filtering on them will actually narrow results. Independent of whether any hop on the DNS resolution path is hint-aware; useful even with stock authoritative software.

### 5.2 Channel 2 — DNS-layer signal

A hint-aware authoritative or recursive server signals its capability in one of two ways:

1. **OPT response echo** (preferred) — described in §4.2. The presence of an echo on a query response is itself the advertisement: "this responder processed your hint."
2. **SVCB advertisement parameter** (optional, static advertisement at zone-discovery time) — a new param key `key65409 = "agent-hint"` on the apex SVCB record at `_agents.{domain}`, with a value like `v=0;selectors=capabilities,intent,transport`. Tells clients before they emit their first hint that this zone's authoritative will honour it. v0 keeps this optional; the echo carries the same information reactively.

Channels are complementary. A client uses Channel 1 to decide *which selectors to populate*, and Channel 2 to know *whether to expect upstream narrowing or rely on local filtering*.

## 6. Reference implementation

The PR that introduces this document ships three modules under `dns_aid.experimental`:

- `AgentHint` — Pydantic model for the request payload, with `encode()`, `signature()`, and `decode_agent_hint()`.
- `AgentHintEcho` — model for the response echo payload.
- `EdnsAwareResolver` — Locus 1 implementation. Wraps `dns.asyncresolver.Resolver`, attaches the option on outgoing queries (when a hint and the env flag are present), caches answers keyed by `(qname, qtype, hint_signature)`, and surfaces any upstream `AgentHintEcho` on the result.

Integration with `dns_aid.discover()`:

```python
from dns_aid import discover
from dns_aid.experimental import AgentHint

result = await discover(
    "example.com",
    agent_hint=AgentHint(capabilities=["chat"], transport="mcp"),
)
```

The `agent_hint` kwarg is accepted unconditionally for forward-compat. The option is only emitted on the wire when `DNS_AID_EXPERIMENTAL_EDNS_HINTS=1` is set in the environment.

A CLI demonstration command is available: `dns-aid edns-probe <domain>` (also env-gated).

## 7. Privacy considerations

Hints leak query intent — capabilities, intent, transport, auth posture — to **every hop that sees them**. This is more than a bare SVCB query reveals.

Clients SHOULD:

- Omit selectors when querying on public networks or for sensitive intents.
- Consider that the recursive resolver, all forwarders, and the authoritative server see the full hint set.
- Treat the hint as opt-in metadata sharing: by sending it, the client opts into being identifiable along axes the bare DNS query would not have exposed.

Operators of recursive resolvers SHOULD consider scrubbing or summarizing `agent-hint` payloads at the recursive boundary, similar to ECS (RFC 7871) source-prefix scrubbing.

EDNS padding (RFC 7830) can be used in conjunction with `agent-hint` to make payload-size analysis less informative.

## 8. Security considerations

- **Programmable-hop trust.** A hint-aware hop that narrows the response set is a trusted relay for filtering semantics. A malicious or compromised hop could omit matching records, return records that don't match the selectors, or fabricate records. DNSSEC continues to protect the answer-set integrity (when present) but cannot vouch for filtering semantics — only that the records returned were authentically published.
- **Echo unauthenticated.** The response echo (§4.2) is unsigned. DNSSEC signs the answer set but not OPT records. A hop could lie about what it filtered. Clients SHOULD validate by re-applying selectors locally to the returned records; treat the echo as a hint, not a guarantee.
- **Cache poisoning at Locus 1.** The reference `EdnsAwareResolver` caches by hint signature. An attacker who can inject a forged DNS response on a cache miss could pollute the cache for any future query with that signature. Standard DNS poisoning mitigations apply; running DNSSEC validation on the path closes the most common vector.
- **Hint tampering on the path.** Forwarders that don't understand the option are required to propagate it per RFC 6891, but a hostile forwarder could rewrite or strip the option. The reference implementation tolerates strip gracefully (the option simply doesn't reach the upstream hop, and local filtering takes over). Rewrite is more concerning: a forwarder injecting a different `intent` or `auth_type` could cause the client to be served a different agent than it asked for. Mitigation is the same as for echo trust — the client SHOULD re-apply selectors locally.

## 9. Open questions

1. **Middlebox transparency.** Novel 65xxx options may be stripped by forwarders that don't pass unknown options through, despite the RFC 6891 requirement. The reference implementation is designed to remain useful even when the option never leaves the client (Locus 1). Operators relying on Locus 2 or 3 should test their path with `tcpdump`.
2. **Selector taxonomy lock-in.** Once selector codes `0x01`–`0x04` ship, changing them is painful — hint-aware implementations will index and cache on those codes. Worth a separate taxonomy review pass before any IANA action.
3. **Echo authentication.** Is unauthenticated echo enough? A signed echo would require a different transport (the OPT record can't be DNSSEC-signed). Alternative: include a hash of the applied-selector set in the answer-section TXT, signed alongside the SVCB. Deferred to future work.
4. **Draft alignment.** Likely a separate `draft-XXX-dnsaid-edns-signaling` rather than an appendix to `draft-mozleywilliams-dnsop-dnsaid-01`, because the wire-format addition and authoritative-side semantics are substantial.

## 10. Future work

- **Hint-aware authoritative reference implementation.** This PR ships the wire format, the client-side spike, and the advertisement schema. A reference hint-aware authoritative is the next major step in the maturity ladder.
- **IANA option-code reservation.** Currently in the private-use range. Promote when the design stabilizes.
- **Recursive-resolver / forwarder reference.** Locus 2 deployment — likely shipped as a sidecar service or an extension to an existing recursive.
- **Integration with the SDK search wrapper (Path B).** A hint-aware Path B directory could carry the hint forward across multi-domain searches.
- **Padding strategy.** Recommended sizing and chaff to mitigate intent-inference attacks on the hint payload.

## 11. References

- [RFC 6891](https://www.rfc-editor.org/rfc/rfc6891) — Extension Mechanisms for DNS (EDNS(0))
- [RFC 7871](https://www.rfc-editor.org/rfc/rfc7871) — Client Subnet in DNS Queries
- [RFC 8914](https://www.rfc-editor.org/rfc/rfc8914) — Extended DNS Errors (echo pattern reference)
- [draft-mozleywilliams-dnsop-dnsaid-01](https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-dnsaid/) — DNS-AID main spec
- [draft-ietf-dnsop-svcb-https](https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/) — SVCB record type (RFC 9460)
