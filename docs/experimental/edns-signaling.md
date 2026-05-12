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

Two pressures motivate adding a query-time signaling channel:

**Filtering at the right layer.** Scenarios 2 and 3 commonly produce *N* candidates of which the client only wants a handful that match its needs. Today the client filters all *N* locally after fetching, often after dereferencing enrichment metadata (cap-docs, agent cards) for records it will discard. Some of that filtering — multi-tenant scope, transport binding, policy posture, jurisdiction — is on data the authoritative server already has at the DNS layer. Pushing those filters into the query lets a hint-aware hop narrow the result set or short-circuit with a cached pre-filtered match.

**Async fan-out / parallel agent workflows.** A client running a multi-agent job — research, draft, review, format — dispatches several discoveries in parallel against different domains. Each sibling query shares lifecycle properties: the same wait budget, the same intent class (the client is about to invoke, not browse), the same expected parallelism count. A query-time signal lets a cache anticipate the fan-out and pre-warm related lookups; lets an auth choose a faster code path when the deadline is tight; lets a forwarder rate-limit discovery probes more aggressively than imminent-invocation lookups. None of that requires changing what records get returned — it changes the lifecycle policy applied to the request.

These two pressures pull in different directions, which is why the design splits selectors into two axes:

- **Axis 1 — substrate filters.** What records the auth/cache returns. Different values → different answer sets → participate in the cache key.
- **Axis 2 — metering / lifecycle.** Policy applied to the request: rate limits, freshness, sibling count, deadline. Do not fragment the cache.

Cost decays across three states (orthogonal to which selectors a client uses):

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

**Locus 1 — in-client programmable hop.** Today this is `EdnsAwareResolver`: a thin resolver wrapper that reads the hint, checks a local cache keyed by `(qname, qtype, hint_signature)`, and short-circuits on a hit. The wire-level emission of the option is also done here. Longer-term, Locus 1 is whatever the SDK grows into — a richer in-process cache that pre-fetches cap-docs on `parallelism` hints, anticipates sibling queries on `client_intent_class=invocation`, and tracks deadlines across a fan-out. The same role might also be filled by a small DNS-like cache process co-located with the agent runtime, fetching agentic metadata out of band and serving warm answers to the agent. Either deployment shape uses the same wire semantics; only the process boundary differs. Locus 1 is always usable — no infrastructure required.

**Locus 2 — hint-aware forwarder / recursive resolver.** A corporate gateway or shared resolver that understands the hint, serves cached pre-filtered responses, or rewrites the query before forwarding. Out of scope for this PR; valid future deployment.

**Locus 3 — hint-aware authoritative server.** A DNS server implementation that inspects the hint on incoming queries and narrows the response set to records matching the selectors. For example: a domain publishes 50 agents, the client queries with `realm=prod & transport=mcp & policy_required=1`, the authoritative returns just the records that match all three. Out of scope for this PR's reference implementation; the wire format and advertisement schema are designed to support this hop without modification.

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

### 4.3 Selectors v0 — two axes

Selector codes are split into two axes by code range. The split is **structural**, not just advisory — it determines cache behaviour (see §4.5).

#### Axis 1 — substrate filters (codes 0x01–0x0F)

Things the auth/cache can decide on without dereferencing anything out-of-band. Different Axis-1 values mean different *answer sets*.

| Code | Name | Value format | What it asks for |
|------|------|--------------|------------------|
| 0x01 | `realm` | UTF-8 | Match SVCB `realm=` param (multi-tenant scope) |
| 0x02 | `transport` | `"mcp"` \| `"a2a"` \| `"https"` | Encoded in `_{proto}._agents` owner-name and `alpn` |
| 0x03 | `policy_required` | `"1"` (or absent) | Only records carrying a `policy=` URI |
| 0x04 | `min_trust` | `"signed"` \| `"dnssec"` \| `"signed+dnssec"` | Gated on `sig` param + DNSSEC chain status |
| 0x05 | `jurisdiction` | ISO region (e.g. `"eu"`, `"us-east"`) | Compliance lever; needs publisher-side metadata |

`policy_required=0` is the default and is **not** emitted on the wire — absence means "don't care," not "forbid."

Codes `0x06`–`0x0F` are reserved for future Axis-1 selectors.

#### Axis 2 — metering / lifecycle (codes 0x10–0x1F)

Things about the request itself. Drive accept/reject/rate-limit/prefetch policy but do NOT change what records get returned (see §4.5).

| Code | Name | Value format | What it asks for |
|------|------|--------------|------------------|
| 0x10 | `client_intent_class` | `"discovery"` \| `"invocation"` | Browsing vs about-to-call; auths can rate-limit discovery harder |
| 0x11 | `max_age` | UTF-8 decimal seconds | Cache freshness budget (analog to HTTP `Cache-Control: max-age`) |
| 0x12 | `parallelism` | UTF-8 decimal uint | Expected sibling-query count; signals fan-out to caches |
| 0x13 | `deadline_ms` | UTF-8 decimal uint | Client's wait budget. **Hint-only** — see honesty note below |

Codes `0x14`–`0x1F` are reserved for future Axis-2 selectors.

**Honesty about `deadline_ms`.** DNS has no semantic for "refuse for SLA reasons." An auth or recursive that sees a tight deadline can: (a) prefer a faster code path; (b) serve a stale cache entry to make the budget; (c) log/audit the deadline class for capacity planning. It cannot return a "won't meet deadline" error in v0 — that would require a new RCODE or a structured error in the OPT response, which is out of scope.

#### Reserved for future axes (0x20+)

| Code | Name | Status | Notes |
|------|------|--------|-------|
| 0x20 | `client_cookie` | Documented, not coded | DNS-cookie-style proof-of-work / auth token. Real value for gating high-cost zones. Skipped in v0 code by design — adds an auth dimension that should be specified separately. |
| 0x21 | `correlation_id` | Documented, not coded | Opaque workflow ID linking sibling queries. Useful for distributed tracing, but linkability across queries has privacy cost. Deferred until taxonomy locks. |

#### Explicitly NOT DNS-layer selectors

`capabilities` and `intent` belong in the **Channel 1 JSON advertisement** (§5.1), not in this wire option. The reason is layering: SVCB doesn't carry capability strings — those live in cap-doc JSON that the auth would have to dereference per-query to filter on. That dereference breaks DNS latency budgets and forces async work into a synchronous handler. The publisher tells the client which selectors are meaningful via `edns_signaling.honored_selectors`; the client uses that list for **post-fetch local filtering**, not query-time signaling.

### 4.4 Worked example: async fan-out

A client running a multi-agent job (research → draft → review → format) dispatches four discoveries in parallel. Each sibling query carries the same metering profile:

- `realm=prod` (Axis 1 — must match published realm)
- `transport=mcp` (Axis 1)
- `client_intent_class=invocation` (Axis 2 — about to call, not browsing)
- `parallelism=4` (Axis 2 — three more siblings coming)
- `deadline_ms=30000` (Axis 2 — caller will wait at most 30 s)

Wire payload:

```
version=0x00  count=0x05
0x01 0x04 "prod"                     (realm)
0x02 0x03 "mcp"                      (transport)
0x10 0x0a "invocation"               (client_intent_class)
0x12 0x01 "4"                        (parallelism)
0x13 0x05 "30000"                    (deadline_ms)
```

A hint-aware cache (Locus 1 or 2) that sees this on one of the four sibling queries can:

- Pre-warm cap-doc fetches for any candidate matching `realm=prod & transport=mcp`
- Keep the cache entry warm long enough to satisfy the other three siblings (which will share the same `signature()` because their Axis 1 values are identical)
- Skip cache-tier policy that would otherwise rate-limit a `discovery` burst, because `client_intent_class=invocation` says these are imminent

A hint-aware authoritative that honoured `realm` and `transport` (but not the metering selectors, which don't apply to it) would echo:

```
version=0x80  count=0x02
0x01 0x02
```

Bytes on the wire: `80 02 01 02` (4 bytes payload).

### 4.5 Cache-key semantics (load-bearing invariant)

Axis 1 selectors participate in `AgentHint.signature()`. Axis 2 selectors do not.

This is the key design invariant: two queries that differ only in Axis 2 fields — say, one with `parallelism=4` and another with `parallelism=64` — MUST hit the same cache entry. They are asking for the same *answer set*, just with different policy applied to *how the request is handled*. Fragmenting the cache on metering would defeat the warm-state amortisation the design is built around.

Equivalently: a hint-aware cache keys its entries on Axis 1 selectors only; Axis 2 selectors drive lifecycle decisions (rate limit, prefetch, deadline-aware serving) without affecting what gets cached or what gets returned.

The reference implementation enforces this — `AgentHint.signature()` only includes Axis 1 fields, and `EdnsAwareResolver` uses that signature as its cache key.

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
    "honored_selectors": ["realm", "transport", "capabilities", "intent"],
    "note": "realm/transport narrow at the DNS layer; capabilities/intent are for client-side post-fetch filtering."
  }
}
```

`honored_selectors` may include both DNS-layer selector names (Axis 1, e.g. `realm`, `transport`) AND JSON-only selectors the client should filter on locally after fetch (e.g. `capabilities`, `intent`). The publisher mixes them because the client uses the same list for both decisions — "what's worth populating in the EDNS option" and "what's worth filtering on locally."

This tells the client which selectors are *meaningful* for this publisher's agents — i.e. the publisher has populated the matching metadata fields so filtering on them will actually narrow results. Independent of whether any hop on the DNS resolution path is hint-aware; useful even with stock authoritative software.

### 5.2 Channel 2 — DNS-layer signal

A hint-aware authoritative or recursive server signals its capability in one of two ways:

1. **OPT response echo** (preferred) — described in §4.2. The presence of an echo on a query response is itself the advertisement: "this responder processed your hint."
2. **SVCB advertisement parameter** (optional, static advertisement at zone-discovery time) — a new param key `key65409 = "agent-hint"` on the apex SVCB record at `_agents.{domain}`, with a value like `v=0;selectors=realm,transport,min_trust`. Tells clients before they emit their first hint that this zone's authoritative will honour those Axis-1 selectors. v0 keeps this optional; the echo carries the same information reactively.

Channels are complementary. A client uses Channel 1 to decide *which selectors to populate* (both DNS-layer and JSON-side), and Channel 2 to know *whether to expect upstream narrowing on the DNS-layer ones or rely on local filtering*.

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
- **Hint tampering on the path.** Forwarders that don't understand the option are required to propagate it per RFC 6891, but a hostile forwarder could rewrite or strip the option. The reference implementation tolerates strip gracefully (the option simply doesn't reach the upstream hop, and local filtering takes over). Rewrite is more concerning: a forwarder injecting a different `realm` or `min_trust` could cause the client to be served a different agent than it asked for. Mitigation is the same as for echo trust — the client SHOULD re-apply Axis-1 selectors locally against the returned record set.
- **Cookies / proof-of-work (future).** A `client_cookie` selector (reserved code 0x20) would let auths gate high-cost zones against query floods. Not coded in v0; documented as a future extension. When introduced, it raises its own threat model — cookie binding, replay windows, recursive-side honesty about cookie propagation — that needs separate treatment.
- **Correlation IDs and linkability (future).** A `correlation_id` selector (reserved code 0x21) would let caches and observability tooling group sibling queries from an async fan-out. The cost is that every hop sees the same opaque ID across the fan-out, which makes per-query traffic analysis substantially easier. Defer until the privacy trade-off is explicit.

## 9. Open questions

1. **Middlebox transparency.** Novel 65xxx options may be stripped by forwarders that don't pass unknown options through, despite the RFC 6891 requirement. The reference implementation is designed to remain useful even when the option never leaves the client (Locus 1). Operators relying on Locus 2 or 3 should test their path with `tcpdump`.
2. **Selector taxonomy lock-in.** Once selector codes ship, changing them is painful — hint-aware implementations will index and cache on those codes. The two-axis split (0x01–0x0F substrate, 0x10–0x1F metering, 0x20+ reserved) buys some headroom, but the specific codes within each axis (REALM=0x01, TRANSPORT=0x02, …) are still a commitment. Worth a separate taxonomy review pass before any IANA action.
3. **Axis-encoded code ranges vs flat numbering.** v0 encodes the axis into the selector-code range. The benefit is that an on-the-wire inspector can tell at a glance which selectors are answer-shaping (Axis 1) and which are policy-shaping (Axis 2). The cost is a hard ceiling of 15 selectors per axis — enough for the foreseeable future, but a future v1 might want flat numbering with axis declared in a separate registry. Documented so the trade-off is explicit.
4. **Echo authentication.** Is unauthenticated echo enough? A signed echo would require a different transport (the OPT record can't be DNSSEC-signed). Alternative: include a hash of the applied-selector set in the answer-section TXT, signed alongside the SVCB. Deferred to future work.
5. **`deadline_ms` enforcement.** v0 makes it a hint-only signal — auth can prefer a faster path or serve stale to make the budget, but cannot return "won't meet deadline." A future revision could add a structured error in the OPT response (RFC 8914-style INFO-CODE) for explicit SLA refusal. Out of scope for v0.
6. **Draft alignment.** Likely a separate `draft-XXX-dnsaid-edns-signaling` rather than an appendix to `draft-mozleywilliams-dnsop-dnsaid-01`, because the wire-format addition and authoritative-side semantics are substantial.

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
