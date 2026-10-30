# dns-aid-ts: design and build plan

Date: 2026-10-27. Status: first cut in `typescript/` of dns-aid-core (27 tests passing,
3 of them live against the system resolver). Reference: dns-aid-core 0.28.1 (Python),
IETF draft-mozleywilliams-dnsop-dnsaid-02.

## 1. Why a TypeScript library

Context: MCP gateways and registries written in TypeScript/Bun want to add DNS-AID support.
That needs an `npm install`-able library.

- The only TS code today (`@dns-aid/mastra`) spawns the Python MCP server over stdio. That is
  not viable inside a Bun service, a Cloudflare Worker, or a browser dashboard.
- Nothing on npm does this: no `dns-aid`, `dnsaid`, or `@dns-aid/*` package exists.
- Half the agent-framework ecosystem (Mastra, Vercel AI SDK, LangChain.js, MCP gateways) is TS.
  A native library unlocks those integrations the same way `dns_aid.integrations` did for Python.

## 2. Runtime constraints that shaped the design

| Fact | Consequence |
|---|---|
| Node 26 `dns.resolve` rejects `SVCB`/`HTTPS`. Deno and Bun do too. | Ship our own RFC 9460 rdata codec. |
| dns-packet 5.6.1 has no SVCB/HTTPS codec, but round-trips unknown types as `UNKNOWN_64` with raw bytes. | Use dns-packet only for the message envelope (header, EDNS0 DO bit, AD flag); decode rdata ourselves. |
| Public DoH (Cloudflare, Google) is intercepted or blocked on corporate networks running DNS security products. | Default transport on Node is classic UDP/TCP to the system resolver. DoH is an option, not the default. |
| The AD flag is only meaningful from a validating resolver you trust. | Expose `ad` as data; let the caller decide. Document that AD from a public DoH server is a trust-the-resolver statement. |
| RFC 9460 forbids name compression in SVCB TargetName. | Rdata decodes standalone; no need for the enclosing message. |
| Ed25519 in WebCrypto is still uneven across runtimes. | Match Python: ES256 only. `jose` on WebCrypto runs everywhere. |

## 3. Architecture

```
src/
  types.ts            AgentRecord / DiscoveryResult / options  (same field names as Python)
  names.ts            owner-name builders + _index TXT grammar
  svcb/
    params.ts         key registry: RFC 9460 keys + private-use 65400..65409
    wire.ts           RFC 9460 rdata codec, typed value decoders
    presentation.ts   `1 host. alpn="mcp" key65400="..."` parser (DoH JSON, dig, zone files)
  record.ts           SvcbRdata (+TXT) -> AgentRecord; bap/well-known rules
  discover.ts         index walk, alias follow, legacy fallback, dedupe, DNSSEC gate, enrichment
  sig.ts              compact JWS ES256, canonical payload, svcb digest, JWKS fetch/cache
  card.ts             agent-card enrichment, resolveMcpEndpoint (/.well-known/agent.json -> /mcp)
  transport/
    types.ts          DnsTransport interface: query(name, type) -> {rcode, ad, signed, answers}
    message.ts        dns-packet envelope (query builder, response parser)
    do53.ts           Node UDP with TCP fallback on TC          (export "@dns-aid/core/node")
    doh.ts            RFC 8484 wire-format over fetch           (every runtime)
```

Design rules:
- One decode path. Presentation text is converted to wire rdata and then to AgentRecord, so
  DoH-JSON, dig output and real wire bytes all produce identical records.
- Transport is injected. Tests use an in-memory zone. Gateways can inject their own resolver
  (customers' internal zones are not visible to 1.1.1.1).
- No publishing in v0.1. Publishing needs provider backends (Route53, Cloudflare, NIOS); that is
  a separate package later; import-by-domain in a gateway does not need it.
- Output JSON is byte-compatible with the Python `AgentRecord.model_dump()` field names, so the
  same conformance fixtures and downstream consumers (agentcensus, ARD) work unchanged.

## 4. Fidelity to dns-aid-core

Reproduced exactly (cited to Python source in the agent survey):
- Owner names: `{name}.{domain}`, `{name}._agents.{domain}` (alias), `_index._agents.{domain}`,
  legacy `_{name}._{proto}._agents.{domain}` only behind `allowLegacy`.
- Index grammar `agents=name:proto,...`; unknown protocols skipped; `v=dns-aid1` alone = no index.
- Probe list when no index: chat, assistant, network, data-cleaner, index, multiagent, api, help, support, agent.
- SVCB -> HTTPS (type 65) retry on empty answer. Alias (priority 0) followed one hop.
- Params: logical names and `keyNNNNN` interchangeable, last wins, values rejected on `["\\` or control chars or >2048.
- `bap` grammar and comma-list collapse; protocol from bap, then alpn in {mcp,a2a,https}, then hint.
- `well-known` bare filename vs leading-slash path.
- TXT: only `capabilities=` consumed as last-resort fallback (plus version/description for display).
- Signature: ES256 only, payload `{fqdn,target,port,alpn,iat,exp[,svcb]}` canonical JSON,
  `svcb` = b64url(SHA-256("svcb1:" + canonical params)), JWKS at `dns-aid.{zone}` then `{zone}`,
  kid preferred then all keys, statuses verified / verified_endpoint_only / unbound / expired / no_key / invalid.
- Agent card: `metadata.endpoints[protocol]` -> endpoint override, `securitySchemes` -> auth_type,
  skills -> capabilities unless a cap doc already supplied them.

Not yet ported (tracked as v0.2):
- `cap` document fetch and `cap-sha256` pin check (Python drops the record on mismatch).
- `verify()` security score, DNSSECDetail chain walk, DANE/TLSA.
- `/.well-known/agent.json` auth fallback and `use_http_index` / ARD catalog pointers.
- `_catalog._agents` resolution.
- Known rough edge: `sigParamsFromRecord` re-derives the raw `well-known` value from the expanded URL.
  Keep the raw param on the record instead (one-line change in record.ts) before relying on
  `verified` for well-known-bearing records.

## 5. Verified behaviour (2026-10-27, corporate laptop)

- `_index._agents.ai.infoblox.com` TXT: 12 agents listed, AD set. None of the leaf SVCB records
  exist under any naming form. `discover()` returns an empty, non-error result. Index/leaf drift is
  real in production and the library must stay tolerant of it.
- `cloudflare.com` HTTPS: decoded from 1.1.1.1, `alpn=h3,h2`, ipv4/ipv6 hints, AD set.
- `mike-hq.com`: index present but empty (`v=dns-aid1`).
- System resolvers reported by Node here are `127.0.0.2` and `::1`; `::1` times out. The transport
  tries servers in order, so put the working one first or pass `servers` explicitly.

## 6. Build plan

Week 1 (done in this scaffold): codec, transports, discover, sig, card, conformance tests.

Week 2:
- `cap` fetch + sha256 pin; keep raw well-known param; `verify()` with the Python scoring rubric.
- Cross-implementation conformance: a JSON fixture set (SVCB text -> expected AgentRecord JSON)
  generated from dns-aid-core and consumed by both test suites. Put it in dns-aid-core
  `tests/fixtures/conformance/` so Python stays the oracle.
- CI matrix: Node 20/22/26, Bun, Deno (DoH only), Cloudflare `workerd` smoke test.
- Publish `@dns-aid/core@0.1.0` to npm under the `dns-aid` org. Claim the org first. Decide with the
  TSC whether the package stays in `typescript/` here or moves to its own repo once it has releases.

Week 3+:
- `@dns-aid/publish` (Route53, Cloudflare, NIOS via WAPI) so TS services can publish their own records.
- Rewrite `@dns-aid/mastra` on top of `@dns-aid/core` and drop the Python spawn.
- Vercel AI SDK and LangChain.js tool wrappers, same three-tool pattern as the Python integrations.

## 7. Dependencies and licence

Runtime: `dns-packet` (MIT), `jose` (MIT). Both are small and widely deployed.
Licence: Apache-2.0, same as the rest of this repository. Downstream platforms under other
licences depend on the npm package rather than vendoring the code.
