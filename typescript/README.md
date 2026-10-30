# @dns-aid/core

DNS-AID (draft-mozleywilliams-dnsop-dnsaid-02) agent discovery and verification for TypeScript.

- Native RFC 9460 SVCB/HTTPS codec (Node, Bun, Deno and browsers have none).
- Pluggable transports: `Do53Transport` (Node UDP/TCP, system resolver, default) and
  `DohTransport` (RFC 8484 wire format, any runtime with `fetch`).
- DNSSEC: EDNS0 DO bit set, resolver AD flag surfaced as `dnssec_validated`; `requireDnssec` gate.
- `sig` SvcParam verification: compact JWS ES256, canonical payload and `svcb` digest identical to dns-aid-core.
- Agent-card enrichment (`/.well-known/agent-card.json`) and `resolveMcpEndpoint()`.
- Output shapes use the same field names as the Python `AgentRecord`, `DiscoveryResult`.

```ts
import { discover, resolveMcpEndpoint } from "@dns-aid/core";
import { Do53Transport } from "@dns-aid/core/node";

const r = await discover({ transport: new Do53Transport() }, "example.com", { protocol: "mcp" });
for (const a of r.agents) {
  const url = await resolveMcpEndpoint(a);        // e.g. https://mcp.example.com:443/mcp
  console.log(a.fqdn, url, a.dnssec_validated, a.signature_status);
}
```

Edge/browser: `new DohTransport({ url: "https://your-resolver.example/dns-query" })`.
Public DoH endpoints are often blocked on corporate networks; prefer the organisation's resolver.

Not yet implemented: `cap` document fetch and `cap-sha256` pin, `verify()` security score,
DANE, catalog pointers, publishing. See [DESIGN.md](DESIGN.md).

Tests: `npm test` (offline vectors from dns-aid-core), `npm run test:live` (system resolver).
