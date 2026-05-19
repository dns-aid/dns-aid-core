# DNS-AID Architecture

## Overview

DNS-AID implements the IETF draft-mozleywilliams-dnsop-dnsaid-01 protocol for
DNS-based agent discovery. This document covers the key architectural decisions.

---

## Metadata Resolution Strategy

Agent metadata is resolved through a **priority-based strategy** aligned with
the DNS-AID specification. Understanding this hierarchy is critical — it
explains why certain fields (description, use_cases, category) may appear as
`null` in the directory even when they exist in DNS TXT records.

### The Three Metadata Sources

| Source | Data Format | Rich Metadata | Authority Level |
|--------|-------------|---------------|-----------------|
| **Cap URI** (SVCB `cap=` param) | JSON document at URI | Full (description, use_cases, category, capabilities, version) | Authoritative |
| **HTTP Index** (`/.well-known/agent-index.json`) | JSON document | Full | Authoritative |
| **TXT Record** (`capabilities=...`) | Key-value strings | Minimal (capabilities + version only) | Fallback |

### Resolution Priority

```
Agent discovered via SVCB record
│
├─ SVCB has cap= parameter?
│  YES → Fetch capability document from cap URI
│        Parse: capabilities, version, description, use_cases, category
│        If document is an A2A Agent Card → also attach agent_card (reuse, no second fetch)
│        Set capability_source = "cap_uri"
│
├─ cap URI missing or fetch failed? → Try A2A Agent Card
│  Fetch /.well-known/agent-card.json from target host
│  If skills present → extract skill IDs as capabilities
│  Set capability_source = "agent_card"
│
├─ No agent card? → Try HTTP Index
│  If agent has capabilities from HTTP index response
│  Set capability_source = "http_index"
│
├─ No HTTP index? → TXT record fallback
│  Query TXT record for capabilities= field
│  Parse: capabilities only
│  Set capability_source = "txt_fallback"
│
└─ No TXT record either?
   → capabilities = [], capability_source = "none"
```

### Why TXT Records Don't Carry Rich Metadata

The `dns-aid publish` CLI writes description, use_cases, and category to the
TXT record for **human readability** (useful when running `dig TXT`). However,
the discoverer intentionally does NOT parse those fields from TXT because:

1. **DNS-AID spec compliance** — The draft specifies that rich metadata should
   come from the capability document (cap URI) or HTTP index, not TXT records.
   TXT records are a lightweight fallback for basic capabilities only.

2. **DNS size constraints** — TXT records have practical size limits (~255 bytes
   per string, ~4KB total). Capability documents have no such limitation and
   can carry arbitrarily rich metadata.

3. **Structured vs. flat data** — A JSON capability document can represent
   nested structures (use_cases as arrays, descriptions with formatting).
   TXT key-value pairs cannot.

### Endpoint Source Tracking

Similarly, the endpoint URL source is tracked:

```
SVCB record found?
├─ YES → endpoint from SVCB target + port
│        Set endpoint_source = "dns_svcb"
│        │
│        └─ .well-known/agent-card.json has endpoints.{protocol}?
│           YES → append path to endpoint
│                 Set endpoint_source = "dns_svcb_enriched"
│
├─ HTTP index has endpoint with path?
│  YES → use HTTP index endpoint
│        Set endpoint_source = "http_index"
│
└─ NO  → endpoint from HTTP index URL field
         Set endpoint_source = "http_index_fallback"
```

### Custom SVCB Parameters (DNS-AID)

The DNS-AID draft defines custom SVCB parameters:

| Parameter | SVCB Key | Purpose |
|-----------|----------|---------|
| `cap` | `cap_uri` | URI to capability descriptor document |
| `capsha256` | `cap_sha256` | Integrity hash of capability document |
| `bap` | `bap` | DNS-AID Application Protocols (e.g., `mcp,a2a`) |
| `policy` | `policy_uri` | URI to agent policy document |
| `realm` | `realm` | Multi-tenant scope / authorization realm |

**Note:** AWS Route 53 does not currently support custom SVCB parameter names.
These must be encoded using the RFC 9460 generic `keyNNNNN` wire format for
Route 53 compatibility. This is tracked as a known interoperability issue.

---

## Path A vs Path B (search surfaces)

DNS-AID exposes two complementary surfaces for finding agents:

| | **Path A** (`discover()`) | **Path B** (`AgentClient.search()`) |
|---|---|---|
| **Source of truth** | The target domain's DNS substrate | An opt-in directory backend (e.g. `api.example.com`) |
| **Scope** | Single domain — one zone at a time | Cross-domain — every indexed domain in one query |
| **Filtering** | Pure-Python predicates over an in-memory list (`<50` agents typical) | Backend SQL/index over millions of agents |
| **Trust signals** | Per-agent JWS verification + DNSSEC | Pre-computed aggregate scores from crawler telemetry |
| **Network calls** | DNS queries to the target's nameservers + optional HTTPS to the target's `/.well-known/` | Single HTTPS GET to the configured directory |
| **Auth** | None needed (DNS is unauthenticated) | Currently anonymous; SDK auth handlers planned (Phase 5.6.1) |
| **Required config** | Nothing | `directory_api_url` (or env var) |
| **Failure isolation** | DNS errors are scoped to the target domain | Directory outage is logged-and-swallowed; never blocks Path A |

### When to use which

**Use Path A when** you already know the target domain and want authoritative DNS-bound
data with no third-party trust assumptions. This is the **zero-trust default**.

**Use Path B when** you don't know which domain hosts the agent you want, or you
need ranking signals across many domains (security score, trust score, popularity)
that DNS alone can't provide.

### Composition pattern (zero-trust)

The recommended pattern is **search → re-verify → invoke**:

```
1. Path B: AgentClient.search(q="payment processing")
   → returns ranked candidates with directory-attested trust signals
2. Path A: discover(candidate.domain, name=candidate.name, require_signed=True)
   → re-verifies the candidate via DNS substrate before any invocation
3. AgentClient.invoke(verified_agent, ...)
   → Path A is the authoritative trust gate; directory is opt-in convenience
```

Path B's trust attestations are useful *signals*, not *guarantees*. The directory
can have stale data, the crawler can be wrong about an endpoint, or a domain can
revoke an agent between crawls. Path A re-verification catches all of these.

### What lives where in code

| Layer | Path A | Path B |
|---|---|---|
| SDK | `dns_aid.core.discoverer.discover()` + `dns_aid.core.filters.apply_filters()` | `dns_aid.sdk.client.AgentClient.search()` + `dns_aid.sdk.search` (typed models) + `dns_aid.sdk.exceptions` |
| CLI | `dns-aid discover` (with new filter flags as of v0.19.0) | `dns-aid search` (new in v0.19.0) |
| MCP tool | `discover_agents_via_dns` | `search_agents` |

The CLI and MCP-tool surfaces are thin wrappers — both path A and path B converge
on the SDK layer, so cross-interface parity (FR-024/FR-025) is enforced by tests
that round-trip the same inputs through every surface.

---

## Discovery Modes

### Pure DNS Discovery

```
1. Query TXT _index._agents.{domain} → list of agent:protocol pairs
2. For each agent: Query SVCB _{name}._{protocol}._agents.{domain}
   → extract endpoint, port, ALPN + DNS-AID custom params (cap, bap, policy, realm)
3. For each agent: If cap URI present → fetch capability document (primary)
   → capabilities, version, description, use_cases, category
4. For each agent: If no cap URI or fetch failed → query TXT for capabilities= (fallback)
```

### HTTP Index Discovery

```
1. Fetch GET https://{domain}/.well-known/agent-index.json
2. Parse JSON → extract agents with full metadata
3. For each agent: Verify SVCB record exists in DNS
   - Found → endpoint_source = "dns_svcb" (authoritative)
   - Not found → endpoint_source = "http_index_fallback"
```

### Future Enhancement: HTTP Index Fallback in DNS Mode

Currently the two discovery modes are independent — pure DNS never consults the
HTTP index and vice versa. Per the DNS-AID draft, the HTTP well-known endpoint
is a complementary discovery mechanism. A future enhancement should add an
HTTP index fallback to the DNS discovery path:

```
(after step 4 in Pure DNS Discovery)
5. If no cap URI and TXT provided only basic capabilities →
   fetch /.well-known/agent-index.json as metadata enrichment
   → backfill description, use_cases, category from HTTP index
   Set capability_source = "http_index_enrichment"
```

This would allow DNS-discovered agents to get rich metadata even when their
SVCB records lack a `cap` parameter, without requiring a full switch to HTTP
Index Discovery mode.

---

## Tier 1: Execution Telemetry SDK

The SDK wraps agent invocations with telemetry capture, enabling performance
monitoring, agent ranking, community-wide ranking queries, and observability export.

### SDK Architecture

```
AgentClient.invoke(agent, method, arguments)
│
├─ ProtocolHandler (MCP / A2A / HTTPS)
│  └─ httpx.AsyncClient → agent endpoint
│     └─ Measures: latency, TTFB, status, cost headers, TLS version
│
├─ SignalCollector (in-memory)
│  └─ Records InvocationSignal per call
│  └─ Computes per-agent scorecards
│
├─ SignalStore (optional, PostgreSQL)
│  └─ Persists signals when persist_signals=True
│
├─ AgentRanker
│  └─ Weighted composite: 40% reliability + 30% latency + 15% cost + 15% freshness
│  └─ Pluggable strategies (LatencyFirst, ReliabilityFirst, WeightedComposite)
│
└─ TelemetryManager (optional, OpenTelemetry)
   └─ Spans: dns-aid.invoke with agent/protocol/status attributes
   └─ Metrics: duration histogram, count/error counters, cost counter
```

### Signal Flow

```
dns_aid.invoke(agent)
    → AgentClient.invoke()
        → ProtocolHandler.invoke() → RawResponse (timing + status)
        → SignalCollector.record() → InvocationSignal (enriched)
        → SignalStore.save()       → PostgreSQL (if persist_signals=True)
        → HTTP Push (thread)       → POST to telemetry API (if http_push_url set)
        → TelemetryManager.emit() → OTEL span + metrics (if otel_enabled=True)
    → InvocationResult (data + signal)
```

### HTTP Telemetry Push (Optional)

The SDK can optionally push telemetry signals to an external collection endpoint via `http_push_url`:

```
SDK invoke() → InvocationSignal
     │
     └─ HTTP POST (daemon thread) → configured http_push_url
```

**Key design decisions:**
- Uses `threading.Thread` with `daemon=True` for true fire-and-forget (survives event loop teardown)
- POST runs in background thread to avoid blocking invoke() calls
- Failures are logged but never raise exceptions
- Disabled by default (`http_push_url=None`); configure via `SDKConfig` or `DNS_AID_SDK_HTTP_PUSH_URL` env var

### Protocol Handlers

| Protocol | Handler | Transport | Method Mapping |
|----------|---------|-----------|----------------|
| MCP | `MCPProtocolHandler` | MCP Streamable HTTP (modern, spec 2025-03-26+) with transparent legacy plain JSON-RPC POST fallback | `tools/list`, `tools/call` |
| A2A | `A2AProtocolHandler` | JSON-RPC 2.0 / HTTPS | `tasks/send`, `tasks/get` |
| HTTPS | `HTTPSProtocolHandler` | REST / HTTPS | Method appended to URL path |

The MCP handler delegates transport to the official `mcp` Python SDK's
`streamablehttp_client`. When a target server signals incompatibility with the
modern transport (HTTP 405/406, refused initialize via JSON-RPC -32601), the
handler transparently falls back to the legacy plain JSON-RPC POST path so
on-premise and pre-2025-03-26 servers keep working. Fallback events are logged
as structured warnings (`transport.legacy_fallback`) so operators can track
which targets need migration.

### Endpoint Path Resolution

DNS SVCB records provide host + port but no HTTP path. The discoverer now
enriches endpoints by fetching `.well-known/agent-card.json` from each agent's
target host:

```
DNS SVCB → booking.example.com:443    (host + port)
.well-known/agent-card.json → endpoints.mcp = "/mcp"
Result → https://booking.example.com:443/mcp
         endpoint_source = "dns_svcb_enriched"
```

Enrichment runs concurrently for all discovered agents, deduplicates by host,
and gracefully skips hosts that don't serve `.well-known/agent-card.json`.

---

## Invocation Layer (`core/invoke.py`)

The invocation module is the single source of truth for agent communication.
Both the CLI (`dns-aid message`, `dns-aid call`, `dns-aid list-tools`) and the
MCP server (`send_a2a_message` tool) delegate to `core/invoke.py` instead of
duplicating protocol logic.

### Resolution Chain

```
send_a2a_message(domain="ai.infoblox.com", name="security-analyzer", message="...")
│
├─ 1. DNS Discovery
│     discover(domain, protocol="a2a", name=name)
│     → AgentRecord with endpoint_url
│
├─ 2. Agent Card Prefetch
│     GET https://{endpoint_host}/.well-known/agent-card.json
│     → canonical URL, name, description, skills
│     │
│     └─ Host mismatch check:
│        card.url hostname != DNS endpoint hostname?
│        YES → log warning, use DNS endpoint (DNS is authoritative)
│        NO  → use agent card URL (may include path)
│
└─ 3. Invoke
      POST {resolved_endpoint}
      JSON-RPC 2.0: {"method": "message/send", "params": {...}}
      → InvokeResult(text, raw, error)
```

### SDK vs Raw httpx Paths

```
invoke.py
├─ SDK available? (dns_aid.sdk importable + AgentRecord available)
│  YES → AgentClient.invoke(agent, method="message/send", ...)
│         → telemetry capture, signal collection, ranking
│         → InvokeResult from InvocationResult
│
└─ NO  → Raw httpx.AsyncClient POST
          → JSON-RPC 2.0 envelope, manual response parsing
          → InvokeResult from httpx.Response
```

The SDK path is preferred when available — it captures telemetry signals and
feeds the ranking system. The raw httpx path exists as a fallback for minimal
installations without the `[sdk]` extra.

### Interface Delegation

```
┌──────────────────┐     ┌──────────────────┐
│   CLI (Typer)    │     │   MCP Server     │
│                  │     │                  │
│ dns-aid message  │     │ send_a2a_message │
│ dns-aid call     │     │ (MCP tool)       │
│ dns-aid list-tools│    │                  │
└────────┬─────────┘     └────────┬─────────┘
         │                        │
         └───────────┬────────────┘
                     │
              ┌──────▼──────┐
              │ core/invoke │
              │             │
              │ send_a2a_message()    │
              │ call_mcp_tool()      │
              │ list_mcp_tools()     │
              │ resolve_a2a_endpoint()│
              └──────┬──────┘
                     │
         ┌───────────┴───────────┐
         │                       │
    ┌────▼─────┐          ┌──────▼──────┐
    │ SDK path │          │ httpx path  │
    │ (prefer) │          │ (fallback)  │
    └──────────┘          └─────────────┘
```

---

## Community Rankings (Optional)

The SDK can fetch community-wide telemetry rankings when a telemetry API is configured:

```
AgentClient.fetch_rankings(fqdns, limit)
    │
    └─ GET {telemetry_api_url}/rankings
       │
       └─ Returns pre-computed composite scores based on aggregated telemetry
```

This enables orchestrators to select agents based on community-observed
reliability and latency, not just cost. Requires `telemetry_api_url` to be
configured in `SDKConfig`.

### LangGraph Integration Pattern

The following LangGraph pattern illustrates how competitive agent selection could work (conceptual — no built-in LangGraph integration is shipped with dns-aid-core):

```
┌──────────┐   ┌────────────┐   ┌────────┐   ┌────────┐   ┌────────┐
│ discover │──▶│fetch_costs │──▶│  rank  │──▶│ select │──▶│ invoke │
│(DNS-AID) │   │(tools/list)│   │(telem.)│   │ (best) │   │        │
└──────────┘   └────────────┘   └────────┘   └────────┘   └────────┘
```

This pattern can be implemented with any orchestrator (LangGraph, LangChain, custom).

---

## JWS Signature Verification

DNS-AID provides application-layer signature verification as an alternative to
DNSSEC for environments where DNSSEC cannot be enabled.

### Problem

DNSSEC adoption is ~30% globally. Many enterprises can't enable DNSSEC due to:
- Legacy DNS infrastructure
- Split-horizon DNS configurations
- Managed DNS providers without DNSSEC support

### Solution: JWS (JSON Web Signature)

Publishers sign DNS record content with a private key. Discoverers verify using
a public key fetched from `.well-known/dns-aid-jwks.json`.

```
┌─────────────────────────────────────────────────────────────────┐
│                        PUBLISHER                                │
│                                                                 │
│  1. Generate EC P-256 keypair (once)                           │
│     └─ dns-aid keys generate --output ./keys/                  │
│                                                                 │
│  2. Publish JWKS to web server                                 │
│     └─ https://example.com/.well-known/dns-aid-jwks.json       │
│                                                                 │
│  3. Sign record payload when publishing                        │
│     └─ dns-aid publish --sign --private-key ./keys/private.pem │
│                                                                 │
│  4. SVCB record includes sig= parameter                        │
│     └─ SVCB 1 target. alpn="mcp" port=443 sig="eyJhbGci..."   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                       DISCOVERER                                │
│                                                                 │
│  1. Query SVCB record                                          │
│     └─ Extract sig= parameter                                  │
│                                                                 │
│  2. Fetch JWKS from domain                                     │
│     └─ GET https://example.com/.well-known/dns-aid-jwks.json   │
│                                                                 │
│  3. Verify JWS signature against public key                    │
│     └─ Check: algorithm, expiration, payload integrity         │
│                                                                 │
│  4. Result                                                     │
│     └─ Valid? Trust record                                     │
│     └─ Invalid? Reject or warn                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Signed Payload Structure

The JWS payload contains the canonical representation of the DNS record:

```json
{
  "fqdn": "_payment._mcp._agents.example.com",
  "target": "payment.example.com",
  "port": 443,
  "alpn": "mcp",
  "iat": 1704067200,
  "exp": 1704153600
}
```

### JWKS Document Format

```json
// GET https://example.com/.well-known/dns-aid-jwks.json
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "kid": "dns-aid-2024",
      "use": "sig",
      "x": "base64url-encoded-x-coordinate",
      "y": "base64url-encoded-y-coordinate"
    }
  ]
}
```

### Verification Priority

```
┌─────────────────────────────────────────────────┐
│            Verification Decision Tree           │
├─────────────────────────────────────────────────┤
│                                                 │
│  DNSSEC available and valid?                    │
│  ├─ YES → Trust (strongest, chain to DNS root) │
│  │                                              │
│  └─ NO → JWS sig= present in SVCB?             │
│          ├─ YES → Fetch JWKS, verify signature │
│          │        ├─ Valid → Trust             │
│          │        └─ Invalid → Reject/Warn     │
│          │                                      │
│          └─ NO → No verification available     │
│                  ├─ Strict mode → Reject       │
│                  └─ Default → Warn but allow   │
└─────────────────────────────────────────────────┘
```

### Usage: Three Interfaces

**Python Library:**
```python
from dns_aid.core.jwks import generate_keypair, export_jwks, sign_record
from dns_aid import publish, discover

# Generate keys
private_key, public_key = generate_keypair()
jwks_json = export_jwks(public_key, kid="dns-aid-2024")

# Publish with signature
await publish(
    name="payment",
    domain="example.com",
    protocol="mcp",
    endpoint="payment.example.com",
    sign=True,
    private_key_path="./keys/private.pem",
)

# Discover with verification
agents = await discover("example.com", verify_signatures=True)
```

**CLI:**
```bash
# Generate keypair
dns-aid keys generate --output ./keys/

# Export JWKS (host at .well-known/dns-aid-jwks.json)
dns-aid keys export-jwks --key ./keys/public.pem --output jwks.json

# Publish with signature
dns-aid publish payment example.com mcp payment.example.com \
    --sign --private-key ./keys/private.pem

# Discover with verification
dns-aid discover example.com --verify-signatures
```

**MCP Server:**
```json
// Tools available via MCP
{
  "name": "publish_agent_to_dns",
  "arguments": {
    "name": "payment",
    "domain": "example.com",
    "sign": true,
    "private_key_path": "./keys/private.pem"
  }
}
```

### Security Model

| Component | Trust Source |
|-----------|--------------|
| Private key | Publisher keeps secret |
| Public key (JWKS) | HTTPS certificate of domain |
| Signature validity | Cryptographic verification (ES256) |

**Trust anchor**: If you trust `https://example.com` (valid TLS cert), you trust
their JWKS, and therefore their signed DNS records.

This is weaker than DNSSEC (which has cryptographic chain to DNS root) but
significantly easier to deploy for organizations without DNSSEC capability.

---

## Domain Control Validation (DCV)

DCV is the second trust primitive in DNS-AID (alongside JWS). Where JWS proves
*key ownership* ("I control this signing key"), DCV proves *zone control* ("I can
write to this DNS zone"). Together they close the two main impersonation vectors:
a forged signed record and an unverified zone-control claim.

### Role split

```
Challenger (e.g. directory service)     Claimant (e.g. registering org)
─────────────────────────────────────   ────────────────────────────────
issue()  → DCVChallenge                 ← receives challenge out-of-band
                                         place() → writes TXT to their zone
verify() → checks TXT in DNS           →
                                         revoke() → deletes TXT record
```

- **Challenger** calls `issue()` and `verify()`. No DNS write credentials required.
  `verify()` uses the async resolver (`dns.asyncresolver`) and is credential-free.
- **Claimant** calls `place()` and `revoke()`. Requires backend write credentials
  for the domain being validated.

### Wire format

```
_agents-challenge.{domain}  TXT  "token=<32-char-base32>  [domain=<domain>]  [bnd-req=svc:<agent>@<issuer>]  expiry=<RFC3339Z>"
```

Fields:
- `token=` — 20-byte base32 nonce; compared constant-time via `hmac.compare_digest`
- `domain=` — binds the token to the queried domain; prevents cross-domain replay
- `bnd-req=` — optional; `verify()` enforces exact match when `expected_bnd_req` is supplied
- `expiry=` — mandatory; `verify()` fails closed if absent, malformed, or past

### Security properties

| Guarantee | Mechanism |
|-----------|-----------|
| Fail-closed expiry | Missing or malformed `expiry=` → `verified=False` |
| Cross-domain replay prevention | `domain=` field checked by `verify()` |
| Cross-vendor token reuse (DCV H2) | `bnd-req` enforced when `expected_bnd_req` supplied |
| Timing side-channel | `hmac.compare_digest` on token and bnd-req |
| DNS cache staleness | `resolver.cache = None` + `lifetime = 4.0` |
| DoS via record flooding | `MAX_CHALLENGE_RECORDS = 10` loop cap |
| DNSSEC | `require_dnssec=True` checks AD flag from upstream resolver |
| Backend TXT quoting | `_parse_txt_value` strips one layer of RFC-1035 outer quotes |

### Tier placement

DCV is **Tier 0** — it depends only on `dns.asyncresolver` (already a core
dependency) and the existing backend abstraction. No SDK or cloud-specific imports.
`place()` and `revoke()` use the same backend interface as `publish()`.

### Use cases

1. **Anonymous / NAT agent asserting org affiliation** — an agent behind NAT proves
   write access to its org's zone by placing the challenger's token there.
2. **Directory anti-impersonation** — a directory requires zone-control proof before
   setting `org_verified=True` on a registered agent.

See [api-reference.md#domain-control-validation](api-reference.md#domain-control-validation-dcv)
for the full public API, parameter tables, and fail-closed contract specification.

---

## Backend API: get_record() Method

All DNS backends now implement `get_record()` for direct API-based record lookup:

```python
async def get_record(
    self,
    zone: str,
    name: str,
    record_type: str,
) -> dict | None:
    """
    Get a specific DNS record by querying the backend API directly.

    Returns:
        Record dict with name, fqdn, type, ttl, values if found, None otherwise
    """
```

### Implementation by Backend

| Backend | Method |
|---------|--------|
| Route53 | `list_resource_record_sets` API with StartRecordName filter |
| Cloudflare | `/zones/{id}/dns_records` API with name+type filter |
| Infoblox BloxOne | `/dns/record` API with `_filter` parameter |
| DDNS | DNS query to configured server (not public resolver) |
| Mock | In-memory dict lookup |

This enables reliable reconciliation state-checking without depending on
public DNS resolver support for SVCB records.

## Experimental namespace (`src/dns_aid/experimental/`)

A fourth subpackage sits alongside `core/`, `sdk/`, and `backends/`: `experimental/`.
It is a stability-marked staging area for forward-looking features that need
real code and a public design doc but are not yet stable enough to commit to
across semver releases.

Rules:

- APIs in `experimental` are **not** subject to semver. They may change shape or
  disappear in any release, including patch versions.
- Symbols are **never** re-exported from `dns_aid/__init__.py`. Callers must
  import explicitly: `from dns_aid.experimental import AgentHint`. This makes
  accidental adoption visible at the import line.
- Each feature has a **per-feature environment flag** (e.g.
  `DNS_AID_EXPERIMENTAL_EDNS_HINTS=1`). When the flag is unset, related runtime
  code paths stay dormant even if the symbols are imported.
- Each feature has a **design doc** under `docs/experimental/`, written with
  section headers that map to future IETF-draft sections (Overview, Motivation,
  Wire Format, Privacy, Security, Open Questions, Future Work).
- When a feature graduates to stable, it moves out of `experimental/` into the
  appropriate tier, gets re-exported from the top-level package, and its design
  doc relocates from `docs/experimental/` to `docs/rfc/`.

Currently shipped:

| Feature | Module | Env flag | Doc |
|---|---|---|---|
| EDNS(0) `agent-hint` signaling | `experimental/edns_hint.py`, `experimental/edns_cache.py` | `DNS_AID_EXPERIMENTAL_EDNS_HINTS` | [edns-signaling.md](experimental/edns-signaling.md) |
