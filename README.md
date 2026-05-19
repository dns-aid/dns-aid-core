# DNS-AID

[![CI](https://github.com/infobloxopen/dns-aid-core/actions/workflows/ci.yml/badge.svg)](https://github.com/infobloxopen/dns-aid-core/actions/workflows/ci.yml)
[![Security](https://github.com/infobloxopen/dns-aid-core/actions/workflows/security.yml/badge.svg)](https://github.com/infobloxopen/dns-aid-core/actions/workflows/security.yml)
[![CodeQL](https://github.com/infobloxopen/dns-aid-core/actions/workflows/codeql.yml/badge.svg)](https://github.com/infobloxopen/dns-aid-core/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/infobloxopen/dns-aid-core/badge)](https://scorecard.dev/viewer/?uri=github.com/infobloxopen/dns-aid-core)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12651/badge)](https://www.bestpractices.dev/projects/12651)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)
[![PyPI](https://img.shields.io/pypi/v/dns-aid)](https://pypi.org/project/dns-aid/)

**DNS-based Agent Identification and Discovery**

Reference implementation for [IETF draft-mozleywilliams-dnsop-dnsaid-01](https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-dnsaid/).

DNS-AID enables AI agents to discover each other via DNS, using the internet's existing naming infrastructure instead of centralized registries or hardcoded URLs.

> **New to DNS-AID?** Start with the [Getting Started Guide](docs/getting-started.md) for install, first agent publication, and backend setup.

## Documentation

- [Getting Started Guide](docs/getting-started.md) — install, first agent publication, backend setup
- [API Reference](docs/api-reference.md) — Python SDK, CLI, and MCP server tool reference
- [Architecture](docs/architecture.md) — protocol layers, metadata resolution, integration points
- [Integrations](docs/integrations.md) — backend-specific setup notes
- [Demo Guide](docs/demo-guide.md) — end-to-end walkthrough for talks and presentations
- [Experimental Features](docs/experimental/README.md) — unstable APIs and forward-looking proposals (e.g., EDNS(0) `agent-hint` signaling)
- [Privacy Policy](PRIVACY.md) | [Security Policy](SECURITY.md) | [Trademarks](TRADEMARKS.md)

## Ecosystem and Integrations

DNS-AID is a **substrate**. The library in this repository is sufficient on its own — it publishes and resolves agent records against any DNS provider, with no dependency on a particular directory, indexer, or telemetry backend.

When a search, indexing, or telemetry layer is useful, the SDK can point at any HTTP endpoint that implements the documented interfaces. Operators are encouraged to run their own — the indexer is a thin layer over the same DNS records this library publishes and discovers, and the SDK telemetry sink is configurable via `DNS_AID_SDK_HTTP_PUSH_URL` (off by default). Independent directory implementations exist across the ecosystem; DNS-AID is designed to remain interoperable with any of them rather than canonicalize a single one.

## Quick Start

### Install

```bash
# Install from PyPI
pip install "dns-aid[cli,mcp]"

# Or install the latest unreleased main from GitHub
pip install "dns-aid[cli,mcp] @ git+https://github.com/infobloxopen/dns-aid-core.git"
```

For backend-specific extras (`route53`, `cloudflare`, `ns1`, `cloud_dns`, `infoblox`, `ddns`), see the [Getting Started Guide](docs/getting-started.md#install).

### Python Library

```python
import dns_aid

# Publish your agent to DNS
await dns_aid.publish(
    name="my-agent",
    domain="example.com",
    protocol="mcp",
    endpoint="agent.example.com",
    capabilities=["chat", "code-review"]
)

# Discover agents at a domain (Path A: DNS substrate)
agents = await dns_aid.discover("example.com")
for agent in agents:
    print(f"{agent.name}: {agent.endpoint_url}")

# Discover via HTTP index (richer metadata; format aligns with the ANS schema)
agents = await dns_aid.discover("example.com", use_http_index=True)

# Filtered discovery — pure-Python predicates over the in-memory result (v0.19.0+)
result = await dns_aid.discover(
    "example.com",
    capabilities=["payment-processing"],
    auth_type="oauth2",
    realm="prod",
    require_signed=True,
    require_signature_algorithm=["ES256", "Ed25519"],
)

# Verify an agent's DNS records
result = await dns_aid.verify("_my-agent._mcp._agents.example.com")
print(f"Security Score: {result.security_score}/100")
```

### Path B: cross-domain search via an external directory (v0.19.0+)

When the caller does not yet know which domain hosts the agent it wants, the SDK can query any directory backend that implements the search endpoint. The directory layer is **opt-in convenience**; the DNS substrate remains the authoritative trust gate.

```python
from dns_aid.sdk import AgentClient, SDKConfig

# Point at whichever directory the caller has chosen to trust.
# Can also be set via DNS_AID_SDK_DIRECTORY_API_URL.
config = SDKConfig(directory_api_url="https://your-directory.example.com")

async with AgentClient(config=config) as client:
    response = await client.search(q="payment processing", protocol="mcp")
    for r in response.results:
        print(r.agent.fqdn)
```

After the directory returns candidates, re-resolve each one through Path A and validate signatures / DNSSEC before invoking. This is the substrate-as-authority pattern: the directory provides ranking and discovery convenience, but never sits in the trust path between the caller and the agent.

```python
async with AgentClient(config=config) as client:
    response = await client.search(q="fraud detection")
    for candidate in response.results:
        verified = await dns_aid.discover(
            candidate.agent.domain,
            name=candidate.agent.name,
            require_signed=True,
        )
        # Invoke only when DNS substrate confirms the directory's claim.
```

The SDK exposes additional filter parameters (`capabilities`, `min_security_score`, `verified_only`, etc.) for directories that compute and return those signals; see [API Reference](docs/api-reference.md) for the full surface. The semantics of those values are defined by whichever directory the caller has chosen — DNS-AID does not centralize them.

### SDK: Invoke Agents & Capture Telemetry (v0.6.0+)

```python
import dns_aid

# Discover + invoke in one line — telemetry captured automatically
result = await dns_aid.discover("example.com", protocol="mcp")
agent = result.agents[0]

resp = await dns_aid.invoke(agent, method="tools/list")
print(f"Latency: {resp.signal.invocation_latency_ms}ms")
print(f"Status:  {resp.signal.status}")
print(f"Tools:   {resp.data}")

# Rank multiple agents by your own local telemetry signals
ranked = await dns_aid.rank(result.agents, method="tools/list")
for r in ranked:
    print(f"{r.agent_fqdn}: score={r.composite_score:.1f}")
```

For advanced usage (connection reuse, OpenTelemetry export, pluggable telemetry sink):

```python
from dns_aid.sdk import AgentClient, SDKConfig

config = SDKConfig(
    otel_enabled=True,         # Export to any OpenTelemetry collector
    caller_id="my-app",
    # Optional: push telemetry to any HTTP endpoint the caller controls
    # http_push_url="https://your-telemetry.example.com/v1/signals",
)

async with AgentClient(config=config) as client:
    resp = await client.invoke(agent, method="tools/call", arguments={...})
    fqdns = [a.fqdn for a in agents]
    ranked = client.rank(fqdns)  # Rank by the caller's own observed telemetry
```

If an external aggregator publishes community-wide rankings over HTTP, the SDK can fetch them via `client.fetch_rankings(...)`; the endpoint is configured by the caller, not by the library.

## CLI Usage

```bash
# Publish an agent to DNS
dns-aid publish \
    --name my-agent \
    --domain example.com \
    --protocol mcp \
    --endpoint agent.example.com \
    --capability chat \
    --capability code-review

# Publish with transport and auth metadata (v0.10.0+)
dns-aid publish \
    --name billing \
    --domain example.com \
    --protocol mcp \
    --endpoint mcp.example.com \
    --capability billing --capability invoicing \
    --transport streamable-http \
    --auth-type bearer

# Publish with DNS-AID custom SVCB parameters (v0.4.8+)
dns-aid publish \
    --name booking \
    --domain example.com \
    --protocol mcp \
    --endpoint mcp.example.com \
    --capability travel --capability booking \
    --cap-uri https://mcp.example.com/.well-known/agent-cap.json \
    --cap-sha256 dGVzdGhhc2g \
    --bap "mcp/1,a2a/1" \
    --policy-uri https://example.com/agent-policy \
    --realm production

# Discover agents at a domain (pure DNS - default)
dns-aid discover example.com

# Discover with substrate filters
dns-aid discover example.com --protocol mcp --name chat

# Discover with in-memory filters (v0.19.0+)
dns-aid discover example.com \
    --capabilities payment-processing --capabilities fraud-detection \
    --auth-type oauth2 --realm prod \
    --require-signed --require-signature-algorithm ES256

# Cross-domain search via a directory the caller has chosen (v0.19.0+)
export DNS_AID_SDK_DIRECTORY_API_URL=https://your-directory.example.com
dns-aid search "payment processing" --protocol mcp

# Discover via HTTP index (richer metadata; format aligns with the ANS schema)
dns-aid discover example.com --use-http-index

# Output as JSON
dns-aid discover example.com --json

# Verify DNS records
dns-aid verify _my-agent._mcp._agents.example.com

# List DNS-AID records in a zone
dns-aid list example.com

# List available zones (Route 53)
dns-aid zones

# Delete an agent
dns-aid delete --name my-agent --domain example.com --protocol mcp

# Index Management (v0.3.0+)
# List agents in a domain's index record
dns-aid index list example.com

# Sync index with actual DNS records (useful for repair)
dns-aid index sync example.com

# Publish without updating the index (for internal agents)
dns-aid publish --name internal-bot --domain example.com --protocol mcp --no-update-index

# Domain Submission to a Directory (v0.4.0+)
# Submit your domain to a directory of your choice for indexing.
# The --to flag (or DNS_AID_SDK_DIRECTORY_API_URL) selects which directory.
dns-aid submit example.com --to https://your-directory.example.com

# Submit with company metadata
dns-aid submit example.com \
    --to https://your-directory.example.com \
    --company-name "Example Corp" \
    --company-website "https://example.com" \
    --company-description "We build AI agents"
```

### Agent Index Records

DNS-AID v0.3.0 automatically maintains an index record at `_index._agents.{domain}` for efficient discovery:

```
_index._agents.example.com. TXT "agents=chat:mcp,billing:a2a,support:https"
```

**Benefits:**
- Single DNS query discovers all agents at a domain
- Crawlers can efficiently index domains
- Explicit list of published agents (no guessing)

The index is updated automatically when you `publish` or `delete` agents. Use `--no-update-index` to opt out for internal agents.

### Domain Control Validation (v0.20.0+)

DCV lets one party prove to another that they control a DNS zone, using a short-lived
TXT record challenge. Two use cases: anonymous agents asserting org affiliation, and
directory anti-impersonation before listing an agent as org-verified.

```bash
# Challenger: issue a challenge for a domain
CHALLENGE=$(dns-aid dcv issue orgb.example.com --agent assistant --issuer orga.example.com --json)
TOKEN=$(echo $CHALLENGE | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# Claimant: place the challenge TXT record in the zone (using their own DNS credentials)
dns-aid dcv place orgb.example.com $TOKEN

# Challenger: verify the record is present and unexpired
dns-aid dcv verify orgb.example.com $TOKEN

# Claimant: revoke after successful verification
dns-aid dcv revoke orgb.example.com $TOKEN
```

```python
from dns_aid.core import dcv

# Challenger
challenge = dcv.issue("orgb.example.com", agent_name="assistant", issuer_domain="orga.example.com")
# ... deliver challenge out-of-band to claimant ...

# Claimant (different process, different credentials)
await dcv.place(challenge.domain, challenge.token, bnd_req=challenge.bnd_req)

# Challenger
result = await dcv.verify(challenge.domain, challenge.token, expected_bnd_req=challenge.bnd_req)
if result.verified:
    await dcv.revoke(challenge.domain, token=challenge.token)
```

See [Domain Control Validation](docs/api-reference.md#domain-control-validation-dcv) in the API reference for full details.

### HTTP Index Discovery

DNS-AID also supports HTTP-based agent discovery, with an index format whose schema aligns with ANS-style directories. This provides richer metadata (descriptions, model cards, capabilities, costs) while still validating endpoints via DNS.

**Endpoint patterns tried (in order):**
1. `https://index.aiagents.{domain}/index-wellknown` (demo-friendly, no underscores)
2. `https://_index._aiagents.{domain}/index-wellknown` (ANS-style)
3. `https://{domain}/.well-known/agents-index.json` (well-known path)

**Capability Document endpoint (v0.4.8+):**
- `https://index.aiagents.{domain}/cap/{agent-name}` — returns a capability document JSON per agent

```bash
# Fetch HTTP index directly
curl https://index.aiagents.example.com/index-wellknown

# Fetch capability document for a specific agent
curl https://index.aiagents.example.com/cap/booking-agent

# CLI with HTTP index
dns-aid discover example.com --use-http-index
```

```python
# Python with HTTP index
agents = await dns_aid.discover("example.com", use_http_index=True)
```

| Discovery Method | When to Use |
|-----------------|-------------|
| **DNS (default)** | Maximum decentralization, offline caching, minimal round trips |
| **HTTP Index** | Rich metadata upfront, ANS compatibility, model cards, capabilities, direct endpoints |

**FQDN as Source of Truth (v0.4.7):** The HTTP index only needs to provide each agent's FQDN (e.g., `_booking._mcp._agents.example.com`). Agent name and protocol are extracted from the FQDN — no separate `protocols` field needed. DNS SVCB lookup then resolves the authoritative endpoint.

**Discovery Transparency (v0.4.6+):** Each discovered agent includes source fields showing how data was resolved:

| Field | Values | Description |
|-------|--------|-------------|
| `endpoint_source` | `dns_svcb`, `http_index_fallback`, `direct` | How the endpoint was resolved |
| `capability_source` | `cap_uri`, `txt_fallback`, `none` | How capabilities were discovered (v0.4.8+) |

**Capability Resolution (v0.4.8+):** Capabilities are resolved with the following priority:
1. **SVCB `cap` URI** → fetch capability document (JSON with capabilities, version, description)
2. **TXT record fallback** → `capabilities=chat,support` from DNS TXT record
3. **HTTP Index inline** → capabilities embedded in the index JSON response

## MCP Server

DNS-AID includes an MCP (Model Context Protocol) server that allows AI agents like Claude to publish and discover other agents.

### Running the MCP Server

```bash
# Run with stdio transport (default - for Claude Desktop, etc.)
dns-aid-mcp

# Run with HTTP transport
dns-aid-mcp --transport http --port 8000
```

### Available MCP Tools

| Tool | Description |
|------|-------------|
| `publish_agent_to_dns` | Publish an AI agent to DNS (auto-updates index) |
| `discover_agents_via_dns` | Discover AI agents at a domain (supports `use_http_index` for HTTP-index discovery) |
| `list_agent_tools` | List available tools on a discovered MCP agent |
| `call_agent_tool` | Call a tool on a discovered MCP agent (proxy requests) |
| `verify_agent_dns` | Verify DNS-AID records and security |
| `list_published_agents` | List all agents in a domain |
| `delete_agent_from_dns` | Remove an agent from DNS (auto-updates index) |
| `list_agent_index` | List agents in domain's index record |
| `sync_agent_index` | Sync index with actual DNS records |
| `diagnose_environment` | Run environment diagnostics (deps, DNS, backends) |

### Claude Desktop Integration

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "dns-aid": {
      "command": "dns-aid-mcp"
    }
  }
}
```

Then Claude can discover and connect to AI agents:

> "Find available agents at example.com"
>
> "Publish my chat agent to DNS at mycompany.com"
>
> "Discover agents at example.com and search for flights from SFO to JFK"

#### Live Demo

Try the live demo with Claude Desktop:

```json
{
  "mcpServers": {
    "dns-aid": {
      "command": "python",
      "args": ["-m", "dns_aid.mcp.server"]
    }
  }
}
```

Then ask Claude to discover and use the booking agent:

> "Discover agents at example.com using HTTP index, find a booking agent, and search for flights from SFO to JFK on March 15th 2026"

Claude will:
1. Call `discover_agents_via_dns` → finds booking-agent at `https://booking.example.com/mcp`
2. Call `list_agent_tools` → sees search_flights, get_flight_details, check_availability, create_reservation
3. Call `call_agent_tool` → searches for flights and returns results

## How It Works

DNS-AID uses SVCB records (RFC 9460) to advertise AI agents:

```
_chat._a2a._agents.example.com. 3600 IN SVCB 1 chat.example.com. alpn="a2a" port=443 mandatory="alpn,port"
_chat._a2a._agents.example.com. 3600 IN TXT "capabilities=chat,assistant" "version=1.0.0"
```

**DNS-AID Custom SVCB Parameters (v0.4.8+):** Per the IETF draft, SVCB records can carry additional custom parameters for richer agent metadata:

```
_booking._mcp._agents.example.com. SVCB 1 mcp.example.com. alpn="mcp" port=443 \
    cap="https://mcp.example.com/.well-known/agent-cap.json" \
    cap-sha256="dGVzdGhhc2g" bap="mcp/1,a2a/1" \
    policy="https://example.com/agent-policy" realm="production"
```

| Parameter | Purpose |
|-----------|---------|
| `cap` | URI to capability document (rich JSON metadata) |
| `cap-sha256` | SHA-256 digest of capability descriptor for integrity verification |
| `bap` | Supported bulk agent protocols with versioning |
| `policy` | URI to agent policy document |
| `realm` | Multi-tenant scope identifier |

This allows any DNS client to discover agents without proprietary protocols or central registries.

### Discovery Flow (DNS-AID Draft Aligned)

```
  Agent A                        DNS                           Agent B
     │                            │                               │
     │  "Find agents at           │                               │
     │   salesforce.com"          │                               │
     │                            │                               │
  ┌──┴──────────────────────────────────────────────────────────────┐
  │  Step 1: Fetch HTTP Index (primary)                             │
  │  ──────────────────────────────────                             │
  │  GET https://index.aiagents.salesforce.com/index-wellknown      │
  │  Response: [{"fqdn":"_chat._a2a._agents.salesforce.com",...}]   │
  │                                                                 │
  │  Fallback: Query TXT Index via DNS                              │
  │  Query: _index._agents.salesforce.com TXT                       │
  │  Response: "agents=chat:a2a,billing:mcp"                        │
  └──┬──────────────────────────────────────────────────────────────┘
     │                            │                               │
  ┌──┴──────────────────────────────────────────────────────────────┐
  │  Step 2: Query SVCB per agent                                   │
  │  ────────────────────────────                                   │
  │  Query: _chat._a2a._agents.salesforce.com SVCB                  │
  │  Response: SVCB 1 chat.salesforce.com. alpn="a2a" port=443      │
  │            cap="https://chat.salesforce.com/.well-known/cap.json"│
  │  (DNSSEC validated)                                             │
  └──┬──────────────────────────────────────────────────────────────┘
     │                            │                               │
  ┌──┴──────────────────────────────────────────────────────────────┐
  │  Step 2b: Fetch Capability Document (if cap URI present)        │
  │  ───────────────────────────────────────────────────            │
  │  GET https://chat.salesforce.com/.well-known/cap.json           │
  │  Response: {"capabilities":["chat","support"],"version":"1.0"}  │
  │  (cap_sha256 integrity verified)                                │
  └──┬──────────────────────────────────────────────────────────────┘
     │                            │                               │
  ┌──┴──────────────────────────────────────────────────────────────┐
  │  Step 3: TXT Capabilities (fallback if no cap document)         │
  │  ──────────────────────────────────────────────────             │
  │  Query: _chat._a2a._agents.salesforce.com TXT                   │
  │  Response: "capabilities=chat,support" "version=1.0.0"          │
  └──┬──────────────────────────────────────────────────────────────┘
     │                            │                               │
     ├────────────────────────────────────────────────────────────►│
     │  Connect to https://chat.salesforce.com:443                │
```

**Index Resolution Priority:** HTTP index endpoint → TXT index record → common name probing.
**Capability Resolution Priority:** SVCB `cap` URI → capability document → TXT record fallback.
Each discovered agent includes `endpoint_source` and `capability_source` showing which path was used.

## Agent Metadata Contract (v0.10.0+)

DNS discovery tells you WHERE an agent is. The **Agent Metadata Contract** tells you HOW to connect, WHAT it can do, and WHETHER it's still active.

Every DNS-AID agent can serve a `.well-known/agent.json` endpoint:

```
GET https://mcp.example.com/.well-known/agent.json

{
  "aid_version": "1.0",
  "identity": { "name": "billing", "version": "2.1.0", "deprecated": false },
  "connection": { "protocol": "mcp", "transport": "streamable-http" },
  "auth": { "type": "bearer", "header_name": "Authorization" },
  "capabilities": {
    "supports_streaming": true,
    "actions": [
      { "name": "get_invoice", "intent": "query", "semantics": "read" },
      { "name": "process_payment", "intent": "transaction", "semantics": "write" }
    ]
  }
}
```

**Why this matters for orchestrators (LangGraph, CrewAI, etc.):**

| Field | Orchestrator Decision |
|-------|----------------------|
| `intent: query` | Safe to call in parallel, cacheable |
| `intent: transaction` | Needs atomic execution, rollback on failure |
| `semantics: read` | Safe to retry on timeout |
| `semantics: write` | NOT safe to retry — may duplicate side effects |
| `auth.type: oauth2` | Needs token exchange before calling |
| `deprecated: true` | Route to `successor_fqdn` instead |

**A2A Compatibility:** Both DNS-AID and Google A2A use `/.well-known/agent.json`. The metadata fetcher auto-detects the format — DNS-AID native (has `aid_version` key) or A2A Agent Card — and normalizes both into the same metadata fields.

## Architecture

### Client-Side: Toolkit

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────────────┐
│   AI Agents     │     │   Developers    │     │   Infrastructure Ops    │
│  (Claude, etc.) │     │                 │     │                         │
└────────┬────────┘     └────────┬────────┘     └────────────┬────────────┘
         │                       │                           │
         │ MCP Protocol          │ CLI                       │ CLI / API
         ▼                       ▼                           ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         DNS-AID TOOLKIT                                 │
│                                                                         │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────┐ │
│  │   MCP Server    │  │      CLI        │  │     Python Library      │ │
│  │                 │  │                 │  │                         │ │
│  │ • publish_agent │  │ • dns-aid       │  │ • dns_aid.publish()     │ │
│  │ • discover_     │  │   publish       │  │ • dns_aid.discover()    │ │
│  │   agents        │  │ • dns-aid       │  │ • dns_aid.verify()      │ │
│  │ • verify_agent  │  │   discover      │  │ • dns_aid.invoke()  ◄── Tier 1 SDK
│  │ • list_agents   │  │ • dns-aid       │  │ • dns_aid.rank()        │ │
│  │ • call_agent    │  │   verify        │  │                         │ │
│  └────────┬────────┘  └────────┬────────┘  └────────────┬────────────┘ │
│           │                    │                        │              │
│           └────────────────────┴────────────────────────┘              │
│                                │                                       │
│                                ▼                                       │
│  ┌─────────────────────────────────────────────────────────────────┐  │
│  │                        CORE ENGINE                              │  │
│  │                                                                 │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │  │
│  │  │  Publisher  │  │ Discoverer  │  │      Validator          │ │  │
│  │  │             │  │             │  │                         │ │  │
│  │  │ Create SVCB │  │ Query DNS   │  │ • DNSSEC validation     │ │  │
│  │  │ Create TXT  │  │ Parse SVCB  │  │ • DANE/TLSA check       │ │  │
│  │  │             │  │ Return      │  │ • Endpoint health       │ │  │
│  │  │             │  │ endpoints   │  │                         │ │  │
│  │  └──────┬──────┘  └──────┬──────┘  └────────────┬────────────┘ │  │
│  │         │                │                      │              │  │
│  └─────────┴────────────────┴──────────────────────┴──────────────┘  │
│                             │                                        │
└─────────────────────────────┼────────────────────────────────────────┘
                              │
                              ▼
┌───────────────────────────────────────────────────────────────────────────────────┐
│                          DNS BACKEND ABSTRACTION                                  │
│                                                                                   │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐      │
│  │  Route53  │  │ Infoblox  │  │   DDNS    │  │Cloudflare │  │   Mock    │      │
│  │  (AWS)    │  │   UDDI    │  │ (RFC2136) │  │           │  │ (Testing) │      │
│  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘      │
│        │              │              │              │              │             │
└────────┴──────────────┴──────────────┴──────────────┴──────────────┴─────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                       DNS INFRASTRUCTURE                                │
│                                                                         │
│   Authoritative DNS servers hosting _agents.{domain} zones              │
│   with SVCB, TXT, and TLSA records secured by DNSSEC                   │
└─────────────────────────────────────────────────────────────────────────┘
```

### Directory and Indexing Layer (External)

Directory and indexing services that build on top of DNS-AID — crawlers that walk public DNS for agent records, services that index `.well-known/agent.json` metadata, search frontends — are **out of scope for this repository**. They build on the substrate but are operated independently. Implementations are free to define their own scoring, ranking, and curation policy; DNS-AID does not centralize those choices.

## Choosing the Right Interface

DNS-AID provides three interfaces. Choose based on your use case:

### Python Library

**Best for:** Application developers building agent discovery into their code.

```python
import dns_aid

# Integrate directly into your Python application
agents = await dns_aid.discover("example.com", protocol="mcp")
```

| Use Case | Example |
|----------|---------|
| Building an AI agent that discovers other agents | Agent mesh applications |
| Embedding discovery into existing Python apps | Adding DNS-AID to a Flask/FastAPI service |
| Automated pipelines and scripts | CI/CD, scheduled publishing |
| Unit testing with mock backend | Testing without real DNS |

### CLI Tool

**Best for:** Operators, DevOps, and quick manual operations.

```bash
dns-aid discover example.com --protocol mcp
```

| Use Case | Example |
|----------|---------|
| Manual publishing/discovery | Testing a new agent deployment |
| Shell scripts and automation | `cron` jobs, deployment scripts |
| Debugging and troubleshooting | Checking DNS records exist |
| Zone management | Listing agents, bulk operations |

### MCP Server

**Best for:** AI assistants (Claude, etc.) that need DNS-AID capabilities.

```bash
dns-aid-mcp  # Claude can now use DNS-AID tools
```

| Use Case | Example |
|----------|---------|
| Claude Desktop integration | "Find agents at salesforce.com" |
| AI-driven infrastructure | Agent self-registration and discovery |
| Natural language DNS management | "Publish my chat agent to DNS" |
| Building agentic workflows | Multi-agent orchestration |

### Decision Matrix

| You want to... | Use |
|----------------|-----|
| Build discovery into your Python app | **Python Library** |
| Run ad-hoc commands from terminal | **CLI** |
| Automate with shell scripts | **CLI** |
| Enable Claude/AI to manage DNS-AID | **MCP Server** |
| Test without real DNS | **Python Library** (with MockBackend) |
| Debug DNS record issues | **CLI** (`dns-aid verify`) |

## DNS Backends

For per-provider environment configuration, see the [Getting Started Guide](docs/getting-started.md) backend sections.

DNS-AID supports multiple DNS backends:

| Backend | Description | Install Extra | Status |
|---------|-------------|---------------|--------|
| Route 53 | AWS Route 53 | `dns-aid[route53]` | ✅ Production |
| Cloudflare | Cloudflare DNS | `dns-aid[cloudflare]` | ✅ Production |
| NS1 | NS1 (now IBM) Managed DNS | `dns-aid[ns1]` | ✅ Production |
| Google Cloud DNS | GCP Cloud DNS | `dns-aid[cloud-dns]` | ✅ Production |
| Infoblox NIOS | Infoblox NIOS (on-prem WAPI) | `dns-aid[nios]` | ✅ Production |
| Infoblox UDDI | Infoblox Universal DDI (cloud) | `dns-aid[infoblox]` | ✅ Production |
| DDNS | RFC 2136 Dynamic DNS (BIND, etc.) | `dns-aid[ddns]` | ✅ Production |
| Mock | In-memory (testing only) | (built-in) | ✅ Production |

### Route 53 Setup

1. Configure AWS credentials:
   ```bash
   export AWS_ACCESS_KEY_ID="your-access-key"
   export AWS_SECRET_ACCESS_KEY="your-secret-key"
   export AWS_DEFAULT_REGION="us-east-1"  # Optional
   ```

   Or use AWS CLI profiles:
   ```bash
   aws configure
   # Or use a named profile
   export AWS_PROFILE="my-profile"
   ```

2. Verify zone access:
   ```bash
   dns-aid zones
   ```

3. Publish your agent:
   ```bash
   dns-aid publish -n my-agent -d myzone.com -p mcp -e mcp.myzone.com
   ```

### Infoblox UDDI Setup

Infoblox UDDI (Universal DDI) is Infoblox's cloud-native DDI platform. DNS-AID supports creating SVCB and TXT records via the Infoblox API.

#### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `INFOBLOX_API_KEY` | Yes | - | Infoblox UDDI API key from Cloud Portal |
| `INFOBLOX_DNS_VIEW` | No | `default` | DNS view name (zones exist within views) |
| `INFOBLOX_BASE_URL` | No | `https://csp.infoblox.com` | API base URL |

#### Step-by-Step Setup

1. **Get your API key** from [Infoblox Cloud Portal](https://csp.infoblox.com):
   - Navigate to **Administration** → **API Keys**
   - Create a new API key with DNS permissions
   - Copy the key (shown only once)

2. **Configure environment variables**:
   ```bash
   export INFOBLOX_API_KEY="your-api-key"
   export INFOBLOX_DNS_VIEW="default"  # Or your specific view name
   ```

3. **Identify your zone and view**:
   - In Infoblox Portal, go to **DNS** → **Authoritative Zones**
   - Note the zone name (e.g., `example.com`) and which view it belongs to

4. **Use in Python**:
   ```python
   from dns_aid.backends.infoblox import InfobloxBloxOneBackend
   from dns_aid.core.publisher import set_default_backend
   from dns_aid import publish

   # Initialize backend (reads from environment variables)
   backend = InfobloxBloxOneBackend()

   # Or with explicit configuration
   backend = InfobloxBloxOneBackend(
       api_key="your-api-key",
       dns_view="default",  # Your DNS view name
   )

   set_default_backend(backend)

   await publish(
       name="my-agent",
       domain="example.com",
       protocol="mcp",
       endpoint="agent.example.com",
       capabilities=["chat", "code-review"]
   )
   ```

#### Infoblox UDDI Limitations & DNS-AID Compliance

> **⚠️ Important**: Infoblox UDDI SVCB records only support "alias mode" (priority 0) and do not
> support SVC parameters (`alpn`, `port`, `mandatory`). This means **Infoblox UDDI is not fully
> compliant with the [DNS-AID draft](https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-dnsaid/)**.
>
> The draft requires ServiceMode SVCB records (priority > 0) with mandatory `alpn` and `port`
> parameters. Infoblox UDDI's limitation is a platform constraint, not a DNS-AID limitation.

| DNS-AID Requirement | Route 53 | Infoblox UDDI |
|---------------------|----------|---------------|
| ServiceMode (priority > 0) | ✅ | ❌ |
| `alpn` parameter | ✅ | ❌ |
| `port` parameter | ✅ | ❌ |
| `mandatory` key | ✅ | ❌ |

**For full DNS-AID compliance, use Route 53 or another RFC 9460-compliant DNS provider.**

DNS-AID stores `alpn` and `port` in TXT records as a fallback for Infoblox UDDI, but this is
a workaround and not standard-compliant for agent discovery.

#### Verify Records via API

Since Infoblox UDDI zones may not be publicly resolvable, verify records via the API:

```python
async with InfobloxBloxOneBackend() as backend:
    async for record in backend.list_records("example.com", name_pattern="my-agent"):
        print(f"{record['type']}: {record['fqdn']}")
```

### DDNS Setup (RFC 2136)

DDNS (Dynamic DNS) is a universal backend that works with any DNS server supporting RFC 2136, including BIND9, Windows DNS, PowerDNS, and Knot DNS. This is ideal for on-premise DNS infrastructure without vendor-specific APIs.

#### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DDNS_SERVER` | Yes | - | DNS server hostname or IP |
| `DDNS_KEY_NAME` | Yes | - | TSIG key name |
| `DDNS_KEY_SECRET` | Yes | - | TSIG key secret (base64) |
| `DDNS_KEY_ALGORITHM` | No | `hmac-sha256` | TSIG algorithm |
| `DDNS_PORT` | No | `53` | DNS server port |

#### Step-by-Step Setup

1. **Create a TSIG key** on your DNS server (BIND example):
   ```bash
   tsig-keygen -a hmac-sha256 dns-aid-key > /etc/bind/dns-aid-key.conf
   ```

2. **Configure your zone** to allow updates with the key:
   ```
   zone "example.com" {
       type master;
       file "/var/lib/bind/example.com.zone";
       allow-update { key "dns-aid-key"; };
   };
   ```

3. **Configure DNS-AID**:
   ```bash
   export DDNS_SERVER="ns1.example.com"
   export DDNS_KEY_NAME="dns-aid-key"
   export DDNS_KEY_SECRET="your-base64-secret"
   ```

4. **Use in Python**:
   ```python
   from dns_aid.backends.ddns import DDNSBackend
   from dns_aid import publish

   backend = DDNSBackend()
   # Or with explicit configuration
   backend = DDNSBackend(
       server="ns1.example.com",
       key_name="dns-aid-key",
       key_secret="base64secret==",
       key_algorithm="hmac-sha256"
   )

   await publish(
       name="my-agent",
       domain="example.com",
       protocol="mcp",
       endpoint="agent.example.com",
       backend=backend
   )
   ```

#### DDNS Advantages

- **Universal**: Works with BIND, Windows DNS, PowerDNS, Knot, and any RFC 2136 server
- **No vendor lock-in**: Standard protocol, no proprietary APIs
- **On-premise friendly**: Perfect for enterprise internal DNS
- **Full DNS-AID compliance**: Supports ServiceMode SVCB with all parameters

### Cloudflare Setup

Cloudflare DNS is ideal for demos, workshops, and quick prototyping thanks to its free tier and excellent API support. DNS-AID fully supports Cloudflare's SVCB record implementation.

#### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CLOUDFLARE_API_TOKEN` | Yes | - | API token with DNS edit permissions |
| `CLOUDFLARE_ZONE_ID` | No | - | Zone ID (auto-discovered if not set) |

#### Step-by-Step Setup

1. **Create an API token** in Cloudflare Dashboard:
   - Go to **My Profile** → **API Tokens** → **Create Token**
   - Use the "Edit zone DNS" template or create custom with:
     - **Permissions**: Zone → DNS → Edit
     - **Zone Resources**: Include → Specific zone → your-domain.com
   - Copy the token (shown only once)

2. **Configure environment variables**:
   ```bash
   export CLOUDFLARE_API_TOKEN="your-api-token"
   # Optional: specify zone ID (otherwise auto-discovered from domain)
   export CLOUDFLARE_ZONE_ID="your-zone-id"
   ```

3. **Publish your first agent**:
   ```bash
   dns-aid publish \
       --name my-agent \
       --domain your-domain.com \
       --protocol mcp \
       --endpoint agent.your-domain.com \
       --backend cloudflare
   ```

4. **Use in Python**:
   ```python
   from dns_aid.backends.cloudflare import CloudflareBackend
   from dns_aid import publish

   # Initialize backend (reads from environment variables)
   backend = CloudflareBackend()

   # Or with explicit configuration
   backend = CloudflareBackend(
       api_token="your-api-token",
       zone_id="optional-zone-id",  # Auto-discovered if not provided
   )

   await publish(
       name="my-agent",
       domain="your-domain.com",
       protocol="mcp",
       endpoint="agent.your-domain.com",
       backend=backend
   )
   ```

#### Cloudflare Advantages

- **Free tier**: DNS hosting is free for unlimited domains
- **SVCB support**: Full RFC 9460 compliance with SVCB Type 64 records
- **Global anycast**: Fast DNS resolution worldwide
- **Simple API**: Well-documented REST API v4
- **Full DNS-AID compliance**: Supports ServiceMode SVCB with all parameters

## How DNS-AID Relates to Other Efforts

Agent discovery is an active design space, with multiple proposals working at different layers of the stack. DNS-AID is intentionally narrow: it standardizes a DNS-layer substrate that publishers and resolvers can rely on, leaving directory, ranking, payments, and namespace policy to other efforts. The summary below is meant to help operators understand where DNS-AID fits — not to position it against other work.

**Adjacent efforts**

- **Agent Name Service (ANS)** — A directory-oriented approach defining a JSON metadata schema and registry interfaces. DNS-AID's HTTP Index format is intentionally aligned with the ANS schema where it overlaps, so an ANS-style directory can be served from the same data a DNS-AID publisher produces.
- **A2A** — A communication protocol for agent-to-agent messaging. DNS-AID is complementary: A2A defines how two agents talk, DNS-AID defines how one agent finds the other's endpoint to talk to.
- **AgentDNS** — A separate proposal that builds an agent-naming layer on top of DNS primitives. The two proposals overlap in spirit and differ in mechanism; DNS-AID's choice is to stay inside RFC 9460 SVCB so existing authoritative servers and resolvers work unchanged.
- **NANDA** — A peer-to-peer overlay approach. Useful in deployments where a DHT-style substrate is preferred; DNS-AID instead targets the DNS infrastructure organizations already operate.
- **ai.txt / llms.txt** — Free-form text files at well-known URLs. Useful for human-readable discovery; DNS-AID adds structured SVCB records and optional DNSSEC-validated trust.
- **`.agent` gTLD** — An ICANN new-gTLD effort by the [Agent Community](https://agentcommunity.org/) to create a dedicated namespace (`mycompany.agent`). Complementary to DNS-AID — when `.agent` domains become available, DNS-AID records will work on them too, the same way they work on any other zone.

**Where DNS-AID is scoped**

DNS-AID standardizes the publish/resolve substrate: SVCB record layout, naming convention, capability and policy parameters, and a DNSSEC-anchored verification path. It does not pick a winning directory, ranking algorithm, payment system, or trust authority. Operators are free to combine DNS-AID with any of the efforts above, or to run it standalone.

## Examples

See the `examples/` directory:

- `demo_route53.py` - Basic Route 53 publish/discover
- `demo_full.py` - Complete end-to-end demonstration

```bash
# Run the full demo
export DNS_AID_TEST_ZONE="your-zone.com"
python examples/demo_full.py
```

## Development

```bash
# Clone the repo
git clone https://github.com/infobloxopen/dns-aid-core.git
cd DNS-AID

# Install all workspace packages (requires uv)
uv sync

# Run all tests
uv run pytest

# Run tests for a specific package
uv run pytest packages/dns-aid-directory/tests/
uv run pytest packages/dns-aid-crawlers/tests/
uv run pytest packages/dns-aid-k8s/tests/

# Run with coverage
uv run pytest --cov=dns_aid_directory --cov=dns_aid_crawlers --cov=dns_aid_k8s
```

## Related Standards

- [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460.html) - SVCB and HTTPS Resource Records
- [RFC 4033-4035](https://www.rfc-editor.org/rfc/rfc4033.html) - DNSSEC
- [RFC 6698](https://www.rfc-editor.org/rfc/rfc6698.html) - DANE TLSA

## License

Apache 2.0

## Contributing

Contributions welcome! This project is intended for contribution to the Linux Foundation Agent AI Foundation.

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Acknowledgments

Thanks to **John Zinky** (Akamai) for design-level input on the experimental EDNS(0) `agent-hint` signaling work — particularly on how hint-aware hops could fit into the broader resolver ecosystem.
