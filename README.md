# DNS-AID

<!-- mcp-name: io.github.dns-aid/dns-aid -->

[![CI](https://github.com/dns-aid/dns-aid-core/actions/workflows/ci.yml/badge.svg)](https://github.com/dns-aid/dns-aid-core/actions/workflows/ci.yml)
[![Security](https://github.com/dns-aid/dns-aid-core/actions/workflows/security.yml/badge.svg)](https://github.com/dns-aid/dns-aid-core/actions/workflows/security.yml)
[![CodeQL](https://github.com/dns-aid/dns-aid-core/actions/workflows/codeql.yml/badge.svg)](https://github.com/dns-aid/dns-aid-core/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/dns-aid/dns-aid-core/badge)](https://scorecard.dev/viewer/?uri=github.com/dns-aid/dns-aid-core)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12651/badge)](https://www.bestpractices.dev/projects/12651)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org/)
[![PyPI](https://img.shields.io/pypi/v/dns-aid)](https://pypi.org/project/dns-aid/)

**DNS-based Agent Identification and Discovery**

Reference implementation for [IETF draft-mozleywilliams-dnsop-dnsaid-02](https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-dnsaid/).

DNS-AID enables AI agents to discover each other via DNS, using the internet's existing naming infrastructure instead of centralized registries or hardcoded URLs.

## Relationship to IETF

The DNS-AID specification is being developed within the IETF: https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-dnsaid/.

This repository provides a reference implementation.

This project does not define the specification. The IETF draft is authoritative.

## Scope of this Repository

This project focuses on implementation, tooling, and ecosystem activities.

Changes to protocol behavior should be discussed within the IETF.

> **New to DNS-AID?** Start with the [Getting Started Guide](docs/getting-started.md) for install, first agent publication, and backend setup.

## Documentation

- [Getting Started Guide](docs/getting-started.md) — install, first agent publication, backend setup
- [API Reference](docs/api-reference.md) — Python SDK, CLI, and MCP server tool reference
- [Architecture](docs/architecture.md) — protocol layers, metadata resolution, integration points
- [Integrations](docs/integrations.md) — backend-specific setup notes
- [Demo Guide](docs/demo-guide.md) — end-to-end walkthrough for talks and presentations
- [Privacy Policy](PRIVACY.md) | [Security Policy](SECURITY.md) | [Trademarks](TRADEMARKS.md)

## Companion services

The DNS-AID protocol is implementation-agnostic — it works against any DNS provider and any directory implementation. The library in this repository is sufficient on its own; the items below are independent, community-operated services that demonstrate what can be built on top of DNS-AID.

🌐 **Hosted Agent Directory** (operated by Infoblox): [directory.example.com](https://directory.example.com) — indexes DNS-AID agents discovered across public DNS, with full-text search, capability filtering, trust scoring, lifecycle/sunset tracking, and copy-paste configs for Claude Desktop / Cursor / the SDK. API docs at [api.example.com/api/v1/docs](https://api.example.com/api/v1/docs).

You are encouraged to run your own directory or telemetry backend — the indexer is a thin layer over the same DNS records this library publishes and discovers, and the SDK telemetry sink is configurable via `DNS_AID_SDK_HTTP_PUSH_URL` (off by default).

## Quick Start

### Install

```bash
# Install from PyPI
pip install "dns-aid[cli,mcp]"

# Or install the latest unreleased main from GitHub
pip install "dns-aid[cli,mcp] @ git+https://github.com/dns-aid/dns-aid-core.git"
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

# Discover via HTTP index (ANS-compatible, richer metadata)
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
result = await dns_aid.verify("my-agent.example.com")
print(f"Security Score: {result.security_score}/100")
```

### Path B: cross-domain search via opt-in directory (v0.19.0+)

When you don't yet know which domain hosts the agent you want, query a configured
directory backend for ranked candidates with pre-computed trust signals:

```python
from dns_aid.sdk import AgentClient, SDKConfig

# directory_api_url can also be set via DNS_AID_SDK_DIRECTORY_API_URL env var.
config = SDKConfig(directory_api_url="https://api.example.com")

async with AgentClient(config=config) as client:
    response = await client.search(
        q="payment processing",
        protocol="mcp",
        capabilities=["payment-processing"],
        min_security_score=70,
        verified_only=True,
    )
    for r in response.results:
        print(f"{r.score:.2f}  {r.agent.fqdn}  T{r.trust.trust_tier}")
```

**Zero-trust composition**: Path B → Path A re-verify before invoking. Directory is
opt-in convenience; DNS substrate is the authoritative trust gate.

```python
async with AgentClient(config=config) as client:
    response = await client.search(q="fraud detection", min_security_score=70)
    for candidate in response.results:
        verified = await dns_aid.discover(
            candidate.agent.domain,
            name=candidate.agent.name,
            require_signed=True,
        )
        # Invoke only when DNS substrate confirms the directory's claim.
```

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

# Rank multiple agents by performance
ranked = await dns_aid.rank(result.agents, method="tools/list")
for r in ranked:
    print(f"{r.agent_fqdn}: score={r.composite_score:.1f}")

# Fetch community-wide rankings from the directory API (v0.19.0+)
from dns_aid.sdk import AgentClient, SDKConfig

config = SDKConfig(directory_api_url="https://api.example.com")
async with AgentClient(config) as client:
    rankings = await client.fetch_rankings(limit=10)
    for r in rankings:
        print(f"{r['agent_fqdn']}: {r['composite_score']}")
```

**OpenTelemetry (v0.23.0+):** install `dns-aid[otel]` and set
`otel_enabled=True` (or `DNS_AID_SDK_OTEL_ENABLED=true`) to emit spans +
metrics per invoke and propagate W3C trace context to downstream agents.
See [docs/integrations/opentelemetry.md](docs/integrations/opentelemetry.md).

For advanced usage (connection reuse, OTEL export):

```python
from dns_aid.sdk import AgentClient, SDKConfig

config = SDKConfig(
    otel_enabled=True,         # Export to OpenTelemetry
    caller_id="my-app",
    http_push_url="https://api.example.com/v1/telemetry/signals",
)

async with AgentClient(config=config) as client:
    resp = await client.invoke(agent, method="tools/call", arguments={...})
    fqdns = [a.fqdn for a in agents]
    ranked = client.rank(fqdns)  # Rank by local telemetry signals
```

### SDK: Per-Invoke Credential Provider Callback (v0.21.0+)

For short-lived credentials (RFC 8693 token exchange, AWS STS assume-role,
HashiCorp Vault dynamic secrets, HSM/KMS-backed signing keys), pass an opt-in
async `credential_provider` callback to `invoke()`. The SDK awaits the callback
lazily at invoke time with the target `AgentRecord` and uses the returned dict
for auth resolution. Strictly additive — every existing call site continues to
work without source change.

```python
async def token_exchange_provider(agent: AgentRecord) -> dict[str, str]:
    # Mint a fresh delegation token per call — e.g., RFC 8693 token exchange
    # against Keycloak / Okta / Auth0 / Microsoft Entra ID.
    return {"token": await my_idp.exchange_token(subject_token, agent.fqdn)}

async with AgentClient(config=config) as client:
    resp = await client.invoke(
        agent,
        method="tools/list",
        credential_provider=token_exchange_provider,
    )
```

Precedence: `auth_handler > credentials > credential_provider > no_auth`.
See [docs/security-credentials.md](docs/security-credentials.md) for the
per-handler security matrix, audit-trail flow, and the
[`examples/integration_oauth2_token_exchange.py`](examples/integration_oauth2_token_exchange.py)
and [`examples/integration_aws_sts_assume_role.py`](examples/integration_aws_sts_assume_role.py)
canonical patterns.

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

# Cross-domain search via configured directory backend (v0.19.0+)
export DNS_AID_SDK_DIRECTORY_API_URL=https://api.example.com
dns-aid search "payment processing" --protocol mcp --min-security-score 70

# Discover via HTTP index (ANS-compatible, richer metadata)
dns-aid discover example.com --use-http-index

# Output as JSON
dns-aid discover example.com --json

# Verify DNS records
dns-aid verify my-agent.example.com

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

# Domain Submission to Agent Directory (v0.4.0+)
# Submit your domain for crawling and indexing
dns-aid submit example.com

# Submit with company metadata
dns-aid submit example.com \
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

### HTTP Index Discovery (ANS-Compatible)

DNS-AID also supports HTTP-based agent discovery for compatibility with ANS-style systems. This provides richer metadata (descriptions, model cards, capabilities, costs) while still validating endpoints via DNS.

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

**FQDN as Source of Truth (v0.4.7):** The HTTP index only needs to provide each agent's FQDN (e.g., `booking.example.com`). Agent name and protocol are extracted from the FQDN — no separate `protocols` field needed. DNS SVCB lookup then resolves the authoritative endpoint.

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
| `discover_agents_via_dns` | Discover AI agents at a domain (supports `use_http_index` for ANS-compatible discovery) |
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
chat.example.com. 3600 IN SVCB 1 chat.example.com. alpn="a2a" port=443 mandatory="alpn,port"
chat.example.com. 3600 IN TXT "capabilities=chat,assistant" "version=1.0.0"
```

**DNS-AID Custom SVCB Parameters (v0.4.8+):** Per the IETF draft, SVCB records can carry additional custom parameters for richer agent metadata:

```
booking.example.com. SVCB 1 mcp.example.com. alpn="mcp" port=443 \
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
  │  Response: [{"fqdn":"chat.salesforce.com",...}]   │
  │                                                                 │
  │  Fallback: Query TXT Index via DNS                              │
  │  Query: _index._agents.salesforce.com TXT                       │
  │  Response: "agents=chat:a2a,billing:mcp"                        │
  └──┬──────────────────────────────────────────────────────────────┘
     │                            │                               │
  ┌──┴──────────────────────────────────────────────────────────────┐
  │  Step 2: Query SVCB per agent                                   │
  │  ────────────────────────────                                   │
  │  Query: chat.salesforce.com SVCB                  │
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
  │  Query: chat.salesforce.com TXT                   │
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

### Server-Side: Agent Directory Pipeline

```
┌──────────────────────────────────────────────────────────────────────────┐
│                    AGENT DIRECTORY PIPELINE                              │
│                                                                          │
│  ┌──────────┐   ┌───────────────┐   ┌──────────────┐   ┌────────────┐  │
│  │ CRAWLING │──▶│   CURATION    │──▶│   INDEXING   │──▶│  SERVING   │  │
│  │          │   │               │   │              │   │            │  │
│  │ DNS SVCB │   │ trust_score   │   │ TSVECTOR     │   │ REST API   │  │
│  │ HTTP Idx │   │ security_score│   │ full-text    │   │ Search     │  │
│  │ .well-   │   │ telemetry     │   │ search       │   │ Rankings   │  │
│  │ known/   │   │ scoring       │   │              │   │            │  │
│  │ agent.json   │               │   │              │   │            │  │
│  └──────────┘   └───────────────┘   └──────────────┘   └────────────┘  │
│       │                                                                  │
│       ▼                                                                  │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │             METADATA ENRICHMENT (Phase 5.5)                      │   │
│  │                                                                  │   │
│  │  GET /.well-known/agent.json                                     │   │
│  │    ├─ "aid_version" present? → Parse as DNS-AID AgentMetadata    │   │
│  │    └─ No? → Try A2A Agent Card → Transform to metadata fields    │   │
│  │                                                                  │   │
│  │  Extracts: transport, auth, capabilities (intent/semantics),     │   │
│  │            lifecycle (deprecated, sunset_date, successor)        │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

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

## Why DNS-AID?

### vs Competing Proposals

| Approach | Problem | DNS-AID Advantage |
|----------|---------|-------------------|
| **ANS (GoDaddy)** | Centralized registry, KYC required, single gatekeeper | Federated — you control your domain, publish instantly |
| **Google (A2A + UCP)** | Discovery via Gemini/Search, payments via UCP | Neutral discovery — no platform lock-in or transaction fees |
| **.agent gTLD** | Requires ICANN approval, ongoing domain fees | Works NOW with domains you already own |
| **AgentDNS (China Telecom)** | Requires 6G infrastructure, carrier control | Works NOW on existing DNS infrastructure |
| **NANDA (MIT)** | New P2P overlay network, new ops paradigm | Uses infrastructure your DNS team already operates |
| **Web3 (ERC-8004)** | Gas fees, crypto wallets, enterprise-hostile | Free DNS queries, no blockchain complexity |
| **ai.txt / llms.txt** | No integrity verification, free-form JSON | DNSSEC cryptographic verification, structured SVCB |

### Feature Comparison

| Feature | DNS-AID | Central Registry | ai.txt |
|---------|---------|------------------|--------|
| **Decentralized** | ✅ | ❌ | ✅ |
| **Secure (DNSSEC)** | ✅ | Varies | ❌ |
| **Sovereign** | ✅ | ❌ | ✅ |
| **Standards-based** | ✅ (IETF) | ❌ | ❌ |
| **Works with existing infra** | ✅ | ❌ | ✅ |

### The Sovereignty Question

> **Who controls agent discovery?**
> - ANS: GoDaddy (US company as gatekeeper)
> - AgentDNS: China Telecom (state-owned carrier)
> - Web3: Ethereum Foundation
> - **DNS-AID: You control your own domain**
>
> DNS-AID preserves sovereignty. Organizations and nations maintain control over their own agent namespaces with no central authority that can block, censor, or surveil agent discovery.

### Google's Agent Ecosystem

Google is building a full-stack agent platform: **A2A** (communication), **UCP** (payments), and **Gemini/Search** (discovery). While A2A is an open protocol, discovery through Google surfaces means:
- Google controls visibility (pay-to-rank)
- Transaction fees via [UCP](https://developers.google.com/merchant/ucp)
- Platform dependency for reach

**DNS-AID complements A2A** by providing neutral, decentralized discovery — find agents anywhere, not just through Google.

### Understanding the .agent Domain Approach

The [Agent Community](https://agentcommunity.org/) is pursuing a `.agent` top-level domain through ICANN's [new gTLD program](https://newgtlds.icann.org/). Here's how the two approaches compare:

**How .agent Domains Would Work:**
1. Apply to ICANN for `.agent` gTLD (~$185,000 application fee)
2. Wait 9-20 months for ICANN approval process
3. Build registry infrastructure (Open Agent Registry, Inc.)
4. Sell `.agent` domains through accredited registrars
5. Users pay annual registration fees (~$15-50/year per domain)

**How DNS-AID Works:**
1. Use your existing domain (you already own `yourcompany.com`)
2. Add DNS-AID records to your zone (`myagent.yourcompany.com`)
3. Start discovering and being discovered immediately

| Factor | .agent gTLD | DNS-AID |
|--------|-------------|---------|
| **Cost to publish** | ~$15-50/year domain fee | Free (use existing domain) |
| **Time to start** | Months (gTLD launch + registration) | Minutes |
| **Who controls discovery** | Registry operator | You (your domain) |
| **Works today** | ❌ Pending ICANN approval | ✅ Works now |
| **Requires new infrastructure** | ✅ Registry, registrars | ❌ Uses existing DNS |
| **Memorable names** | ✅ `myagent.agent` | `myagent.example.com` |

**The Friendly Take:**

Both approaches share the goal of making AI agents discoverable. The `.agent` gTLD creates a dedicated namespace that's easy to remember (`mycompany.agent`), while DNS-AID leverages existing infrastructure so you can start publishing agents today.

DNS-AID doesn't require waiting for ICANN approval or paying for new domains—it works with the DNS infrastructure your organization already operates. If you own `example.com`, you can publish agents to `myagent.example.com` right now.

*Fun fact: When `.agent` domains become available, DNS-AID records will work on them too! The approaches are complementary.*

## Background and Comparison

For background on how DNS-AID compares to other agent-discovery approaches (ANS, Google A2A+UCP, `.agent` gTLD, AgentDNS, NANDA, Web3, `ai.txt`) and "The Sovereignty Question", see [docs/positioning.md](docs/positioning.md). That content is non-normative — protocol positioning is determined at the IETF.

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
git clone https://github.com/dns-aid/dns-aid-core.git
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

Contributions welcome! This project supports an implementation ecosystem with planned hosting in the Linux Foundation. The DNS-AID specification is developed in the IETF.

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.
