# DNS-AID API Reference

Complete API documentation for DNS-AID - DNS-based Agent Identification and Discovery.

## Table of Contents

- [Quick Start](#quick-start)
- [Core Functions](#core-functions)
  - [publish()](#publish)
  - [discover()](#discover)
  - [verify()](#verify)
- [Domain Control Validation (DCV)](#domain-control-validation-dcv)
  - [dcv.issue()](#dcvissue)
  - [dcv.place()](#dcvplace)
  - [dcv.verify()](#dcvverify)
  - [dcv.revoke()](#dcvrevoke)
  - [DCVChallenge](#dcvchallenge)
  - [DCVPlaceResult](#dcvplaceresult)
  - [DCVVerifyResult](#dcvverifyresult)
  - [DCVRevokeResult](#dcvrevokeresult)
- [Data Models](#data-models)
  - [AgentRecord](#agentrecord)
  - [DiscoveryResult](#discoveryresult)
  - [PublishResult](#publishresult)
  - [VerifyResult](#verifyresult)
  - [Protocol](#protocol)
- [Backends](#backends)
  - [DNSBackend Interface](#dnsbackend-interface)
  - [Route53Backend](#route53backend)
  - [InfobloxBloxOneBackend](#infobloxbloxonebackend)
  - [InfobloxNIOSBackend](#infobloxniosbackend)
  - [NS1Backend](#ns1backend)
  - [CloudflareBackend](#cloudflarebackend)
  - [DDNSBackend](#ddnsbackend)
  - [MockBackend](#mockbackend)
- [JWS Signatures](#jws-signatures)
  - [generate_keypair()](#generate_keypair)
  - [sign_record()](#sign_record)
  - [verify_signature()](#verify_signature)
- [Validation Utilities](#validation-utilities)
- [CLI Reference](#cli-reference)
- [MCP Server](#mcp-server)
- [Invocation Module](#invocation-module-coreinvokepy)
  - [send_a2a_message()](#send_a2a_message)
  - [call_mcp_tool()](#call_mcp_tool)
  - [list_mcp_tools()](#list_mcp_tools)
  - [resolve_a2a_endpoint()](#resolve_a2a_endpoint)
  - [InvokeResult](#invokeresult)
- [SDK: Invocation & Telemetry](#sdk-invocation--telemetry)
  - [AgentClient](#agentclient)
  - [SDKConfig](#sdkconfig)
  - [AgentClient.search() — Path B cross-domain search (v0.19.0+)](#agentclientsearch--path-b-cross-domain-search-v0190)
  - [SearchResponse / SearchResult / TrustAttestation / Provenance (v0.19.0+)](#searchresponse--searchresult--trustattestation--provenance-v0190)
  - [Directory exceptions (v0.19.0+)](#directory-exceptions-v0190)
  - [InvocationResult](#invocationresult)
  - [InvocationSignal](#invocationsignal)
  - [Ranking](#ranking)

---

## Quick Start

```python
import asyncio
from dns_aid import publish, discover, verify, Protocol

async def main():
    # Publish an agent
    result = await publish(
        name="my-agent",
        domain="example.com",
        protocol="mcp",
        endpoint="agent.example.com",
        capabilities=["chat", "code-review"],
    )

    # Discover agents at a domain
    discovery = await discover("example.com", protocol=Protocol.MCP)

    # Verify an agent's DNS records
    verification = await verify("_my-agent._mcp._agents.example.com")

asyncio.run(main())
```

---

## Core Functions

### publish()

Publish an AI agent to DNS using the DNS-AID protocol.

```python
async def publish(
    name: str,
    domain: str,
    protocol: str | Protocol,
    endpoint: str,
    port: int = 443,
    capabilities: list[str] | None = None,
    version: str = "1.0.0",
    description: str | None = None,
    ttl: int = 3600,
    backend: DNSBackend | None = None,
    cap_uri: str | None = None,
    cap_sha256: str | None = None,
    bap: list[str] | None = None,
    policy_uri: str | None = None,
    realm: str | None = None,
    ipv4_hint: str | None = None,
    ipv6_hint: str | None = None,
) -> PublishResult
```

#### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `name` | `str` | Yes | - | Agent identifier (e.g., "chat", "network-specialist"). Must be DNS label format: lowercase alphanumeric with hyphens, 1-63 chars. |
| `domain` | `str` | Yes | - | Domain to publish under (e.g., "example.com") |
| `protocol` | `str \| Protocol` | Yes | - | Communication protocol: "mcp" or "a2a" |
| `endpoint` | `str` | Yes | - | Hostname where agent is reachable |
| `port` | `int` | No | 443 | Port number (1-65535) |
| `capabilities` | `list[str]` | No | `[]` | List of agent capabilities |
| `version` | `str` | No | "1.0.0" | Agent version (semver format) |
| `description` | `str` | No | `None` | Human-readable description |
| `ttl` | `int` | No | 3600 | DNS record TTL in seconds (60-86400) |
| `backend` | `DNSBackend` | No | `None` | DNS backend to use (uses default if None) |
| `cap_uri` | `str` | No | `None` | URI to capability document (DNS-AID custom param) |
| `cap_sha256` | `str` | No | `None` | Base64url SHA-256 digest of capability descriptor |
| `bap` | `list[str]` | No | `None` | Supported protocols with versions (e.g., `["mcp/1", "a2a/1"]`) |
| `policy_uri` | `str` | No | `None` | URI to agent policy document |
| `realm` | `str` | No | `None` | Multi-tenant scope identifier |
| `ipv4_hint` | `str` | No | `None` | IPv4 address hint for SVCB record (reduces A query round trips) |
| `ipv6_hint` | `str` | No | `None` | IPv6 address hint for SVCB record (reduces AAAA query round trips) |

#### Returns

`PublishResult` - Contains the published agent and created DNS records.

#### Example

```python
from dns_aid import publish

result = await publish(
    name="network-specialist",
    domain="example.com",
    protocol="mcp",
    endpoint="mcp.example.com",
    capabilities=["ipam", "dns", "vpn"],
    ttl=300,
)

if result.success:
    print(f"Published: {result.agent.fqdn}")
    print(f"Records: {result.records_created}")
else:
    print(f"Failed: {result.message}")
```

#### DNS Records Created

- **SVCB**: `_{name}._{protocol}._agents.{domain}` → Service binding record
- **TXT**: `_{name}._{protocol}._agents.{domain}` → Capabilities and metadata

---

### discover()

Discover AI agents at a domain using DNS-AID protocol (Path A — DNS substrate).

```python
async def discover(
    domain: str,
    protocol: str | Protocol | None = None,
    name: str | None = None,
    require_dnssec: bool = False,
    use_http_index: bool = False,
    enrich_endpoints: bool = True,
    verify_signatures: bool = False,
    *,
    # Path A in-memory filter kwargs (v0.19.0+)
    capabilities: list[str] | None = None,
    capabilities_any: list[str] | None = None,
    auth_type: str | None = None,
    intent: str | None = None,
    transport: str | None = None,
    realm: str | None = None,
    min_dnssec: bool = False,
    text_match: str | None = None,
    require_signed: bool = False,
    require_signature_algorithm: list[str] | None = None,
) -> DiscoveryResult
```

#### Parameters

**Substrate parameters:**

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `domain` | `str` | Yes | - | Domain to search for agents |
| `protocol` | `str \| Protocol` | No | `None` | Filter by protocol (None for all) |
| `name` | `str` | No | `None` | Filter by specific agent name (case-insensitive per RFC 1035) |
| `require_dnssec` | `bool` | No | `False` | Require DNSSEC validation |
| `use_http_index` | `bool` | No | `False` | Use HTTP index endpoint instead of DNS-only discovery |
| `enrich_endpoints` | `bool` | No | `True` | Fetch cap docs / agent cards to enrich AgentRecords |
| `verify_signatures` | `bool` | No | `False` | Fetch JWKS and verify per-agent JWS signatures |

**Filter kwargs (v0.19.0+, all keyword-only, all default no-op):**

| Parameter | Type | Description |
|-----------|------|-------------|
| `capabilities` | `list[str] \| None` | All-of capability match — every entry must be present on the agent. Empty list = no-match (explicit). |
| `capabilities_any` | `list[str] \| None` | Any-of capability match — at least one entry must be present. Empty list = no-match. |
| `auth_type` | `str \| None` | Case-insensitive exact match against `agent.auth_type`. |
| `intent` | `str \| None` | Match against `agent.category`; falls back to substring match across capabilities. |
| `transport` | `str \| None` | Match against the agent's protocol identifier (Path A surfaces protocol, not wire transport). |
| `realm` | `str \| None` | Exact match against `agent.realm`. |
| `min_dnssec` | `bool` | When `True`, only records whose DNS response was DNSSEC-validated pass. |
| `text_match` | `str \| None` | Case-insensitive substring match across `description`, `use_cases`, and `capabilities`. Empty string raises `ValueError`. |
| `require_signed` | `bool` | When `True`, only records whose JWS signature verified pass. Auto-enables `verify_signatures=True`. |
| `require_signature_algorithm` | `list[str] \| None` | Restrict `require_signed` matches to records whose verified algorithm is in this allow-list. Requires `require_signed=True`. |

All filter predicates compose with logical AND. None / `False` means "no constraint".
When every filter is unset, the input list is returned unchanged with no allocation
(no-op fast path keeps existing callers free of overhead).

#### Discovery Methods

| Method | Endpoint | Use Case |
|--------|----------|----------|
| **DNS (default)** | `_index._agents.{domain}` TXT record | Decentralized, cached, minimal round trips |
| **HTTP Index** | `https://_index._aiagents.{domain}/index-wellknown` | ANS-compatible, rich metadata (descriptions, model cards) |

#### Returns

`DiscoveryResult` - Contains list of discovered agents and query metadata.

#### Raises

- `ValueError` — `text_match` is an empty string, or `require_signature_algorithm`
  is set without `require_signed=True`.
- `DNSSECError` — `require_dnssec=True` but the domain's response is not
  authenticated.

#### Example

```python
from dns_aid import discover, Protocol

# Discover all agents (pure DNS - default)
result = await discover("example.com")

# Discover MCP agents only
result = await discover("example.com", protocol=Protocol.MCP)

# Discover specific agent
result = await discover("example.com", protocol="mcp", name="chat")

# Discover via HTTP index (ANS-compatible, richer metadata)
result = await discover("example.com", use_http_index=True)

# Filter by capabilities + auth type (v0.19.0+)
result = await discover(
    "example.com",
    capabilities=["payment-processing", "fraud-detection"],
    auth_type="oauth2",
    realm="prod",
)

# Trust-gated discovery: only signed agents with allow-listed algorithms
result = await discover(
    "example.com",
    require_signed=True,
    require_signature_algorithm=["ES256", "Ed25519"],
)

for agent in result.agents:
    print(f"{agent.name}: {agent.endpoint_url}")
    print(f"  Capabilities: {', '.join(agent.capabilities)}")
    if agent.description:
        print(f"  Description: {agent.description}")
```

---

### verify()

Verify DNS-AID records for an agent with security validation.

```python
async def verify(fqdn: str) -> VerifyResult
```

#### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `fqdn` | `str` | Yes | Fully qualified domain name (e.g., "_chat._mcp._agents.example.com") |

#### Returns

`VerifyResult` - Contains security validation results and score.

#### Example

```python
from dns_aid import verify

result = await verify("_chat._mcp._agents.example.com")

print(f"Record exists: {result.record_exists}")
print(f"DNSSEC valid: {result.dnssec_valid}")
print(f"Security Score: {result.security_score}/100")
print(f"Rating: {result.security_rating}")
```

---

## Domain Control Validation (DCV)

DCV is a stateless challenge/verify primitive that lets one party prove control of a
domain to another using a short-lived TXT record at `_agents-challenge.{domain}`.
It implements [draft-ietf-dnsop-domain-verification-techniques-12](https://datatracker.ietf.org/doc/draft-ietf-dnsop-domain-verification-techniques/)
plus the `bnd-req` binding extension from
[draft-mozleywilliams-dnsop-dnsaid-01](https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-dnsaid/).

**Role split:**
- *Challenger* — calls `issue()` and `verify()`; no DNS write credentials required.
- *Claimant* — calls `place()` and `revoke()`; needs backend write credentials for the domain.

**Wire format** (space-separated key=value at `_agents-challenge.{domain}` TXT):

```
token=<32-char-base32>  [domain=<domain>]  [bnd-req=svc:<agent>@<issuer>]  expiry=<RFC3339Z>
```

```python
from dns_aid.core import dcv

# Challenger
challenge = dcv.issue("example.com", agent_name="assistant", issuer_domain="orga.test")
# ... deliver challenge to claimant out-of-band ...

# Claimant
await dcv.place(challenge.domain, challenge.token, bnd_req=challenge.bnd_req)

# Challenger
result = await dcv.verify(challenge.domain, challenge.token,
                          expected_bnd_req=challenge.bnd_req)
if result.verified:
    await dcv.revoke(challenge.domain, token=challenge.token)  # claimant cleanup
```

### dcv.issue()

Generate a stateless DCV challenge. Nothing is written to DNS — the returned
`DCVChallenge` is delivered to the claimant out-of-band.

```python
def issue(
    domain: str,
    *,
    agent_name: str | None = None,
    issuer_domain: str | None = None,
    ttl_seconds: int = 3600,
) -> DCVChallenge
```

#### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `domain` | `str` | Yes | - | Domain the claimant must prove control of |
| `agent_name` | `str` | No | `None` | Agent name to scope the `bnd-req` field |
| `issuer_domain` | `str` | No | `None` | Issuer domain to scope the `bnd-req` field |
| `ttl_seconds` | `int` | No | `3600` | Challenge validity window (30–86400) |

Returns a [`DCVChallenge`](#dcvchallenge). Raises `ValueError` if `ttl_seconds` is out of range; `ValidationError` for invalid domain or agent name.

### dcv.place()

Write the DCV challenge TXT record to DNS via the configured backend.

```python
async def place(
    domain: str,
    token: str,
    *,
    bnd_req: str | None = None,
    expiry_seconds: int = 3600,
    ttl: int = 300,
    backend: DNSBackend | None = None,
) -> DCVPlaceResult
```

#### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `domain` | `str` | Yes | - | Zone to write the challenge into |
| `token` | `str` | Yes | - | Token from the challenger (32-char lowercase base32) |
| `bnd_req` | `str` | No | `None` | Binding scope from the issued challenge |
| `expiry_seconds` | `int` | No | `3600` | Placed-record validity (30–86400). Prefer aligning with `DCVChallenge.expiry`. |
| `ttl` | `int` | No | `300` | DNS record TTL — keep short for quick cleanup |
| `backend` | `DNSBackend` | No | `None` | Defaults to `DNS_AID_BACKEND` env var |

Returns a [`DCVPlaceResult`](#dcvplaceresult).

### dcv.verify()

Resolve `_agents-challenge.{domain}` and confirm the token is present, unexpired,
and (optionally) bound to the expected scope.

```python
async def verify(
    domain: str,
    token: str,
    *,
    nameserver: str | None = None,
    port: int = 53,
    expected_bnd_req: str | None = None,
    require_dnssec: bool = False,
) -> DCVVerifyResult
```

#### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `domain` | `str` | Yes | - | Domain to check |
| `token` | `str` | Yes | - | Token originally issued by the challenger |
| `nameserver` | `str` | No | `None` | Operator-trusted nameserver IP (testbeds only) |
| `port` | `int` | No | `53` | DNS port |
| `expected_bnd_req` | `str` | No | `None` | When set, record `bnd-req` must match exactly |
| `require_dnssec` | `bool` | No | `False` | When `True`, resolver must set AD flag (silently downgraded when `nameserver=` is used) |

#### Fail-closed contract

| Condition | Result |
|---|---|
| Missing `expiry=` field | `verified=False` |
| Malformed `expiry=` | `verified=False` |
| Bare token (no `token=` prefix) | Not matched |
| `domain=` mismatched with queried domain | Record skipped |
| Invalid nameserver IP | `DCVVerifyResult(verified=False)` — never raises |
| `require_dnssec=True` + no AD flag | `verified=False` |
| `>10` challenge records (DoS guard) | `verified=False` |

Returns a [`DCVVerifyResult`](#dcvverifyresult).

> **Security:** The `nameserver` parameter accepts any syntactically valid IP including loopback,
> link-local (169.254/16), and RFC1918 ranges. It is operator-trusted and intentionally omitted
> from the MCP tool surface. Do not expose it to untrusted callers.

### dcv.revoke()

Delete the DCV challenge TXT record. Should be called immediately after a successful
`verify()` to prevent token reuse within the validity window.

```python
async def revoke(
    domain: str,
    *,
    token: str,
    backend: DNSBackend | None = None,
) -> DCVRevokeResult
```

#### Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `domain` | `str` | Yes | - | Zone to remove the challenge from |
| `token` | `str` | Yes | - | Token that was placed (must match the record in DNS) |
| `backend` | `DNSBackend` | No | `None` | Defaults to `DNS_AID_BACKEND` env var |

Returns a [`DCVRevokeResult`](#dcvrevokeresult). The token must be present in DNS
before deletion (check-then-delete reduces racing with concurrent challengers; not
atomic — `expiry=` remains the true security gate).

### DCVChallenge

Issued challenge, delivered to the claimant out-of-band.

| Field | Type | Description |
|-------|------|-------------|
| `token` | `str` | Base32-encoded nonce to place in DNS |
| `domain` | `str` | Domain being challenged |
| `fqdn` | `str` | Full owner name (`_agents-challenge.{domain}`) |
| `txt_value` | `str` | Verbatim TXT RDATA to place |
| `expiry` | `datetime` | UTC expiry time |
| `bnd_req` | `str \| None` | Binding scope (`svc:<agent>@<issuer>`), if set |

### DCVPlaceResult

| Field | Type | Description |
|-------|------|-------------|
| `fqdn` | `str` | Full owner name where the challenge was placed |
| `domain` | `str` | Zone domain |
| `expires_at` | `datetime` | UTC time the placed challenge expires |

### DCVVerifyResult

| Field | Type | Description |
|-------|------|-------------|
| `verified` | `bool` | `True` if a valid, unexpired matching record was found |
| `domain` | `str` | Domain that was queried |
| `token` | `str` | Token that was checked |
| `fqdn` | `str` | Full owner name queried |
| `expired` | `bool` | `True` if a matching record was found but past `expiry` |
| `dnssec_validated` | `bool` | `True` if `require_dnssec=True` and resolver set AD=1 |
| `error` | `str \| None` | Human-readable failure reason when `verified=False` |

### DCVRevokeResult

| Field | Type | Description |
|-------|------|-------------|
| `removed` | `bool` | `True` if the challenge record was deleted |
| `domain` | `str` | Zone domain |
| `fqdn` | `str` | Full owner name that was targeted |

---

## Data Models

### AgentRecord

Represents an AI agent published via DNS-AID.

```python
from dns_aid import AgentRecord, Protocol

agent = AgentRecord(
    name="network-specialist",
    domain="example.com",
    protocol=Protocol.MCP,
    target_host="mcp.example.com",
    port=443,
    capabilities=["ipam", "dns", "vpn"],
    version="1.0.0",
    description="Network automation agent",
    ttl=3600,
)
```

#### Fields

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `name` | `str` | Yes | - | Agent identifier (1-63 chars, DNS label format) |
| `domain` | `str` | Yes | - | Domain where agent is published |
| `protocol` | `Protocol` | Yes | - | Communication protocol |
| `target_host` | `str` | Yes | - | Hostname where agent is reachable |
| `port` | `int` | No | 443 | Port number |
| `ipv4_hint` | `str` | No | `None` | IPv4 address hint |
| `ipv6_hint` | `str` | No | `None` | IPv6 address hint |
| `capabilities` | `list[str]` | No | `[]` | Agent capabilities |
| `version` | `str` | No | "1.0.0" | Agent version |
| `description` | `str` | No | `None` | Description |
| `ttl` | `int` | No | 3600 | DNS TTL (60-86400) |
| `cap_uri` | `str` | No | `None` | URI to capability document (DNS-AID) |
| `cap_sha256` | `str` | No | `None` | SHA-256 digest of capability descriptor |
| `bap` | `list[str]` | No | `[]` | Supported protocols with versions |
| `policy_uri` | `str` | No | `None` | URI to agent policy document |
| `realm` | `str` | No | `None` | Multi-tenant scope identifier |
| `capability_source` | `str` | No | `None` | Where capabilities came from: `cap_uri`, `agent_card`, `http_index`, `txt_fallback`, `none` |
| `endpoint_source` | `str` | No | `None` | Where endpoint came from: `dns_svcb`, `dns_svcb_enriched`, `http_index`, `http_index_fallback`, `direct` |

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `fqdn` | `str` | Full DNS-AID record name: `_{name}._{protocol}._agents.{domain}` |
| `endpoint_url` | `str` | Full URL: `https://{target_host}:{port}` |
| `svcb_target` | `str` | SVCB target with trailing dot |

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `to_svcb_params()` | `dict[str, str]` | SVCB record parameters |
| `to_txt_values()` | `list[str]` | TXT record values |

---

### DiscoveryResult

Result of a DNS-AID discovery query.

#### Fields

| Field | Type | Description |
|-------|------|-------------|
| `query` | `str` | DNS query made |
| `domain` | `str` | Domain that was queried |
| `agents` | `list[AgentRecord]` | Discovered agents |
| `dnssec_validated` | `bool` | Whether DNSSEC was verified |
| `cached` | `bool` | Whether result was cached |
| `query_time_ms` | `float` | Query latency in milliseconds |

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `count` | `int` | Number of agents discovered |

---

### PublishResult

Result of publishing an agent to DNS.

#### Fields

| Field | Type | Description |
|-------|------|-------------|
| `agent` | `AgentRecord` | The published agent |
| `records_created` | `list[str]` | DNS records created |
| `zone` | `str` | DNS zone used |
| `backend` | `str` | DNS backend used |
| `success` | `bool` | Whether publish succeeded |
| `message` | `str \| None` | Status message |

---

### VerifyResult

Result of verifying an agent's DNS records.

#### Fields

| Field | Type | Description |
|-------|------|-------------|
| `fqdn` | `str` | FQDN that was verified |
| `record_exists` | `bool` | DNS record exists |
| `svcb_valid` | `bool` | SVCB record is valid |
| `dnssec_valid` | `bool` | DNSSEC chain validated |
| `dane_valid` | `bool \| None` | DANE/TLSA verified |
| `endpoint_reachable` | `bool` | Endpoint responds |
| `endpoint_latency_ms` | `float \| None` | Response time |

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `security_score` | `int` | Security score (0-100) |
| `security_rating` | `str` | "Excellent", "Good", "Fair", or "Poor" |

#### Security Scoring

| Check | Points |
|-------|--------|
| Record exists | 20 |
| SVCB valid | 20 |
| DNSSEC valid | 30 |
| DANE valid | 15 |
| Endpoint reachable | 15 |
| **Total** | **100** |

---

### Protocol

Enumeration of supported agent communication protocols.

```python
from dns_aid import Protocol

Protocol.MCP   # Model Context Protocol (Anthropic)
Protocol.A2A   # Agent-to-Agent (Google)
Protocol.HTTPS # Standard HTTPS
```

---

## Backends

### DNSBackend Interface

Abstract base class for DNS providers.

```python
from dns_aid.backends.base import DNSBackend

class CustomBackend(DNSBackend):
    @property
    def name(self) -> str:
        return "custom"

    async def create_svcb_record(self, zone, name, priority, target, params, ttl) -> str:
        ...

    async def create_txt_record(self, zone, name, values, ttl) -> str:
        ...

    async def delete_record(self, zone, name, record_type) -> bool:
        ...

    async def list_records(self, zone, name_pattern, record_type):
        ...

    async def zone_exists(self, zone) -> bool:
        ...
```

### Route53Backend

AWS Route 53 implementation.

```python
from dns_aid.backends.route53 import Route53Backend

# Auto-discover zones from AWS
backend = Route53Backend()

# Or specify zone ID directly
backend = Route53Backend(zone_id="Z1234567890ABC")

# Use with publish
from dns_aid import publish
from dns_aid.core.publisher import set_default_backend

set_default_backend(backend)
result = await publish(name="my-agent", ...)
```

**Requirements**: `pip install dns-aid[route53]` and AWS credentials configured.

### InfobloxBloxOneBackend

Infoblox UDDI (Universal DDI) implementation.

```python
from dns_aid.backends.infoblox import InfobloxBloxOneBackend

# From environment variables (recommended)
backend = InfobloxBloxOneBackend()

# Or with explicit configuration
backend = InfobloxBloxOneBackend(
    api_key="your-api-key",
    dns_view="default",  # DNS view name
    base_url="https://csp.infoblox.com",  # Optional
)

# Use as context manager
async with InfobloxBloxOneBackend() as backend:
    zones = await backend.list_zones()
    print(zones)
```

**Environment Variables**:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `INFOBLOX_API_KEY` | Yes | - | Infoblox UDDI API key |
| `INFOBLOX_DNS_VIEW` | No | `default` | DNS view name |
| `INFOBLOX_BASE_URL` | No | `https://csp.infoblox.com` | API URL |

**DNS-AID Compliance**: Infoblox UDDI is **not fully compliant** with the [DNS-AID draft](https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-dnsaid-01/). It only supports alias mode SVCB (priority 0) and lacks `alpn`, `port`, and `mandatory` parameters. For full compliance, use Route53Backend, InfobloxNIOSBackend, NS1Backend, or DDNSBackend.

### InfobloxNIOSBackend

Infoblox NIOS on-premise WAPI implementation. Supports full ServiceMode SVCB with custom DNS-AID parameters.

```python
from dns_aid.backends.infoblox import InfobloxNIOSBackend

# From environment variables (recommended)
backend = InfobloxNIOSBackend()

# Or with explicit configuration
backend = InfobloxNIOSBackend(
    host="nios.example.com",
    username="admin",
    password="your-password",
    dns_view="default",       # DNS view name
    wapi_version="2.13.7",    # WAPI version
    verify_ssl=False,         # TLS certificate verification
)
```

**Environment Variables**:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `NIOS_HOST` | Yes | - | Grid Manager hostname or IP |
| `NIOS_USERNAME` | Yes | - | WAPI username |
| `NIOS_PASSWORD` | Yes | - | WAPI password |
| `NIOS_DNS_VIEW` | No | `default` | DNS view name |
| `NIOS_WAPI_VERSION` | No | `2.13.7` | WAPI version |
| `NIOS_VERIFY_SSL` | No | `false` | Verify TLS certificate |

**DNS-AID Compliance**: NIOS WAPI supports ServiceMode SVCB records (priority > 0) with full SVC parameters including custom DNS-AID keys (`key65400`–`key65408`). NIOS natively supports private-use SVCB keys via the `supports_private_svcb_keys` property.

### NS1Backend

NS1 (IBM NS1 Connect) REST API v1 implementation.

```python
from dns_aid.backends.ns1 import NS1Backend

backend = NS1Backend()  # reads NS1_API_KEY from env

# Or with explicit configuration
backend = NS1Backend(
    api_key="your-api-key",
    base_url="https://api.nsone.net/v1",  # default
)
```

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `NS1_API_KEY` | Yes | - | NS1 API key with DNS read/write permissions |
| `NS1_BASE_URL` | No | `https://api.nsone.net/v1` | API base URL (for private/dedicated deployments) |

**DNS-AID Compliance**: NS1 supports ServiceMode SVCB records with full SVC parameters including private-use keys (`key65400`–`key65408`). NS1 natively accepts private-use SVCB keys — cap_uri, policy_uri, and realm go directly into the SVCB record without TXT demotion.

### DDNSBackend

RFC 2136 Dynamic DNS implementation. Works with BIND, Windows DNS, PowerDNS, Knot DNS, and any RFC 2136 compliant server.

```python
from dns_aid.backends.ddns import DDNSBackend

# From environment variables (recommended)
backend = DDNSBackend()

# Or with explicit configuration
backend = DDNSBackend(
    server="ns1.example.com",
    key_name="dns-aid-key",
    key_secret="YourBase64SecretHere==",
    key_algorithm="hmac-sha256",  # default
    port=53,                       # default
    timeout=10.0,                  # default
)

# Or load from BIND key file
backend = DDNSBackend(key_file="/etc/bind/dns-aid-key.conf")

# Use as context manager
async with DDNSBackend() as backend:
    exists = await backend.zone_exists("example.com")
```

**Environment Variables**:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DDNS_SERVER` | Yes | - | DNS server hostname or IP |
| `DDNS_KEY_NAME` | Yes | - | TSIG key name |
| `DDNS_KEY_SECRET` | Yes | - | TSIG key secret (base64) |
| `DDNS_KEY_ALGORITHM` | No | `hmac-sha256` | TSIG algorithm |
| `DDNS_PORT` | No | `53` | DNS server port |
| `DDNS_TIMEOUT` | No | `10` | Query timeout in seconds |

**Supported TSIG Algorithms**:
- `hmac-sha256` (recommended)
- `hmac-sha384`
- `hmac-sha512`
- `hmac-sha224`
- `hmac-md5` (legacy)

**Full DNS-AID Compliance**: DDNSBackend supports ServiceMode SVCB records (priority > 0) with all required parameters (`alpn`, `port`, `mandatory`).

### MockBackend

In-memory backend for testing.

```python
from dns_aid.backends.mock import MockBackend

backend = MockBackend()

# Pre-populate zones
backend = MockBackend(zones={"example.com": {}})
```

---

## JWS Signatures

Application-layer signature verification as an alternative to DNSSEC.

### generate_keypair()

Generate an EC P-256 keypair for signing DNS records.

```python
from dns_aid.core.jwks import generate_keypair

private_key, public_key = generate_keypair()
# private_key: EllipticCurvePrivateKey
# public_key: EllipticCurvePublicKey
```

### export_jwks()

Export public key as JWKS JSON for hosting at `.well-known/dns-aid-jwks.json`.

```python
from dns_aid.core.jwks import export_jwks

jwks_dict = export_jwks(public_key, kid="dns-aid-2024")
# {
#   "keys": [{
#     "kty": "EC",
#     "crv": "P-256",
#     "kid": "dns-aid-2024",
#     "use": "sig",
#     "x": "...",
#     "y": "..."
#   }]
# }
```

### sign_record()

Sign a DNS record payload with a private key.

```python
from dns_aid.core.jwks import sign_record, RecordPayload

payload = RecordPayload(
    fqdn="_payment._mcp._agents.example.com",
    target="payment.example.com",
    port=443,
    alpn="mcp",
)

jws_compact = sign_record(payload, private_key)
# Returns: "eyJhbGciOiJFUzI1NiIs..."
```

### verify_signature()

Verify a JWS signature against a public key.

```python
from dns_aid.core.jwks import verify_signature

is_valid, payload = verify_signature(jws_compact, public_key)
# is_valid: bool
# payload: RecordPayload if valid, None if invalid
```

### Publishing with Signatures

```python
from dns_aid import publish

result = await publish(
    name="payment",
    domain="example.com",
    protocol="mcp",
    endpoint="payment.example.com",
    sign=True,
    private_key_path="./keys/private.pem",
)
```

### Discovery with Verification

```python
from dns_aid import discover

agents = await discover(
    "example.com",
    verify_signatures=True,  # Verify JWS sig= parameter
)
```

---

## Validation Utilities

Input validation functions for security compliance.

```python
from dns_aid.utils.validation import (
    validate_agent_name,
    validate_domain,
    validate_protocol,
    validate_endpoint,
    validate_port,
    validate_ttl,
    validate_capabilities,
    validate_fqdn,
    ValidationError,
)
```

### Functions

| Function | Input | Returns | Description |
|----------|-------|---------|-------------|
| `validate_agent_name(name)` | `str` | `str` | Validate/normalize agent name |
| `validate_domain(domain)` | `str` | `str` | Validate/normalize domain |
| `validate_protocol(protocol)` | `str` | `Literal["mcp", "a2a"]` | Validate protocol |
| `validate_endpoint(endpoint)` | `str` | `str` | Validate endpoint hostname |
| `validate_port(port)` | `int` | `int` | Validate port (1-65535) |
| `validate_ttl(ttl)` | `int` | `int` | Validate TTL (60-604800) |
| `validate_capabilities(caps)` | `list[str]` | `list[str]` | Validate capability list |
| `validate_fqdn(fqdn)` | `str` | `str` | Validate DNS-AID FQDN |

### ValidationError

Custom exception with structured error details.

```python
try:
    validate_agent_name("INVALID NAME!")
except ValidationError as e:
    print(f"Field: {e.field}")
    print(f"Message: {e.message}")
    print(f"Value: {e.value}")
```

---

## CLI Reference

The `dns-aid` CLI provides command-line access to all DNS-AID functions.

### Commands

```bash
# Publish an agent (auto-updates index)
dns-aid publish --name my-agent --domain example.com --protocol mcp \
    --endpoint agent.example.com --capability chat --capability code

# Publish without updating index
dns-aid publish --name internal-bot --domain example.com --protocol mcp \
    --endpoint bot.example.com --no-update-index

# Discover agents (pure DNS - default)
dns-aid discover example.com
dns-aid discover example.com --protocol mcp

# Discover via HTTP index (ANS-compatible)
dns-aid discover example.com --use-http-index

# Verify an agent
dns-aid verify _my-agent._mcp._agents.example.com

# List all agents in a zone
dns-aid list example.com

# Delete an agent (auto-removes from index)
dns-aid delete --name my-agent --domain example.com --protocol mcp --force

# Delete without updating index
dns-aid delete --name my-agent --domain example.com --protocol mcp --force --no-update-index

# List available DNS zones
dns-aid zones

# Agent Index Commands
dns-aid index list example.com           # List agents in domain's index
dns-aid index sync example.com           # Sync index with actual DNS records
```

### Agent Communication Commands

```bash
# Send a message to an A2A agent (discover-first: DNS → agent card → invoke)
dns-aid message --domain ai.infoblox.com --name security-analyzer \
    "Analyze security of _marketing._a2a._agents.ai.infoblox.com"

# Send a message to an A2A agent (direct endpoint)
dns-aid message --endpoint https://security-analyzer.ai.infoblox.com \
    "Analyze DNS-AID security posture"

# JSON output
dns-aid message --endpoint https://chat.example.com "Hello" --json

# Custom timeout (seconds)
dns-aid message --domain example.com --name chat "Hello" --timeout 60
```

| Option | Description |
|--------|-------------|
| `--domain` | Domain for DNS discovery (used with `--name`) |
| `--name` | Agent name for DNS discovery (used with `--domain`) |
| `--endpoint` | Direct endpoint URL (skips discovery) |
| `--json` | Output raw JSON response |
| `--timeout` | Request timeout in seconds (default: 30) |

```bash
# List tools on a remote MCP agent (discover-first)
dns-aid list-tools --domain example.com --name network-specialist

# List tools via direct endpoint
dns-aid list-tools --endpoint https://mcp.example.com/mcp

# Call a tool on a remote MCP agent
dns-aid call --endpoint https://mcp.example.com/mcp search_flights \
    --arguments '{"origin": "SFO", "destination": "JFK"}'

# Call with discover-first
dns-aid call --domain example.com --name network-specialist get_subnets \
    --arguments '{"network": "10.0.0.0/8"}'
```

### Environment Variables

**General:**

| Variable | Description |
|----------|-------------|
| `DNS_AID_BACKEND` | Default backend: "route53", "cloudflare", "ns1", "infoblox", "nios", "ddns", or "mock" |
| `DNS_AID_LOG_LEVEL` | Logging level: DEBUG, INFO, WARNING, ERROR |

**AWS Route 53:**

Route 53 uses boto3's credential chain. No env vars are required if `~/.aws/credentials` or an IAM role is configured.

| Variable | Required | Description |
|----------|----------|-------------|
| `AWS_ACCESS_KEY_ID` | No | AWS access key (or use `aws configure` / IAM role) |
| `AWS_SECRET_ACCESS_KEY` | No | AWS secret key |
| `AWS_DEFAULT_REGION` | No | AWS region (default: us-east-1) |
| `AWS_PROFILE` | No | Named profile from `~/.aws/credentials` |

**Infoblox UDDI:**

| Variable | Description |
|----------|-------------|
| `INFOBLOX_API_KEY` | Infoblox UDDI API key (required) |
| `INFOBLOX_DNS_VIEW` | DNS view name (default: "default") |
| `INFOBLOX_BASE_URL` | API URL (default: https://csp.infoblox.com) |

**Infoblox NIOS (On-Prem):**

| Variable | Description |
|----------|-------------|
| `NIOS_HOST` | Grid Manager hostname or IP (required) |
| `NIOS_USERNAME` | WAPI username (required) |
| `NIOS_PASSWORD` | WAPI password (required) |
| `NIOS_DNS_VIEW` | DNS view name (default: "default") |
| `NIOS_WAPI_VERSION` | WAPI version (default: "2.13.7") |
| `NIOS_VERIFY_SSL` | Verify TLS certificate (default: "false") |

**DDNS (RFC 2136):**

| Variable | Description |
|----------|-------------|
| `DDNS_SERVER` | DNS server hostname or IP (required) |
| `DDNS_KEY_NAME` | TSIG key name (required) |
| `DDNS_KEY_SECRET` | TSIG key secret, base64 (required) |
| `DDNS_KEY_ALGORITHM` | TSIG algorithm (default: hmac-sha256) |
| `DDNS_PORT` | DNS server port (default: 53) |

---

## MCP Server

The MCP server (`dns-aid-mcp`) exposes DNS-AID as tools for AI assistants.

### Starting the Server

```bash
# Stdio transport (for Claude Desktop)
dns-aid-mcp

# HTTP transport (for remote access)
dns-aid-mcp --transport http --port 8000

# HTTP with custom host binding
dns-aid-mcp --transport http --host 0.0.0.0 --port 8000
```

### Available Tools

| Tool | Description |
|------|-------------|
| `publish_agent_to_dns` | Publish an agent to DNS (auto-updates index) |
| `discover_agents_via_dns` | Discover agents at a domain (supports `use_http_index` param) |
| `verify_agent_dns` | Verify agent DNS records |
| `list_published_agents` | List all agents in a zone |
| `delete_agent_from_dns` | Delete an agent from DNS (auto-updates index) |
| `list_agent_index` | List agents in domain's index |
| `sync_agent_index` | Sync index with actual DNS records |
| `send_a2a_message` | Send a message to an A2A agent. Accepts `domain` + `name` (discover-first) or `endpoint` (direct). |

### Health Endpoints (HTTP Transport)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Server info and available tools |
| `/health` | GET | Basic health check |
| `/ready` | GET | Readiness check (DNS backend available) |

### Claude Desktop Integration

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "dns-aid": {
      "command": "dns-aid-mcp"
    }
  }
}
```

---

## Error Handling

All functions may raise exceptions. Recommended pattern:

```python
from dns_aid import publish, discover
from dns_aid.utils.validation import ValidationError

try:
    result = await publish(
        name="my-agent",
        domain="example.com",
        protocol="mcp",
        endpoint="agent.example.com",
    )
    if not result.success:
        print(f"Publish failed: {result.message}")
except ValidationError as e:
    print(f"Invalid input: {e.field} - {e.message}")
except Exception as e:
    print(f"Unexpected error: {e}")
```


## Invocation Module (`core/invoke.py`)

Single source of truth for agent invocation. Both CLI and MCP server delegate to these functions.

### send_a2a_message()

Send a message to an A2A agent using discover-first or direct endpoint.

```python
from dns_aid.core.invoke import send_a2a_message, InvokeResult

# Discover-first (DNS → agent card → invoke)
result: InvokeResult = await send_a2a_message(
    message="Analyze DNS-AID security posture",
    domain="ai.infoblox.com",
    name="security-analyzer",
    timeout=30.0,
)

# Direct endpoint (skip discovery)
result = await send_a2a_message(
    message="Hello",
    endpoint="https://chat.example.com",
)

print(result.text)       # Extracted text response
print(result.raw)        # Full JSON-RPC response dict
print(result.error)      # Error message if failed (None on success)
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `message` | `str` | Yes | Message text to send |
| `domain` | `str` | No | Domain for DNS discovery (used with `name`) |
| `name` | `str` | No | Agent name for DNS discovery (used with `domain`) |
| `endpoint` | `str` | No | Direct endpoint URL (skips discovery). Either `domain`+`name` or `endpoint` required. |
| `timeout` | `float` | No | Request timeout in seconds (default: 30) |

### call_mcp_tool()

Call a tool on a remote MCP agent via JSON-RPC `tools/call`.

```python
from dns_aid.core.invoke import call_mcp_tool

result = await call_mcp_tool(
    endpoint="https://mcp.example.com/mcp",
    tool_name="search_flights",
    arguments={"origin": "SFO", "destination": "JFK"},
)
```

### list_mcp_tools()

List available tools on a remote MCP agent via JSON-RPC `tools/list`.

```python
from dns_aid.core.invoke import list_mcp_tools

result = await list_mcp_tools(
    endpoint="https://mcp.example.com/mcp",
)
```

### resolve_a2a_endpoint()

Resolve an A2A agent endpoint via DNS discovery and agent card fetch.

```python
from dns_aid.core.invoke import resolve_a2a_endpoint

endpoint_url = await resolve_a2a_endpoint(
    domain="ai.infoblox.com",
    name="security-analyzer",
)
# Returns: "https://security-analyzer.ai.infoblox.com:443"
```

Resolution chain:
1. DNS discovery (`discover(domain, protocol="a2a", name=name)`)
2. Agent card fetch (`/.well-known/agent-card.json`) for canonical URL
3. Host mismatch protection: if agent card URL hostname differs from DNS endpoint, DNS wins

### InvokeResult

Returned by all invocation functions.

| Field | Type | Description |
|-------|------|-------------|
| `text` | `str \| None` | Extracted text from response |
| `raw` | `dict \| None` | Full response payload |
| `error` | `str \| None` | Error message if invocation failed |

---

## SDK: Invocation & Telemetry

The Tier 1 SDK provides agent invocation with automatic telemetry capture, and community-wide ranking queries.

### Top-Level Functions

#### invoke()

```python
async def invoke(
    agent: AgentRecord,
    *,
    method: str | None = None,
    arguments: dict | None = None,
    timeout: float | None = None,
    config: SDKConfig | None = None,
) -> InvocationResult
```

One-shot agent invocation with telemetry. Creates an AgentClient, calls the agent, returns the result with an attached signal.

**Examples:**
```python
import dns_aid

# MCP agent: list tools
result = await dns_aid.discover("example.com", protocol="mcp")
resp = await dns_aid.invoke(result.agents[0], method="tools/list")
print(resp.signal.invocation_latency_ms)  # 148.2

# A2A agent: send a message (standard JSON-RPC message/send)
result = await dns_aid.discover("ai.infoblox.com", protocol="a2a")
resp = await dns_aid.invoke(
    result.agents[0],
    method="message/send",
    arguments={
        "message": {
            "messageId": "unique-id",
            "role": "user",
            "parts": [{"kind": "text", "text": "What is DNS-AID?"}],
        }
    },
)
# Standard A2A methods (message/send, tasks/get, etc.) are automatically
# wrapped in a JSON-RPC 2.0 envelope by the A2A protocol handler.
```

#### rank()

```python
async def rank(
    agents: list[AgentRecord],
    *,
    method: str | None = None,
    arguments: dict | None = None,
    config: SDKConfig | None = None,
) -> list[RankedAgent]
```

Invoke multiple agents and rank by telemetry performance (composite score).

### Protocol Handlers

The SDK routes invocations through protocol-specific handlers:

| Protocol | Handler | Wire Format |
|----------|---------|-------------|
| MCP | `MCPProtocolHandler` | MCP Streamable HTTP (modern, spec 2025-03-26+) for `tools/call` and `tools/list`, with transparent legacy plain JSON-RPC POST fallback when the target rejects the modern transport |
| A2A | `A2AProtocolHandler` | JSON-RPC 2.0 for standard methods (`message/send`, `tasks/get`); generic payload for custom methods |
| HTTPS | `HTTPSProtocolHandler` | HTTP POST with JSON body |

**MCP Protocol Handler** delegates transport to the official `mcp` Python SDK
(`mcp.client.streamable_http.streamablehttp_client` and `mcp.ClientSession`)
for the modern path. The handler injects a per-invocation telemetry adapter
(latency, TTFB, response size, cost headers, TLS version) and propagates the
dns-aid `X-DNS-AID-Caller-Domain` header on every request when
`DNS_AID_CALLER_DOMAIN` is set. On transport mismatch (HTTP 405/406, refused
initialize via JSON-RPC -32601) the handler transparently falls back to the
legacy plain JSON-RPC POST path; the fallback event is logged as a structured
warning (`transport.legacy_fallback`) carrying the endpoint, the failure
reason, and the modern attempt latency.

**A2A Protocol Handler** automatically wraps standard A2A methods in a JSON-RPC 2.0 envelope:

```python
# Standard methods (message/send, message/stream, tasks/get, tasks/cancel, etc.)
# are wrapped in: {"jsonrpc": "2.0", "method": "...", "params": {...}, "id": "..."}

# Non-standard/custom methods use generic format for backward compatibility:
# {"method": "custom_task", ...arguments}
```

### AgentClient

The main SDK class. Use as async context manager for connection reuse.

```python
from dns_aid.sdk import AgentClient, SDKConfig

config = SDKConfig(timeout_seconds=30.0, caller_id="my-app")

async with AgentClient(config=config) as client:
    result = await client.invoke(agent, method="tools/list")
    ranked = client.rank()
```

**Methods:**

| Method | Description |
|--------|-------------|
| `invoke(agent, method, arguments, timeout)` | Invoke agent, return `InvocationResult` |
| `rank(strategy)` | Rank all invoked agents by composite score |
| `fetch_rankings(fqdns, limit)` | Fetch community-wide rankings from telemetry API |
| `signals` | Property: list of all collected `InvocationSignal` objects |

#### fetch_rankings()

```python
async def fetch_rankings(
    self,
    fqdns: list[str] | None = None,
    limit: int = 50,
) -> list[dict]
```

Fetch community-wide rankings from a configured telemetry API endpoint. Returns pre-computed composite scores based on aggregated telemetry.

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `fqdns` | `list[str] \| None` | `None` | Filter rankings to specific agent FQDNs |
| `limit` | `int` | `50` | Maximum number of rankings to return |

**Returns:** List of ranking dictionaries with `agent_fqdn`, `composite_score`, etc.

**Example:**
```python
async with AgentClient(config) as client:
    # Get all rankings
    rankings = await client.fetch_rankings()

    # Get rankings for specific agents only
    rankings = await client.fetch_rankings(
        fqdns=["_booking._mcp._agents.example.com"],
        limit=10
    )

    for r in rankings:
        print(f"{r['agent_fqdn']}: {r['composite_score']}")
```

**Note:** Requires `telemetry_api_url` to be configured in SDKConfig. Returns empty list if not configured.

### SDKConfig

```python
from dns_aid.sdk import SDKConfig

config = SDKConfig(
    timeout_seconds=30.0,        # Default request timeout
    caller_id="my-app",          # Caller identifier for signals
    persist_signals=False,       # Auto-save signals to PostgreSQL
    database_url=None,           # DB URL (falls back to DATABASE_URL env)
    otel_enabled=False,          # Enable OpenTelemetry export
    otel_endpoint=None,          # OTLP endpoint URL
    otel_export_format="otlp",   # "otlp" or "console"
    http_push_url=None,          # POST signals to remote telemetry API
    directory_api_url=None,      # Base URL for AgentClient.search() and fetch_rankings()
    telemetry_api_url=None,      # Deprecated alias for directory_api_url
)

# Or from environment variables:
config = SDKConfig.from_env()
```

**Environment Variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `DNS_AID_SDK_TIMEOUT` | 30.0 | Request timeout in seconds |
| `DNS_AID_SDK_CALLER_ID` | None | Caller identifier |
| `DNS_AID_SDK_PERSIST_SIGNALS` | false | Enable DB persistence |
| `DATABASE_URL` | None | PostgreSQL connection URL |
| `DNS_AID_SDK_OTEL_ENABLED` | false | Enable OpenTelemetry |
| `DNS_AID_SDK_OTEL_ENDPOINT` | None | OTLP collector URL |
| `DNS_AID_SDK_HTTP_PUSH_URL` | None | POST signals to this URL |
| `DNS_AID_SDK_DIRECTORY_API_URL` | None | Base URL for `AgentClient.search()` + `fetch_rankings()` (v0.19.0+) |
| `DNS_AID_SDK_TELEMETRY_API_URL` | None | Deprecated alias for `DNS_AID_SDK_DIRECTORY_API_URL` |

The `resolved_directory_url` property returns `directory_api_url` when set, falling
back to `telemetry_api_url` for backwards compatibility. Using the legacy alias
emits a `DeprecationWarning` once per process.

---

### AgentClient.search() — Path B cross-domain search (v0.19.0+)

```python
async def search(
    self,
    q: str | None = None,
    *,
    protocol: Literal["mcp", "a2a", "https"] | None = None,
    domain: str | None = None,
    capabilities: list[str] | None = None,
    min_security_score: int | None = None,
    verified_only: bool = False,
    intent: str | None = None,
    auth_type: str | None = None,
    transport: str | None = None,
    realm: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> SearchResponse
```

Issues `GET {directory_api_url}/api/v1/search` and returns a typed `SearchResponse`.
Path B is **opt-in**: invoking `search()` without `directory_api_url` configured
raises `DirectoryConfigError` immediately, before any network work.

#### Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `q` | `str \| None` | `None` | Free-text query, or `None` for browse-all-with-filters mode. |
| `protocol` | `Literal["mcp","a2a","https"] \| None` | `None` | Restrict to a protocol. |
| `domain` | `str \| None` | `None` | Restrict to a single domain. |
| `capabilities` | `list[str] \| None` | `None` | All-of capability match. |
| `min_security_score` | `int \| None` | `None` | Minimum security score (0–100). |
| `verified_only` | `bool` | `False` | Restrict to DCV-verified domains. |
| `intent` | `str \| None` | `None` | Action intent filter (`query` / `command` / `transaction` / `subscription`). |
| `auth_type` | `str \| None` | `None` | Auth type filter. |
| `transport` | `str \| None` | `None` | Transport filter (`streamable-http`, `https`, `sse`, `stdio`). |
| `realm` | `str \| None` | `None` | Multi-tenant realm filter. |
| `limit` | `int` | `20` | Page size, 1–10000. |
| `offset` | `int` | `0` | Pagination offset. |

#### Returns

`SearchResponse` — query echo, ranked results, pagination state.

#### Raises

- `DirectoryConfigError` — `directory_api_url` not configured.
- `DirectoryAuthError` — Directory rejected credentials (HTTP 401/403).
- `DirectoryRateLimitedError` — Directory rate-limited (HTTP 429); the
  `retry_after_seconds` detail mirrors the `Retry-After` header.
- `DirectoryUnavailableError` — Transient: connect refused, timeout, 5xx, 404,
  unexpected redirect, oversized response, or response shape the SDK can't validate.
- `RuntimeError` — Client not in an async context manager.

#### Example

```python
from dns_aid.sdk import AgentClient, SDKConfig

async with AgentClient(config=SDKConfig.from_env()) as client:
    response = await client.search(
        "payment processing",
        protocol="mcp",
        capabilities=["payment-processing"],
        min_security_score=70,
    )
    for result in response.results:
        print(f"{result.score:.2f}  {result.agent.fqdn}  T{result.trust.trust_tier}")
        print(f"   sec={result.trust.security_score}  trust={result.trust.trust_score}")

    # Paginate
    while response.has_more:
        response = await client.search(q="payment", offset=response.next_offset)
```

#### Composition pattern (zero-trust)

Path B returns directory-attested candidates. Path A re-verifies via DNS substrate
before invoking — directory is opt-in convenience, never a trust bottleneck.

```python
from dns_aid.sdk import AgentClient
from dns_aid.core.discoverer import discover

async with AgentClient() as client:
    # 1. Cross-domain candidate discovery
    response = await client.search(q="fraud detection", min_security_score=70)

    for candidate in response.results:
        # 2. DNS-substrate re-verification with signature requirement
        verified = await discover(
            candidate.agent.domain,
            name=candidate.agent.name,
            require_signed=True,
            require_signature_algorithm=["ES256", "Ed25519"],
        )
        if verified.agents:
            # 3. Safe to invoke
            ...
```

---

### SearchResponse / SearchResult / TrustAttestation / Provenance (v0.19.0+)

Typed result models in `dns_aid.sdk.search`. All immutable (`frozen=True`) and
forward-compatible (`extra="ignore"`) so directory schema additions don't break
SDK consumers.

```python
class SearchResponse(BaseModel):
    query: str | None              # Echo of the q parameter from the directory.
    results: list[SearchResult]    # Ranked results, length <= limit.
    total: int                     # Matches across all pages (after skip-and-log).
    limit: int
    offset: int

    @property
    def has_more(self) -> bool: ...
    @property
    def next_offset(self) -> int | None: ...

class SearchResult(BaseModel):
    agent: AgentRecord
    score: float                       # Raw relevance score, not normalized.
    trust: TrustAttestation            # Defaults to all-zero if directory omits.
    provenance: Provenance | None      # Built when first_seen / last_seen present.

class TrustAttestation(BaseModel):
    security_score: int = 0            # 0–100
    trust_score: int = 0               # 0–100
    popularity_score: int = 0          # 0–100
    trust_tier: int = 0                # 0–3 (untiered / basic / enhanced / continuous)
    safety_status: Literal["active", "blocked"] = "active"
    dnssec_valid: bool | None = None
    dane_valid: bool | None = None
    svcb_valid: bool | None = None
    endpoint_reachable: bool | None = None
    protocol_verified: bool | None = None
    threat_flags: dict[str, Any] = {}
    breakdown: dict[str, Any] | None = None   # Directory's trust_breakdown.
    badges: list[str] | None = None           # Directory's trust_badges.

class Provenance(BaseModel):
    discovery_level: int = 0           # 0 observed / 1 beacon / 2 manifest / 3 federated
    first_seen: datetime
    last_seen: datetime
    last_verified: datetime | None = None
    company: dict[str, Any] | None = None
```

---

### Directory exceptions (v0.19.0+)

```python
from dns_aid.sdk import (
    DirectoryError,                # Base exception class.
    DirectoryConfigError,          # directory_api_url not configured (78 EX_CONFIG).
    DirectoryUnavailableError,     # Transient (75 EX_TEMPFAIL).
    DirectoryRateLimitedError,     # 429; carries retry_after_seconds detail.
    DirectoryAuthError,            # 401/403 (77 EX_NOPERM); does NOT inherit from Unavailable.
)
```

Every exception carries a `details: dict[str, Any]` attribute with structured fields
(`directory_url`, `status_code`, `underlying`, etc.) so callers can dispatch on type
*and* inspect details for richer error handling.

### InvocationResult

Returned by `invoke()`. Contains response data and telemetry signal.

| Field | Type | Description |
|-------|------|-------------|
| `success` | bool | Whether invocation succeeded |
| `data` | dict \| str \| None | Response payload |
| `signal` | InvocationSignal | Telemetry signal for this call |
| `error_message` | str \| None | Error description if failed |

### InvocationSignal

Per-call telemetry captured automatically.

| Field | Type | Description |
|-------|------|-------------|
| `id` | UUID | Unique signal identifier |
| `agent_fqdn` | str | Agent DNS-AID FQDN |
| `agent_endpoint` | str | Endpoint URL used |
| `protocol` | str | Protocol (mcp, a2a, https) |
| `method` | str | Method called |
| `status` | InvocationStatus | success, error, timeout, refused |
| `invocation_latency_ms` | float | Total invocation time |
| `ttfb_ms` | float | Time to first byte |
| `http_status_code` | int | HTTP response status |
| `cost_units` | float | Cost from X-Cost-Units header |
| `cost_currency` | str | Currency from X-Cost-Currency header |
| `response_size_bytes` | int | Response payload size |
| `tls_version` | str | TLS version used |
| `timestamp` | datetime | When the call was made |
| `caller_id` | str | Caller identifier from config |

### Ranking

```python
ranked = client.rank()  # Default: WeightedCompositeStrategy

for r in ranked:
    print(f"{r.agent_fqdn}: {r.composite_score:.1f}")
```

**Scoring Formula (WeightedComposite):**
```
composite = 0.40 * reliability   (success_rate * 100)
          + 0.30 * latency       (100 * (1 - avg_latency/5000))
          + 0.15 * cost          (relative to cheapest)
          + 0.15 * freshness     (recency weighted)
```

**Available Strategies:**
- `WeightedCompositeStrategy` (default)
- `LatencyFirstStrategy` — prioritizes lowest latency
- `ReliabilityFirstStrategy` — prioritizes highest success rate

### HTTP Telemetry Push (Optional)

The SDK can optionally push signals to an external telemetry collection endpoint:

```python
config = SDKConfig(
    http_push_url="https://your-telemetry-server.example.com/signals"
)

async with AgentClient(config=config) as client:
    # Signals automatically pushed in a background thread
    await client.invoke(agent, method="tools/list")
```

Disabled by default (`http_push_url=None`). Configure via `SDKConfig` or the `DNS_AID_SDK_HTTP_PUSH_URL` environment variable.

---

## Experimental: EDNS(0) signaling

> ⚠ **Unstable.** APIs in this section live in `dns_aid.experimental` and may change or be removed in any release. They are not covered by semver guarantees. Full design rationale: [docs/experimental/edns-signaling.md](experimental/edns-signaling.md).

Lets a client attach selector filters to outgoing DNS queries via an EDNS(0) option (code 65430, private use). Hint-aware DNS hops — including hint-aware authoritative servers — can narrow the response or short-circuit with a cached match. Stock authoritative servers treat the option as inert per RFC 6891.

Activate by setting `DNS_AID_EXPERIMENTAL_EDNS_HINTS=1` in the environment. Without the flag the code paths are dormant even when the symbols are imported.

### AgentHint

Two-axis selector taxonomy (see [design doc §4.3](experimental/edns-signaling.md) for the full rationale).

```python
from dns_aid.experimental import AgentHint

# Axis 1: shape the answer set; participate in the cache key
# Axis 2: shape the request lifecycle; do NOT fragment the cache
hint = AgentHint(
    realm="prod",
    transport="mcp",
    min_trust="signed+dnssec",
    client_intent_class="invocation",
    parallelism=4,
    deadline_ms=30000,
)
```

**Axis 1 — substrate filters** (codes 0x01–0x0F). Different values mean different answer sets.

| Field | Type | Code | Notes |
|-------|------|------|-------|
| `realm` | `str \| None` | 0x01 | Multi-tenant scope; matches SVCB `realm=` param. |
| `transport` | `str \| None` | 0x02 | `"mcp"` \| `"a2a"` \| `"https"`. |
| `policy_required` | `bool` | 0x03 | When `True`, only records carrying `policy=` URI. Default `False`; not emitted on wire when False (absence = "don't care"). |
| `min_trust` | `str \| None` | 0x04 | `"signed"` \| `"dnssec"` \| `"signed+dnssec"`. Gated on `sig` param + DNSSEC chain. |
| `jurisdiction` | `str \| None` | 0x05 | ISO region tag (e.g. `"eu"`, `"us-east"`). |

**Axis 2 — metering / lifecycle** (codes 0x10–0x1F). Drive request policy; do not change the answer set.

| Field | Type | Code | Notes |
|-------|------|------|-------|
| `client_intent_class` | `str \| None` | 0x10 | `"discovery"` (browsing) \| `"invocation"` (about to call). |
| `max_age` | `int \| None` | 0x11 | Seconds; don't return cache entries older than this. |
| `parallelism` | `int \| None` | 0x12 | Expected sibling-query count. Signals fan-out to caches. |
| `deadline_ms` | `int \| None` | 0x13 | Wait budget in ms. **Hint-only** — auth cannot refuse for SLA in v0; may prefer faster path / serve stale to meet it. |

Methods:
- `encode() -> bytes` — produce the EDNS(0) option payload (raises `ValueError` if any selector value exceeds 255 UTF-8 bytes or the total payload exceeds 512).
- `signature() -> str` — stable cache-key string. **Axis 1 only** — two hints differing only in Axis 2 share a signature, so they hit the same cache entry. This is a load-bearing invariant of the design.

**Not DNS-layer selectors.** `capabilities` and `intent` are intentionally NOT fields on `AgentHint`. They live in the publisher's well-known JSON (see [`EdnsSignalingAdvertisement.honored_selectors`](#ednssignalingadvertisement)) and clients use them for *post-fetch local filtering*, not query-time signaling. The reason is layering: SVCB doesn't carry capability strings, so an auth would have to dereference cap-doc URIs per-query to filter on them, which breaks DNS latency budgets.

### AgentHintEcho

Response-side echo from a hint-aware hop, listing the selector codes the responder actually applied. Absence means no upstream filtering happened — fall back to local filtering.

```python
from dns_aid.experimental import AgentHintEcho

echo = AgentHintEcho(applied_selectors=[0x01, 0x02])
```

### EdnsSignalingAdvertisement

Publisher advertisement carried in `cap-doc`, `agent-card`, or `agents-index.json`:

```json
{
  "edns_signaling": {
    "version": 0,
    "honored_selectors": ["capabilities", "intent", "transport"],
    "note": "Recommends client-side pre-filtering."
  }
}
```

Lifted automatically onto `CapabilityDocument.edns_signaling`, `A2AAgentCard.edns_signaling`, and `HttpIndexAgent.edns_signaling`. Stored as `dict | None` (forward-compat on unknown shapes).

### EdnsAwareResolver

In-process programmable hop (Locus 1 in the design doc). Wraps `dns.asyncresolver.Resolver`, attaches the hint as an EDNS option on outgoing queries (when the env flag is set), and caches answers keyed by `(qname, qtype, hint_signature)`.

```python
from dns_aid.experimental import AgentHint, EdnsAwareResolver

resolver = EdnsAwareResolver(ttl_seconds=60)
result = await resolver.resolve(
    "_chat._mcp._agents.example.com", "SVCB",
    agent_hint=AgentHint(realm="prod", transport="mcp"),
)
# result.answer — dnspython Answer
# result.echo   — AgentHintEcho | None (presence == upstream is hint-aware)
```

### Integration with discover()

```python
from dns_aid import discover
from dns_aid.experimental import AgentHint

result = await discover(
    "example.com",
    agent_hint=AgentHint(realm="prod", transport="mcp", parallelism=4, deadline_ms=30000),
)
```

The `agent_hint=` kwarg is accepted unconditionally for forward-compat. The option is only emitted on the wire when `DNS_AID_EXPERIMENTAL_EDNS_HINTS=1` is set.

### CLI: `dns-aid edns-probe`

```bash
DNS_AID_EXPERIMENTAL_EDNS_HINTS=1 \
  dns-aid edns-probe example.com \
  --realm prod --transport mcp \
  --intent-class invocation --parallelism 4 --deadline-ms 30000 \
  --show-wire
```

Flags are grouped by axis: `--realm`, `--transport`, `--policy-required`, `--min-trust`, `--jurisdiction` (Axis 1); `--intent-class`, `--max-age`, `--parallelism`, `--deadline-ms` (Axis 2).

Prints an `[experimental]` banner on stderr, performs a cache-miss → cache-hit demonstration with `EdnsAwareResolver`, and reports any `AgentHintEcho` received.

---

## Version

```python
import dns_aid
print(dns_aid.__version__)  # "0.6.0"
```

---

## See Also

- [Getting Started Guide](getting-started.md)
- [IETF Draft: DNS-AID](https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-dnsaid-01/)
- [RFC 9460: SVCB Records](https://www.rfc-editor.org/rfc/rfc9460.html)
- [GitHub Repository](https://github.com/infobloxopen/dns-aid-core)
