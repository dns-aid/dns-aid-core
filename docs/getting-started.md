# Getting Started with DNS-AID

This guide will walk you through installing, configuring, and testing DNS-AID.

> **Version 0.17.0** - Adds policy-to-RPZ compiler, Infoblox Threat Defense integration (`dns-aid enforce`), CEL-to-DNS compilation, bind-aid zone writer, and 4 new MCP tools for policy enforcement.

## Relationship to IETF

This guide describes usage of the reference implementation.

The DNS-AID specification is defined in the IETF draft: https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-dnsaid/.

## Prerequisites

- Python 3.11 or higher
- One of the following DNS backends:
  - **Cloudflare** (recommended for beginners - free tier available)
  - AWS account with Route 53 access
  - Google Cloud project with Cloud DNS access
  - Infoblox UDDI account with API key
  - Infoblox NIOS (on-prem) with WAPI 2.13+ (required for native private-use SVCB keys)
  - Any RFC 2136 compliant DNS server (BIND, Windows DNS, PowerDNS, etc.)
- A domain with a hosted zone in your DNS provider

## Installation

### Option 1: Install from source (recommended for testing)

```bash
# Clone the repository
git clone https://github.com/dns-aid/dns-aid-core.git
cd dns-aid-core

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install with all dependencies
pip install -e ".[all]"
```

### Option 2: Install specific components

```bash
pip install -e "."              # Core library only
pip install -e ".[cli]"         # Core + CLI
pip install -e ".[mcp]"         # Core + MCP server
pip install -e ".[route53]"     # Core + Route 53 backend
pip install -e ".[cloud-dns]"   # Core + Google Cloud DNS backend
pip install -e ".[cloudflare]"  # Core + Cloudflare backend
pip install -e ".[ns1]"         # Core + NS1 (IBM) backend
pip install -e ".[infoblox]"    # Core + Infoblox BloxOne backend
pip install -e ".[nios]"        # Core + Infoblox NIOS (on-prem) backend
pip install -e ".[ddns]"        # Core + RFC 2136 Dynamic DNS backend
pip install -e ".[cel]"         # Core + CEL custom policy rules
```

## Configuration

### Automated setup (recommended)

The easiest way to get started is the interactive setup wizard:

```bash
dns-aid init
```

The wizard will:
1. Ask which backend you want to use (or discover-only mode)
2. Show required and optional environment variables
3. Generate a `.env` snippet you can paste into your configuration
4. Offer to verify the setup with `dns-aid doctor`

### Manual setup

DNS-AID reads configuration from environment variables. The easiest way to manage these is with a `.env` file — the CLI, MCP server, and example scripts all load it automatically on startup.

```bash
# Copy the template (every variable is documented and commented out)
cp .env.example .env
```

Then open `.env` and uncomment the variables you need:

1. **General** — pick your backend and set the domain
2. **Backend section** — uncomment the section matching your backend (Route 53, Cloudflare, Infoblox, NIOS, or DDNS)
3. **Optional** — log level, SDK telemetry, etc.

For example, to use Cloudflare:

```bash
# ─── General ─────────────────────────────────────────────
DNS_AID_BACKEND=cloudflare
DNS_AID_LOG_LEVEL=DEBUG             # See what's happening in real-time
DNS_AID_TEST_ZONE=yourdomain.com

# ─── Cloudflare ─────────────────────────────────────────
CLOUDFLARE_API_TOKEN=your-api-token
```

> **Note:** Environment variables set via `export` take precedence over `.env` values, so existing workflows are unaffected.

See [`.env.example`](../.env.example) for the full list of supported variables.

## Docker Playground (Zero-Credential Setup)

No cloud account needed! The repo includes a self-contained BIND9 DNS server for local testing.
This is the fastest way to evaluate DNS-AID — publish and discover agents in under 2 minutes.

### 1. Start the local DNS server

```bash
docker compose -f tests/integration/bind/docker-compose.yml up -d
```

### 2. Configure environment

```bash
cp .env.example .env
```

Then uncomment the **Docker Playground** section at the bottom of `.env`:

```bash
DDNS_SERVER=127.0.0.1
DDNS_PORT=15353
DDNS_KEY_NAME=dns-aid-key
DDNS_KEY_SECRET=c2VjcmV0a2V5Zm9yZG5zYWlkdGVzdGluZzEyMzQ1Ng==
DDNS_KEY_ALGORITHM=hmac-sha256
DNS_AID_TEST_ZONE=test.dns-aid.local
```

### 3. Publish and discover

```bash
# Publish a test agent
dns-aid publish my-agent --domain test.dns-aid.local --backend ddns

# Discover it
dns-aid discover test.dns-aid.local --backend ddns
```

### 4. Clean up

```bash
docker compose -f tests/integration/bind/docker-compose.yml down
```

## Verify Your Environment

Run the built-in diagnostics to check that everything is configured correctly:

```bash
dns-aid doctor
dns-aid doctor --domain example.com    # also test agent discovery for your domain
```

This checks Python version, core dependencies, DNS resolution, backend credentials, optional features (MCP, JWS, OpenTelemetry), and `.env` configuration. Use `--domain` (or `DNS_AID_DOCTOR_DOMAIN` env var) to test agent discovery against your domain. Each check shows ✓ (pass), ✗ (fail), or ○ (warning/optional).

## Quick Test (No AWS needed)

Test with the mock backend:

```bash
# Run unit tests
pytest tests/unit/ -v

# Test CLI help
dns-aid --help

# Test MCP server help
dns-aid-mcp --help
```

## AWS Route 53 Setup

### 1. Configure AWS Credentials

Route 53 uses boto3's credential chain. Pick any method (in priority order):

| Priority | Method | Best for |
|----------|--------|----------|
| 1 | `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` env vars | CI/CD, containers |
| 2 | `~/.aws/credentials` (`aws configure`) | Local development |
| 3 | `AWS_PROFILE=name` (named profile) | Multiple AWS accounts |
| 4 | SSO (`aws sso login --profile name`) | Enterprise SSO |
| 5 | IAM role (EC2/ECS/Lambda) | Cloud workloads |

**Easiest setup:**
```bash
aws configure
# Enter: Access Key ID, Secret Access Key, Region, Output format
```

**Or with environment variables:**
```bash
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="us-east-1"
```

DNS-AID auto-detects Route 53 when any credential source is configured — no `--backend` flag needed.

### 2. Verify Zone Access

```bash
dns-aid zones
```

Expected output:
```
Available DNS zones (route53):

┌─────────────────────────────┬────────────────┬─────────┬────────┐
│ Domain                      │ Zone ID        │ Records │ Type   │
├─────────────────────────────┼────────────────┼─────────┼────────┤
│ yourdomain.com              │ Z1234567890ABC │ 5       │ Public │
└─────────────────────────────┴────────────────┴─────────┴────────┘
```

### 3. Set Test Zone

```bash
export DNS_AID_TEST_ZONE="yourdomain.com"
```

## Infoblox UDDI Setup

Infoblox UDDI is Infoblox's cloud-native DDI platform. Follow these steps to configure DNS-AID with Infoblox UDDI.

### 1. Get Your API Key

1. Log in to [Infoblox Cloud Portal](https://csp.infoblox.com)
2. Navigate to **Administration** → **API Keys**
3. Click **Create API Key**
4. Select appropriate permissions (DNS read/write)
5. Copy the API key (it's only shown once!)

### 2. Configure Environment Variables

```bash
# Required: Your Infoblox UDDI API key
export INFOBLOX_API_KEY="your-api-key-here"

# Optional: DNS view name (default: "default")
export INFOBLOX_DNS_VIEW="default"

# Optional: Custom API URL (rarely needed)
# export INFOBLOX_BASE_URL="https://csp.infoblox.com"
```

### 3. Identify Your Zone and View

In the Infoblox Portal:
1. Go to **DNS** → **Authoritative Zones**
2. Find your zone (e.g., `example.com`)
3. Note which **DNS View** it belongs to (visible in the zone details)

> **Important**: Zones exist within DNS Views. If your zone is in a view other than
> "default", you must set `INFOBLOX_DNS_VIEW` to match.

### 4. Set Test Zone

```bash
export INFOBLOX_TEST_ZONE="your-zone.com"
```

### 5. Verify Connection (Python)

```python
import asyncio
from dns_aid.backends.infoblox import InfobloxBloxOneBackend

async def verify_connection():
    backend = InfobloxBloxOneBackend()

    # List zones to verify API access
    zones = await backend.list_zones()
    print(f"Found {len(zones)} zones:")
    for zone in zones[:5]:  # Show first 5
        print(f"  - {zone['name']}")

    # Check if your test zone exists
    exists = await backend.zone_exists("your-zone.com")
    print(f"\nTest zone exists: {exists}")

    await backend.close()

asyncio.run(verify_connection())
```

### Infoblox UDDI Limitations & DNS-AID Compliance

> **⚠️ Important**: Infoblox UDDI is **not fully compliant** with the
> [DNS-AID draft](https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-dnsaid-02/).
>
> Infoblox UDDI SVCB only supports "alias mode" (priority 0) and lacks support for required
> SVC parameters (`alpn`, `port`, `mandatory`). The DNS-AID draft requires ServiceMode
> SVCB records (priority > 0) with these parameters.
>
> **For full compliance, use Route 53 or another RFC 9460-compliant provider.**
>
> DNS-AID stores `alpn` and `port` in TXT records as a fallback, but this is a
> workaround, not a standard-compliant solution.

### Verifying Records

Since Infoblox UDDI zones may be private (not publicly resolvable), verify records via API instead of `dig`:

```python
async with InfobloxBloxOneBackend() as backend:
    async for record in backend.list_records("your-zone.com"):
        if "_agents" in record["fqdn"]:
            print(f"{record['type']}: {record['fqdn']}")
```

## Infoblox NIOS Setup (On-Prem)

Infoblox NIOS is the on-premise DDI platform with WAPI (Web API). DNS-AID creates SVCB and TXT records via WAPI v2.13.7+, with full ServiceMode SVCB support including custom DNS-AID parameters.

### 1. Configure Environment Variables

```bash
# Required: Grid Manager hostname and credentials
export NIOS_HOST="nios.example.com"
export NIOS_USERNAME="admin"
export NIOS_PASSWORD="your-password"

# Optional: DNS view and WAPI settings
export NIOS_DNS_VIEW="default"         # Or your specific view name
export NIOS_WAPI_VERSION="2.13.7"      # Default
export NIOS_VERIFY_SSL="false"         # Set to true with valid TLS certs
```

### 2. Verify Connection

```bash
# Check NIOS credentials and connectivity
dns-aid doctor --domain example.com
```

### 3. Set Test Zone

```bash
export DNS_AID_TEST_ZONE="your-zone.com"
```

### 4. Verify Connection (Python)

```python
import asyncio
from dns_aid.backends.infoblox import InfobloxNIOSBackend

async def verify_connection():
    backend = InfobloxNIOSBackend()

    # Check if your test zone exists
    exists = await backend.zone_exists("your-zone.com")
    print(f"Test zone exists: {exists}")

    # List records
    async for record in backend.list_records("your-zone.com"):
        if "_agents" in record["fqdn"]:
            print(f"  {record['type']}: {record['fqdn']}")

asyncio.run(verify_connection())
```

### 5. Quick CLI Test

```bash
# Publish a test agent
dns-aid publish \
    --name test-agent \
    --domain $DNS_AID_TEST_ZONE \
    --protocol mcp \
    --endpoint mcp.$DNS_AID_TEST_ZONE \
    --backend nios

# Verify it was created
dns-aid list $DNS_AID_TEST_ZONE --backend nios

# Clean up
dns-aid delete \
    --name test-agent \
    --domain $DNS_AID_TEST_ZONE \
    --protocol mcp \
    --backend nios \
    --force
```

### NIOS DNS-AID Compliance

NIOS WAPI supports ServiceMode SVCB records (priority > 0) with full SVC parameters, including custom DNS-AID keys natively via `key65400`–`key65405`. This makes it fully compliant with the DNS-AID draft.

## DDNS Setup (RFC 2136)

DDNS (Dynamic DNS) works with any DNS server supporting RFC 2136, including BIND9, Windows DNS, PowerDNS, and Knot DNS. This is ideal for on-premise infrastructure without vendor-specific APIs.

### 1. Create a TSIG Key

On your DNS server (BIND9 example):

```bash
# Generate a TSIG key
tsig-keygen -a hmac-sha256 dns-aid-key > /etc/bind/dns-aid-key.conf
```

This creates a key file like:
```
key "dns-aid-key" {
    algorithm hmac-sha256;
    secret "YourBase64SecretHere==";
};
```

### 2. Configure Your DNS Zone

Add the key to your zone configuration:

```
include "/etc/bind/dns-aid-key.conf";

zone "example.com" {
    type master;
    file "/var/lib/bind/example.com.zone";
    allow-update { key "dns-aid-key"; };
};
```

### 3. Configure Environment Variables

```bash
# Required
export DDNS_SERVER="ns1.example.com"
export DDNS_KEY_NAME="dns-aid-key"
export DDNS_KEY_SECRET="YourBase64SecretHere=="

# Optional
export DDNS_KEY_ALGORITHM="hmac-sha256"  # default
export DDNS_PORT="53"                     # default
```

### 4. Set Test Zone

```bash
export DNS_AID_TEST_ZONE="example.com"
```

### 5. Verify Connection (Python)

```python
import asyncio
from dns_aid.backends.ddns import DDNSBackend

async def verify_connection():
    backend = DDNSBackend()

    # Check if zone exists
    exists = await backend.zone_exists("example.com")
    print(f"Zone exists: {exists}")

asyncio.run(verify_connection())
```

### DDNS Advantages

- **Universal**: Works with BIND, Windows DNS, PowerDNS, Knot, and any RFC 2136 server
- **Full DNS-AID compliance**: Supports ServiceMode SVCB with all parameters
- **No vendor lock-in**: Standard protocol, no proprietary APIs
- **On-premise friendly**: Perfect for enterprise internal DNS

### DDNS Troubleshooting

#### "TSIG key not configured" error
- Ensure `DDNS_KEY_NAME` and `DDNS_KEY_SECRET` are set
- Check the key secret is base64 encoded

#### "DDNS update failed: NOTAUTH"
- The zone doesn't permit updates with your key
- Check `allow-update` in your zone configuration

#### "DDNS update failed: REFUSED"
- DNS server refused the update
- Verify TSIG key name and secret match the server configuration

#### Connection timeout
- Check firewall rules allow TCP/UDP port 53 (or your configured port)
- Verify the DNS server is reachable: `dig @ns1.example.com example.com SOA`

## Cloudflare Setup (Recommended for Beginners)

Cloudflare is the easiest way to get started with DNS-AID thanks to its free tier and simple API. Perfect for demos, workshops, and quick prototyping.

### 1. Add Your Domain to Cloudflare

If you don't already have a domain on Cloudflare:

1. Log into [Cloudflare Dashboard](https://dash.cloudflare.com)
2. Click **"Add a Site"**
3. Enter your domain name
4. Select **Free plan**
5. Cloudflare will scan your existing DNS records
6. Update your domain's nameservers to the ones Cloudflare provides

### 2. Create an API Token

1. Go to **My Profile** → **API Tokens** → **Create Token**
2. Use the **"Edit zone DNS"** template, or create custom with:
   - **Permissions**: Zone → DNS → Edit
   - **Zone Resources**: Include → Specific zone → your-domain.com
3. Click **Continue to Summary** → **Create Token**
4. **Copy the token immediately** (shown only once!)

### 3. Configure Environment Variables

```bash
# Required: Your Cloudflare API token
export CLOUDFLARE_API_TOKEN="your-api-token-here"

# Optional: Zone ID (auto-discovered from domain if not set)
# export CLOUDFLARE_ZONE_ID="your-zone-id"
```

### 4. Set Test Zone

```bash
export DNS_AID_TEST_ZONE="your-domain.com"
```

### 5. Verify Connection (Python)

```python
import asyncio
from dns_aid.backends.cloudflare import CloudflareBackend

async def verify_connection():
    backend = CloudflareBackend()

    # List zones to verify API access
    zones = await backend.list_zones()
    print(f"Found {len(zones)} zones:")
    for zone in zones:
        print(f"  - {zone['name']} (Status: {zone['status']})")

    await backend.close()

asyncio.run(verify_connection())
```

### 6. Quick CLI Test

```bash
# Publish a test agent (auto-creates index)
dns-aid publish \
    --name test-agent \
    --domain $DNS_AID_TEST_ZONE \
    --protocol mcp \
    --endpoint mcp.$DNS_AID_TEST_ZONE \
    --backend cloudflare

# Verify it was created
dig test-agent.$DNS_AID_TEST_ZONE TXT +short

# View the agent index
dns-aid index list $DNS_AID_TEST_ZONE --backend cloudflare

# Clean up (auto-removes from index)
dns-aid delete \
    --name test-agent \
    --domain $DNS_AID_TEST_ZONE \
    --protocol mcp \
    --backend cloudflare \
    --force
```

### Cloudflare Advantages

- **Free tier**: DNS hosting is free for unlimited domains
- **Simple setup**: Just an API token, no IAM policies or TSIG keys
- **Full DNS-AID compliance**: Supports ServiceMode SVCB with all parameters
- **Global anycast**: Fast DNS resolution worldwide
- **Great documentation**: Well-documented REST API

### Cloudflare Troubleshooting

#### "API token not configured" error
- Ensure `CLOUDFLARE_API_TOKEN` is set (not `CLOUDFLARE_TOKEN`)
- Check the token value isn't wrapped in extra quotes

#### "400 Bad Request" on API calls
- Verify your API token has DNS edit permissions
- Check the token hasn't expired

#### "No zone found for domain" error
- Ensure the domain is added to your Cloudflare account
- Check the domain status is "Active" in Cloudflare dashboard
- Verify the API token has access to that specific zone

## NS1 (IBM) Setup

NS1 (now IBM NS1 Connect) is an enterprise DNS platform with a REST API. NS1 supports RFC 9460 private-use SVCB keys natively, so DNS-AID custom parameters (cap_uri, policy_uri, realm) go directly into the SVCB record without TXT demotion.

### 1. Get an API Key

1. Log in to the [NS1 portal](https://my.nsone.net)
2. Navigate to **Account Settings → API Keys**
3. Create a new key with **DNS read/write** permissions for your zone
4. Copy the API key

### 2. Configure Credentials

```bash
# Required
export NS1_API_KEY="your-api-key-here"

# Optional — for private/dedicated NS1 deployments
# export NS1_BASE_URL="https://api.nsone.net/v1"
```

### 3. Verify Setup

```bash
dns-aid doctor
# Should show: ✓ NS1 (IBM)  credentials configured

dns-aid zones --backend ns1
# Lists your NS1 zones
```

### 4. Publish Your First Agent

```bash
dns-aid publish \
  --name billing \
  --domain your-zone.example \
  --protocol mcp \
  --endpoint mcp.your-zone.example \
  --capability invoicing \
  --capability payments \
  --backend ns1
```

### 5. Use in Python

```python
from dns_aid.backends.ns1 import NS1Backend

backend = NS1Backend()  # reads NS1_API_KEY from env

# Or with explicit configuration
backend = NS1Backend(
    api_key="your-api-key",
    base_url="https://api.nsone.net/v1",  # default
)
```

### NS1 Advantages

- **Native private-use SVCB keys**: cap_uri, policy_uri, realm go directly into SVCB — single-record agent discovery
- **REST API v1**: well-documented, stable API with PUT/POST upsert semantics
- **Enterprise features**: traffic steering, DNS analytics, DNSSEC
- **IBM backing**: enterprise support, SOC2 compliance

## End-to-End Test

### Step 1: Publish an Agent

```bash
dns-aid publish \
  --name test-agent \
  --domain $DNS_AID_TEST_ZONE \
  --protocol mcp \
  --endpoint mcp.$DNS_AID_TEST_ZONE \
  --capability demo \
  --capability test \
  --ttl 300
```

Expected output:
```
Publishing agent to DNS...

✓ Agent published successfully!

  FQDN: test-agent.yourdomain.com
  Endpoint: https://mcp.yourdomain.com:443

  Records created:
    • SVCB test-agent.yourdomain.com
    • TXT test-agent.yourdomain.com

Verify with:
  dig test-agent.yourdomain.com SVCB
  dig test-agent.yourdomain.com TXT
```

### Step 2: Verify DNS Records

```bash
# Using DNS-AID
dns-aid verify test-agent.$DNS_AID_TEST_ZONE

# Using dig (external verification)
dig test-agent.$DNS_AID_TEST_ZONE SVCB +short
dig test-agent.$DNS_AID_TEST_ZONE TXT +short
```

### Step 3: Discover Agents

```bash
# Discover via DNS (default)
dns-aid discover $DNS_AID_TEST_ZONE

# Or discover via HTTP index (ANS-compatible, richer metadata)
dns-aid discover $DNS_AID_TEST_ZONE --use-http-index
```

Expected output:
```
Discovering agents at yourdomain.com...

Found 1 agent(s) at yourdomain.com:

┌────────────┬──────────┬────────────────────────────────┬─────────────┐
│ Name       │ Protocol │ Endpoint                       │ Capabilities│
├────────────┼──────────┼────────────────────────────────┼─────────────┤
│ test-agent │ mcp      │ https://mcp.yourdomain.com:443 │ demo, test  │
└────────────┴──────────┴────────────────────────────────┴─────────────┘
```

### Step 4: List All Records

```bash
dns-aid list $DNS_AID_TEST_ZONE
```

### Step 5: View Agent Index

The agent index (`_index._agents.{domain}`) provides efficient single-query discovery:

```bash
# List agents in the index
dns-aid index list $DNS_AID_TEST_ZONE
```

Expected output:
```
Agent index for yourdomain.com:

┌────────────┬──────────┬─────────────────────────────────────────────┐
│ Name       │ Protocol │ FQDN                                        │
├────────────┼──────────┼─────────────────────────────────────────────┤
│ test-agent │ mcp      │ test-agent.yourdomain.com     │
└────────────┴──────────┴─────────────────────────────────────────────┘

Total: 1 agent(s) in index
```

> **Note:** The index is automatically updated when you publish or delete agents.
> Use `--no-update-index` to skip index updates if needed.

## HTTP Index Discovery (ANS-Compatible)

DNS-AID supports HTTP-based agent discovery for compatibility with ANS-style systems. This provides richer metadata (descriptions, model cards, costs) while still validating endpoints via DNS.

### HTTP Index Endpoint

The HTTP index is served at: `https://_index._aiagents.{domain}/index-wellknown`

### Using HTTP Index Discovery

```bash
# CLI with HTTP index
dns-aid discover example.com --use-http-index

# Compare outputs
dns-aid discover example.com --json              # DNS only
dns-aid discover example.com --use-http-index --json  # HTTP index
```

### Python Library

```python
from dns_aid import discover

# Pure DNS discovery (default)
result = await discover("example.com")

# HTTP index discovery (richer metadata)
result = await discover("example.com", use_http_index=True)

for agent in result.agents:
    print(f"{agent.name}: {agent.endpoint_url}")
    if agent.description:
        print(f"  Description: {agent.description}")
```

### When to Use Each Method

| Scenario | Use |
|----------|-----|
| Maximum decentralization | DNS (default) |
| Rich metadata upfront | HTTP index |
| Offline/cached discovery | DNS |
| ANS compatibility | HTTP index |
| Minimal network round trips | DNS |

### Step 6: Clean Up

```bash
dns-aid delete --name test-agent --domain $DNS_AID_TEST_ZONE --protocol mcp --force
```

> The delete command automatically removes the agent from the index.

## Agent Index Management

DNS-AID provides automatic index management. The `_index._agents.{domain}` TXT record lists all agents at a domain, enabling efficient single-query discovery.

### Automatic Index Updates

By default, `publish` and `delete` commands automatically update the index:

```bash
# First agent - index created automatically
dns-aid publish --name chat --domain example.com --protocol mcp --endpoint chat.example.com
# ✓ Created index at _index._agents.example.com (1 agent)

# Second agent - index updated automatically
dns-aid publish --name billing --domain example.com --protocol a2a --endpoint billing.example.com
# ✓ Updated index at _index._agents.example.com (2 agents)

# Delete agent - removed from index automatically
dns-aid delete --name chat --domain example.com --protocol mcp --force
# ✓ Updated index at _index._agents.example.com (1 agent)
```

### Skip Index Updates

For internal or test agents that shouldn't be indexed:

```bash
dns-aid publish --name internal-bot --domain example.com --protocol mcp \
  --endpoint internal.example.com --no-update-index
```

### Index Commands

```bash
# List agents in the index
dns-aid index list example.com

# Sync index with actual DNS records (discover and rebuild)
dns-aid index sync example.com
```

### Index Format

The index is stored as a TXT record:
```
_index._agents.example.com. TXT "agents=chat:mcp,billing:a2a,support:https"
```

## Using the Python Library

```python
import asyncio
from dns_aid import publish, discover, verify

async def main():
    # Publish an agent
    result = await publish(
        name="my-agent",
        domain="yourdomain.com",
        protocol="mcp",
        endpoint="mcp.yourdomain.com",
        capabilities=["chat", "code-review"],
    )
    print(f"Published: {result.agent.fqdn}")

    # Discover agents
    discovery = await discover("yourdomain.com")
    for agent in discovery.agents:
        print(f"Found: {agent.name} at {agent.endpoint_url}")

    # Verify an agent
    verification = await verify("my-agent.yourdomain.com")
    print(f"Security Score: {verification.security_score}/100")

asyncio.run(main())
```


## Policy Enforcement via Threat Defense

DNS-AID can compile policy documents into Infoblox Threat Defense named lists,
enforcing agent access control at the DNS layer.

### Step 1: Write a Policy Document

```json
{
  "version": "1.0",
  "agent": "inventory.example.com",
  "rules": {
    "allowed_caller_domains": ["ai-platform.example.com"],
    "blocked_caller_domains": ["*.sandbox.example.com"],
    "cel_rules": [
      {
        "id": "block-shadow",
        "expression": "!request.caller_domain.endsWith(\".shadow.example.com\")",
        "effect": "deny",
        "enforcement_layers": ["layer0", "layer1"]
      }
    ]
  }
}
```

### Step 2: Shadow Mode (Safe Dry Run)

```bash
dns-aid enforce -d example.com -p policy.json --mode shadow
```

This shows what WOULD be blocked without making any changes.

### Step 3: Monitor Mode (Log Without Blocking)

```bash
dns-aid enforce -d example.com -p policy.json \
  --mode enforce -b infoblox --td-action action_log
```

This pushes a named list to Infoblox TD and binds it with `action_log` —
matching queries are logged but not blocked. Check TD dashboards to see matches.

### Step 4: Enforce (Block Unauthorized Callers)

```bash
dns-aid enforce -d example.com -p policy.json \
  --mode enforce -b infoblox --td-action action_block
```

Blocked domains now receive NXDOMAIN from Threat Defense.

### How CEL Rules Work

CEL expressions that match domain patterns compile to DNS zone entries:
- `!request.caller_domain.endsWith(".shadow.example.com")` → TD named list entry `*.shadow.example.com` → NXDOMAIN

Complex CEL (trust scores, tool restrictions) can't be expressed in DNS and is
enforced at runtime by the Rust CEL evaluator (~2µs per rule) in the caller SDK.

## JWS Signatures

JWS (JSON Web Signature) provides application-layer verification when DNSSEC isn't available (~70% of domains). Signatures are embedded in SVCB records and verified against a JWKS published at `.well-known/dns-aid-jwks.json`.

### Generate Keys

```bash
# Generate EC P-256 keypair
dns-aid keys generate --output ./keys/

# Export public keys as JWKS (host at .well-known/)
dns-aid keys export-jwks --output .well-known/dns-aid-jwks.json
```

### Publish with Signature

```bash
# Sign record with private key
dns-aid publish \
    --name payment \
    --domain example.com \
    --protocol mcp \
    --endpoint mcp.example.com \
    --sign \
    --private-key ./keys/private.pem
```

The SVCB record will include a `sig=` parameter with the JWS.

### Verify on Discovery

```bash
# Verify signature against JWKS
dns-aid discover example.com --verify-signature
```

### Python SDK

```python
from dns_aid.core.jws import generate_keypair, sign_record, verify_signature

# Generate keypair
private_key, public_key = generate_keypair()

# Sign a record
signature = sign_record(
    private_key=private_key,
    fqdn="payment.example.com",
    target="mcp.example.com",
    port=443,
)

# Verify (fetches JWKS from .well-known/dns-aid-jwks.json)
is_valid = await verify_signature(
    domain="example.com",
    signature=signature,
    fqdn="payment.example.com",
    target="mcp.example.com",
    port=443,
)
```

### Verification Priority

```
1. DNSSEC available and valid? → Trust (strongest)
2. No DNSSEC but JWS sig valid? → Trust (application-layer)
3. Neither? → Warn but allow (strict mode rejects)
```

---

## Invoking Agents (High-Level API)

The `core.invoke` module is the simplest way to call discovered agents. It handles DNS resolution, agent card prefetch, protocol handling, and telemetry in a single call.

### A2A Messaging

```python
import asyncio
from dns_aid.core.invoke import send_a2a_message

async def main():
    # Discover-first: DNS lookup → agent card fetch → invoke
    result = await send_a2a_message(
        domain="ai.infoblox.com",
        name="security-analyzer",
        message="Analyze security of marketing.ai.infoblox.com",
        timeout=60.0,
    )
    if result.success:
        print(result.data["response_text"])
        print(f"Resolved via: {result.data['agent_info']['resolved_via']}")
    else:
        print(f"Error: {result.error}")

asyncio.run(main())
```

The discover-first flow:
1. Queries DNS for `security-analyzer.ai.infoblox.com` SVCB record
2. Fetches `/.well-known/agent-card.json` for canonical URL and metadata
3. Validates card URL hostname matches DNS endpoint (prevents internal URL leakage)
4. Sends the A2A JSON-RPC 2.0 `message/send` request

### MCP Tool Calling

DNS-AID's MCP client speaks the modern Streamable HTTP transport (spec
revision 2025-03-26 and later) by default, so it works against AWS Bedrock
AgentCore, Anthropic MCP Connector Directory listings, agentgateway-fronted
servers, and any other modern MCP target. On-premise or older servers that
only speak the legacy plain JSON-RPC POST transport are reached via a
transparent fallback — no caller-side configuration required.

If your target enforces Layer 2 caller-identity policy, set
`DNS_AID_CALLER_DOMAIN` so the SDK propagates `X-DNS-AID-Caller-Domain` on
every request. The header is omitted entirely when the env var is unset.

```python
import os
from dns_aid.core.invoke import call_mcp_tool, list_mcp_tools

# Optional: identify the caller for Layer 2 policy enforcement
os.environ["DNS_AID_CALLER_DOMAIN"] = "your-org.example.com"

# List available tools on an MCP agent (modern transport, auto-fallback to legacy)
tools_result = await list_mcp_tools("https://mcp.example.com/mcp")
for tool in tools_result.data:
    print(f"  {tool['name']}: {tool.get('description', '')}")

# Call a specific tool — credentials passed via the credentials kwarg
result = await call_mcp_tool(
    "https://mcp.example.com/mcp",
    "search_flights",
    {"origin": "SFO", "destination": "JFK"},
    credentials={"bearer_token": "your-bearer-token"},
)
print(result.data)         # Tool result
print(result.telemetry)    # latency_ms, status, etc.
```

### Endpoint Resolution

You can also resolve endpoints separately:

```python
from dns_aid.core.invoke import resolve_a2a_endpoint

resolved = await resolve_a2a_endpoint(domain="ai.infoblox.com", name="security-analyzer")
print(f"Endpoint: {resolved.endpoint}")
print(f"Agent: {resolved.agent_name}")
print(f"Skills: {resolved.skills}")
print(f"Resolved via: {resolved.resolved_via}")
```

---

## SDK: Agent Invocation & Telemetry

The Tier 1 SDK adds low-level invocation with telemetry capture, agent ranking, and optional OpenTelemetry export. For most use cases, the [high-level API](#invoking-agents-high-level-api) above is simpler.

### Quick Invocation

```python
import asyncio
import dns_aid

async def main():
    # Discover agents
    result = await dns_aid.discover("example.com", protocol="mcp")
    agent = result.agents[0]

    # Invoke and capture telemetry
    resp = await dns_aid.invoke(agent, method="tools/list")
    print(f"Success: {resp.success}")
    print(f"Latency: {resp.signal.invocation_latency_ms:.0f}ms")
    print(f"Data:    {resp.data}")

asyncio.run(main())
```

### Authenticated Invocation (v0.13.2+)

The SDK automatically resolves authentication from agent metadata.
Agents publish their auth requirements in `/.well-known/agent-card.json`
(primary) or `/.well-known/agent.json` (fallback). You just supply
credentials — the SDK picks the right handler.

**Bearer token** (most common — Claude MCP, OpenAI, SaaS APIs):

```python
agents = await dns_aid.discover("example.com", protocol="mcp")
agent = agents[0]  # agent.auth_type auto-populated from agent-card.json

async with AgentClient() as client:
    result = await client.invoke(
        agent,
        method="tools/list",
        credentials={"token": "my-bearer-token"},
    )
```

**OAuth2 client-credentials** (Okta, Auth0, AWS Cognito, Azure AD):

```python
async with AgentClient() as client:
    result = await client.invoke(
        agent,
        method="message/send",
        arguments={"message": {"role": "user", "parts": [{"text": "Hello"}]}},
        credentials={
            "client_id": "my-app-id",
            "client_secret": "my-app-secret",
        },
        # SDK auto-discovers token endpoint via OIDC, fetches + caches token
    )
```

**API key** (header or query parameter):

```python
async with AgentClient() as client:
    result = await client.invoke(
        agent,
        method="tools/call",
        arguments={"name": "search", "arguments": {"query": "DNS"}},
        credentials={"api_key": "sk-live-abc123"},
    )
```

**AWS SigV4** (VPC Lattice, API Gateway with IAM auth):

```python
async with AgentClient() as client:
    result = await client.invoke(
        agent,  # agent.auth_type="sigv4", auth_config={"region":"us-east-1"}
        method="message/send",
        arguments={"message": {"role": "user", "parts": [{"text": "hello"}]}},
        credentials={"profile_name": "okta-sso"},  # uses boto3 chain
    )
```

**HTTP Message Signatures** (RFC 9421, Ed25519 or ML-DSA-65 post-quantum):

```python
async with AgentClient() as client:
    result = await client.invoke(
        agent,
        method="message/send",
        arguments={"message": {"role": "user", "parts": [{"text": "signed"}]}},
        credentials={
            "private_key_pem": open("my-key.pem").read(),
            "key_id": "my-key-id",
            "algorithm": "ed25519",  # or "ml-dsa-65" for post-quantum
        },
    )
```

**Explicit handler override** (bypass auto-resolution):

```python
from dns_aid.sdk.auth.simple import BearerAuthHandler

handler = BearerAuthHandler(token="my-static-token")

async with AgentClient() as client:
    result = await client.invoke(
        agent,
        method="tools/list",
        auth_handler=handler,  # ignores agent metadata, uses this directly
    )
```

**Multi-agent with different auth** (real-world pattern):

```python
agents = await dns_aid.discover("enterprise.com")

credentials_map = {
    "billing":  {"token": "billing-bearer-token"},
    "crm":      {"client_id": "crm-id", "client_secret": "crm-secret"},
    "internal": {"profile_name": "aws-prod"},  # SigV4
}

async with AgentClient() as client:
    for agent in agents:
        result = await client.invoke(
            agent,
            method="tools/list",
            credentials=credentials_map.get(agent.name),  # right handler per agent
        )
        print(f"{agent.name}: {result.success} ({agent.auth_type})")
```

**No auth** (public agents — default, no credentials needed):

```python
async with AgentClient() as client:
    result = await client.invoke(agent, method="tools/list")
    # No credentials → request sent bare
```

**Auth type coverage:**

| `auth_type` | Credential keys | What it does |
|---|---|---|
| `none` | — | No auth (default) |
| `api_key` | `api_key` | Injects key in header or query param |
| `bearer` | `token` | `Authorization: Bearer <token>` |
| `oauth2` | `client_id`, `client_secret` | Client-credentials flow with token caching |
| `sigv4` | `region` (+ boto3 chain) | AWS SigV4 for VPC Lattice / API Gateway |
| `http_msg_sig` | `private_key_pem`, `key_id`, `algorithm` | RFC 9421 (Ed25519 + ML-DSA-65) |

### Rank Multiple Agents

```python
import dns_aid

result = await dns_aid.discover("example.com", protocol="mcp")
ranked = await dns_aid.rank(result.agents, method="tools/list")

for r in ranked:
    print(f"{r.agent_fqdn}: score={r.composite_score:.1f}")
```

### Path A: Filtered single-domain discovery (v0.19.0+)

`discover()` now accepts in-memory filter kwargs that operate on the post-enrichment
agent list. Useful when you already know the target domain but only want a subset:

```python
from dns_aid import discover

# All-of capability match + auth type + realm
result = await discover(
    "example.com",
    capabilities=["payment-processing", "fraud-detection"],
    auth_type="oauth2",
    realm="prod",
)

# Trust-gated: only signed agents with allow-listed algorithms
result = await discover(
    "example.com",
    require_signed=True,
    require_signature_algorithm=["ES256", "Ed25519"],
)

# Substring search across description / use_cases / capabilities
result = await discover("example.com", text_match="payment")
```

The same filters are exposed on the CLI:

```bash
dns-aid discover example.com \
    --capabilities payment-processing --capabilities fraud-detection \
    --auth-type oauth2 --realm prod --json

dns-aid discover example.com \
    --require-signed \
    --require-signature-algorithm ES256 \
    --require-signature-algorithm Ed25519
```

### Path B: Cross-domain search via the directory (v0.19.0+)

`AgentClient.search()` is opt-in: configure a directory backend, then query across
every domain it has indexed.

```bash
# Configure the directory once via env var
export DNS_AID_SDK_DIRECTORY_API_URL=https://api.example.com
```

```python
from dns_aid.sdk import AgentClient, SDKConfig

async with AgentClient(config=SDKConfig.from_env()) as client:
    response = await client.search(
        q="payment processing",
        protocol="mcp",
        capabilities=["payment-processing"],
        min_security_score=70,
        verified_only=True,
        limit=10,
    )

    for r in response.results:
        print(f"{r.score:.2f}  {r.agent.fqdn}  T{r.trust.trust_tier}/{r.trust.trust_score}")

    # Walk subsequent pages
    while response.has_more:
        response = await client.search(q="payment", offset=response.next_offset)
```

CLI:

```bash
dns-aid search "payment processing" --protocol mcp \
    --capabilities payment-processing --min-security-score 70 --verified-only --json
```

#### Zero-trust composition

Path B candidates → Path A re-verification before invoking:

```python
from dns_aid.sdk import AgentClient
from dns_aid.core.discoverer import discover

async with AgentClient() as client:
    response = await client.search(q="fraud detection", min_security_score=70)

    for candidate in response.results:
        verified = await discover(
            candidate.agent.domain,
            name=candidate.agent.name,
            require_signed=True,
        )
        if verified.agents:
            agent = verified.agents[0]
            # Safe to invoke — DNS substrate confirms the directory's claim.
            ...
```

### Advanced: Connection Reuse & DB Persistence

```python
from dns_aid.sdk import AgentClient, SDKConfig

config = SDKConfig(
    persist_signals=True,      # Store signals in PostgreSQL
    otel_enabled=True,         # Export to OpenTelemetry (v0.23.0+)
    otel_endpoint="http://localhost:4317",  # http:// plaintext, https:// TLS
    caller_id="my-app",
)

async with AgentClient(config=config) as client:
    # Reuse HTTP connection across calls
    for agent in agents:
        await client.invoke(agent, method="tools/list")

    # Rank all invoked agents
    ranked = client.rank()
```

**OpenTelemetry (v0.23.0+).** With `otel_enabled=True` the SDK emits a span
per invoke, propagates W3C trace context (`traceparent`) to downstream
agents, records metrics, and correlates structlog events with the active
span. Configure via these env vars (no code change):

```bash
export DNS_AID_SDK_OTEL_ENABLED=true
export DNS_AID_SDK_OTEL_ENDPOINT=http://collector:4317   # http:// plaintext, https:// TLS
export DNS_AID_SDK_OTEL_SAMPLER=traceidratio             # optional sampler
export DNS_AID_SDK_OTEL_ENVIRONMENT=production           # deployment.environment
export DNS_AID_SDK_OTEL_METRIC_LABELS=fqdn,caller        # opt-in metric labels
# Standard OTEL_* env vars also honored: OTEL_TRACES_SAMPLER,
# OTEL_RESOURCE_ATTRIBUTES, OTEL_EXPORTER_OTLP_HEADERS, OTEL_PROPAGATORS.
```

Requires the `otel` extra: `pip install 'dns-aid[otel]'`. Full guide
(sampling, propagation, managed-collector auth, runnable Jaeger example):
[docs/integrations/opentelemetry.md](integrations/opentelemetry.md).

### Telemetry API

When the API server is running, telemetry data is available at:

```bash
# Global stats
curl http://localhost:8000/api/v1/telemetry/stats

# Agent rankings
curl http://localhost:8000/api/v1/telemetry/rankings

# Signal history
curl http://localhost:8000/api/v1/telemetry/signals?limit=10

# Per-agent scorecard
curl http://localhost:8000/api/v1/telemetry/agents/{fqdn}/scorecard
```

To enable HTTP telemetry push to a custom collection endpoint:

```python
config = SDKConfig(
    http_push_url="https://your-telemetry-server.example.com/signals"
)
```

Or via environment variable:
```bash
export DNS_AID_SDK_HTTP_PUSH_URL="https://your-telemetry-server.example.com/signals"
```

## Using the MCP Server

### Start the Server

```bash
# Stdio transport (for Claude Desktop)
dns-aid-mcp

# HTTP transport (for remote access)
dns-aid-mcp --transport http --port 8000
```

### Test Health Endpoints (HTTP mode)

```bash
# Start server in background
dns-aid-mcp --transport http --port 8000 &

# Test endpoints
curl http://localhost:8000/health
curl http://localhost:8000/ready
curl http://localhost:8000/
```

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

Restart Claude Desktop, then ask:
- "Discover agents at example.com"
- "Publish my agent to DNS"
- "Send a message to the security-analyzer agent at ai.infoblox.com" *(uses discover-first flow)*
- "What tools does the booking agent at example.com have?"

### MCP Agent Proxying

The MCP server can now proxy tool calls to discovered agents:

```
You: "What tools does the booking agent at example.com have?"
Claude: [uses list_agent_tools] "The booking-agent has 3 tools: search_flights,
        book_flight, and get_booking_status..."

You: "Search for flights from NYC to London on March 15"
Claude: [uses call_agent_tool] "I found 5 flights: AA100 departing 8am,
        BA178 departing 10am..."
```

Available MCP tools for agent proxying:
- `list_agent_tools`: List available tools from a discovered agent
- `call_agent_tool`: Call a specific tool on a discovered agent

### Discovery Transparency

Each discovered agent includes transparency fields showing how data was resolved:

| Field | Value | Meaning |
|-------|-------|---------|
| `endpoint_source` | `dns_svcb` | Endpoint resolved via DNS SVCB lookup (proper DNS-AID flow) |
| | `http_index_fallback` | DNS lookup failed, using HTTP index data only |
| | `direct` | Endpoint was explicitly provided |
| `capability_source` | `cap_uri` | Capabilities fetched from SVCB `cap` URI document |
| | `agent_card` | Capabilities from A2A Agent Card skills (`.well-known/agent-card.json`) |
| | `http_index` | Capabilities from HTTP index response |
| | `txt_fallback` | Capabilities from DNS TXT record |
| | `none` | No capabilities found |

Agent name and protocol are extracted from the FQDN in the HTTP index — no separate `protocols` field needed. The FQDN is the single source of truth.

Capabilities are resolved with priority: SVCB `cap` URI → A2A Agent Card skills → HTTP Index → TXT record fallback. When the cap URI points to an A2A Agent Card, the document is parsed once and reused — no redundant HTTP fetch for `.well-known/agent-card.json`.

### DNS-AID Custom SVCB Parameters

Per the IETF draft, SVCB records can carry custom parameters for richer agent metadata:

```bash
# Publish with DNS-AID custom SVCB parameters
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
```

| Parameter | CLI Flag | Description |
|-----------|----------|-------------|
| `cap` | `--cap-uri` | URI to capability document (rich JSON metadata) |
| `cap-sha256` | `--cap-sha256` | SHA-256 digest for integrity verification |
| `bap` | `--bap` | Supported protocols with versions (comma-separated) |
| `policy` | `--policy-uri` | URI to agent policy document |
| `realm` | `--realm` | Multi-tenant scope identifier |
| `ipv4hint` | `--ipv4hint` | IPv4 address hint (RFC 9460 SvcParamKey 4) |
| `ipv6hint` | `--ipv6hint` | IPv6 address hint (RFC 9460 SvcParamKey 6) |

**Discovery priority:** When discovering agents, DNS-AID resolves capabilities with the following chain: SVCB `cap` URI → A2A Agent Card (`.well-known/agent-card.json`) skills → HTTP Index → TXT record fallback. The `capability_source` field shows the source: `cap_uri`, `agent_card`, `http_index`, or `txt_fallback`.

### Live Demo with Claude Desktop

Try it now with our live demo agent:

```
You: "Discover agents at example.com"
Claude: [uses discover_agents_via_dns] "Found 1 agent: booking-agent (MCP protocol)
        at https://booking.example.com/mcp"

You: "What tools does the booking agent have?"
Claude: [uses list_agent_tools] "The booking-agent has these tools: ..."
```

## Running the Full Demo

```bash
# Set your zone
export DNS_AID_TEST_ZONE="yourdomain.com"

# Run interactive demo
python examples/demo_full.py
```

## Troubleshooting

### Route 53 Issues

#### "Zone not found" error
- Verify AWS credentials: `aws sts get-caller-identity`
- Check zone exists: `dns-aid zones`
- Ensure correct region: `export AWS_DEFAULT_REGION=us-east-1`

#### DNS records not appearing
- Wait for propagation (up to 60 seconds for Route 53)
- Check TTL settings
- Verify with `dig` directly

### Infoblox UDDI Issues

#### "No zone found for domain" error
- Verify `INFOBLOX_DNS_VIEW` matches your zone's view
- Check zone name spelling (with or without trailing dot)
- Ensure API key has DNS permissions

#### "401 Unauthorized" error
- Regenerate your API key in the Cloud Portal
- Ensure the key hasn't expired
- Check `INFOBLOX_API_KEY` is set correctly

#### "400 Bad Request" on zone lookup
- The DNS view name may be incorrect
- Check available views in the Infoblox Portal under DNS → Views

#### Records created but can't dig them
- Infoblox UDDI zones may be private (not publicly resolvable)
- Verify records via API instead:
  ```python
  async for rec in backend.list_records("zone.com"):
      print(rec)
  ```

### MCP Server Issues

#### MCP server not connecting
- Check if server is running: `ps aux | grep dns-aid-mcp`
- Test health endpoint: `curl http://localhost:8000/health`
- Check Claude Desktop logs

## Environment Variables Reference

### Core Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DNS_AID_BACKEND` | Yes (if no `backend=` arg) | — | DNS backend: `route53`, `cloudflare`, `ns1`, `infoblox`, `nios`, `ddns`, `mock` |
| `DNS_AID_SVCB_STRING_KEYS` | No | `0` | Set `1` to emit human-readable SVCB param names instead of keyNNNNN |
| `DNS_AID_FETCH_ALLOWLIST` | No | — | Comma-separated hostnames to bypass SSRF protection (testing only) |

### SDK Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DNS_AID_HTTP_PUSH_URL` | No | — | Optional endpoint to push telemetry signals |
| `DNS_AID_SDK_DIRECTORY_API_URL` | No | — | Base URL for `AgentClient.search()` and `fetch_rankings()` (Path B) (v0.19.0+) |
| `DNS_AID_SDK_TELEMETRY_API_URL` | No | — | **Deprecated alias** for `DNS_AID_SDK_DIRECTORY_API_URL`. Emits one `DeprecationWarning` per process. |
| `DNS_AID_FETCH_ALLOWLIST` | No | — | Comma-separated hostnames to bypass SSRF DNS-resolution check (testing only) |

### Backend-Specific Variables

| Variable | Backend | Description |
|----------|---------|-------------|
| `AWS_REGION` | route53 | AWS region for Route 53 API calls |
| `INFOBLOX_API_KEY` | infoblox | BloxOne DDI API key |
| `INFOBLOX_DNS_VIEW` | infoblox | DNS view name (default: `default`) |
| `CLOUDFLARE_API_TOKEN` | cloudflare | Cloudflare API token with DNS edit permissions |
| `NIOS_HOST` | nios | Grid Manager hostname or IP |
| `NIOS_USERNAME` | nios | WAPI username |
| `NIOS_PASSWORD` | nios | WAPI password |
| `NIOS_DNS_VIEW` | nios | DNS view name (default: `default`) |
| `NIOS_WAPI_VERSION` | nios | WAPI version (default: `2.13.7`) |
| `NIOS_VERIFY_SSL` | nios | Verify TLS certificate (default: `false`) |

## Experimental Models

The following modules define forward-looking data models for `.well-known/agent-card.json`
enrichment. They are **defined but not yet wired** into `discover()` or `publish()`:

- `dns_aid.core.agent_metadata` — `AgentMetadata` schema (identity, connection, auth, capabilities, contact)
- `dns_aid.core.capability_model` — `CapabilitySpec` with machine-readable `Action` descriptors (intent, semantics, tags)

These models are available for import and experimentation but are not part of the
stable public API. They will be integrated in a future release once the
`.well-known/agent-card.json` enrichment pipeline is finalized.

## Next Steps

- Read the [API Reference](api-reference.md)
- Explore [examples/](../examples/)
- Review the [IETF draft specification](https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-dnsaid-02/)
