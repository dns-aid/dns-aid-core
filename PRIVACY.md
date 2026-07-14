# DNS-AID Privacy Policy

**Effective Date:** April 14, 2026
**Last Updated:** April 14, 2026

## Overview

DNS-AID is an open source toolkit for DNS-based AI agent discovery. This policy describes how the DNS-AID MCP server and CLI tools handle data.

## What DNS-AID Does

DNS-AID queries and publishes DNS records (SVCB, TXT) to enable AI agents to discover each other. It operates on public DNS infrastructure using standard protocols (RFC 9460, RFC 4033-4035).

## Data Handling Summary

- **No automatic telemetry.** The toolkit sends no usage data to any server by default.
- **No analytics.** No tracking, metrics collection, or behavioral data is gathered.
- **No user accounts.** DNS-AID has no user registration or authentication system.
- **No conversation access.** The MCP server does not read, store, or access chat history, memory, conversation summaries, or uploaded files from the host AI application.

## Data That Flows Through DNS-AID

When you use DNS-AID tools, the following data is processed **locally on your machine**:

| Operation | Data involved | Where it goes |
|-----------|--------------|---------------|
| `discover_agents` | Domain name you query | Public DNS resolvers (your configured DNS server) |
| `verify_agent_dns` | Agent FQDN | Public DNS resolvers + DNSSEC validators |
| `publish_agent_to_dns` | Agent name, endpoint, capabilities | Your configured DNS backend (Route53, Infoblox, Cloudflare, etc.) |
| `delete_agent_from_dns` | Agent name, domain | Your configured DNS backend |
| `compile_policy_to_rpz` | Policy JSON | Local only (no network calls) |
| `diagnose_environment` | System config checks | Local only (no network calls) |
| `list_agent_index` | Domain name | Your configured DNS backend |
| `sync_agent_index` | Domain name | Your configured DNS backend |
| `list_published_agents` | Domain name | Your configured DNS backend |
| `list_rpz_rules` | RPZ zone name | Your configured DNS backend |
| `list_td_security_policies` | None | Your configured Infoblox backend |

## Agent Invocation Tools and Telemetry

Three tools interact with external agent endpoints:

| Operation | Data involved | Where it goes |
|-----------|--------------|---------------|
| `call_agent_tool` | Tool name, arguments | The target agent's MCP endpoint |
| `list_agent_tools` | None | The target agent's MCP endpoint |
| `send_a2a_message` | Message content | The target agent's A2A endpoint |

### In-response telemetry field

When the optional Infoblox DNS-AID SDK is installed (`pip install dns-aid[sdk]`), the responses returned by `call_agent_tool` and `send_a2a_message` include a small `telemetry` field with exactly two values:

| Field | Type | Description |
|-------|------|-------------|
| `latency_ms` | float | Wall-clock duration of the remote agent invocation in milliseconds (rounded to 2 decimals) |
| `status` | string | Outcome enum: `success`, `error`, or `timeout` |

This telemetry is computed locally and returned in-process to the calling host (e.g. Claude Desktop). It is **never** transmitted off the user's machine by the MCP server itself. No tool arguments, no response payloads, no caller identity, and no agent FQDN are included in this field.

### Optional remote telemetry (off by default)

These tools also use the DNS-AID SDK which supports **opt-in remote telemetry**. Remote telemetry is **disabled by default** and is only activated when you explicitly set the `DNS_AID_SDK_HTTP_PUSH_URL` environment variable to a telemetry endpoint URL. When enabled, the SDK sends invocation signals (latency, status, agent FQDN) to the URL you specified via a fire-and-forget HTTP POST. No telemetry data is sent to DNS-AID maintainers or any third party unless you configure it to do so.

Remote telemetry fields sent (when opted in): agent FQDN, endpoint, protocol, method, invocation latency, status (success/error/timeout), HTTP status code, response size, DNSSEC validation result, TLS version, auth type.

Other opt-in remote endpoints (all off by default, all configured via environment variables):

- `DNS_AID_SDK_OTEL_ENDPOINT` — OTLP endpoint for OpenTelemetry export.
- `DNS_AID_SDK_TELEMETRY_API_URL` — base URL queried by `fetch_rankings()` to retrieve community-wide agent rankings.

## Credentials

- DNS backend credentials (AWS keys, Infoblox API keys, Cloudflare tokens) are read from **your local environment variables or `.env` file**.
- Credentials are never logged, cached beyond the current session, or transmitted anywhere other than the DNS backend you configured.
- No credentials are sent to DNS-AID maintainers or any third party.

## DNS Queries

- DNS discovery queries go to **your system's configured DNS resolver** (e.g., your ISP, Google 8.8.8.8, Cloudflare 1.1.1.1).
- DNS-AID does not operate its own DNS resolvers or proxy DNS traffic.
- DNSSEC validation uses standard resolution chains through your resolver.

## Third-Party Services

DNS-AID interacts with third-party DNS providers **only when you explicitly configure a backend**:

- **AWS Route 53** — governed by [AWS Privacy Policy](https://aws.amazon.com/privacy/)
- **Cloudflare** — governed by [Cloudflare Privacy Policy](https://www.cloudflare.com/privacypolicy/)
- **Infoblox** — governed by [Infoblox Privacy Policy](https://www.infoblox.com/privacy-policy/)
- **NS1 (IBM)** — governed by [IBM Privacy Policy](https://www.ibm.com/privacy)

DNS-AID does not select or default to any third-party service. You choose your DNS backend.

## Open Source

DNS-AID is open source under the Apache License 2.0. You can inspect all code at:
https://github.com/dns-aid/dns-aid-core

## Changes to This Policy

Material changes to this policy will be documented in the project's release notes and CHANGELOG.

## Contact

- **GitHub Issues:** https://github.com/dns-aid/dns-aid-core/issues
- **Email:** iracic@infoblox.com
- **IETF Draft:** draft-mozleywilliams-dnsop-dnsaid
