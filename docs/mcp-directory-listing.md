# Anthropic MCP Directory — Submission Notes

## Listing Description

DNS-AID enables AI agents to discover and connect to other AI agents using DNS.
Publish agents to DNS so others can find them, discover agents at any domain,
and verify their DNS records and DNSSEC security — all using standard DNS
infrastructure (RFC 9460 SVCB records).

## Demo Prompts

Use these three prompts with the DNS-AID MCP server to demonstrate core functionality.
Each works against live DNS records with no credentials required.

### Prompt 1: Discover agents at a domain

> Discover what AI agents are published at example.com

Expected: Returns a list of agents with their names, protocols (MCP/A2A),
endpoints, and capabilities. Demonstrates DNS-based agent discovery using
SVCB record queries.

### Prompt 2: Verify an agent's DNS security

> Verify the DNS records for network.example.com
> and tell me if DNSSEC is valid

Expected: Returns DNS record validation results including SVCB record
existence, DNSSEC validation status, DANE/TLSA configuration, endpoint
reachability, and a security score.

### Prompt 3: Diagnose the environment

> Run DNS-AID environment diagnostics for the domain example.com

Expected: Returns a structured diagnostic report checking Python version,
DNS resolution capability, backend configuration, and agent discovery
against the specified domain. No credentials required for the diagnostic.

## Category

Developer Tools / Infrastructure / AI Agent Discovery

## Tags

dns, agent-discovery, mcp, a2a, svcb, dnssec, ai-agents, infrastructure

## Privacy Policy URL

https://github.com/dns-aid/dns-aid-core/blob/main/PRIVACY.md
