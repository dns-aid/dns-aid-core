# IANA Considerations

This document describes the IANA registrations required for DNS-AID (DNS-based Agent Identification and Discovery) as specified in [draft-mozleywilliams-dnsop-dnsaid-02](https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-dnsaid-02/).

## 1. Underscored Node Names Registry

### 1.1 Registration: `_agents`

Per [RFC 8552](https://www.rfc-editor.org/rfc/rfc8552.html) (Scoped Interpretation of DNS Resource Records through "Underscored" Naming of Attribute Leaves), this document requests registration of the following entry:

| RR Type | _NODE NAME | Reference |
|---------|------------|-----------|
| SVCB | `_agents` | draft-mozleywilliams-dnsop-dnsaid-02 |
| SVCB | `_index` | draft-mozleywilliams-dnsop-dnsaid-02 |
| TXT | `_agents-challenge` | draft-mozleywilliams-dnsop-dnsaid-02 (experimental, §DCV) |

**Purpose:** Under -02, the agent's primary owner name is a flat FQDN `{agent}.{domain}` (no underscore-prefix labels, x.509-SAN-valid). Operators MAY additionally publish a walkable AliasMode record at `{agent}._agents.{domain}` so that crawlers and DNS-SD-style consumers can enumerate. The `_index._agents.{domain}` SVCB record points at the organization-level agent index. The `_agents-challenge.{domain}` TXT record is used by the experimental domain-control-validation mechanism described in -02 §FutureWork.

**Examples:**
```
# Flat primary owner — the form publishers SHOULD support and consumers MUST try first
network.example.com.   SVCB 1 mcp.example.com. alpn="mcp" port=443 bap="mcp"
chat.example.com.      SVCB 1 chat.example.com. alpn="a2a" port=443 bap="a2a"

# Optional walkable AliasMode at the _agents leaf
chat._agents.example.com. SVCB 0 chat.example.com.

# Organization index — TargetName must not contain underscores (it carries a public x.509 cert)
_index._agents.example.com. SVCB 1 agent-index.example.com.
```

## 2. TLS Application-Layer Protocol Negotiation (ALPN) Protocol IDs

### 2.1 Registration: `mcp`

This document requests registration of the following ALPN Protocol ID in the "TLS Application-Layer Protocol Negotiation (ALPN) Protocol IDs" registry:

| Protocol | Identification Sequence | Reference |
|----------|------------------------|-----------|
| Model Context Protocol | `0x6D 0x63 0x70` ("mcp") | draft-mozleywilliams-dnsop-dnsaid-02 |

**Description:** The Model Context Protocol (MCP) is a protocol for AI model context sharing and tool invocation, originally developed by Anthropic. The `mcp` ALPN identifier signals that the TLS connection will carry MCP traffic.

**Specification:** See [Model Context Protocol Specification](https://spec.modelcontextprotocol.io/)

### 2.2 Registration: `a2a`

This document requests registration of the following ALPN Protocol ID:

| Protocol | Identification Sequence | Reference |
|----------|------------------------|-----------|
| Agent-to-Agent Protocol | `0x61 0x32 0x61` ("a2a") | draft-mozleywilliams-dnsop-dnsaid-02 |

**Description:** The Agent-to-Agent (A2A) protocol enables direct communication between AI agents, originally developed by Google. The `a2a` ALPN identifier signals that the TLS connection will carry A2A traffic.

**Specification:** See [A2A Protocol Documentation](https://google.github.io/A2A/)

## 3. DNS-AID Error Code Registry (New Registry)

This document requests IANA establish a new registry titled "DNS-AID Error Codes" with the following initial entries:

### 3.1 Registry Definition

**Registry Name:** DNS-AID Error Codes

**Registration Procedure:** Specification Required

**Reference:** draft-mozleywilliams-dnsop-dnsaid-02

### 3.2 Initial Registry Contents

| Code | Name | Description | HTTP Equivalent |
|------|------|-------------|-----------------|
| DNS_AID_001 | DOMAIN_NOT_VERIFIED | Domain ownership not verified | 403 Forbidden |
| DNS_AID_002 | AGENT_NOT_FOUND | Agent FQDN not in index | 404 Not Found |
| DNS_AID_003 | RATE_LIMITED | Too many requests | 429 Too Many Requests |
| DNS_AID_004 | DNSSEC_INVALID | DNSSEC validation failed | 422 Unprocessable Entity |
| DNS_AID_005 | SVCB_MALFORMED | Invalid SVCB record format | 422 Unprocessable Entity |
| DNS_AID_006 | CRAWL_FAILED | Crawler could not reach domain | 502 Bad Gateway |
| DNS_AID_007 | THREAT_DETECTED | Indicator of compromise found | 451 Unavailable For Legal Reasons |

### 3.3 Registration Template

Future registrations in this registry MUST include:

1. **Code:** Unique identifier in format `DNS_AID_NNN`
2. **Name:** Short identifier (SCREAMING_SNAKE_CASE)
3. **Description:** Brief description of the error condition
4. **HTTP Equivalent:** Corresponding HTTP status code
5. **Reference:** Document defining the error code

## 4. SVCB Service Parameter Registry

### 4.1 Existing Parameters Used

DNS-AID uses the following existing parameters defined in [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460.html):

| Parameter | Key ID | Reference |
|-----------|--------|-----------|
| mandatory | 0 | RFC 9460 Section 8 |
| alpn | 1 | RFC 9460 Section 7.1.1 |
| port | 3 | RFC 9460 Section 7.2 |

### 4.2 DNS-AID Custom Parameters (draft-02 §4 IANA Considerations)

This document requests IANA registration of six SvcParamKeys per RFC 9460 §14.3.2. The numeric code points are deferred to IANA assignment; until then, implementations use the private-use range (65280-65534). The keys below sit at 65400-65409.

| Parameter | Proposed Key ID | Value Format | Description | Reference |
|-----------|-----------------|--------------|-------------|-----------|
| `cap` | 65400 | URI or URN (RFC 3986) or compact JSON-Ref | Capability descriptor locator or inline identifier. | draft-mozleywilliams-dnsop-dnsaid-02 |
| `cap-sha256` | 65401 | Base64url (RFC 4648 §5) | Base64url SHA-256 of the canonical capability descriptor for integrity verification. | draft-mozleywilliams-dnsop-dnsaid-02 |
| `bap` | 65402 | Comma-separated tokens | Bulk agent protocols supported at this endpoint (e.g., `mcp`, `a2a`). The agent protocol the endpoint speaks once TLS is established. | draft-mozleywilliams-dnsop-dnsaid-02 |
| `policy` | 65403 | URI (RFC 3986) | URI of an associated policy bundle (terms of use, data handling, compliance). Payload semantics deferred to a future revision. | draft-mozleywilliams-dnsop-dnsaid-02 |
| `realm` | 65404 | Token | Opaque token for multi-tenant scoping or authz realm selection during protocol bootstrapping. Payload semantics deferred to a future revision. | draft-mozleywilliams-dnsop-dnsaid-02 |
| `well-known` | 65409 | RFC 8615 path | Well-known URI path suffix (e.g., `agent-card.json`). Consumer constructs `https://<target>/.well-known/<value>`. Complements `cap` (which is a flexible locator); the two are independent keys. | draft-mozleywilliams-dnsop-dnsaid-02 |

The following keys remain at private-use code points but are NOT in the -02 normative SvcParamKey set; they back features that are either in §FutureWork or shipping in dns-aid-core as extensions:

| Parameter | Key ID | Notes |
|-----------|--------|-------|
| `sig` | 65405 | JWS signature over the record. Backs the optional record-signature flow. |
| `connect-class` | 65406 | Transport-class hint (§FutureWork — `direct`, `lattice`, `apphub-psc`). |
| `connect-meta` | 65407 | Transport-class metadata for the selected `connect-class`. |
| `enroll-uri` | 65408 | Zero-trust enrollment URI (§FutureWork). |

**Wire Format:** Until IANA allocates permanent key IDs, implementations MUST use the generic `keyNNNNN` presentation format (e.g., `key65400="https://..."`) for interoperability with DNS providers that do not recognize custom parameter names. See Section 2.2 of RFC 9460.

**Note on Route 53 Compatibility:** AWS Route 53 currently rejects custom SVCB parameter names (e.g., `cap=`). Records MUST use the `keyNNNNN` encoding until Route 53 adds support for the registered parameter names.

## 5. Expert Review Guidelines

For the DNS-AID Error Code Registry, designated experts SHOULD consider:

1. **Necessity:** Is the error code genuinely needed, or can an existing code be used?
2. **Clarity:** Is the error description clear and unambiguous?
3. **HTTP Mapping:** Does the HTTP equivalent mapping make semantic sense?
4. **Consistency:** Does the code fit the existing naming conventions?

## References

### Normative References

- [RFC 8552](https://www.rfc-editor.org/rfc/rfc8552.html) - Scoped Interpretation of DNS Resource Records through "Underscored" Naming of Attribute Leaves
- [RFC 9460](https://www.rfc-editor.org/rfc/rfc9460.html) - Service Binding and Parameter Specification via the DNS (SVCB and HTTPS Resource Records)
- [RFC 7301](https://www.rfc-editor.org/rfc/rfc7301.html) - Transport Layer Security (TLS) Application-Layer Protocol Negotiation Extension

### Informative References

- [draft-mozleywilliams-dnsop-dnsaid-02](https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-dnsaid-02/) - DNS-based Agent Identification and Discovery (DNS-AID)
- [Model Context Protocol](https://spec.modelcontextprotocol.io/) - MCP Specification
- [A2A Protocol](https://google.github.io/A2A/) - Agent-to-Agent Protocol Documentation
