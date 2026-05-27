# Privacy Considerations

This document describes the privacy considerations for DNS-AID (DNS-based Agent Identification and Discovery) as specified in [draft-mozleywilliams-dnsop-dnsaid-02](https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-dnsaid-02/).

## 1. Privacy Model

DNS-AID operates with public DNS records, which introduces specific privacy characteristics:

### 1.1 Data Classification

| Data Type | Classification | Source | Privacy Impact |
|-----------|---------------|--------|----------------|
| Agent FQDN | Public | DNS records | Low - intentionally published |
| Endpoint URL | Public | SVCB target | Low - service endpoint |
| Capabilities | Public | TXT records | Low - intentionally published |
| Domain ownership | Metadata | Verification | Medium - links identity to domain |
| Query patterns | Derived | pDNS data | High - reveals usage patterns |
| User queries | Transient | API requests | Medium - reveals interests |

### 1.2 Privacy Principles

DNS-AID implementations SHOULD follow these privacy principles:

1. **Transparency:** Users should know what data is collected and how it's used
2. **Data Minimization:** Collect only data necessary for the stated purpose
3. **Purpose Limitation:** Use data only for the purpose for which it was collected
4. **Storage Limitation:** Retain data only as long as necessary
5. **Integrity and Confidentiality:** Protect data from unauthorized access

## 2. GDPR Alignment

For deployments subject to GDPR, the following considerations apply:

### 2.1 Lawful Basis for Processing

| Processing Activity | Data Categories | Lawful Basis | GDPR Article |
|---------------------|-----------------|--------------|--------------|
| Agent indexing | Public DNS records | Legitimate interest | Art. 6(1)(f) |
| Domain verification | Email, DNS TXT | Contract performance | Art. 6(1)(b) |
| pDNS popularity | Aggregated query counts | Legitimate interest | Art. 6(1)(f) |
| Threat detection | IOC matches | Legitimate interest | Art. 6(1)(f) |
| API usage logging | IP address, timestamps | Legitimate interest | Art. 6(1)(f) |

### 2.2 Data Subject Rights

DNS-AID directory services MUST support:

| Right | Implementation | Response Time |
|-------|---------------|---------------|
| **Right of Access** (Art. 15) | GET /api/v1/data-export?domain={domain} | 30 days |
| **Right to Rectification** (Art. 16) | Re-crawl on request | 72 hours |
| **Right to Erasure** (Art. 17) | DELETE /api/v1/agents/{fqdn} | 72 hours |
| **Right to Restriction** (Art. 18) | Opt-out via DNS TXT record | 24 hours |
| **Right to Object** (Art. 21) | Remove from index on request | 72 hours |

### 2.3 Right to Erasure Implementation

Domain owners can request removal of their agents from the directory:

**Option 1: API Request (Verified Domain)**
```http
DELETE /api/v1/agents/_network._mcp._agents.example.com
Authorization: Bearer <domain-verified-token>
```

**Option 2: DNS Signal (Self-Service)**
```
; Add this TXT record to opt-out of directory indexing
_dns-aid-optout.example.com. TXT "optout=true"
```

**Processing:**
1. Directory detects opt-out record via regular crawl or explicit check
2. All agents for the domain are removed from the index
3. Domain is added to exclusion list
4. Confirmation sent to domain contact (if known)

### 2.4 Data Retention

| Data Type | Retention Period | Justification |
|-----------|------------------|---------------|
| Active agent records | Until removed or stale | Service operation |
| Stale agent records | 30 days after last seen | Grace period for temporary outages |
| Crawl history | 90 days | Debugging and auditing |
| API access logs | 90 days | Security monitoring |
| Verification tokens | 7 days after verification | Authentication |
| Deleted agent records | 30 days (anonymized) | Compliance audit trail |

### 2.5 Article 30 Records of Processing

DNS-AID operators MUST maintain records per GDPR Article 30:

```yaml
# GDPR Article 30 - Records of Processing Activities

controller:
  name: "Example Corp"
  contact: "privacy@example.com"
  dpo: "dpo@example.com"

processing_activities:
  - name: "Agent Directory Indexing"
    purpose: "Enable discovery of AI agents via DNS"
    data_categories:
      - "Public DNS records (SVCB, TXT)"
      - "Domain names"
      - "Agent capabilities"
    data_subjects: "Domain owners who publish DNS-AID records"
    recipients:
      - "Directory API users (public access)"
    transfers: "None (EU-hosted)"
    retention: "90 days after agent removal"
    security_measures:
      - "Encryption at rest (AES-256)"
      - "Encryption in transit (TLS 1.3)"
      - "Access controls (IAM)"

  - name: "Passive DNS Analysis"
    purpose: "Calculate agent popularity scores"
    data_categories:
      - "Aggregated DNS query counts"
      - "No individual query data"
    data_subjects: "None (aggregated data only)"
    recipients:
      - "Directory API users (via popularity score)"
    transfers: "Infoblox (US) - Standard Contractual Clauses"
    retention: "30 days (aggregates)"
    security_measures:
      - "Data aggregation (k-anonymity)"
      - "No individual query logging"
```

## 3. Privacy by Design

### 3.1 Data Minimization

DNS-AID collects only:
- **SVCB records:** Priority, target, ALPN, port
- **TXT records:** Capabilities, version
- **Verification data:** Domain ownership proof (temporary)

DNS-AID does NOT collect:
- Personal information about agent operators
- User queries to agents
- Agent response content
- Payment or financial information

### 3.2 Aggregation for pDNS Data

When using passive DNS data for popularity scoring:

```python
class PrivacyPreservingPopularity:
    """
    Calculate popularity without exposing individual queries.
    """

    def calculate_score(self, fqdn: str) -> int:
        """
        Returns popularity score (0-100) without revealing:
        - Individual query sources
        - Exact query counts
        - Query timing patterns
        """
        # Get aggregated count (not individual queries)
        aggregate = self.pdns.get_aggregate_count(
            fqdn=fqdn,
            period="30d",
            min_count=10  # k-anonymity threshold
        )

        if aggregate.count < 10:
            return 0  # Suppress low-count data

        # Logarithmic bucketing (differential privacy)
        return self._bucket_score(aggregate.count)

    def _bucket_score(self, count: int) -> int:
        """Map count to privacy-preserving bucket."""
        # Buckets: 0, 10-99, 100-999, 1K-10K, 10K-100K, 100K+
        buckets = [0, 10, 100, 1000, 10000, 100000]
        scores = [0, 20, 40, 60, 80, 100]

        for i, threshold in enumerate(buckets):
            if count < threshold:
                return scores[max(0, i-1)]
        return 100
```

### 3.3 Query Privacy

Directory API implementations SHOULD:

1. **Minimize logging:** Log query metadata, not full query content
2. **Use encrypted transport:** TLS 1.2+ for all API traffic
3. **Support anonymous queries:** Allow unauthenticated search
4. **Implement query aggregation:** Use differential privacy for analytics

```yaml
# Privacy-preserving logging configuration
logging:
  # Log this
  include:
    - timestamp
    - http_method
    - endpoint_path
    - response_status
    - response_time_ms

  # Do NOT log this
  exclude:
    - query_parameters  # Contains search terms
    - client_ip         # Use hashed identifier
    - user_agent        # Can fingerprint users
    - referrer          # Reveals source
```

## 4. Cross-Border Data Transfers

### 4.1 Transfer Mechanisms

For international deployments:

| Scenario | Mechanism | Documentation |
|----------|-----------|---------------|
| EU → US (Infoblox pDNS) | Standard Contractual Clauses | DPA required |
| EU → UK | UK Adequacy Decision | No additional measures |
| EU → Other | Case-by-case assessment | TIA required |

### 4.2 Data Localization

DNS-AID supports data residency requirements:

```yaml
# Multi-region deployment with data residency
regions:
  eu-west-1:
    data_residency: "EU"
    serves: ["EU", "UK", "EEA"]
    cross_border: false

  us-east-1:
    data_residency: "US"
    serves: ["US", "CA", "LATAM"]
    cross_border: false

  ap-southeast-1:
    data_residency: "SG"
    serves: ["APAC"]
    cross_border: false
```

## 5. Privacy-Enhancing Technologies

### 5.1 Applicable Technologies

| Technology | Applicability | Implementation Status |
|------------|---------------|----------------------|
| **DNSSEC** | Integrity, not privacy | Required |
| **DNS over HTTPS (DoH)** | Query privacy | Recommended for clients |
| **DNS over TLS (DoT)** | Query privacy | Recommended for clients |
| **Oblivious DNS (ODoH)** | Query unlinkability | Optional |
| **k-Anonymity** | pDNS aggregation | Required for popularity |
| **Differential Privacy** | Query analytics | Recommended |

### 5.2 DoH/DoT Recommendation

Clients SHOULD use encrypted DNS:

```python
# Recommended: Use DoH for DNS-AID queries
import dns.resolver

resolver = dns.resolver.Resolver()
resolver.nameservers = ["1.1.1.1"]  # Cloudflare DoH
resolver.nameserver_ports = {"1.1.1.1": 443}

# Configure DoH
# This prevents ISP visibility into agent discovery queries
```

## 6. Privacy Checklist

### 6.1 For Directory Operators

- [ ] Privacy policy published and accessible
- [ ] GDPR Article 30 records maintained
- [ ] Data retention policy implemented
- [ ] Right to erasure mechanism available
- [ ] Opt-out mechanism via DNS TXT supported
- [ ] pDNS data aggregated (k-anonymity ≥ 10)
- [ ] Query logs minimized
- [ ] Cross-border transfers documented
- [ ] DPO contact published (if applicable)

### 6.2 For Domain Owners

- [ ] Understand that DNS-AID records are public
- [ ] Use DNSSEC for integrity protection
- [ ] Know how to opt-out if desired
- [ ] Review published capabilities for accuracy

### 6.3 For Agent Operators

- [ ] Minimize data in TXT records
- [ ] Do not include PII in agent names
- [ ] Implement privacy by design in agent endpoints
- [ ] Document data handling in agent privacy policy

## References

- [GDPR](https://gdpr-info.eu/) - General Data Protection Regulation
- [RFC 7816](https://www.rfc-editor.org/rfc/rfc7816.html) - DNS Query Name Minimisation
- [RFC 8484](https://www.rfc-editor.org/rfc/rfc8484.html) - DNS Queries over HTTPS (DoH)
- [RFC 7858](https://www.rfc-editor.org/rfc/rfc7858.html) - DNS over TLS (DoT)
- [RFC 9230](https://www.rfc-editor.org/rfc/rfc9230.html) - Oblivious DNS over HTTPS
