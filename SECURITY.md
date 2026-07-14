# Security Policy

## Scope

This security policy covers vulnerabilities in this reference implementation.

Protocol-level security considerations belong with the IETF draft: https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-dnsaid/.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.8.x   | :white_check_mark: |
| 0.7.x   | :white_check_mark: |
| < 0.7   | :x:                |

## Reporting a Vulnerability

We take the security of DNS-AID seriously. If you believe you have found a security vulnerability, please report it responsibly.

### How to Report

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report security vulnerabilities using one of these methods:

1. **GitHub Private Reporting**: Go to the [Security tab](../../security) of this repository, click "Report a vulnerability", and provide a detailed description
2. **Email**: Send details to [iracic82@gmail.com](mailto:iracic82@gmail.com) (interim; will migrate to LF mailing list when provisioned)

### What to Include

- Type of vulnerability (e.g., injection, authentication bypass, DNSSEC bypass)
- Full paths of source file(s) related to the vulnerability
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the vulnerability

### Response Timeline

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Resolution Target**: Within 30 days for critical issues

## Security Architecture

### DNSSEC Validation

DNS-AID checks the **AD (Authenticated Data) flag** returned by the upstream resolver to determine whether a DNS response was DNSSEC-validated.

**Limitations:**

- DNS-AID does **not** perform independent DNSSEC chain validation (signature verification, key chain walking, or trust anchor management).
- The AD flag reflects the resolver's validation result. If the resolver is compromised or misconfigured, the AD flag may be unreliable.
- A validating resolver (e.g., Unbound, BIND with DNSSEC enabled) is required for meaningful results.

### DANE / TLSA Verification

DNS-AID supports two modes of DANE/TLSA verification per IETF draft Section 4.4.1:

- **Advisory mode** (default): Checks whether a TLSA record exists for the agent endpoint (`_port._tcp.hostname`). TLSA existence is treated as a signal, not an enforcement mechanism.
- **Full certificate matching** (`verify_dane_cert=True`): Connects to the endpoint via TLS, retrieves the peer certificate, and compares its digest against the TLSA association data. Supports DANE-EE (usage 3), selectors 0 (full cert) and 1 (SPKI), and matching types 0 (exact), 1 (SHA-256), and 2 (SHA-512). The recommended profile is **TLSA 3 1 1** (DANE-EE, SPKI, SHA-256).

**Limitations:**

- DANE is only meaningful when DNSSEC is validated. DNS-AID warns when DANE records exist but DNSSEC validation fails.
- DNS-AID relies on the upstream resolver's AD flag for DNSSEC validation (see above).

### SSRF Protection

All outbound HTTP fetches (capability document retrieval, A2A agent card fetches) are protected against Server-Side Request Forgery:

- **HTTPS-only**: Only `https://` URLs are permitted; `http://` is rejected.
- **Private IP blocking**: Connections to private (RFC 1918), loopback (127.0.0.0/8), and link-local (169.254.0.0/16) addresses are blocked via DNS resolution checks before the request is made.
- **Redirect limits**: HTTP clients enforce `max_redirects=3` to prevent redirect-based SSRF.
- **Allowlist**: The `DNS_AID_FETCH_ALLOWLIST` environment variable can whitelist specific hostnames for testing purposes.

### Capability Document Integrity (cap_sha256)

When a `cap-sha256` (key65401) value is present in an SVCB record, DNS-AID verifies the integrity of the fetched capability document:

- The SHA-256 digest of the fetched document body is computed and base64url-encoded (unpadded).
- The computed digest is compared to the `cap-sha256` value from DNS.
- On mismatch, the capability document is rejected (treated as if the fetch failed).
- When no `cap-sha256` is present, the fetch proceeds without integrity verification.

### SVCB Custom Parameter Keys

DNS-AID uses SVCB SvcParamKeys in the **RFC 9460 Private Use range** (65280–65534):

| Key     | Number   | Purpose                          |
| ------- | -------- | -------------------------------- |
| cap     | key65400 | Capability document URI          |
| cap-sha256 | key65401 | Capability document SHA-256 hash |
| bap     | key65402 | DNS-AID Application Protocols    |
| policy  | key65403 | Policy document URI              |
| realm   | key65404 | Administrative realm             |
| sig     | key65405 | JWS signature                    |

These key numbers are in the Private Use range pending IANA registration through the IETF draft process. The numeric form (`key65400`) is the default wire format; the string form (`cap`) can be enabled via the `DNS_AID_SVCB_STRING_KEYS` environment variable for human-readable debugging.

## Input Validation

All user inputs are validated before use:
- Agent names: alphanumeric with hyphens, max 63 characters
- Domain names: RFC 1035 compliant
- Ports: 1-65535
- TTL: 60-604800 seconds

## Network Security

- **MCP HTTP Transport**: Binds to `127.0.0.1` by default
- **AWS Credentials**: Never logged or exposed; use IAM roles in production
- **TLS/HTTPS**: All endpoint connections use HTTPS by default

## Security Best Practices

When using DNS-AID in production:

1. **Use IAM Roles**: Don't use access keys; use IAM roles for AWS services
2. **Enable DNSSEC**: Sign your zones with DNSSEC for authenticated DNS
3. **Use a Validating Resolver**: The AD flag is only meaningful with a DNSSEC-validating resolver
4. **Network Isolation**: Run MCP servers in isolated network segments
5. **Reverse Proxy**: Use nginx/traefik in front of HTTP transport
6. **Audit Logging**: Enable structlog for audit trails

## Known Security Limitations

- The mock backend is for testing only and should not be used in production
- DNSSEC validation depends on the upstream resolver's AD flag; no independent chain validation is performed
- DANE/TLSA defaults to advisory mode (existence check); full certificate matching requires `verify_dane_cert=True`
- SVCB custom keys use private-use numbers pending IANA registration

## Accepted dependency vulnerabilities

We publish accepted (documented, risk-assessed) dependency CVEs here so reviewers and downstream users can verify the rationale. Each entry is also suppressed in `.github/workflows/security.yml` with a per-CVE comment and tracked via a GitHub issue.

*(none currently)*

### Previously accepted, since resolved

- **CVE-2025-45768 — pyjwt** (disputed "weak encryption" claim; tracked
  in [#141](https://github.com/dns-aid/dns-aid-core/issues/141)):
  suppressed 2026-05 → 2026-07 while the OSV/PYSEC entry listed all
  pyjwt versions as affected. On 2026-05-21 OSV bounded the affected
  range to `<= 2.10.1`
  ([PYSEC-2025-183](https://osv.dev/vulnerability/PYSEC-2025-183));
  this project ships pyjwt ≥ 2.13.0, so `pip-audit` no longer reports
  it and the suppression was removed. The dispute itself was never
  resolved — the maintainer's position ("key length is chosen by the
  application") stands, pyjwt's own GHSA list and Snyk never carried
  the CVE, and DNS-AID's exposure was definitionally zero throughout
  (the SDK does not generate JWTs; tokens come from the application's
  IdP with operator-chosen key lengths).

## Security Updates

Security updates will be released as patch versions. Subscribe to releases to stay informed.
