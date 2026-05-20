# Security Policy

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

### CVE-2025-45768 — pyjwt (disputed; "weak encryption" claim)

- **Package**: `pyjwt 2.12.1` (transitive via the `mcp` extra; also in `all`).
- **Status — DISPUTED**: This CVE is **disputed by the pyjwt maintainer**.
  Per the [NVD entry](https://nvd.nist.gov/vuln/detail/CVE-2025-45768)
  (status: Analyzed), the maintainer's published note states:
  *"this is disputed by the Supplier because the key length is chosen
  by the application that uses the library."* The maintainer's own
  [pyjwt Security Advisories](https://github.com/jpadilla/pyjwt/security/advisories)
  list does NOT include CVE-2025-45768 — only three substantive,
  fixed CVEs are listed there (CVE-2026-32597, CVE-2024-53861,
  CVE-2022-29217). The [Snyk vulnerability database](https://security.snyk.io/package/pip/PyJWT/2.12.1)
  does not list this CVE either ("No direct vulnerabilities have been
  found for this package in Snyk's vulnerability database"). The CVE
  was filed by a third party with a gist as the supporting evidence
  and no fix commit. CVSS 3.1 `AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H`
  per NVD, but the underlying claim is contested.
- **Why we suppress in CI rather than re-prioritise as resolved**:
  `pip-audit` mirrors OSV/PYSEC entries which retain the CVE without
  the dispute annotation. The `--ignore-vuln` suppression keeps CI
  green; this document carries the substantive context.
- **DNS-AID exposure**: **Definitionally zero**. The disputed claim is
  about applications that pick short keys; DNS-AID does not generate
  JWTs in the SDK path. The `credential_provider` callback returns
  tokens for transport (the application's IdP client generates them);
  decoding is the receiving server's responsibility. The `mcp` extra
  includes pyjwt for OAuth-protected MCP servers, which use
  operator-issued tokens with operator-chosen key lengths.
- **Mitigation**: None required at the SDK layer.
- **Re-evaluation criteria**: Close [tracking issue #141](https://github.com/infobloxopen/dns-aid-core/issues/141)
  when ANY of the following changes:
  - NVD status changes away from "Analyzed / Disputed".
  - Snyk adds this CVE to their database.
  - The pyjwt maintainer accepts the report and ships a fix.

## Security Updates

Security updates will be released as patch versions. Subscribe to releases to stay informed.
