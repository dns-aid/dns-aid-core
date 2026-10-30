/**
 * Public types. Field names mirror dns-aid-core (Python) `AgentRecord`,
 * `DiscoveryResult` and `VerifyResult` so JSON produced by either
 * implementation is interchangeable.
 */

export type Protocol = "mcp" | "a2a" | "https";

export type CapabilitySource =
  | "cap_uri"
  | "well_known"
  | "agent_card"
  | "http_index"
  | "ard_catalog"
  | "txt_fallback"
  | "descriptor_unreachable"
  | "none";

export type EndpointSource =
  | "dns_svcb"
  | "dns_svcb_enriched"
  | "http_index"
  | "http_index_fallback"
  | "ard_card"
  | "ard_inline"
  | "direct"
  | "directory";

export type SignatureStatus =
  | "verified"
  | "verified_endpoint_only"
  | "invalid"
  | "unbound"
  | "expired"
  | "no_key"
  | "not_signed"
  | "not_checked";

/** DNS-AID SvcParams carried on the SVCB record (draft-02 + dns-aid-core extensions). */
export interface DnsAidParams {
  cap?: string;
  "cap-sha256"?: string;
  bap?: string;
  policy?: string;
  realm?: string;
  sig?: string;
  "connect-class"?: string;
  "connect-meta"?: string;
  "enroll-uri"?: string;
  "well-known"?: string;
}

export interface AgentRecord {
  name: string;
  domain: string;
  protocol: Protocol;
  target_host: string;
  port: number;
  ipv4_hint: string | null;
  ipv6_hint: string | null;
  alpn: string[];
  capabilities: string[];
  version: string;
  description: string | null;
  cap_uri: string | null;
  cap_sha256: string | null;
  cap_sha256_verified: boolean;
  well_known_path: string | null;
  bap: string | null;
  policy_uri: string | null;
  realm: string | null;
  connect_class: string | null;
  connect_meta: string | null;
  enroll_uri: string | null;
  sig: string | null;
  capability_source: CapabilitySource | null;
  ttl: number;
  endpoint_override: string | null;
  endpoint_source: EndpointSource | null;
  auth_type: string | null;
  dnssec_validated: boolean;
  legacy_resolved: boolean;
  signature_verified: boolean | null;
  signature_status: SignatureStatus | null;
  signature_expires_at: number | null;
  /** Derived: flat primary owner `{name}.{domain}`. */
  fqdn: string;
  /** Derived: `endpoint_override ?? https://{target_host}:{port}`. */
  endpoint_url: string;
}

export interface DiscoveryResult {
  query: string;
  domain: string;
  agents: AgentRecord[];
  dnssec_validated: boolean;
  cached: boolean;
  query_time_ms: number;
  count: number;
}

export interface DiscoverOptions {
  protocol?: Protocol;
  name?: string;
  /** Throw if any in-scope record is not DNSSEC-validated (AD flag). */
  requireDnssec?: boolean;
  /** Fetch `/.well-known/agent-card.json` to learn endpoint path + auth. Default true. */
  enrichEndpoints?: boolean;
  /** Verify the `sig` SvcParam against the zone JWKS. Default false. */
  verifySignatures?: boolean;
  /** Try the draft-01 `_{name}._{proto}._agents.` owner when the primary is empty. */
  allowLegacy?: boolean;
  /** Fetch timeout for HTTP descriptors, ms. Default 10000. */
  httpTimeoutMs?: number;
  /** Override global fetch (tests, custom proxies). */
  fetch?: typeof fetch;
}

export class DnsAidError extends Error {
  constructor(message: string, public readonly code: string) {
    super(message);
    this.name = "DnsAidError";
  }
}
export class DnssecError extends DnsAidError {
  constructor(public readonly failedFqdns: string[]) {
    super(`DNSSEC validation failed for: ${failedFqdns.join(", ")}`, "DNSSEC_FAILED");
    this.name = "DnssecError";
  }
}
