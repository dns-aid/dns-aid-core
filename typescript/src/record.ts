/** Build an AgentRecord from decoded SVCB rdata (+ optional TXT strings). */
import { isProtocol, primaryFqdn } from "./names.js";
import { extractDnsAidParams } from "./svcb/params.js";
import { decodeAlpn, decodeIpv4Hints, decodeIpv6Hints, decodePort, decodeText, type SvcbRdata } from "./svcb/wire.js";
import type { AgentRecord, DnsAidParams, Protocol } from "./types.js";

/** `bap` grammar from dns-aid-core core/bap.py. Legacy comma-lists collapse to the first token. */
const BAP_RE = /^[a-z][a-z0-9]*(=[A-Za-z0-9][A-Za-z0-9._-]{0,63})?$/;
export function normalizeBap(raw: string | undefined): string | null {
  if (!raw) return null;
  const first = raw.trim().split(",")[0]!.trim();
  if (first.length > 128 || !BAP_RE.test(first)) return null;
  return first;
}
export function bapProtocol(bap: string | null): string | null {
  return bap ? bap.split("=")[0]! : null;
}

/** well-known: bare filename -> /.well-known/{v}; leading slash -> literal path. */
export function wellKnownUrl(target: string, v: string): string | null {
  if (v.startsWith("/")) {
    if (!v.split("/").every((seg) => seg === "" || /^[A-Za-z0-9._-]+$/.test(seg))) return null;
    return `https://${target}${v}`;
  }
  if (!/^[A-Za-z0-9._-]+$/.test(v)) return null;
  return `https://${target}/.well-known/${v}`;
}

export interface BuildRecordInput {
  name: string;
  domain: string;
  rdata: SvcbRdata;
  ttl: number;
  /** Protocol hint from the index or caller; used when alpn/bap are ambiguous. */
  protocolHint?: Protocol;
  txtStrings?: readonly string[];
  dnssecValidated?: boolean;
  legacyResolved?: boolean;
}

export function svcbParamsAsText(rdata: SvcbRdata): Map<number, string> {
  const m = new Map<number, string>();
  for (const [k, v] of rdata.params) {
    if (k === 1) m.set(k, decodeAlpn(v).join(","));
    else if (k === 3) m.set(k, String(decodePort(v)));
    else if (k === 4) m.set(k, decodeIpv4Hints(v).join(","));
    else if (k === 6) m.set(k, decodeIpv6Hints(v).join(","));
    else if (k === 0 || k === 2 || k === 5) continue;
    else m.set(k, decodeText(v));
  }
  return m;
}

export function buildAgentRecord(input: BuildRecordInput): AgentRecord | null {
  const { rdata } = input;
  if (rdata.priority === 0) return null; // AliasMode must be followed by the caller
  const text = svcbParamsAsText(rdata);
  const p: DnsAidParams = extractDnsAidParams(text);
  const alpn = rdata.params.has(1) ? decodeAlpn(rdata.params.get(1)!) : [];
  const port = rdata.params.has(3) ? decodePort(rdata.params.get(3)!) : 443;
  const target = rdata.target || primaryFqdn(input.name, input.domain);

  const bap = normalizeBap(p.bap);
  const fromBap = bapProtocol(bap);
  const fromAlpn = alpn.find(isProtocol);
  const proto = (fromBap && isProtocol(fromBap) ? fromBap : fromAlpn) ?? input.protocolHint;
  if (!proto) return null;

  let capabilities: string[] = [];
  let capability_source: AgentRecord["capability_source"] = null;
  for (const s of input.txtStrings ?? []) {
    if (s.startsWith("capabilities=")) {
      capabilities = s.slice("capabilities=".length).split(",").map((x) => x.trim()).filter(Boolean);
      capability_source = "txt_fallback";
    }
  }
  const version = (input.txtStrings ?? []).find((s) => s.startsWith("version="))?.slice(8) ?? "1.0.0";
  const description = (input.txtStrings ?? []).find((s) => s.startsWith("description="))?.slice(12) ?? null;

  const ipv4 = rdata.params.has(4) ? decodeIpv4Hints(rdata.params.get(4)!)[0] ?? null : null;
  const ipv6 = rdata.params.has(6) ? decodeIpv6Hints(rdata.params.get(6)!)[0] ?? null : null;
  const wk = p["well-known"] ? wellKnownUrl(target, p["well-known"]) : null;

  return {
    name: input.name,
    domain: input.domain,
    protocol: proto,
    target_host: target,
    port,
    ipv4_hint: ipv4,
    ipv6_hint: ipv6,
    alpn,
    capabilities,
    version,
    description,
    cap_uri: p.cap ?? null,
    cap_sha256: p["cap-sha256"] ?? null,
    cap_sha256_verified: false,
    well_known_path: wk,
    bap,
    policy_uri: p.policy ?? null,
    realm: p.realm ?? null,
    connect_class: p["connect-class"] ?? null,
    connect_meta: p["connect-meta"] ?? null,
    enroll_uri: p["enroll-uri"] ?? null,
    sig: p.sig ?? null,
    capability_source,
    ttl: input.ttl,
    endpoint_override: null,
    endpoint_source: "dns_svcb",
    auth_type: null,
    dnssec_validated: input.dnssecValidated ?? false,
    legacy_resolved: input.legacyResolved ?? false,
    signature_verified: null,
    signature_status: p.sig ? "not_checked" : "not_signed",
    signature_expires_at: null,
    fqdn: primaryFqdn(input.name, input.domain),
    endpoint_url: `https://${target}:${port}`,
  };
}
