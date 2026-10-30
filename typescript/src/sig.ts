/**
 * `sig` SvcParam: compact JWS (ES256 only) over a canonical JSON payload
 * binding the record to {fqdn,target,port,alpn,iat,exp[,svcb]}.
 * Mirrors dns-aid-core core/jwks.py. Uses `jose` so it runs on WebCrypto
 * everywhere (Node >= 20, browsers, Workers, Deno, Bun).
 */
import { compactVerify, importJWK, type JWK } from "jose";
import { DNS_AID_KEY_NAMES } from "./svcb/params.js";
import type { AgentRecord, SignatureStatus } from "./types.js";

export const SIG_PARAM_KEYS = DNS_AID_KEY_NAMES.filter((k) => k !== "sig");

/** Canonical JSON: sorted keys, no whitespace, non-ASCII kept (ensure_ascii=False). */
export function canonicalJson(obj: Record<string, unknown>): string {
  const sorted: Record<string, unknown> = {};
  for (const k of Object.keys(obj).sort()) sorted[k] = obj[k];
  return JSON.stringify(sorted);
}

function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Params covered by the `svcb` claim, taken from the record (empty values treated as absent). */
export function sigParamsFromRecord(a: AgentRecord): Record<string, string> {
  const map: Record<string, string | null> = {
    cap: a.cap_uri,
    "cap-sha256": a.cap_sha256,
    bap: a.bap,
    policy: a.policy_uri,
    realm: a.realm,
    "connect-class": a.connect_class,
    "connect-meta": a.connect_meta,
    "enroll-uri": a.enroll_uri,
    "well-known": a.well_known_path ? rawWellKnown(a) : null,
  };
  const out: Record<string, string> = {};
  for (const k of SIG_PARAM_KEYS) {
    const v = map[k];
    if (v) out[k] = v;
  }
  return out;
}
// well_known_path is the expanded URL; the signed value is the raw param. Keep the raw
// value around by re-deriving: this is a known limitation, see design doc "sig well-known".
function rawWellKnown(a: AgentRecord): string {
  const u = a.well_known_path!;
  const prefix = `https://${a.target_host}/.well-known/`;
  return u.startsWith(prefix) ? u.slice(prefix.length) : u.replace(`https://${a.target_host}`, "");
}

/** `svcb` claim = base64url(SHA-256("svcb1:" + canonicalJson(params))). */
export async function svcbDigest(params: Record<string, string>): Promise<string> {
  const data = new TextEncoder().encode("svcb1:" + canonicalJson(params));
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", data));
  return b64url(hash);
}

export function jwksUrls(zone: string): string[] {
  const z = zone.replace(/\.$/, "");
  return [`https://dns-aid.${z}/.well-known/dns-aid-jwks.json`, `https://${z}/.well-known/dns-aid-jwks.json`];
}

export interface SigPayload {
  fqdn: string;
  target: string;
  port: number;
  alpn: string;
  iat: number;
  exp: number;
  svcb?: string;
}

export interface VerifySigResult {
  status: SignatureStatus;
  verified: boolean | null;
  expires_at: number | null;
  algorithm: string | null;
  covers_params: boolean;
  detail?: string;
}

export interface JwksFetcher {
  (zone: string): Promise<JWK[]>;
}

export function defaultJwksFetcher(fetchImpl: typeof fetch = fetch, timeoutMs = 10_000): JwksFetcher {
  const cache = new Map<string, { at: number; keys: JWK[] }>();
  return async (zone) => {
    const hit = cache.get(zone);
    if (hit && Date.now() - hit.at < 3_600_000) return hit.keys;
    for (const url of jwksUrls(zone)) {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), timeoutMs);
      try {
        const res = await fetchImpl(url, { redirect: "error", signal: ctrl.signal });
        if (!res.ok) continue;
        const text = await res.text();
        if (text.length > 65_536) continue;
        const keys = (JSON.parse(text) as { keys?: JWK[] }).keys ?? [];
        cache.set(zone, { at: Date.now(), keys });
        return keys;
      } catch {
        /* try next */
      } finally {
        clearTimeout(t);
      }
    }
    return [];
  };
}

function decodeJwsPart(part: string): unknown {
  const b64 = part.replace(/-/g, "+").replace(/_/g, "/");
  return JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0))));
}

export async function verifyRecordSignature(
  a: AgentRecord,
  getJwks: JwksFetcher,
  now: number = Math.floor(Date.now() / 1000),
): Promise<VerifySigResult> {
  const none: VerifySigResult = { status: "not_signed", verified: null, expires_at: null, algorithm: null, covers_params: false };
  if (!a.sig) return none;
  const parts = a.sig.split(".");
  if (parts.length !== 3) return { ...none, status: "invalid", verified: false, detail: "not compact JWS" };
  let header: { alg?: string; kid?: string };
  try {
    header = decodeJwsPart(parts[0]!) as typeof header;
  } catch {
    return { ...none, status: "invalid", verified: false, detail: "bad header" };
  }
  if (header.alg !== "ES256") return { ...none, status: "invalid", verified: false, detail: `alg ${header.alg} not allowed` };

  const keys = (await getJwks(a.domain)).filter((k) => k.kty === "EC" && k.crv === "P-256" && (!k.use || k.use === "sig"));
  if (keys.length === 0) return { ...none, status: "no_key", verified: null, algorithm: "ES256" };
  const ordered = header.kid ? [...keys.filter((k) => k.kid === header.kid), ...keys.filter((k) => k.kid !== header.kid)] : keys;

  let payload: SigPayload | null = null;
  for (const jwk of ordered) {
    try {
      const key = await importJWK(jwk, "ES256");
      const { payload: raw } = await compactVerify(a.sig, key, { algorithms: ["ES256"] });
      payload = JSON.parse(new TextDecoder().decode(raw)) as SigPayload;
      break;
    } catch {
      /* next key */
    }
  }
  if (!payload) return { ...none, status: "invalid", verified: false, algorithm: "ES256", detail: "signature did not verify" };
  if (typeof payload.exp === "number" && payload.exp < now)
    return { ...none, status: "expired", verified: false, algorithm: "ES256", expires_at: payload.exp };

  const eq = (x: string, y: string) => x.replace(/\.$/, "").toLowerCase() === y.replace(/\.$/, "").toLowerCase();
  const bound =
    eq(payload.fqdn, a.fqdn) && eq(payload.target, a.target_host) && payload.port === a.port && payload.alpn.toLowerCase() === a.protocol;
  if (!bound) return { ...none, status: "unbound", verified: false, algorithm: "ES256", expires_at: payload.exp ?? null, detail: "endpoint claims do not match record" };

  if (payload.svcb) {
    const expect = await svcbDigest(sigParamsFromRecord(a));
    if (expect !== payload.svcb)
      return { ...none, status: "unbound", verified: false, algorithm: "ES256", expires_at: payload.exp, detail: "svcb claim mismatch" };
    return { status: "verified", verified: true, expires_at: payload.exp, algorithm: "ES256", covers_params: true };
  }
  return { status: "verified_endpoint_only", verified: true, expires_at: payload.exp, algorithm: "ES256", covers_params: false };
}
