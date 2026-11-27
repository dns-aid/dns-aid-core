/**
 * DNS-AID SvcParamKey registry (RFC 9460 private-use range) and
 * the well-known RFC 9460 keys. Mirrors dns-aid-core models.py DNS_AID_KEY_MAP.
 */
import type { DnsAidParams } from "../types.js";

export const RFC9460_KEYS = {
  mandatory: 0,
  alpn: 1,
  "no-default-alpn": 2,
  port: 3,
  ipv4hint: 4,
  ech: 5,
  ipv6hint: 6,
} as const;

/** Private-use code points pending IANA assignment. */
export const DNS_AID_KEYS = {
  cap: 65400,
  "cap-sha256": 65401,
  bap: 65402,
  policy: 65403,
  realm: 65404,
  sig: 65405,
  "connect-class": 65406,
  "connect-meta": 65407,
  "enroll-uri": 65408,
  "well-known": 65409,
} as const;

export type DnsAidKeyName = keyof typeof DNS_AID_KEYS;

export const DNS_AID_KEY_NAMES = Object.keys(DNS_AID_KEYS) as DnsAidKeyName[];

const NUM_TO_NAME = new Map<number, string>();
for (const [k, v] of Object.entries(RFC9460_KEYS)) NUM_TO_NAME.set(v, k);
for (const [k, v] of Object.entries(DNS_AID_KEYS)) NUM_TO_NAME.set(v, k);

const NAME_TO_NUM = new Map<string, number>();
for (const [k, v] of NUM_TO_NAME) NAME_TO_NUM.set(v, k);

export function keyNumberToName(n: number): string {
  return NUM_TO_NAME.get(n) ?? `key${n}`;
}

/** Accepts `alpn`, `cap`, or `keyNNNNN`; returns the numeric key or null. */
export function keyNameToNumber(name: string): number | null {
  const lower = name.toLowerCase();
  const direct = NAME_TO_NUM.get(lower);
  if (direct !== undefined) return direct;
  const m = /^key(\d{1,5})$/.exec(lower);
  if (m) {
    const n = Number(m[1]);
    return n <= 65535 ? n : null;
  }
  return null;
}

export function isDnsAidKey(name: string): name is DnsAidKeyName {
  return name in DNS_AID_KEYS;
}

/** Values the Python validators reject: control chars, quotes, backslash, >2048 bytes. */
const FORBIDDEN = /["\\\u0000-\u001f\u007f]/;
export function isSafeParamValue(v: string): boolean {
  return v.length <= 2048 && !FORBIDDEN.test(v);
}

/**
 * Pull the DNS-AID params out of a decoded param map. Keys may arrive as
 * logical names or `keyNNNNN`; both are accepted, last one wins (matches
 * Python). Unsafe values are dropped.
 */
export function extractDnsAidParams(params: ReadonlyMap<number, string>): DnsAidParams {
  const out: DnsAidParams = {};
  for (const [num, value] of params) {
    const name = keyNumberToName(num);
    if (!isDnsAidKey(name)) continue;
    if (!value || !isSafeParamValue(value)) continue;
    out[name] = value;
  }
  return out;
}
