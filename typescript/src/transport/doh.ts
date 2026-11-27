/**
 * DNS over HTTPS, RFC 8484 wire format (application/dns-message).
 * Works on any runtime with fetch: browsers, Cloudflare Workers, Deno, Bun, Node.
 * Note: corporate networks may intercept public DoH endpoints; prefer the
 * organisation's own DoH resolver URL there.
 */
import { buildQuery, parseResponse } from "./message.js";
import type { DnsResponse, DnsTransport, RrType } from "./types.js";

export interface DohOptions {
  /** e.g. https://cloudflare-dns.com/dns-query or https://dns.google/dns-query */
  url: string;
  fetch?: typeof fetch;
  timeoutMs?: number;
}

function toBase64Url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export class DohTransport implements DnsTransport {
  readonly kind = "doh";
  private readonly url: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  constructor(opts: DohOptions) {
    this.url = opts.url;
    this.fetchImpl = opts.fetch ?? fetch;
    this.timeoutMs = opts.timeoutMs ?? 5000;
  }

  async query(name: string, type: RrType, opts: { timeoutMs?: number } = {}): Promise<DnsResponse> {
    // id=0 per RFC 8484 §4.1 for cacheability.
    const q = buildQuery(name, type, 0);
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), opts.timeoutMs ?? this.timeoutMs);
    try {
      const res = await this.fetchImpl(`${this.url}?dns=${toBase64Url(q)}`, {
        method: "GET",
        headers: { accept: "application/dns-message" },
        signal: ctrl.signal,
        redirect: "error",
      });
      const ct = res.headers.get("content-type") ?? "";
      if (!res.ok || !ct.includes("application/dns-message")) {
        throw new Error(`DoH ${res.status} ${ct || "no content-type"} from ${this.url}`);
      }
      return parseResponse(new Uint8Array(await res.arrayBuffer()));
    } finally {
      clearTimeout(timer);
    }
  }
}
