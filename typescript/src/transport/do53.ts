/**
 * Classic DNS over UDP/TCP (Node only). Default transport on Node because
 * enterprise zones (and this laptop's corporate network) are frequently
 * unreachable through public DoH, and the validating recursive resolver that
 * sets the AD flag is usually the local one.
 */
import dgram from "node:dgram";
import net from "node:net";
import { getServers } from "node:dns";
import { buildQuery, parseResponse, type ParsedResponse } from "./message.js";
import type { DnsResponse, DnsTransport, RrType } from "./types.js";

export interface Do53Options {
  /** Resolver addresses; defaults to the system resolvers (node:dns getServers()). */
  servers?: string[];
  port?: number;
  timeoutMs?: number;
}

export class Do53Transport implements DnsTransport {
  readonly kind = "do53";
  private readonly servers: string[];
  private readonly port: number;
  private readonly timeoutMs: number;

  constructor(opts: Do53Options = {}) {
    this.servers = opts.servers ?? getServers().filter((s) => !s.includes(":") || net.isIPv6(s));
    if (this.servers.length === 0) this.servers = ["127.0.0.1"];
    this.port = opts.port ?? 53;
    this.timeoutMs = opts.timeoutMs ?? 3000;
  }

  async query(name: string, type: RrType, opts: { timeoutMs?: number } = {}): Promise<DnsResponse> {
    const timeoutMs = opts.timeoutMs ?? this.timeoutMs;
    let lastErr: unknown;
    for (const server of this.servers) {
      try {
        // Unpredictable id (RFC 5452 §4.3): Math.random is not a CSPRNG.
        const id = crypto.getRandomValues(new Uint16Array(1))[0]!;
        const q = buildQuery(name, type, id);
        const matches = (r: ParsedResponse) => answersQuery(r, id, name, type);
        let res = await this.udp(server, q, timeoutMs, matches);
        if (res.tc) {
          res = await this.tcp(server, q, timeoutMs);
          if (!matches(res)) throw new Error("DNS response does not match the query");
        }
        return res;
      } catch (e) {
        lastErr = e;
      }
    }
    throw lastErr instanceof Error ? lastErr : new Error("all resolvers failed");
  }

  /**
   * Send over UDP and wait for a reply that comes from the server we asked and
   * matches the query (id, name, type). Anything else -- a spoofed or stray
   * datagram -- is ignored and we keep listening until the timeout, so an
   * off-path packet cannot end the query early (RFC 5452 §9.1).
   */
  private udp(server: string, q: Uint8Array, timeoutMs: number, matches: (r: ParsedResponse) => boolean) {
    return new Promise<ParsedResponse>((resolve, reject) => {
      const sock = dgram.createSocket(net.isIPv6(server) ? "udp6" : "udp4");
      const timer = setTimeout(() => {
        sock.close();
        reject(new Error(`UDP timeout to ${server}`));
      }, timeoutMs);
      sock.once("error", (e) => {
        clearTimeout(timer);
        sock.close();
        reject(e);
      });
      const from = normalizeAddress(server);
      sock.on("message", (msg, rinfo) => {
        if (normalizeAddress(rinfo.address) !== from || rinfo.port !== this.port) return;
        let res: ParsedResponse;
        try {
          res = parseResponse(new Uint8Array(msg));
        } catch {
          return; // unparseable: not our answer
        }
        if (!matches(res)) return;
        clearTimeout(timer);
        sock.close();
        resolve(res);
      });
      sock.send(q, this.port, server);
    });
  }

  private tcp(server: string, q: Uint8Array, timeoutMs: number) {
    return new Promise<ParsedResponse>((resolve, reject) => {
      const sock = net.connect({ host: server, port: this.port });
      const chunks: Buffer[] = [];
      sock.setTimeout(timeoutMs, () => {
        sock.destroy();
        reject(new Error(`TCP timeout to ${server}`));
      });
      sock.once("error", reject);
      sock.on("data", (c) => chunks.push(c));
      sock.once("close", () => {
        const all = Buffer.concat(chunks);
        if (all.length < 2) return reject(new Error("short TCP response"));
        const len = all.readUInt16BE(0);
        try {
          resolve(parseResponse(new Uint8Array(all.subarray(2, 2 + len))));
        } catch (e) {
          reject(e);
        }
      });
      sock.once("connect", () => {
        const framed = Buffer.alloc(2 + q.length);
        framed.writeUInt16BE(q.length, 0);
        framed.set(q, 2);
        sock.end(framed);
      });
    });
  }
}

/** The reply echoes our id and question (case-insensitive name, RFC 4343). */
export function answersQuery(r: ParsedResponse, id: number, name: string, type: RrType): boolean {
  if (r.id !== id || !r.question) return false;
  const norm = (n: string) => n.replace(/\.$/, "").toLowerCase();
  return norm(r.question.name) === norm(name) && r.question.type === type;
}

/** IPv4-mapped IPv6 (::ffff:a.b.c.d) and plain IPv4 compare equal; IPv6 is lowercased. */
function normalizeAddress(a: string): string {
  const lower = a.toLowerCase();
  return lower.startsWith("::ffff:") && net.isIPv4(lower.slice(7)) ? lower.slice(7) : lower;
}
