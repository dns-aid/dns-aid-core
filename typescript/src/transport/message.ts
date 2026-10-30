/**
 * DNS message envelope via dns-packet. We ask dns-packet for the header and
 * section framing only; SVCB/HTTPS rdata it does not understand comes back as
 * raw bytes under `data`, which is exactly what we want. TXT comes back
 * decoded, so we re-encode it to a uniform rdata byte form.
 */
import dnsPacket from "dns-packet";
import type { DnsAnswer, DnsResponse, RrType } from "./types.js";
import { RRTYPE } from "./types.js";

// dns-packet 5.x has no SVCB/HTTPS codec. It round-trips unknown types as
// `UNKNOWN_<n>` with raw rdata bytes, which is exactly the contract we rely on.
const TYPE_NAMES: Record<number, string> = { 16: "TXT", 64: "UNKNOWN_64", 65: "UNKNOWN_65", 46: "RRSIG" };

export function buildQuery(name: string, type: RrType, id: number): Uint8Array {
  const typeName = TYPE_NAMES[type] ?? `TYPE${type}`;
  const buf = dnsPacket.encode({
    type: "query",
    id,
    flags: dnsPacket.RECURSION_DESIRED,
    questions: [{ type: typeName as never, name }],
    additionals: [
      {
        type: "OPT",
        name: ".",
        udpPayloadSize: 1232,
        flags: dnsPacket.DNSSEC_OK,
        extendedRcode: 0,
        ednsVersion: 0,
        flag_do: true,
        options: [],
      },
    ],
  });
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

export function parseResponse(bytes: Uint8Array): DnsResponse & { tc: boolean; id: number } {
  const pkt = dnsPacket.decode(Buffer.from(bytes)) as dnsPacket.Packet & {
    rcode?: string;
    flag_ad?: boolean;
    flag_tc?: boolean;
    id?: number;
  };
  const answers: DnsAnswer[] = [];
  let signed = false;
  for (const a of pkt.answers ?? []) {
    const anyA = a as { type: string; name: string; ttl?: number; data: unknown };
    if (anyA.type === "RRSIG") {
      signed = true;
      continue;
    }
    if (anyA.type === "TXT") {
      answers.push({ name: anyA.name, type: RRTYPE.TXT, ttl: anyA.ttl ?? 0, rdata: encodeTxt(anyA.data) });
      continue;
    }
    const m = /^(?:TYPE|UNKNOWN_)(\d+)$/i.exec(anyA.type);
    const num = m ? Number(m[1]) : anyA.type === "SVCB" ? 64 : anyA.type === "HTTPS" ? 65 : -1;
    if (num === 64 || num === 65) {
      const d = anyA.data as Buffer | Uint8Array;
      answers.push({ name: anyA.name, type: num, ttl: anyA.ttl ?? 0, rdata: new Uint8Array(d) });
    }
  }
  return {
    rcode: pkt.rcode ?? "NOERROR",
    ad: Boolean(pkt.flag_ad),
    signed,
    answers,
    tc: Boolean(pkt.flag_tc),
    id: pkt.id ?? 0,
  };
}

function encodeTxt(data: unknown): Uint8Array {
  const parts: Uint8Array[] = Array.isArray(data) ? data.map(toBytes) : [toBytes(data)];
  const total = parts.reduce((n, p) => n + 1 + p.length, 0);
  const out = new Uint8Array(total);
  let pos = 0;
  for (const p of parts) {
    out[pos++] = p.length;
    out.set(p, pos);
    pos += p.length;
  }
  return out;
}
function toBytes(x: unknown): Uint8Array {
  if (x instanceof Uint8Array) return x;
  return new TextEncoder().encode(String(x));
}
