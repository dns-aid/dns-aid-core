/**
 * Pluggable DNS transport. Discovery only needs: query a name for a type,
 * get back rdata + TTL + the resolver's AD (Authenticated Data) flag.
 */

export const RRTYPE = { TXT: 16, SVCB: 64, HTTPS: 65 } as const;
export type RrType = (typeof RRTYPE)[keyof typeof RRTYPE];

export interface DnsAnswer {
  name: string;
  type: number;
  ttl: number;
  /** Raw RDATA bytes. For TXT this is the full <len><bytes>... sequence. */
  rdata: Uint8Array;
}

export interface DnsResponse {
  rcode: "NOERROR" | "NXDOMAIN" | "SERVFAIL" | "REFUSED" | "FORMERR" | "NOTIMP" | string;
  /** Resolver set AD: the chain validated. Only meaningful with a validating resolver. */
  ad: boolean;
  /** RRSIG present in the answer section (diagnostic). */
  signed: boolean;
  answers: DnsAnswer[];
}

export interface DnsTransport {
  readonly kind: string;
  query(name: string, type: RrType, opts?: { timeoutMs?: number }): Promise<DnsResponse>;
}

/** Split TXT RDATA into its character-strings. */
export function decodeTxtRdata(rdata: Uint8Array): string[] {
  const out: string[] = [];
  const td = new TextDecoder();
  let pos = 0;
  while (pos < rdata.length) {
    const len = rdata[pos]!;
    pos += 1;
    out.push(td.decode(rdata.subarray(pos, pos + len)));
    pos += len;
  }
  return out;
}
