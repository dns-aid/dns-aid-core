/**
 * RFC 9460 §2.1 presentation format, as returned by DoH JSON endpoints and
 * `dig`. Example:
 *   1 mcp.example.com. alpn="mcp" port=443 key65400="https://x/cap.json"
 *
 * Python dns-aid-core parses the same text with shlex; this follows the same
 * tolerant rules: tokens split on whitespace, values optionally double-quoted,
 * `keyNNNNN` and logical names accepted interchangeably, last one wins.
 */
import { keyNameToNumber } from "./params.js";
import { encodeAlpn, encodePort, type SvcbRdata } from "./wire.js";

export interface SvcbPresentation {
  priority: number;
  target: string;
  /** Decoded params as text (alpn stays comma-joined, port as decimal string). */
  params: Map<number, string>;
}

function tokenize(text: string): string[] {
  const out: string[] = [];
  let cur = "";
  let inQuote = false;
  let has = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (inQuote) {
      if (c === "\\" && i + 1 < text.length) {
        cur += text[++i];
      } else if (c === '"') {
        inQuote = false;
      } else cur += c;
      has = true;
    } else if (c === '"') {
      inQuote = true;
      has = true;
    } else if (/\s/.test(c)) {
      if (has) out.push(cur);
      cur = "";
      has = false;
    } else {
      cur += c;
      has = true;
    }
  }
  if (inQuote) throw new Error("unterminated quote in SVCB presentation text");
  if (has) out.push(cur);
  return out;
}

export function parseSvcbPresentation(text: string): SvcbPresentation {
  const tokens = tokenize(text.trim());
  if (tokens.length < 2) throw new Error("SVCB presentation needs priority and target");
  const priority = Number(tokens[0]);
  if (!Number.isInteger(priority) || priority < 0 || priority > 65535) throw new Error("bad priority");
  const target = tokens[1]!.replace(/\.$/, "");
  const params = new Map<number, string>();
  for (const tok of tokens.slice(2)) {
    const eq = tok.indexOf("=");
    const keyName = (eq < 0 ? tok : tok.slice(0, eq)).toLowerCase();
    const value = eq < 0 ? "" : tok.slice(eq + 1);
    const num = keyNameToNumber(keyName);
    if (num === null) continue;
    params.set(num, value);
  }
  return { priority, target, params };
}

/** Convert presentation params to wire rdata so one code path builds AgentRecords. */
export function presentationToRdata(p: SvcbPresentation): SvcbRdata {
  const params = new Map<number, Uint8Array>();
  const te = new TextEncoder();
  for (const [k, v] of p.params) {
    switch (k) {
      case 1:
        params.set(k, encodeAlpn(v.split(",").filter(Boolean)));
        break;
      case 3:
        params.set(k, encodePort(Number(v)));
        break;
      case 0:
        params.set(
          k,
          new Uint8Array(
            v
              .split(",")
              .map((n) => keyNameToNumber(n) ?? 0)
              .flatMap((n) => [(n >> 8) & 0xff, n & 0xff]),
          ),
        );
        break;
      case 4:
        params.set(k, new Uint8Array(v.split(",").flatMap((ip) => ip.split(".").map(Number))));
        break;
      case 6:
        params.set(k, encodeIpv6List(v));
        break;
      default:
        params.set(k, te.encode(v));
    }
  }
  return { priority: p.priority, target: p.target, params };
}

function encodeIpv6List(list: string): Uint8Array {
  const out: number[] = [];
  for (const addr of list.split(",")) {
    const [headRaw, tailRaw] = addr.split("::");
    const head = headRaw ? headRaw.split(":").filter(Boolean) : [];
    const tail = tailRaw ? tailRaw.split(":").filter(Boolean) : [];
    const fill = 8 - head.length - tail.length;
    const groups = [...head, ...Array(Math.max(0, fill)).fill("0"), ...tail];
    for (const g of groups) {
      const n = parseInt(g, 16);
      out.push((n >> 8) & 0xff, n & 0xff);
    }
  }
  return new Uint8Array(out);
}
