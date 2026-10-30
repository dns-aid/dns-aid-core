/**
 * RFC 9460 SVCB/HTTPS RDATA wire codec.
 *
 * Neither Node's dns module nor dns-packet (5.6.x) understand type 64/65,
 * so this is implemented here. RFC 9460 §2.2: TargetName MUST NOT be
 * compressed, so RDATA can be decoded without the enclosing message.
 */

export interface SvcbRdata {
  /** 0 = AliasMode, >0 = ServiceMode (lower preferred). */
  priority: number;
  /** Target name without trailing dot; "" for "." (the owner itself). */
  target: string;
  /** SvcParams, raw bytes, in wire order (ascending key). */
  params: Map<number, Uint8Array>;
}

export class SvcbDecodeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SvcbDecodeError";
  }
}

function readName(buf: Uint8Array, offset: number): { name: string; next: number } {
  const labels: string[] = [];
  let pos = offset;
  for (;;) {
    if (pos >= buf.length) throw new SvcbDecodeError("truncated target name");
    const len = buf[pos]!;
    if (len === 0) {
      pos += 1;
      break;
    }
    if (len & 0xc0) throw new SvcbDecodeError("compressed target name not allowed in SVCB");
    pos += 1;
    if (pos + len > buf.length) throw new SvcbDecodeError("truncated label");
    labels.push(decodeLabel(buf.subarray(pos, pos + len)));
    pos += len;
  }
  return { name: labels.join("."), next: pos };
}

function decodeLabel(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) {
    if (b >= 0x21 && b <= 0x7e && b !== 0x2e && b !== 0x5c) s += String.fromCharCode(b);
    else s += `\\${b.toString().padStart(3, "0")}`;
  }
  return s;
}

function writeName(name: string): Uint8Array {
  const trimmed = name.replace(/\.$/, "");
  if (trimmed === "") return new Uint8Array([0]);
  const parts: number[] = [];
  for (const label of trimmed.split(".")) {
    const bytes = new TextEncoder().encode(label);
    if (bytes.length === 0 || bytes.length > 63) throw new SvcbDecodeError(`bad label: ${label}`);
    parts.push(bytes.length, ...bytes);
  }
  parts.push(0);
  return new Uint8Array(parts);
}

export function decodeSvcbRdata(rdata: Uint8Array): SvcbRdata {
  if (rdata.length < 2) throw new SvcbDecodeError("rdata too short");
  const view = new DataView(rdata.buffer, rdata.byteOffset, rdata.byteLength);
  const priority = view.getUint16(0);
  const { name: target, next } = readName(rdata, 2);
  const params = new Map<number, Uint8Array>();
  let pos = next;
  let lastKey = -1;
  while (pos < rdata.length) {
    if (pos + 4 > rdata.length) throw new SvcbDecodeError("truncated SvcParam header");
    const key = view.getUint16(pos);
    const len = view.getUint16(pos + 2);
    pos += 4;
    if (key <= lastKey) throw new SvcbDecodeError("SvcParamKeys must be strictly increasing");
    lastKey = key;
    if (pos + len > rdata.length) throw new SvcbDecodeError("truncated SvcParam value");
    params.set(key, rdata.subarray(pos, pos + len));
    pos += len;
  }
  if (priority === 0 && params.size > 0) {
    // RFC 9460 §2.4.2: AliasMode records SHOULD NOT carry params; tolerate but keep.
  }
  return { priority, target, params };
}

export function encodeSvcbRdata(r: SvcbRdata): Uint8Array {
  const keys = [...r.params.keys()].sort((a, b) => a - b);
  const name = writeName(r.target);
  let total = 2 + name.length;
  for (const k of keys) total += 4 + r.params.get(k)!.length;
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  view.setUint16(0, r.priority);
  out.set(name, 2);
  let pos = 2 + name.length;
  for (const k of keys) {
    const v = r.params.get(k)!;
    view.setUint16(pos, k);
    view.setUint16(pos + 2, v.length);
    out.set(v, pos + 4);
    pos += 4 + v.length;
  }
  return out;
}

/* ---- typed value decoders for the keys DNS-AID cares about ---- */

export function decodeAlpn(v: Uint8Array): string[] {
  const out: string[] = [];
  let pos = 0;
  const td = new TextDecoder();
  while (pos < v.length) {
    const len = v[pos]!;
    pos += 1;
    out.push(td.decode(v.subarray(pos, pos + len)));
    pos += len;
  }
  return out;
}

export function encodeAlpn(ids: readonly string[]): Uint8Array {
  const parts: number[] = [];
  for (const id of ids) {
    const b = new TextEncoder().encode(id);
    parts.push(b.length, ...b);
  }
  return new Uint8Array(parts);
}

export function decodePort(v: Uint8Array): number {
  if (v.length !== 2) throw new SvcbDecodeError("port must be 2 bytes");
  return (v[0]! << 8) | v[1]!;
}

export function encodePort(p: number): Uint8Array {
  return new Uint8Array([(p >> 8) & 0xff, p & 0xff]);
}

export function decodeIpv4Hints(v: Uint8Array): string[] {
  const out: string[] = [];
  for (let i = 0; i + 4 <= v.length; i += 4) out.push(`${v[i]}.${v[i + 1]}.${v[i + 2]}.${v[i + 3]}`);
  return out;
}

export function decodeIpv6Hints(v: Uint8Array): string[] {
  const out: string[] = [];
  for (let i = 0; i + 16 <= v.length; i += 16) {
    const groups: string[] = [];
    for (let g = 0; g < 16; g += 2) groups.push(((v[i + g]! << 8) | v[i + g + 1]!).toString(16));
    out.push(groups.join(":"));
  }
  return out;
}

export function decodeMandatory(v: Uint8Array): number[] {
  const out: number[] = [];
  for (let i = 0; i + 2 <= v.length; i += 2) out.push((v[i]! << 8) | v[i + 1]!);
  return out;
}

/** Opaque DNS-AID values are UTF-8 strings on the wire. */
export function decodeText(v: Uint8Array): string {
  return new TextDecoder().decode(v);
}
