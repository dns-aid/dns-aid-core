/** Regression tests for the #286 review: Python parity and robustness. */
import dgram from "node:dgram";
import dnsPacket from "dns-packet";
import { CompactSign, exportJWK, generateKeyPair, type JWK } from "jose";
import { afterEach, describe, expect, it } from "vitest";
import {
  buildAgentRecord,
  canonicalJson,
  discover,
  encodeSvcbRdata,
  enrichFromAgentCard,
  parseSvcbPresentation,
  presentationToRdata,
  RRTYPE,
  sigParamsFromRecord,
  svcbDigest,
  verifyRecordSignature,
} from "../src/index.js";
import type { AgentRecord, DnsAnswer, DnsResponse, DnsTransport, RrType, SvcbRdata } from "../src/index.js";
import { Do53Transport } from "../src/transport/do53.js";

type Zone = Record<string, { svcb?: (string | SvcbRdata)[]; txt?: string[][]; throws?: boolean }>;

class MemTransport implements DnsTransport {
  readonly kind = "mem";
  constructor(private zone: Zone) {}
  async query(name: string, type: RrType): Promise<DnsResponse> {
    const e = this.zone[name.replace(/\.$/, "").toLowerCase()];
    if (e?.throws) throw new Error(`timeout for ${name}`);
    if (!e) return { rcode: "NXDOMAIN", ad: false, signed: false, answers: [] };
    const answers: DnsAnswer[] = [];
    if (type === RRTYPE.SVCB)
      for (const s of e.svcb ?? [])
        answers.push({ name, type, ttl: 300, rdata: encodeSvcbRdata(typeof s === "string" ? presentationToRdata(parseSvcbPresentation(s)) : s) });
    if (type === RRTYPE.TXT)
      for (const strs of e.txt ?? []) {
        const parts = strs.map((x) => new TextEncoder().encode(x));
        const out = new Uint8Array(parts.reduce((n, p) => n + p.length + 1, 0));
        let i = 0;
        for (const p of parts) { out[i++] = p.length; out.set(p, i); i += p.length; }
        answers.push({ name, type, ttl: 300, rdata: out });
      }
    return { rcode: "NOERROR", ad: false, signed: false, answers };
  }
}

const opts = { enrichEndpoints: false } as const;

describe("one bad agent does not fail discover()", () => {
  it("a transport error on one name drops only that agent", async () => {
    const t = new MemTransport({
      "_index._agents.ex.test": { txt: [["agents=good:mcp,slow:mcp"]] },
      "good.ex.test": { svcb: ['1 good.ex.test. alpn="mcp"'] },
      "slow.ex.test": { throws: true },
    });
    const r = await discover({ transport: t }, "ex.test", opts);
    expect(r.agents.map((a) => a.name)).toEqual(["good"]);
  });

  it("a probe-name timeout does not reject the probe sweep", async () => {
    const t = new MemTransport({ "chat.ex.test": { svcb: ['1 chat.ex.test. alpn="mcp"'] }, "api.ex.test": { throws: true } });
    const r = await discover({ transport: t }, "ex.test", opts);
    expect(r.agents.map((a) => a.name)).toEqual(["chat"]);
  });

  it("a record with a malformed port drops only that record", async () => {
    const badPort: SvcbRdata = {
      priority: 1,
      target: "bad.ex.test",
      params: new Map([
        [1, new Uint8Array([3, 0x6d, 0x63, 0x70])], // alpn=mcp
        [3, new Uint8Array([1, 2, 3])], // port: 3 bytes
      ]),
    };
    const t = new MemTransport({
      "_index._agents.ex.test": { txt: [["agents=good:mcp,bad:mcp"]] },
      "good.ex.test": { svcb: ['1 good.ex.test. alpn="mcp"'] },
      "bad.ex.test": { svcb: [badPort] },
    });
    const r = await discover({ transport: t }, "ex.test", opts);
    expect(r.agents.map((a) => a.name)).toEqual(["good"]);
  });

  it("a card fetch that throws keeps the DNS-only record", async () => {
    const t = new MemTransport({ "_index._agents.ex.test": { txt: [["agents=good:mcp"]] }, "good.ex.test": { svcb: ['1 good.ex.test. alpn="mcp"'] } });
    const boom: typeof fetch = async () => {
      throw new Error("network down");
    };
    const r = await discover({ transport: t, fetch: boom }, "ex.test", {});
    expect(r.count).toBe(1);
  });
});

describe("records keep their own protocol (Python _reconcile_protocol)", () => {
  it("an index entry chat:mcp whose record says a2a comes back as a2a", async () => {
    const t = new MemTransport({ "_index._agents.ex.test": { txt: [["agents=chat:mcp"]] }, "chat.ex.test": { svcb: ['1 chat.ex.test. alpn="a2a"'] } });
    const all = await discover({ transport: t }, "ex.test", opts);
    expect(all.agents.map((a) => a.protocol)).toEqual(["a2a"]);
    const mcpOnly = await discover({ transport: t }, "ex.test", { ...opts, protocol: "mcp" });
    expect(mcpOnly.count).toBe(0);
  });

  it("a probed alpn=https agent is returned", async () => {
    const t = new MemTransport({ "chat.ex.test": { svcb: ['1 chat.ex.test. alpn="https"'] } });
    const r = await discover({ transport: t }, "ex.test", opts);
    expect(r.agents.map((a) => [a.name, a.protocol])).toEqual([["chat", "https"]]);
  });

  it("a probed alpn=h2 agent falls back to the probe protocol instead of vanishing", async () => {
    const t = new MemTransport({ "chat.ex.test": { svcb: ['1 chat.ex.test. alpn="h2"'] } });
    const r = await discover({ transport: t }, "ex.test", opts);
    expect(r.agents.map((a) => [a.name, a.protocol])).toEqual([["chat", "mcp"]]);
  });
});

describe("sig payload checks", () => {
  async function setup() {
    const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
    const jwk: JWK = { ...(await exportJWK(publicKey)), kid: "k1", use: "sig" };
    const base = buildAgentRecord({
      name: "assistant",
      domain: "example.com",
      rdata: presentationToRdata(parseSvcbPresentation('1 mcp.example.com. alpn="mcp" port=443 well-known="/custom/card.json"')),
      ttl: 60,
    })!;
    const now = Math.floor(Date.now() / 1000);
    const claims = { fqdn: base.fqdn, target: base.target_host, port: 443, alpn: "mcp", iat: now, exp: now + 3600 };
    const sign = (p: Record<string, unknown>) =>
      new CompactSign(new TextEncoder().encode(canonicalJson(p))).setProtectedHeader({ alg: "ES256", kid: "k1" }).sign(privateKey);
    return { base, claims, sign, jwks: async () => [jwk] };
  }

  it("a sig with no exp is expired, not valid forever", async () => {
    const { base, claims, sign, jwks } = await setup();
    const { exp: _drop, ...noExp } = claims;
    const r = await verifyRecordSignature({ ...base, sig: await sign(noExp) }, jwks);
    expect(r.status).toBe("expired");
    expect(r.verified).toBe(false);
  });

  it("a payload missing alpn is invalid instead of throwing", async () => {
    const { base, claims, sign, jwks } = await setup();
    const { alpn: _drop, ...noAlpn } = claims;
    const r = await verifyRecordSignature({ ...base, sig: await sign(noAlpn) }, jwks);
    expect(r.status).toBe("invalid");
  });

  it("a payload with a wrong-typed claim is invalid", async () => {
    const { base, claims, sign, jwks } = await setup();
    const r = await verifyRecordSignature({ ...base, sig: await sign({ ...claims, port: "443" }) }, jwks);
    expect(r.status).toBe("invalid");
  });

  it("a signature covering a literal well-known path verifies (raw value is what is signed)", async () => {
    const { base, claims, sign, jwks } = await setup();
    expect(base.well_known_path).toBe("/custom/card.json");
    expect(sigParamsFromRecord(base)["well-known"]).toBe("/custom/card.json");
    const svcb = await svcbDigest(sigParamsFromRecord(base));
    const r = await verifyRecordSignature({ ...base, sig: await sign({ ...claims, svcb }) }, jwks);
    expect(r.status).toBe("verified");
  });

  it("an unsafe well-known value is still covered by the signature check", async () => {
    const rec = buildAgentRecord({
      name: "a",
      domain: "example.com",
      rdata: presentationToRdata(parseSvcbPresentation('1 mcp.example.com. alpn="mcp" well-known="../etc"')),
      ttl: 60,
    })!;
    expect(rec.well_known_path).toBe("../etc");
    expect(rec.well_known_url).toBeNull();
    expect(sigParamsFromRecord(rec)["well-known"]).toBe("../etc");
  });
});

describe("agent card endpoints stay on the SVCB target", () => {
  const rec = (port = 8443): AgentRecord =>
    buildAgentRecord({ name: "a", domain: "example.com", rdata: presentationToRdata(parseSvcbPresentation(`1 a.example.com. alpn="mcp" port=${port}`)), ttl: 60 })!;
  const cardWith = (path: string): typeof fetch => async () =>
    new Response(JSON.stringify({ metadata: { endpoints: { mcp: path } } }), { status: 200 });

  it("an off-host absolute URL is ignored", async () => {
    const out = await enrichFromAgentCard(rec(), cardWith("https://evil.example.net/mcp"), 1000);
    expect(out.endpoint_override).toBeNull();
    expect(out.endpoint_url).toBe("https://a.example.com:8443");
  });

  it("a same-host absolute URL contributes only its path; DNS port is kept", async () => {
    const out = await enrichFromAgentCard(rec(), cardWith("http://a.example.com:9000/mcp/v1?x=1"), 1000);
    expect(out.endpoint_url).toBe("https://a.example.com:8443/mcp/v1?x=1");
  });

  it("a relative path keeps working", async () => {
    const out = await enrichFromAgentCard(rec(), cardWith("/mcp"), 1000);
    expect(out.endpoint_url).toBe("https://a.example.com:8443/mcp");
  });
});

describe("Do53 only accepts the reply to its query", () => {
  const sockets: dgram.Socket[] = [];
  afterEach(() => {
    for (const s of sockets.splice(0)) s.close();
  });
  const bind = () =>
    new Promise<dgram.Socket>((resolve) => {
      const s = dgram.createSocket("udp4");
      sockets.push(s);
      s.bind(0, "127.0.0.1", () => resolve(s));
    });
  const reply = (id: number, name: string, text: string) =>
    dnsPacket.encode({
      type: "response",
      id,
      flags: dnsPacket.RECURSION_DESIRED,
      questions: [{ type: "TXT", name }],
      answers: [{ type: "TXT", name, ttl: 60, data: [text] }],
    });

  it("ignores wrong id, wrong question and a spoofed source port, then takes the real reply", async () => {
    const server = await bind();
    const spoofer = await bind();
    server.on("message", (msg, rinfo) => {
      const q = dnsPacket.decode(msg);
      const id = q.id!;
      const name = q.questions![0]!.name;
      const to = (s: dgram.Socket, b: Buffer) => s.send(b, rinfo.port, rinfo.address);
      to(server, reply((id + 1) & 0xffff, name, "wrong-id"));
      to(server, reply(id, "other.example.com", "wrong-question"));
      to(spoofer, reply(id, name, "spoofed-port"));
      setTimeout(() => to(server, reply(id, name, "real")), 50);
    });
    const t = new Do53Transport({ servers: ["127.0.0.1"], port: server.address().port, timeoutMs: 2000 });
    const res = await t.query("_index._agents.example.com", RRTYPE.TXT);
    const texts = res.answers.map((a) => new TextDecoder().decode(a.rdata.subarray(1)));
    expect(texts).toEqual(["real"]);
  });

  it("uses an unpredictable query id", async () => {
    const server = await bind();
    const ids: number[] = [];
    server.on("message", (msg, rinfo) => {
      const q = dnsPacket.decode(msg);
      ids.push(q.id!);
      server.send(reply(q.id!, q.questions![0]!.name, "x"), rinfo.port, rinfo.address);
    });
    const t = new Do53Transport({ servers: ["127.0.0.1"], port: server.address().port, timeoutMs: 2000 });
    for (let i = 0; i < 8; i++) await t.query("a.example.com", RRTYPE.TXT);
    expect(new Set(ids).size).toBe(8);
  });
});
