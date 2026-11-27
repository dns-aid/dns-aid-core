/** discover() against an in-memory transport: index walk, alias follow, legacy fallback, AD flag. */
import { describe, expect, it } from "vitest";
import { discover, encodeSvcbRdata, parseSvcbPresentation, presentationToRdata, RRTYPE, DnssecError } from "../src/index.js";
import type { DnsAnswer, DnsResponse, DnsTransport, RrType } from "../src/index.js";

class MemTransport implements DnsTransport {
  readonly kind = "mem";
  readonly log: string[] = [];
  constructor(private zone: Record<string, { svcb?: string[]; txt?: string[][]; ad?: boolean }>) {}
  async query(name: string, type: RrType): Promise<DnsResponse> {
    this.log.push(`${type}:${name}`);
    const e = this.zone[name.replace(/\.$/, "").toLowerCase()];
    if (!e) return { rcode: "NXDOMAIN", ad: false, signed: false, answers: [] };
    const answers: DnsAnswer[] = [];
    if (type === RRTYPE.SVCB) for (const s of e.svcb ?? []) answers.push({ name, type, ttl: 300, rdata: encodeSvcbRdata(presentationToRdata(parseSvcbPresentation(s))) });
    if (type === RRTYPE.TXT) for (const strs of e.txt ?? []) answers.push({ name, type, ttl: 300, rdata: txt(strs) });
    return { rcode: "NOERROR", ad: e.ad ?? false, signed: false, answers };
  }
}
function txt(strs: string[]) {
  const te = new TextEncoder();
  const parts = strs.map((s) => te.encode(s));
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length + 1, 0));
  let i = 0;
  for (const p of parts) { out[i++] = p.length; out.set(p, i); i += p.length; }
  return out;
}
const noFetch: typeof fetch = async () => new Response("", { status: 404 });

describe("discover", () => {
  const zone = {
    "_index._agents.orga.test": { txt: [["agents=assistant:mcp,legacy:a2a,ghost:mcp"]], ad: true },
    "assistant.orga.test": { svcb: ['1 assistant.orga.test. mandatory=alpn,port alpn="mcp" port=443'], txt: [["version=1.0.0"], ["description=Org A assistant agent"]], ad: true },
    "assistant._agents.orga.test": { svcb: ["0 assistant.orga.test."], ad: true },
    "_legacy._a2a._agents.orga.test": { svcb: ['1 legacy.orga.test. alpn="a2a"'], ad: false },
  };
  it("walks the index, skips stale entries, carries AD", async () => {
    const t = new MemTransport(zone);
    const r = await discover({ transport: t }, "orga.test", { enrichEndpoints: false });
    expect(r.count).toBe(1);
    expect(r.agents[0]!.description).toBe("Org A assistant agent");
    expect(r.agents[0]!.dnssec_validated).toBe(true);
    expect(r.dnssec_validated).toBe(true);
    expect(t.log).toContain("64:ghost.orga.test"); // stale index entry probed, NXDOMAIN, dropped
  });
  it("legacy -01 fallback only when allowed", async () => {
    const t = new MemTransport(zone);
    const r = await discover({ transport: t }, "orga.test", { enrichEndpoints: false, allowLegacy: true, protocol: "a2a" });
    expect(r.count).toBe(1);
    expect(r.agents[0]!.legacy_resolved).toBe(true);
    expect(r.agents[0]!.dnssec_validated).toBe(false);
  });
  it("requireDnssec throws listing failed fqdns", async () => {
    const t = new MemTransport(zone);
    await expect(discover({ transport: t }, "orga.test", { enrichEndpoints: false, allowLegacy: true, requireDnssec: true })).rejects.toBeInstanceOf(DnssecError);
  });
  it("follows an AliasMode record when queried by name+protocol via alias owner", async () => {
    const t = new MemTransport({ ...zone, "assistant.orga.test": { svcb: ["0 real.orga.test."], ad: true }, "real.orga.test": { svcb: ['1 real.orga.test. alpn="mcp" port=8443'] } });
    const r = await discover({ transport: t }, "orga.test", { name: "assistant", protocol: "mcp", enrichEndpoints: false });
    expect(r.agents[0]!.target_host).toBe("real.orga.test");
    expect(r.agents[0]!.port).toBe(8443);
  });
  it("enriches from agent card when present", async () => {
    const t = new MemTransport(zone);
    const fetchImpl: typeof fetch = async (u) =>
      String(u).endsWith("/.well-known/agent-card.json")
        ? new Response(JSON.stringify({ skills: [{ id: "chat" }], metadata: { endpoints: { mcp: "/mcp/v1" } }, securitySchemes: { o: { type: "oauth2" } } }), { status: 200 })
        : new Response("", { status: 404 });
    const r = await discover({ transport: t, fetch: fetchImpl }, "orga.test", { protocol: "mcp" });
    const a = r.agents[0]!;
    expect(a.endpoint_url).toBe("https://assistant.orga.test:443/mcp/v1");
    expect(a.endpoint_source).toBe("dns_svcb_enriched");
    expect(a.auth_type).toBe("oauth2");
    expect(a.capabilities).toEqual(["chat"]);
  });
  it("probes default names when there is no index", async () => {
    const t = new MemTransport({ "chat.example.com": { svcb: ['1 chat.example.com. alpn="mcp"'] } });
    const r = await discover({ transport: t, fetch: noFetch }, "example.com", { enrichEndpoints: false });
    expect(r.agents.map((a) => a.name)).toEqual(["chat"]);
  });
});
