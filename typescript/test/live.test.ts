/** Live network tests (DNS_AID_LIVE=1). Uses the system resolver via Do53. */
import { describe, expect, it } from "vitest";
import { discover, parseIndex, RRTYPE, decodeTxtRdata, decodeSvcbRdata, decodeAlpn } from "../src/index.js";
import { Do53Transport } from "../src/transport/do53.js";

describe("live", () => {
  const t = new Do53Transport();
  it("reads the ai.infoblox.com index with AD set", async () => {
    const res = await t.query("_index._agents.ai.infoblox.com", RRTYPE.TXT);
    const strs = res.answers.flatMap((a) => decodeTxtRdata(a.rdata));
    const idx = parseIndex(strs)!;
    expect(idx.length).toBeGreaterThan(5);
    expect(res.ad).toBe(true);
  });
  it("decodes a real HTTPS record (cloudflare.com)", async () => {
    const res = await t.query("cloudflare.com", RRTYPE.HTTPS);
    const r = decodeSvcbRdata(res.answers[0]!.rdata);
    expect(decodeAlpn(r.params.get(1)!)).toContain("h2");
  });
  it("discover() tolerates a stale index (no leaf records)", async () => {
    const r = await discover({ transport: t }, "ai.infoblox.com", { enrichEndpoints: false });
    expect(Array.isArray(r.agents)).toBe(true);
  }, 30_000);
});
