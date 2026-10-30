/**
 * Conformance vectors lifted from dns-aid-core tests:
 *  tests/unit/test_discoverer.py, tests/unit/core/test_svcb_param_coverage.py,
 *  tests/unit/core/test_svcb_claim.py, tests/testbed/bind-orga/zones/orga.test.zone
 */
import { describe, expect, it } from "vitest";
import {
  buildAgentRecord,
  canonicalJson,
  decodeSvcbRdata,
  encodeSvcbRdata,
  parseIndex,
  parseSvcbPresentation,
  presentationToRdata,
  svcbDigest,
  sigParamsFromRecord,
  legacyFqdn,
  primaryFqdn,
  walkableFqdn,
  indexFqdn,
  jwksUrls,
  wellKnownUrl,
  normalizeBap,
} from "../src/index.js";

const rec = (text: string, name = "assistant", domain = "example.com") =>
  buildAgentRecord({ name, domain, rdata: presentationToRdata(parseSvcbPresentation(text)), ttl: 300 });

describe("owner names (draft-02)", () => {
  it("builds the four forms", () => {
    expect(primaryFqdn("assistant", "orga.test.")).toBe("assistant.orga.test");
    expect(walkableFqdn("assistant", "orga.test")).toBe("assistant._agents.orga.test");
    expect(indexFqdn("Orga.Test")).toBe("_index._agents.orga.test");
    expect(legacyFqdn("assistant", "mcp", "orga.test")).toBe("_assistant._mcp._agents.orga.test");
  });
});

describe("index TXT", () => {
  it("parses the live ai.infoblox.com shape", () => {
    const r = parseIndex(["agents=board-update-drafter:a2a,dr-pickle:a2a,dr-pickle:mcp,bad-entry,x:unknown"]);
    expect(r).toEqual([
      { name: "board-update-drafter", protocol: "a2a" },
      { name: "dr-pickle", protocol: "a2a" },
      { name: "dr-pickle", protocol: "mcp" },
    ]);
  });
  it("empty index vs no index", () => {
    expect(parseIndex(["agents="])).toEqual([]);
    expect(parseIndex(["v=dns-aid1"])).toBeNull();
  });
});

describe("SVCB presentation -> record", () => {
  it("orga.test testbed record", () => {
    const a = rec('1 assistant.orga.test. mandatory=alpn,port alpn="mcp" port=443', "assistant", "orga.test")!;
    expect(a.protocol).toBe("mcp");
    expect(a.target_host).toBe("assistant.orga.test");
    expect(a.port).toBe(443);
    expect(a.endpoint_url).toBe("https://assistant.orga.test:443");
    expect(a.fqdn).toBe("assistant.orga.test");
    expect(a.signature_status).toBe("not_signed");
  });
  it("custom params by name and keyNNNNN (test_discoverer.py vectors)", () => {
    const a = rec('1 mcp.example.com. alpn="mcp" port="443" cap="https://cap.example.com/cap.json" realm="demo" key65409="agent-card.json" bap="mcp=1.0" connect-meta="arn:aws:vpc-lattice:::service/svc-123"')!;
    expect(a.cap_uri).toBe("https://cap.example.com/cap.json");
    expect(a.realm).toBe("demo");
    expect(a.well_known_path).toBe("https://mcp.example.com/.well-known/agent-card.json");
    expect(a.bap).toBe("mcp=1.0");
    expect(a.connect_meta).toBe("arn:aws:vpc-lattice:::service/svc-123");
  });
  it("sig param survives round trip (test_svcb_param_coverage.py)", () => {
    const sig = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcWRuIjoiYSJ9.c2lnbmF0dXJl";
    const a = rec(`1 mcp.example.com. alpn="mcp" port="443" key65405="${sig}" cap-sha256="dGVzdGhhc2g"`)!;
    expect(a.sig).toBe(sig);
    expect(a.cap_sha256).toBe("dGVzdGhhc2g");
    expect(a.signature_status).toBe("not_checked");
  });
  it("protocol comes from bap before alpn, alias mode returns null", () => {
    expect(rec('1 h.example.com. alpn="h2" bap="a2a"')!.protocol).toBe("a2a");
    expect(rec("0 assistant.example.com.")).toBeNull();
    expect(rec('1 h.example.com. alpn="h2"')).toBeNull(); // no protocol derivable
  });
  it("TXT fallback capabilities", () => {
    const a = buildAgentRecord({
      name: "a",
      domain: "example.com",
      rdata: presentationToRdata(parseSvcbPresentation('1 a.example.com. alpn="mcp"')),
      ttl: 60,
      txtStrings: ["capabilities=chat,code-review", "version=2.0.0"],
    })!;
    expect(a.capabilities).toEqual(["chat", "code-review"]);
    expect(a.capability_source).toBe("txt_fallback");
    expect(a.version).toBe("2.0.0");
  });
});

describe("SVCB wire codec", () => {
  it("round-trips including private-use keys and hints", () => {
    const p = parseSvcbPresentation('1 mcp.example.com. alpn="mcp,h2" port=8443 ipv4hint=10.0.0.1,10.0.0.2 ipv6hint=2001:db8::1 key65400="https://x/cap.json" realm=demo');
    const wire = encodeSvcbRdata(presentationToRdata(p));
    const back = decodeSvcbRdata(wire);
    expect(back.priority).toBe(1);
    expect(back.target).toBe("mcp.example.com");
    expect([...back.params.keys()]).toEqual([1, 3, 4, 6, 65400, 65404]);
    const a = buildAgentRecord({ name: "x", domain: "example.com", rdata: back, ttl: 1 })!;
    expect(a.alpn).toEqual(["mcp", "h2"]);
    expect(a.port).toBe(8443);
    expect(a.ipv4_hint).toBe("10.0.0.1");
    expect(a.ipv6_hint).toBe("2001:db8:0:0:0:0:0:1");
    expect(a.cap_uri).toBe("https://x/cap.json");
  });
  it("rejects compression pointers and non-increasing keys", () => {
    expect(() => decodeSvcbRdata(new Uint8Array([0, 1, 0xc0, 0x0c]))).toThrow(/compressed/);
    const dup = new Uint8Array([0, 1, 0, 0, 3, 0, 1, 97, 0, 3, 0, 1, 97]); // key 3 twice
    expect(() => decodeSvcbRdata(dup)).toThrow(/increasing/);
  });
  it("decodes the live cloudflare.com HTTPS rdata shape", () => {
    // 1 . alpn="h3,h2"  -> priority 1, target root, alpn list
    const wire = new Uint8Array([0, 1, 0, 0, 1, 0, 6, 2, 104, 51, 2, 104, 50]);
    const r = decodeSvcbRdata(wire);
    expect(r.target).toBe("");
    expect(r.params.get(1)).toEqual(new Uint8Array([2, 104, 51, 2, 104, 50]));
  });
});

describe("helpers", () => {
  it("well-known expansion rules", () => {
    expect(wellKnownUrl("h", "agent-card.json")).toBe("https://h/.well-known/agent-card.json");
    expect(wellKnownUrl("h", "/custom/path.json")).toBe("https://h/custom/path.json");
    expect(wellKnownUrl("h", "../etc")).toBeNull();
  });
  it("bap normalisation collapses legacy comma lists", () => {
    expect(normalizeBap("mcp=1.0,a2a")).toBe("mcp=1.0");
    expect(normalizeBap("Bad Token")).toBeNull();
  });
  it("jwks url order", () => {
    expect(jwksUrls("example.com.")).toEqual([
      "https://dns-aid.example.com/.well-known/dns-aid-jwks.json",
      "https://example.com/.well-known/dns-aid-jwks.json",
    ]);
  });
});

describe("sig canonicalisation (test_svcb_claim.py)", () => {
  it("canonical JSON sorts keys with compact separators", () => {
    expect(canonicalJson({ b: 1, a: "é" })).toBe('{"a":"é","b":1}');
  });
  it("svcb digest is stable and ignores empty values", async () => {
    const a = rec('1 mcp.example.com. alpn="mcp" cap="https://x/c.json" realm="r" key65409="agent-card.json"')!;
    const params = sigParamsFromRecord(a);
    expect(params).toEqual({ cap: "https://x/c.json", realm: "r", "well-known": "agent-card.json" });
    const d1 = await svcbDigest(params);
    const d2 = await svcbDigest({ realm: "r", "well-known": "agent-card.json", cap: "https://x/c.json" });
    expect(d1).toBe(d2);
    expect(d1).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });
});
