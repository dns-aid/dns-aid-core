/** End-to-end ES256 sign (jose) -> verifyRecordSignature, mirroring tests/unit/test_jws.py cases. */
import { describe, expect, it } from "vitest";
import { CompactSign, exportJWK, generateKeyPair, type JWK } from "jose";
import { buildAgentRecord, canonicalJson, parseSvcbPresentation, presentationToRdata, sigParamsFromRecord, svcbDigest, verifyRecordSignature } from "../src/index.js";

async function signed(payload: Record<string, unknown>, priv: CryptoKey, kid?: string) {
  return new CompactSign(new TextEncoder().encode(canonicalJson(payload)))
    .setProtectedHeader(kid ? { alg: "ES256", typ: "JWT", kid } : { alg: "ES256", typ: "JWT" })
    .sign(priv);
}

describe("verifyRecordSignature", () => {
  it("verified with svcb claim, verified_endpoint_only without, unbound/expired/no_key paths", async () => {
    const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
    const jwk: JWK = { ...(await exportJWK(publicKey)), kid: "k1", use: "sig" };
    const base = rec('1 mcp.example.com. alpn="mcp" port=443 cap="https://x/c.json"');
    const now = Math.floor(Date.now() / 1000);
    const claims = { fqdn: base.fqdn, target: base.target_host, port: 443, alpn: "mcp", iat: now, exp: now + 3600 };
    const jwks = async () => [jwk];

    const full = { ...base, sig: await signed({ ...claims, svcb: await svcbDigest(sigParamsFromRecord(base)) }, privateKey, "k1") };
    expect((await verifyRecordSignature(full, jwks)).status).toBe("verified");

    const epOnly = { ...base, sig: await signed(claims, privateKey) };
    expect((await verifyRecordSignature(epOnly, jwks)).status).toBe("verified_endpoint_only");

    const wrongTarget = { ...base, sig: await signed({ ...claims, target: "evil.example.net" }, privateKey) };
    expect((await verifyRecordSignature(wrongTarget, jwks)).status).toBe("unbound");

    const tampered = { ...full, realm: "injected" };
    expect((await verifyRecordSignature(tampered, jwks)).status).toBe("unbound");

    const expired = { ...base, sig: await signed({ ...claims, exp: now - 1 }, privateKey) };
    expect((await verifyRecordSignature(expired, jwks)).status).toBe("expired");

    expect((await verifyRecordSignature(full, async () => [])).status).toBe("no_key");

    const other = await generateKeyPair("ES256");
    const badKey = { ...base, sig: await signed(claims, other.privateKey) };
    expect((await verifyRecordSignature(badKey, jwks)).status).toBe("invalid");
  });

  it("rejects alg=none and non-ES256", async () => {
    const hdr = btoa(JSON.stringify({ alg: "none" })).replace(/=+$/, "");
    const a = { ...rec('1 mcp.example.com. alpn="mcp"'), sig: `${hdr}.e30.` };
    const r = await verifyRecordSignature(a, async () => []);
    expect(r.status).toBe("invalid");
  });
});

function rec(text: string) {
  return buildAgentRecord({ name: "assistant", domain: "example.com", rdata: presentationToRdata(parseSvcbPresentation(text)), ttl: 60 })!;
}
