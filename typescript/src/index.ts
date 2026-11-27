export * from "./types.js";
export * from "./names.js";
export { discover, PROBE_NAMES, type DiscovererDeps } from "./discover.js";
export { buildAgentRecord, normalizeBap, wellKnownUrl, svcbParamsAsText } from "./record.js";
export { verifyRecordSignature, svcbDigest, canonicalJson, sigParamsFromRecord, jwksUrls, defaultJwksFetcher, type JwksFetcher, type VerifySigResult } from "./sig.js";
export { enrichFromAgentCard, resolveMcpEndpoint, authTypeFromCard, type AgentCard } from "./card.js";
export { decodeSvcbRdata, encodeSvcbRdata, decodeAlpn, encodeAlpn, decodePort, encodePort, SvcbDecodeError, type SvcbRdata } from "./svcb/wire.js";
export { parseSvcbPresentation, presentationToRdata } from "./svcb/presentation.js";
export { DNS_AID_KEYS, RFC9460_KEYS, keyNameToNumber, keyNumberToName, extractDnsAidParams } from "./svcb/params.js";
export { RRTYPE, decodeTxtRdata, type DnsTransport, type DnsResponse, type DnsAnswer, type RrType } from "./transport/types.js";
export { DohTransport, type DohOptions } from "./transport/doh.js";
// Do53Transport is Node-only; import from "@dns-aid/core/node".
