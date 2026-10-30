/**
 * discover(): index walk -> per-agent SVCB (+TXT) -> AgentRecord[]
 * Mirrors dns-aid-core core/discoverer.py discover()/_discover_agents_in_zone.
 */
import { enrichFromAgentCard } from "./card.js";
import { indexFqdn, legacyFqdn, normalizeDomain, parseIndex, primaryFqdn, type IndexEntry } from "./names.js";
import { buildAgentRecord } from "./record.js";
import { defaultJwksFetcher, verifyRecordSignature, type JwksFetcher } from "./sig.js";
import { decodeSvcbRdata, type SvcbRdata } from "./svcb/wire.js";
import { decodeTxtRdata, RRTYPE, type DnsResponse, type DnsTransport } from "./transport/types.js";
import { DnssecError, type AgentRecord, type DiscoverOptions, type DiscoveryResult, type Protocol } from "./types.js";

/** Names probed when a zone has no `_index._agents` TXT (same list as Python). */
export const PROBE_NAMES = ["chat", "assistant", "network", "data-cleaner", "index", "multiagent", "api", "help", "support", "agent"];
const PROBE_PROTOCOLS: Protocol[] = ["mcp", "a2a"];
const CONCURRENCY = 20;

export interface DiscovererDeps {
  transport: DnsTransport;
  fetch?: typeof fetch;
  jwks?: JwksFetcher;
}

async function querySvcb(t: DnsTransport, fqdn: string): Promise<{ rrs: SvcbRdata[]; ttl: number; res: DnsResponse } | null> {
  let res = await t.query(fqdn, RRTYPE.SVCB);
  if (res.rcode === "NXDOMAIN") return null;
  if (res.answers.length === 0) {
    // Some providers only serve type 65; dns-aid-core retries as HTTPS.
    res = await t.query(fqdn, RRTYPE.HTTPS);
  }
  const rrs: SvcbRdata[] = [];
  let ttl = 0;
  for (const a of res.answers) {
    if (a.type !== RRTYPE.SVCB && a.type !== RRTYPE.HTTPS) continue;
    try {
      rrs.push(decodeSvcbRdata(a.rdata));
      ttl = ttl ? Math.min(ttl, a.ttl) : a.ttl;
    } catch {
      /* skip malformed */
    }
  }
  return rrs.length ? { rrs, ttl, res } : null;
}

async function queryTxt(t: DnsTransport, fqdn: string): Promise<string[]> {
  try {
    const res = await t.query(fqdn, RRTYPE.TXT);
    return res.answers.filter((a) => a.type === RRTYPE.TXT).flatMap((a) => decodeTxtRdata(a.rdata));
  } catch {
    return [];
  }
}

/** Resolve one agent at its primary owner (following one AliasMode hop), else legacy. */
async function resolveAgent(
  deps: DiscovererDeps,
  name: string,
  domain: string,
  protocolHint: Protocol | undefined,
  allowLegacy: boolean,
): Promise<AgentRecord[]> {
  const t = deps.transport;
  let fqdn = primaryFqdn(name, domain);
  let legacy = false;
  let got = await querySvcb(t, fqdn);
  if (!got && allowLegacy && protocolHint) {
    fqdn = legacyFqdn(name, protocolHint, domain);
    got = await querySvcb(t, fqdn);
    legacy = got !== null;
  }
  if (!got) return [];

  let { rrs, ttl } = got;
  const ad = got.res.ad;
  // AliasMode: follow target once, keep first ServiceMode rdata.
  const alias = rrs.find((r) => r.priority === 0);
  if (alias && !rrs.some((r) => r.priority > 0)) {
    const followed = await querySvcb(t, alias.target);
    if (!followed) return [];
    rrs = followed.rrs.filter((r) => r.priority > 0);
    ttl = Math.min(ttl || followed.ttl, followed.ttl);
  }
  const txt = await queryTxt(t, fqdn);
  const out: AgentRecord[] = [];
  for (const r of rrs.filter((r) => r.priority > 0).sort((a, b) => a.priority - b.priority)) {
    const rec = buildAgentRecord({ name, domain, rdata: r, ttl, txtStrings: txt, dnssecValidated: ad, legacyResolved: legacy, ...(protocolHint ? { protocolHint } : {}) });
    if (rec && (!protocolHint || rec.protocol === protocolHint)) out.push(rec);
  }
  return out;
}

async function mapLimit<T, R>(items: T[], limit: number, fn: (x: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let i = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      for (;;) {
        const idx = i++;
        if (idx >= items.length) return;
        out[idx] = await fn(items[idx]!);
      }
    }),
  );
  return out;
}

export async function discover(deps: DiscovererDeps, domainIn: string, opts: DiscoverOptions = {}): Promise<DiscoveryResult> {
  const started = performance.now();
  const domain = normalizeDomain(domainIn);
  const fetchImpl = opts.fetch ?? deps.fetch ?? fetch;
  const allowLegacy = opts.allowLegacy ?? false;
  const t = deps.transport;

  let entries: IndexEntry[];
  let query: string;
  if (opts.name && opts.protocol) {
    entries = [{ name: opts.name, protocol: opts.protocol }];
    query = primaryFqdn(opts.name, domain);
  } else {
    query = opts.protocol ? `_index._${opts.protocol}._agents.${domain}` : indexFqdn(domain);
    const idx = parseIndex(await queryTxt(t, indexFqdn(domain)));
    if (idx) {
      entries = idx.filter((e) => !opts.protocol || e.protocol === opts.protocol);
    } else {
      entries = PROBE_NAMES.flatMap((n) => PROBE_PROTOCOLS.filter((p) => !opts.protocol || p === opts.protocol).map((p) => ({ name: n, protocol: p })));
    }
  }

  // Dedupe by (name, protocol); one DNS resolution per distinct name.
  const byName = new Map<string, Set<Protocol>>();
  for (const e of entries) byName.set(e.name, (byName.get(e.name) ?? new Set()).add(e.protocol));

  const nested = await mapLimit([...byName.entries()], CONCURRENCY, async ([name, protos]) => {
    const hint = protos.size === 1 ? [...protos][0] : opts.protocol;
    const recs = await resolveAgent(deps, name, domain, hint, allowLegacy);
    return recs.filter((r) => protos.has(r.protocol));
  });

  let agents = nested.flat();
  const seen = new Set<string>();
  agents = agents.filter((a) => {
    const k = `${a.fqdn.toLowerCase()}|${a.protocol}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  if (opts.name && !opts.protocol) agents = agents.filter((a) => a.name.toLowerCase() === opts.name!.toLowerCase());

  if (opts.requireDnssec) {
    const failed = agents.filter((a) => !a.dnssec_validated).map((a) => a.fqdn);
    if (failed.length) throw new DnssecError(failed);
  }

  if (opts.enrichEndpoints ?? true) {
    agents = await mapLimit(agents, CONCURRENCY, (a) => enrichFromAgentCard(a, fetchImpl, opts.httpTimeoutMs ?? 10_000));
  }

  if (opts.verifySignatures) {
    const jwks = deps.jwks ?? defaultJwksFetcher(fetchImpl);
    agents = await mapLimit(agents, CONCURRENCY, async (a) => {
      const r = await verifyRecordSignature(a, jwks);
      return { ...a, signature_verified: r.verified, signature_status: r.status, signature_expires_at: r.expires_at };
    });
  }

  return {
    query,
    domain,
    agents,
    dnssec_validated: agents.length > 0 && agents.every((a) => a.dnssec_validated),
    cached: false,
    query_time_ms: Math.round(performance.now() - started),
    count: agents.length,
  };
}
