/**
 * Owner-name construction and index parsing (draft-02).
 * Mirrors dns-aid-core core/fqdn.py, core/indexer.py.
 */
import type { Protocol } from "./types.js";

const PROTOCOLS: ReadonlySet<string> = new Set(["mcp", "a2a", "https"]);

export function isProtocol(p: string): p is Protocol {
  return PROTOCOLS.has(p);
}

export function normalizeDomain(domain: string): string {
  return domain.trim().replace(/\.+$/, "").toLowerCase();
}

/** Flat primary owner: `{name}.{domain}`. Valid as an X.509 SAN. */
export function primaryFqdn(name: string, domain: string): string {
  return `${name}.${normalizeDomain(domain)}`;
}

/** Walkable AliasMode owner: `{name}._agents.{domain}`. */
export function walkableFqdn(name: string, domain: string): string {
  return `${name}._agents.${normalizeDomain(domain)}`;
}

/** Org index TXT owner: `_index._agents.{domain}`. */
export function indexFqdn(domain: string): string {
  return `_index._agents.${normalizeDomain(domain)}`;
}

/** Catalog pointer SVCB owner: `_catalog._agents.{domain}`. */
export function catalogFqdn(domain: string): string {
  return `_catalog._agents.${normalizeDomain(domain)}`;
}

/** draft-01 legacy owner: `_{name}._{protocol}._agents.{domain}`. */
export function legacyFqdn(name: string, protocol: Protocol, domain: string): string {
  return `_${name}._${protocol}._agents.${normalizeDomain(domain)}`;
}

export interface IndexEntry {
  name: string;
  protocol: Protocol;
}

/**
 * Parse `_index._agents` TXT strings.
 * Grammar: a string `agents=name:proto,name:proto`. Entries without `:` or
 * with unknown protocols are skipped. A bare `v=dns-aid1` or `agents=` is an
 * empty index. Returns null when no `agents=` string is present at all.
 */
export function parseIndex(txtStrings: readonly string[]): IndexEntry[] | null {
  let found = false;
  const out: IndexEntry[] = [];
  for (const s of txtStrings) {
    const str = s.trim();
    if (!str.startsWith("agents=")) continue;
    found = true;
    const body = str.slice("agents=".length);
    if (!body) continue;
    for (const raw of body.split(",")) {
      const token = raw.trim();
      const i = token.indexOf(":");
      if (i < 0) continue;
      const name = token.slice(0, i).trim();
      const protocol = token.slice(i + 1).trim().toLowerCase();
      if (!name || !isProtocol(protocol)) continue;
      out.push({ name, protocol });
    }
  }
  return found ? out : null;
}
