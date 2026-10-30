/**
 * HTTP enrichment: agent card (A2A-style) and MCP endpoint resolution.
 * Mirrors dns-aid-core discoverer._apply_agent_card and invoke.resolve_mcp_endpoint.
 */
import type { AgentRecord } from "./types.js";

export interface AgentCard {
  skills?: Array<{ id?: string; name?: string }>;
  metadata?: { endpoints?: Record<string, string> };
  securitySchemes?: Record<string, { type?: string; scheme?: string }>;
  authentication?: { schemes?: string[] };
  auth?: { type?: string };
}

async function getJson(fetchImpl: typeof fetch, url: string, timeoutMs: number, maxBytes = 262_144): Promise<unknown | null> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, { signal: ctrl.signal, headers: { accept: "application/json" } });
    if (!res.ok) return null;
    const text = await res.text();
    if (text.length > maxBytes) return null;
    return JSON.parse(text);
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

export function authTypeFromCard(card: AgentCard): string | null {
  if (card.auth?.type) return card.auth.type;
  const scheme = card.securitySchemes ? Object.values(card.securitySchemes)[0] : undefined;
  if (scheme?.type === "oauth2") return "oauth2";
  if (scheme?.type === "http" && scheme.scheme) return scheme.scheme === "bearer" ? "bearer" : scheme.scheme;
  if (scheme?.type === "apiKey") return "api_key";
  const legacy = card.authentication?.schemes?.[0];
  return legacy ? legacy.toLowerCase() : null;
}

/** Apply `/.well-known/agent-card.json` to a record (endpoint path, auth, capabilities). */
export async function enrichFromAgentCard(a: AgentRecord, fetchImpl: typeof fetch, timeoutMs: number): Promise<AgentRecord> {
  if (a.endpoint_override) return a;
  const card = (await getJson(fetchImpl, `https://${a.target_host}/.well-known/agent-card.json`, timeoutMs)) as AgentCard | null;
  if (!card || typeof card !== "object") return a;
  const out: AgentRecord = { ...a };
  const path = card.metadata?.endpoints?.[a.protocol];
  if (path && (a.capability_source === null || a.capability_source === "txt_fallback" || a.capability_source === "none")) {
    const skills = (card.skills ?? []).map((s) => s.id ?? s.name).filter((x): x is string => Boolean(x));
    if (skills.length) {
      out.capabilities = skills;
      out.capability_source = "agent_card";
    }
  }
  if (path) {
    out.endpoint_override = path.startsWith("http") ? path : `https://${a.target_host}:${a.port}${path.startsWith("/") ? path : `/${path}`}`;
    out.endpoint_url = out.endpoint_override;
    out.endpoint_source = "dns_svcb_enriched";
  }
  out.auth_type = authTypeFromCard(card) ?? a.auth_type;
  return out;
}

/** For `alpn=mcp`: final URL to open a streamable-HTTP session on. */
export async function resolveMcpEndpoint(a: AgentRecord, fetchImpl: typeof fetch = fetch, timeoutMs = 5000): Promise<string> {
  const base = a.endpoint_url;
  const u = new URL(base);
  if (u.pathname && u.pathname !== "/") return base;
  const doc = (await getJson(fetchImpl, `${base.replace(/\/$/, "")}/.well-known/agent.json`, timeoutMs, 102_400)) as
    | { endpoints?: { mcp?: string } }
    | null;
  const mcp = doc?.endpoints?.mcp;
  if (mcp) return mcp.startsWith("http") ? mcp : `${base.replace(/\/$/, "")}${mcp.startsWith("/") ? "" : "/"}${mcp}`;
  return `${base.replace(/\/$/, "")}/mcp`;
}
