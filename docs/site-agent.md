# Site agent convention (experimental)

A naming convention for advertising **the domain's own website** as an agent:
the agent named `site` at a domain is, by convention, the canonical interface
to that domain's web content — as opposed to task agents such as `billing` or
`chat`. An accompanying `bap` token, `webmcp`, marks a record whose target is
an **in-browser WebMCP surface**: a web origin whose pages register tools via
the browser's [`navigator.modelContext`](https://github.com/webmachinelearning/webmcp)
when loaded in a WebMCP-capable user agent.

This is **experimental and fully opt-in**. It is not part of
[draft-mozleywilliams-dnsop-dnsaid-02](https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-dnsaid/);
it is prototyped here in the spirit of the draft's §5 (Future Work and
Experimental Mechanisms). Nothing here changes the wire format: `site` is an
ordinary agent name under the existing grammar, and `webmcp` is a valid `bap`
token under the draft-02 value shape. A domain that publishes nothing new
behaves exactly as before.

## Motivation

Infrastructure operators have started turning existing websites into
agent-usable surfaces *on the domain owner's behalf* — Cloudflare's
[WebMCP developer preview](https://blog.cloudflare.com/webmcp/) enables it with
one switch, and registrars and hosting providers can do the equivalent by
fronting a site's content with a remote MCP server.

What's missing is a way to **advertise** the result. Agent names are free-form, so DNS-AID can enumerate a domain's agents but cannot say which one *is* the site: a consumer must know a name out of band or guess, and nothing marks an in-browser WebMCP surface as such. A fixed name closes the gap with one DNS query — on both sides. Consumers get a deterministic probe: a browser agent can try `site.<domain>` before loading a page, and a crawler gets one probe name across all domains. Publishers get determinism too: a CDN switch, a registrar button, and a hosting provider all write the same name, so any consumer interoperates with any publisher without out-of-band agreement — the `www` / `robots.txt` / MX pattern applied to agents.

Reserving exactly one name is deliberate. `site` names the domain's *own* web representation — a fixed point of which every domain has exactly one — not a functional role. Roles (`shop`, `support`, …) are an open set and belong to capability vocabulary, not name reservation; the in-browser vs remote distinction belongs to `bap`. The convention adds identity, nothing more.

## The convention

Two record shapes, both ordinary draft-02 flat-owner records. They may coexist
in one RRset — one record per protocol surface, per draft-02 §3.1.1:

```
; Remote MCP interface serving the site's content.
site.example.com.  3600 IN SVCB 1 mcp.example.com. alpn="mcp" port=443 mandatory=alpn,port

; In-browser WebMCP surface: load the target in a WebMCP-capable UA
; and the page registers its tools. key65402 is the bap SvcParamKey.
site.example.com.  3600 IN SVCB 1 example.com. alpn="https" port=443 mandatory=alpn,port key65402="webmcp"
```

When the MCP server lives on the same domain (or at the owner name
itself), the TargetName expresses that too: a record whose target is
`mcp.example.com.` stays in-zone, and a TargetName of `.` means "the owner
name itself" (RFC 9460), with A/AAAA published alongside — SVCB coexists
with address records, unlike CNAME.

Key invariants:

- **`alpn` keeps carrying real connection protocols only.** The webmcp marker
  lives in `bap` (key65402) — the draft-02 §5.1 experimental slot for agent
  protocol signaling — not in `alpn`. Nothing ever negotiates "webmcp" in a
  TLS handshake, so it must not appear as an ALPN identifier.
- **The name is inside the existing grammar.** `site` passes agent-name
  validation unchanged; no underscored leaf, no new registry entry, no new
  record type. A domain that already runs an agent named `site` for another
  purpose is unaffected mechanically — the convention is semantic.
- **Discovery order is unchanged.** `site.<domain>` is a draft-02 flat primary
  owner — the form requestors try first — and the agent appears in
  `_index._agents.<domain>` like any other.
- **Everything else is inherited.** `port`, TargetName, and address hints keep
  their per-record RFC 9460 semantics unchanged — this convention adds a name
  and a `bap` token, nothing more.

## Publishing

CLI — the existing `publish` command covers both shapes:

```bash
# Remote MCP interface for the site's content
dns-aid publish --name site --domain example.com \
  --protocol mcp --endpoint mcp.example.com

# In-browser WebMCP surface
dns-aid publish --name site --domain example.com \
  --protocol https --endpoint example.com --bap webmcp
```

Python:

```python
from dns_aid import publish

await publish(
    name="site",
    domain="example.com",
    protocol="mcp",
    endpoint="mcp.example.com",
    capabilities=["web-content"],
    description="Canonical MCP interface to example.com's web content",
)
```

## Discovery

```python
from dns_aid.core.site_agent import discover_site_agent, is_webmcp_surface

agent = await discover_site_agent("example.com")
if agent is not None:
    if is_webmcp_surface(agent):
        print(f"Open https://{agent.target_host}/ in a WebMCP-capable browser")
    else:
        print(f"Site MCP endpoint: {agent.endpoint_url}")
```

`discover_site_agent` is a thin wrapper over `discover_at_fqdn("site.<domain>")`;
the generic paths (`dns-aid discover example.com`, `dns-aid verify
site.example.com`) work unchanged.

## Open questions

- **The name.** `site` is the strawman (role-based, mirroring how `_index`
  names a role); `web` and `webmcp` have been floated. A name that collides
  with a common hostname label is mechanically safe (SVCB is a distinct
  RRType) but semantically ambiguous; feedback welcome.
- **The marker's long-term home.** If the convention proves out, `webmcp`
  could graduate from `bap` to a registered ALPN identifier
  (Specification Required per RFC 7301, the draft's §7.3 path) — though it
  arguably never belongs in ALPN, since it is not a connection protocol.
- **Capability vocabulary.** Whether a conventional capability (e.g.
  `web-content`) should accompany the name, so index- and directory-level
  filtering can find site agents without resolving each one.
