# DNS-AID: Background and Comparison

> **Non-normative.** This document provides background context comparing the DNS-AID approach to other agent-discovery proposals. It describes positioning of the DNS-AID *specification* (developed at the IETF), not features specific to this reference implementation. The authoritative specification is the IETF draft: https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-dnsaid/.

## vs Competing Proposals

| Approach | Problem | DNS-AID Advantage |
|----------|---------|-------------------|
| **ANS (GoDaddy)** | Centralized registry, KYC required, single gatekeeper | Federated — you control your domain, publish instantly |
| **Google (A2A + UCP)** | Discovery via Gemini/Search, payments via UCP | Neutral discovery — no platform lock-in or transaction fees |
| **.agent gTLD** | Requires ICANN approval, ongoing domain fees | Works NOW with domains you already own |
| **AgentDNS (China Telecom)** | Requires 6G infrastructure, carrier control | Works NOW on existing DNS infrastructure |
| **NANDA (MIT)** | New P2P overlay network, new ops paradigm | Uses infrastructure your DNS team already operates |
| **Web3 (ERC-8004)** | Gas fees, crypto wallets, enterprise-hostile | Free DNS queries, no blockchain complexity |
| **ai.txt / llms.txt** | No integrity verification, free-form JSON | DNSSEC cryptographic verification, structured SVCB |

## Feature Comparison

| Feature | DNS-AID | Central Registry | ai.txt |
|---------|---------|------------------|--------|
| **Decentralized** | ✅ | ❌ | ✅ |
| **Secure (DNSSEC)** | ✅ | Varies | ❌ |
| **Sovereign** | ✅ | ❌ | ✅ |
| **Standards-based** | ✅ (IETF) | ❌ | ❌ |
| **Works with existing infra** | ✅ | ❌ | ✅ |

## The Sovereignty Question

> **Who controls agent discovery?**
> - ANS: GoDaddy (US company as gatekeeper)
> - AgentDNS: China Telecom (state-owned carrier)
> - Web3: Ethereum Foundation
> - **DNS-AID: You control your own domain**
>
> DNS-AID preserves sovereignty. Organizations and nations maintain control over their own agent namespaces with no central authority that can block, censor, or surveil agent discovery.

## Google's Agent Ecosystem

Google is building a full-stack agent platform: **A2A** (communication), **UCP** (payments), and **Gemini/Search** (discovery). While A2A is an open protocol, discovery through Google surfaces means:
- Google controls visibility (pay-to-rank)
- Transaction fees via [UCP](https://developers.google.com/merchant/ucp)
- Platform dependency for reach

**DNS-AID complements A2A** by providing neutral, decentralized discovery — find agents anywhere, not just through Google.

## Understanding the .agent Domain Approach

The [Agent Community](https://agentcommunity.org/) is pursuing a `.agent` top-level domain through ICANN's [new gTLD program](https://newgtlds.icann.org/). Here's how the two approaches compare:

**How .agent Domains Would Work:**
1. Apply to ICANN for `.agent` gTLD (~$185,000 application fee)
2. Wait 9-20 months for ICANN approval process
3. Build registry infrastructure (Open Agent Registry, Inc.)
4. Sell `.agent` domains through accredited registrars
5. Users pay annual registration fees (~$15-50/year per domain)

**How DNS-AID Works:**
1. Use your existing domain (you already own `yourcompany.com`)
2. Add DNS-AID records to your zone (`_myagent._mcp._agents.yourcompany.com`)
3. Start discovering and being discovered immediately

| Factor | .agent gTLD | DNS-AID |
|--------|-------------|---------|
| **Cost to publish** | ~$15-50/year domain fee | Free (use existing domain) |
| **Time to start** | Months (gTLD launch + registration) | Minutes |
| **Who controls discovery** | Registry operator | You (your domain) |
| **Works today** | ❌ Pending ICANN approval | ✅ Works now |
| **Requires new infrastructure** | ✅ Registry, registrars | ❌ Uses existing DNS |
| **Memorable names** | ✅ `myagent.agent` | `_myagent._mcp._agents.example.com` |

**The Friendly Take:**

Both approaches share the goal of making AI agents discoverable. The `.agent` gTLD creates a dedicated namespace that's easy to remember (`mycompany.agent`), while DNS-AID leverages existing infrastructure so you can start publishing agents today.

DNS-AID doesn't require waiting for ICANN approval or paying for new domains—it works with the DNS infrastructure your organization already operates. If you own `example.com`, you can publish agents to `_myagent._mcp._agents.example.com` right now.

*Fun fact: When `.agent` domains become available, DNS-AID records will work on them too! The approaches are complementary.*
