# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Site agent convention — the domain's canonical website interface.

**Experimental.** This module implements a naming convention that is not
part of draft-mozleywilliams-dnsop-dnsaid-02; it is prototyped here in
the spirit of the draft's §5 (Future Work and Experimental Mechanisms)
and may change or be removed.

Motivation
----------
Infrastructure operators have started turning existing websites into
agent-usable surfaces on the domain owner's behalf — Cloudflare's WebMCP
developer preview (https://blog.cloudflare.com/webmcp/) enables it with
one switch, and registrars/hosting providers can do the same by fronting
a site with a remote MCP server. What is missing is a deterministic way
to *advertise* the result: DNS-AID agent names are free-form, so a
consumer wanting "the MCP interface to this domain's website" cannot
resolve it without out-of-band knowledge or an index walk.

Convention
----------
- The agent named ``site`` at a domain is, by convention, the canonical
  interface to that domain's *website content* (as opposed to task
  agents such as ``billing`` or ``chat``). Publishers MAY publish it
  like any other draft-02 flat-name agent::

      site.example.com.  IN SVCB 1 mcp.example.com. alpn="mcp" port=443

- An in-browser WebMCP surface (a page that registers tools via the
  browser's ``navigator.modelContext`` when loaded in a WebMCP-capable
  user agent) is marked with the ``bap`` token ``webmcp``. ``bap`` is
  itself experimental (draft-02 §5.1), which makes it the right
  low-friction slot for this marker — ``alpn`` keeps carrying real
  connection protocols only::

      site.example.com.  IN SVCB 1 example.com. alpn="https" port=443 key65402="webmcp"

  Both records may coexist in one RRset (one record per protocol
  surface, per draft-02 §3.1.1).

Nothing here changes the wire format: ``site`` is an ordinary agent
name under the existing grammar, and ``webmcp`` is a valid ``bap``
token under :data:`dns_aid.core.bap.BAP_VALUE_PATTERN`. This module
only gives the convention a first-class, testable home.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

import structlog

from dns_aid.core.bap import split_bap_token

if TYPE_CHECKING:
    from dns_aid.core.models import AgentRecord

logger = structlog.get_logger(__name__)

# Conventional name of the domain's canonical website agent.
# Experimental — see module docstring. The name itself is subject to
# upstream discussion (`web` and `webmcp` have been floated); consumers
# should reference this constant rather than the literal.
SITE_AGENT_NAME: Final = "site"

# ``bap`` token marking an in-browser WebMCP surface: the SVCB target
# is a web origin whose pages register tools via the browser's
# ``navigator.modelContext`` (https://github.com/webmachinelearning/webmcp)
# when loaded in a WebMCP-capable user agent.
WEBMCP_BAP_TOKEN: Final = "webmcp"


def site_agent_fqdn(domain: str) -> str:
    """Return the draft-02 flat FQDN of a domain's conventional site agent.

    >>> site_agent_fqdn("example.com")
    'site.example.com'
    """
    return f"{SITE_AGENT_NAME}.{domain.strip().rstrip('.')}"


def is_webmcp_surface(agent: AgentRecord) -> bool:
    """True when the record advertises an in-browser WebMCP surface.

    The marker is the ``webmcp`` token in ``bap`` (with or without a
    version suffix); the agent's ``alpn``/protocol keeps describing the
    plain connection protocol used to fetch the page.
    """
    token, _version = split_bap_token(agent.bap)
    return token == WEBMCP_BAP_TOKEN


async def discover_site_agent(domain: str) -> AgentRecord | None:
    """Resolve a domain's conventional site agent, if it publishes one.

    A thin wrapper over :func:`dns_aid.core.discoverer.discover_at_fqdn`
    querying the flat owner ``site.<domain>`` (the form draft-02 says
    requestors MUST try first). Returns None when the domain does not
    publish the convention.
    """
    from dns_aid.core.discoverer import discover_at_fqdn

    fqdn = site_agent_fqdn(domain)
    agent = await discover_at_fqdn(fqdn)
    if agent is None:
        logger.debug("No site agent published", domain=domain, fqdn=fqdn)
    return agent
