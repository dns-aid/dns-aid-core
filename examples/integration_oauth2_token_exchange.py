# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
RFC 8693 OAuth 2.0 Token Exchange via ``credential_provider`` callback.

This example demonstrates the canonical pattern for using
``AgentClient.invoke(credential_provider=...)`` to perform RFC 8693
token exchange against any compliant OAuth 2.0 authorization server
(Keycloak, Okta, Auth0, Microsoft Entra ID, etc.). The provider is
invoked once per ``AgentClient.invoke()`` call and the resulting access
token is consumed exactly once — no SDK-side caching.

The pattern is identical across IdPs; only the token endpoint URL,
client ID/secret, and audience/scope values change.

------------------------------------------------------------------------
Audit trail
------------------------------------------------------------------------

When the agent invokes ``credential_provider`` per call, the token
returned carries the actor-vs-subject claim chain RFC 8693 prescribes:

    sub  = end user (the human on whose behalf the agent is acting)
    act  = agent (the workload identity making the call)
    azp  = the client that requested the exchange (the agent's client)

This gives downstream services a complete audit trail. Logs at the
target side can record "user U via agent A called tool T" without any
proprietary header conventions.

------------------------------------------------------------------------
Required environment variables
------------------------------------------------------------------------

    OAUTH2_TOKEN_URL          – RFC 8693 token endpoint
                                e.g. https://keycloak.example.com/realms/
                                     myrealm/protocol/openid-connect/token
    OAUTH2_CLIENT_ID          – OAuth client representing the agent
    OAUTH2_CLIENT_SECRET      – Confidential client secret (or omit
                                for public clients using PKCE)
    OAUTH2_SUBJECT_TOKEN      – A token representing the end user
                                (typically a session JWT or refresh token
                                fetched from your application's existing
                                user authentication flow)
    OAUTH2_AUDIENCE           – Optional. The target audience claim.
                                e.g. "urn:dns-aid:agent:network-specialist"

------------------------------------------------------------------------
Running the example
------------------------------------------------------------------------

    uv run python examples/integration_oauth2_token_exchange.py \\
        --domain example.com --agent-name network-specialist

The example queries DNS to discover the agent, then performs a single
``invoke()`` with the token-exchange credential provider attached.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from typing import Any

import httpx

from dns_aid.core.discoverer import AgentDiscoverer
from dns_aid.core.models import AgentRecord
from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.client import AgentClient

LOGGER = logging.getLogger("dns_aid.example.oauth2")


def _env(name: str, required: bool = True) -> str | None:
    val = os.environ.get(name)
    if required and not val:
        print(f"ERROR: required environment variable {name} is not set.", file=sys.stderr)
        sys.exit(2)
    return val


def make_rfc8693_provider(
    token_url: str,
    client_id: str,
    client_secret: str | None,
    subject_token: str,
    audience: str | None,
):
    """Return a credential_provider that performs RFC 8693 token exchange.

    The closure captures all configuration once; the returned coroutine
    is invoked once per ``AgentClient.invoke()`` call. Each call results
    in a single HTTP POST to the IdP's token endpoint and returns a
    fresh, short-lived access token.

    No tokens are cached inside the provider; the caller's application
    layer is the appropriate place to add caching with TTL/refresh
    semantics if needed (the SDK deliberately does not cache to keep the
    security model "one exchange per invoke").
    """

    async def rfc8693_provider(agent: AgentRecord) -> dict[str, Any]:
        # Build the RFC 8693 token-exchange request. The grant type is
        # the standard urn:ietf:params:oauth:grant-type:token-exchange.
        data: dict[str, str] = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": client_id,
            "subject_token": subject_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        }
        if client_secret is not None:
            data["client_secret"] = client_secret
        # Per-target audience derivation: the agent's fqdn can be used
        # to scope the resulting token to a specific resource. This is
        # what makes the provider "per-target".
        if audience is not None:
            data["audience"] = audience
        else:
            data["audience"] = f"urn:dns-aid:agent:{agent.name}"

        LOGGER.info(
            "Exchanging subject token for agent %s at %s (audience=%s)",
            agent.fqdn,
            token_url,
            data["audience"],
        )

        async with httpx.AsyncClient(timeout=10.0) as http:
            response = await http.post(token_url, data=data)
            response.raise_for_status()
            payload = response.json()

        # The handler expects {"token": "..."} for bearer auth and
        # {"access_token": "..."} for the oauth2 handler. Both are
        # accepted shapes; we use "token" here as the canonical key.
        return {"token": payload["access_token"]}

    return rfc8693_provider


async def main() -> int:
    parser = argparse.ArgumentParser(
        description="Invoke an agent using RFC 8693 token exchange per call."
    )
    parser.add_argument(
        "--domain",
        required=True,
        help="Parent domain (e.g., example.com) under which to look up the agent.",
    )
    parser.add_argument(
        "--agent-name", required=True, help="Underscored agent label (e.g., network-specialist)."
    )
    parser.add_argument(
        "--protocol",
        default="mcp",
        choices=("mcp", "a2a", "https"),
        help="Agent protocol (default: mcp).",
    )
    parser.add_argument(
        "--method",
        default="tools/list",
        help="RPC method to invoke on the agent (default: tools/list).",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    token_url = _env("OAUTH2_TOKEN_URL")
    client_id = _env("OAUTH2_CLIENT_ID")
    client_secret = _env("OAUTH2_CLIENT_SECRET", required=False)
    subject_token = _env("OAUTH2_SUBJECT_TOKEN")
    audience = _env("OAUTH2_AUDIENCE", required=False)

    # Defensive: type checker can't see _env's "required=True ⇒ str" path.
    assert token_url is not None
    assert client_id is not None
    assert subject_token is not None

    provider = make_rfc8693_provider(
        token_url=token_url,
        client_id=client_id,
        client_secret=client_secret,
        subject_token=subject_token,
        audience=audience,
    )

    # Discover the agent via DNS. This is the standard DNS-AID lookup;
    # the SVCB/TXT records must be published in DNS for it to succeed.
    discoverer = AgentDiscoverer()
    agents = await discoverer.discover(args.domain, protocol=args.protocol)
    target = next((a for a in agents if a.name == args.agent_name), None)
    if target is None:
        print(
            f"ERROR: no agent named {args.agent_name!r} under {args.domain!r}.",
            file=sys.stderr,
        )
        return 3
    LOGGER.info("Discovered agent: %s (target=%s)", target.fqdn, target.target_host)

    # Configure auth_type on the discovered record. In production this
    # would already be set via SVCB/TXT metadata; we set it here for
    # the example.
    if target.auth_type is None:
        target.auth_type = "bearer"
        target.auth_config = {"header_name": "Authorization"}

    async with AgentClient(config=SDKConfig(timeout_seconds=15.0)) as client:
        result = await client.invoke(
            agent=target,
            method=args.method,
            credential_provider=provider,
        )

    if result.success:
        LOGGER.info("Invoke succeeded. Response: %s", result.response)
        return 0
    LOGGER.error("Invoke failed: %s", result.error)
    return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
