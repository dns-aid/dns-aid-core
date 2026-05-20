# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Live integration test for the credential_provider callback against Okta.

Implements T017 from ``specs/003-credential-provider-callback/tasks.md``.
Exercises RFC 8693 token exchange against a real Okta tenant using Okta's
Workforce Identity Cloud token-exchange grant.

Set ``OKTA_TENANT_DOMAIN`` to your own Okta tenant (e.g.,
``your-org.okta.com``). The test is skipped when this variable is unset —
there is no default tenant.

The subject token (the user's existing Okta-issued access token) is supplied
externally via the ``OKTA_SUBJECT_TOKEN`` env var rather than acquired by the
test itself. This reflects production usage: the calling application already
holds the user's access token (obtained via authorization code + PKCE during
the user's sign-in flow) and the credential_provider's job is to exchange it
for a delegation token via the actor app. Okta's newer admin UI no longer
exposes the Resource Owner Password Credentials grant for new app creation,
and OAuth 2.1 has effectively deprecated ROPC — so this test deliberately
sidesteps that grant entirely.

To obtain a subject token for the test, use any of:

    1. Authorization code + PKCE flow (with a local callback handler).
    2. Okta developer console's "Token Preview" feature on the authorization
       server, configured for a specific user.
    3. Any production token-acquisition flow you already have running.

Skipped when any required env var is missing. See
``tests/integration/fixtures/README.md`` for the Okta admin setup required
to enable token exchange on the tenant.

Tenant licensing requirement
----------------------------

Okta token exchange is part of the **Workforce Identity Cloud — Cross-App
Access (XAA) / Identity Propagation** feature set. Empirically confirmed
during feature 003 integration validation:

* A correctly-configured Custom Authorization Server (audience set, scopes
  defined, access policy with Token Exchange grant explicitly enabled) will
  accept the token-exchange request shape (subject_token, actor_token,
  audience, grant_type are all validated successfully).
* The authorization-server's well-known metadata will still NOT list
  ``urn:ietf:params:oauth:grant-type:token-exchange`` under
  ``grant_types_supported`` when XAA is not licensed on the tenant.
* Every exchange returns ``access_denied`` from the policy layer with no
  specific reason in the System Log's debugData.

If your tenant has XAA enabled, the SDK code under test is validated by the
parallel Keycloak Docker test (``test_credential_provider_oauth_keycloak.py``)
which exercises the same RFC 8693 token-exchange path against a
reproducible local Keycloak instance.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
from typing import Any

import httpx
import pytest

from dns_aid.core.models import AgentRecord, Protocol
from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.client import AgentClient

pytestmark = [pytest.mark.integration, pytest.mark.live]


# ---------------------------------------------------------------------------
# Configuration — environment variables. No tenant default is supplied;
# the operator must set OKTA_TENANT_DOMAIN to their own Okta tenant. This
# test is skipped when the tenant variable is unset.
# ---------------------------------------------------------------------------

OKTA_TENANT_DOMAIN = os.environ.get("OKTA_TENANT_DOMAIN")
OKTA_AUTH_SERVER_ID = os.environ.get("OKTA_AUTH_SERVER_ID", "default")

# Subject token — the user's pre-acquired access token. Test does not acquire
# it via ROPC because Okta's newer admin UI no longer exposes that grant for
# new app creation.
OKTA_SUBJECT_TOKEN = os.environ.get("OKTA_SUBJECT_TOKEN")

# Actor app — service-to-service client with Token Exchange grant enabled.
OKTA_ACTOR_CLIENT_ID = os.environ.get("OKTA_ACTOR_CLIENT_ID")
OKTA_ACTOR_CLIENT_SECRET = os.environ.get("OKTA_ACTOR_CLIENT_SECRET")

# Optional audience claim for the delegation token.
OKTA_TARGET_AUDIENCE = os.environ.get("OKTA_TARGET_AUDIENCE")


OKTA_TOKEN_ENDPOINT = f"https://{OKTA_TENANT_DOMAIN}/oauth2/{OKTA_AUTH_SERVER_ID}/v1/token"


# ---------------------------------------------------------------------------
# Skip conditions
# ---------------------------------------------------------------------------


_REQUIRED_VARS = {
    "OKTA_TENANT_DOMAIN": OKTA_TENANT_DOMAIN,
    "OKTA_SUBJECT_TOKEN": OKTA_SUBJECT_TOKEN,
    "OKTA_ACTOR_CLIENT_ID": OKTA_ACTOR_CLIENT_ID,
    "OKTA_ACTOR_CLIENT_SECRET": OKTA_ACTOR_CLIENT_SECRET,
}

_missing = [name for name, value in _REQUIRED_VARS.items() if not value]

skip_unless_okta_configured = pytest.mark.skipif(
    bool(_missing),
    reason=(
        f"Live Okta integration test requires env vars: "
        f"{', '.join(_missing) if _missing else '(none missing)'}. "
        f"OKTA_SUBJECT_TOKEN is the user's pre-acquired access token from the "
        f"Okta tenant (obtain via auth-code + PKCE or developer-console Token "
        f"Preview). OKTA_ACTOR_CLIENT_ID / _SECRET identify the service app "
        f"that performs the RFC 8693 exchange (Token Exchange grant must be "
        f"enabled on it). See tests/integration/fixtures/README.md."
    ),
)


# ---------------------------------------------------------------------------
# JWT helper — decode WITHOUT verification (claim inspection only)
# ---------------------------------------------------------------------------


def _decode_jwt_unverified(token: str) -> dict[str, Any]:
    """Decode a JWT's payload without verifying the signature.

    Used purely for test assertions on claim contents. NEVER use this pattern
    in production code — verify signatures via the issuer's JWKS endpoint.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT structure: expected 3 dot-separated parts, got {len(parts)}")
    payload_segment = parts[1]
    padding = "=" * (-len(payload_segment) % 4)
    decoded = base64.urlsafe_b64decode(payload_segment + padding)
    return json.loads(decoded)


def _extract_actor_identity(claims: dict[str, Any]) -> str | None:
    """Return the actor (calling agent) identity from a delegation token's claims.

    RFC 8693 §4.1 defines a standard ``act`` claim, but implementations vary:
    Keycloak v1 emits via ``azp``, Okta may emit ``act`` / ``cid`` / ``actor``
    depending on authorization-server policy. This helper centralises lookup.
    """
    act = claims.get("act")
    if isinstance(act, dict) and isinstance(act.get("sub"), str) and act["sub"]:
        return act["sub"]
    if isinstance(act, str) and act:
        return act
    azp = claims.get("azp")
    if isinstance(azp, str) and azp:
        return azp
    for fallback in ("cid", "actor"):
        value = claims.get(fallback)
        if isinstance(value, str) and value:
            return value
    return None


# ---------------------------------------------------------------------------
# Subject token retrieval (externally supplied)
# ---------------------------------------------------------------------------


def _get_user_access_token() -> str:
    """Return the externally-supplied subject token.

    pytest skips the test before this is called when OKTA_SUBJECT_TOKEN is
    unset (via the skip_unless_okta_configured marker), so this raises only
    if the marker is bypassed.
    """
    if not OKTA_SUBJECT_TOKEN:
        raise RuntimeError(
            "OKTA_SUBJECT_TOKEN env var is not set. Obtain a user access token "
            "from Okta (auth-code + PKCE, developer-console Token Preview, etc.) "
            "and export it before running this test."
        )
    return OKTA_SUBJECT_TOKEN


# ---------------------------------------------------------------------------
# Provider — RFC 8693 token exchange against Okta
# ---------------------------------------------------------------------------


async def _fetch_actor_token() -> str:
    """Acquire the actor app's own access token via client_credentials.

    Okta requires the ``actor_token`` parameter to be present in token-exchange
    requests (RFC 8693 §2.1 — Okta enforces what the RFC permits). This helper
    fetches a fresh actor token per exchange so the test exercises the full
    RFC 8693 delegation chain (user identity in subject_token + actor identity
    in actor_token).
    """
    assert OKTA_ACTOR_CLIENT_ID and OKTA_ACTOR_CLIENT_SECRET
    async with httpx.AsyncClient(timeout=10.0) as http:
        response = await http.post(
            OKTA_TOKEN_ENDPOINT,
            data={"grant_type": "client_credentials"},
            auth=(OKTA_ACTOR_CLIENT_ID, OKTA_ACTOR_CLIENT_SECRET),
        )
        if response.status_code != 200:
            raise RuntimeError(
                f"Okta actor client_credentials failed (HTTP {response.status_code}): "
                f"{response.text[:200]}. Verify the actor app is configured correctly "
                f"and DPoP is disabled."
            )
        token = response.json().get("access_token")
        if not isinstance(token, str) or not token:
            raise RuntimeError("Okta client_credentials response missing access_token")
        return token


def _make_okta_token_exchange_provider(user_token: str):  # type: ignore[no-untyped-def]
    """Build the credential_provider callable that exchanges the user's token
    for a delegation token via Okta's RFC 8693 grant.

    The actor app authenticates two ways simultaneously:
      1. HTTP Basic on the token endpoint (Okta's default client-auth).
      2. ``actor_token`` parameter carrying the actor's own access token
         (Okta requires this for token-exchange; RFC 8693 §2.1 permits it).
    """
    assert OKTA_ACTOR_CLIENT_ID and OKTA_ACTOR_CLIENT_SECRET

    async def okta_token_exchange_provider(_agent: AgentRecord) -> dict[str, str]:
        # Acquire a fresh actor_token for every exchange. Per FR-006 the SDK
        # does not cache provider returns — this provider does not cache
        # either, mirroring production usage where each invocation produces
        # a fresh delegation chain.
        actor_token = await _fetch_actor_token()

        form_data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": user_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "actor_token": actor_token,
            "actor_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
        }
        # Audience — Okta's authz server policy requires this to match a
        # configured audience on the server (not an arbitrary URI). Set
        # OKTA_TARGET_AUDIENCE to a known audience for your tenant.
        if OKTA_TARGET_AUDIENCE:
            form_data["audience"] = OKTA_TARGET_AUDIENCE

        async with httpx.AsyncClient(timeout=10.0) as http:
            response = await http.post(
                OKTA_TOKEN_ENDPOINT,
                data=form_data,
                auth=(OKTA_ACTOR_CLIENT_ID, OKTA_ACTOR_CLIENT_SECRET),
            )
            if response.status_code != 200:
                raise RuntimeError(
                    f"Okta token-exchange failed (HTTP {response.status_code}): "
                    f"{response.text[:200]}. Verify the actor app has the "
                    f"token-exchange grant enabled, the authorization server "
                    f"policy permits exchange, and OKTA_TARGET_AUDIENCE is set "
                    f"to a configured audience of the authz server. Verify the "
                    f"subject token is still valid (Okta access tokens typically "
                    f"expire in 60 minutes)."
                )
            payload = response.json()
            delegation_token = payload.get("access_token")
            if not isinstance(delegation_token, str) or not delegation_token:
                raise RuntimeError("Okta token-exchange response missing access_token")
            return {"token": delegation_token}

    return okta_token_exchange_provider


# ---------------------------------------------------------------------------
# Target AgentRecord — points at a localhost loopback that won't accept the
# request. The credential_provider path runs entirely before any HTTP call
# to the target, so we don't need a real MCP server.
# ---------------------------------------------------------------------------


def _bearer_agent_localhost() -> AgentRecord:
    return AgentRecord(
        name="okta-integration",
        domain="example.com",
        protocol=Protocol.MCP,
        target_host="127.0.0.1",
        port=1,
        capabilities=[],
        auth_type="bearer",
        auth_config={"header_name": "Authorization"},
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@skip_unless_okta_configured
@pytest.mark.asyncio
async def test_credential_provider_against_okta_token_exchange() -> None:
    """End-to-end: provider exchanges user token at Okta; SDK applies the result.

    Mirrors the Keycloak integration test (T015) but exercises Okta's
    Workforce Identity Cloud token-exchange grant against the configured
    real tenant. The SDK code under test is identical — that's the point:
    the credential_provider contract is IdP-agnostic.
    """
    user_token = _get_user_access_token()
    provider = _make_okta_token_exchange_provider(user_token)
    agent = _bearer_agent_localhost()

    credentials = await provider(agent)
    delegation_token = credentials["token"]
    claims = _decode_jwt_unverified(delegation_token)

    # The delegation token MUST carry a 'sub' identifying the user.
    assert "sub" in claims, f"Okta delegation token missing 'sub' claim: {claims}"
    user_sub = claims["sub"]
    assert isinstance(user_sub, str) and user_sub, "'sub' must be a non-empty string"

    # Actor identity is required; the exact claim name varies by IdP.
    actor_identity = _extract_actor_identity(claims)
    assert actor_identity, (
        f"Okta delegation token missing actor identity claim (act / azp / cid / actor). "
        f"Claims: {claims}. Verify the token-exchange policy on the Okta authorization "
        f"server emits the actor identity in the minted token."
    )

    # Per-invoke freshness check via the full SDK path.
    invoke_tokens: list[str] = []

    async def capturing_provider(target_agent: AgentRecord) -> dict[str, str]:
        creds = await provider(target_agent)
        invoke_tokens.append(creds["token"])
        return creds

    config = SDKConfig(timeout_seconds=2.0, caller_id="okta-integration", console_signals=False)
    async with AgentClient(config=config) as client:
        for _ in range(2):
            # Transport failure expected — no MCP server at 127.0.0.1:1.
            with contextlib.suppress(Exception):
                await client.invoke(
                    agent=agent,
                    method="tools/list",
                    credential_provider=capturing_provider,
                )

    assert len(invoke_tokens) == 2, (
        f"Expected 2 provider awaits across 2 invokes; got {len(invoke_tokens)}."
    )
    # Tokens are minted server-side per request; verify distinct jti or iat.
    claims_a = _decode_jwt_unverified(invoke_tokens[0])
    claims_b = _decode_jwt_unverified(invoke_tokens[1])
    distinct = claims_a.get("jti") != claims_b.get("jti") or claims_a.get("iat") != claims_b.get(
        "iat"
    )
    assert distinct, (
        f"Per-invoke freshness violation: two consecutive Okta token-exchange "
        f"requests returned identical tokens. claims_a={claims_a!r} claims_b={claims_b!r}"
    )


@skip_unless_okta_configured
@pytest.mark.asyncio
async def test_okta_audit_chain_user_via_agent() -> None:
    """Verify the 'user X via agent Y' audit chain composition for Okta.

    Same invariants as the Keycloak version, with the actor-claim shape
    accepted across multiple emission patterns (``act`` per RFC 8693,
    ``azp`` Keycloak-style, ``cid`` / ``actor`` per Okta-specific policy).
    """
    user_token = _get_user_access_token()
    provider = _make_okta_token_exchange_provider(user_token)
    agent = _bearer_agent_localhost()
    credentials = await provider(agent)
    claims = _decode_jwt_unverified(credentials["token"])

    user_sub = claims["sub"]
    actor_identity = _extract_actor_identity(claims)

    assert actor_identity is not None, (
        f"Could not identify the actor (calling agent) in the Okta delegation "
        f"token. Claims: {claims}. Verify the authorization-server policy "
        f"emits the actor's identity."
    )

    assert user_sub != actor_identity, (
        f"Audit chain malformed: user 'sub' ({user_sub!r}) equals actor identity "
        f"({actor_identity!r}). The user and the calling agent must be distinct."
    )

    # Optional: if Okta emits the standard 'aud' claim, verify the requested
    # audience landed in the token.
    if OKTA_TARGET_AUDIENCE and "aud" in claims:
        aud = claims["aud"]
        if isinstance(aud, list):
            assert OKTA_TARGET_AUDIENCE in aud, (
                f"Requested audience {OKTA_TARGET_AUDIENCE!r} missing from 'aud' claim list: {aud}"
            )
        else:
            assert aud == OKTA_TARGET_AUDIENCE, (
                f"'aud' claim {aud!r} does not match requested audience {OKTA_TARGET_AUDIENCE!r}"
            )
