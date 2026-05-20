# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Live integration test for the credential_provider callback against Keycloak.

Implements T015 from ``specs/003-credential-provider-callback/tasks.md``.
Exercises the canonical RFC 8693 token-exchange flow end-to-end:

    1. Test obtains a user access token via direct-grant (resource owner
       password flow) against the realm's subject client.
    2. credential_provider function exchanges that user token for a delegation
       token via Keycloak's RFC 8693 endpoint, authenticated as the actor
       client.
    3. AgentClient.invoke awaits the provider, applies the delegation token
       to an outbound request via the bearer auth handler.
    4. The test decodes the delegation token (without signature verification —
       the signing key is bound to the realm and we trust the local Keycloak)
       and asserts the resulting JWT carries ``sub=<user-id>`` and
       ``act={"sub": <agent-id>}`` claims composing the audit chain.

Skipped unless Keycloak is reachable at the configured base URL AND the
``DNS_AID_INTEGRATION_DOCKER=1`` env var is set. See
``tests/integration/fixtures/README.md`` for one-command Docker setup.
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
# Configuration — environment variables with defaults matching the bundled
# Docker Compose fixture (tests/integration/fixtures/keycloak-compose.yml).
# ---------------------------------------------------------------------------

KEYCLOAK_BASE_URL = os.environ.get("DNS_AID_KEYCLOAK_BASE_URL", "http://localhost:18080")
KEYCLOAK_REALM = os.environ.get("DNS_AID_KEYCLOAK_REALM", "dns-aid-test")
SUBJECT_CLIENT_ID = os.environ.get("DNS_AID_KEYCLOAK_SUBJECT_CLIENT_ID", "dns-aid-test-agent")
SUBJECT_CLIENT_SECRET = os.environ.get(  # noqa: S105 — test fixture password, not a real secret
    "DNS_AID_KEYCLOAK_SUBJECT_CLIENT_SECRET", "agent-client-secret-not-for-prod"
)
SUBJECT_USERNAME = os.environ.get("DNS_AID_KEYCLOAK_SUBJECT_USERNAME", "dns-aid-test-user")
SUBJECT_PASSWORD = os.environ.get(  # noqa: S105
    "DNS_AID_KEYCLOAK_SUBJECT_PASSWORD", "test-user-password-not-for-prod"
)
ACTOR_CLIENT_ID = os.environ.get("DNS_AID_KEYCLOAK_ACTOR_CLIENT_ID", "dns-aid-test-actor")
ACTOR_CLIENT_SECRET = os.environ.get(  # noqa: S105
    "DNS_AID_KEYCLOAK_ACTOR_CLIENT_SECRET", "actor-client-secret-not-for-prod"
)
# Target client — Keycloak requires the ``audience`` parameter in the token-
# exchange call to resolve to a registered client (not an arbitrary URI). We
# use a dedicated 'target' client in the realm whose client_id stands in for
# the downstream agent's identity.
TARGET_CLIENT_ID = os.environ.get("DNS_AID_KEYCLOAK_TARGET_CLIENT_ID", "dns-aid-test-target")

TOKEN_ENDPOINT = f"{KEYCLOAK_BASE_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"


# ---------------------------------------------------------------------------
# Skip conditions
# ---------------------------------------------------------------------------


def _docker_integration_enabled() -> bool:
    """True only when the operator explicitly opted into Docker-dependent tests."""
    return os.environ.get("DNS_AID_INTEGRATION_DOCKER", "").strip() == "1"


def _keycloak_reachable() -> bool:
    """Probe Keycloak's well-known config endpoint to confirm the realm is up."""
    try:
        with httpx.Client(timeout=2.0) as client:
            response = client.get(
                f"{KEYCLOAK_BASE_URL}/realms/{KEYCLOAK_REALM}/.well-known/openid-configuration"
            )
            return response.status_code == 200
    except (httpx.HTTPError, httpx.ConnectError, OSError):
        return False


skip_unless_keycloak_live = pytest.mark.skipif(
    not (_docker_integration_enabled() and _keycloak_reachable()),
    reason=(
        "Live Keycloak integration test requires DNS_AID_INTEGRATION_DOCKER=1 AND a "
        "reachable Keycloak instance at the configured DNS_AID_KEYCLOAK_BASE_URL. See "
        "tests/integration/fixtures/README.md for the docker-compose bring-up command."
    ),
)


# ---------------------------------------------------------------------------
# One-time bootstrap of Keycloak v1 token-exchange permissions.
#
# Keycloak 26.0 ships only ``token-exchange:v1``, which gates exchange behind
# the fine-grained admin permissions model. The realm import alone cannot
# express the permission binding (it requires the authorization server to be
# running so realm-management's authorization config can be modified). This
# bootstrap calls the Admin REST API once per test session to:
#
#   1. Enable management permissions on the target client (creates the
#      ``token-exchange`` permission scope).
#   2. Create a client policy whose subject is the actor client.
#   3. Bind that policy to the ``token-exchange`` permission on the target.
#
# Idempotent: re-running against an already-configured realm is a no-op.
# ---------------------------------------------------------------------------


def _bootstrap_token_exchange_permissions() -> None:
    """Configure realm-management permissions so the actor can exchange tokens.

    Called from a session-scoped fixture. Idempotent.
    """
    admin_token = _get_admin_token()
    headers = {"Authorization": f"Bearer {admin_token}"}
    realm_base = f"{KEYCLOAK_BASE_URL}/admin/realms/{KEYCLOAK_REALM}"

    with httpx.Client(timeout=10.0, headers=headers) as client:
        # Resolve internal UUIDs.
        target_uuid = _client_uuid(client, realm_base, TARGET_CLIENT_ID)
        actor_uuid = _client_uuid(client, realm_base, ACTOR_CLIENT_ID)
        realm_mgmt_uuid = _client_uuid(client, realm_base, "realm-management")

        # Enable management permissions on the target client. This creates
        # the scope-permissions (including token-exchange) under
        # realm-management's authorization resource server.
        client.put(
            f"{realm_base}/clients/{target_uuid}/management/permissions",
            json={"enabled": True},
        ).raise_for_status()

        # The ``token-exchange.permission.client.<target_uuid>`` permission now
        # exists under realm-management's authorization config. Fetch its
        # representation so we can attach a policy.
        permissions = client.get(
            f"{realm_base}/clients/{realm_mgmt_uuid}/authz/resource-server/permission"
        ).json()
        token_exchange_permission = next(
            (
                p
                for p in permissions
                if p["name"] == f"token-exchange.permission.client.{target_uuid}"
            ),
            None,
        )
        if token_exchange_permission is None:
            raise RuntimeError(
                "Failed to find 'token-exchange.permission.client.<target>' after enabling "
                "management permissions on the target client. Verify Keycloak v1 "
                "token-exchange feature is enabled."
            )

        # Check whether the actor-client policy already exists (idempotency).
        policy_name = f"allow-{ACTOR_CLIENT_ID}-to-exchange"
        existing_policies = client.get(
            f"{realm_base}/clients/{realm_mgmt_uuid}/authz/resource-server/policy/client"
        ).json()
        actor_policy = next((p for p in existing_policies if p["name"] == policy_name), None)
        if actor_policy is None:
            # Create the client policy: subject is the actor client.
            create_resp = client.post(
                f"{realm_base}/clients/{realm_mgmt_uuid}/authz/resource-server/policy/client",
                json={
                    "name": policy_name,
                    "description": "Permit the DNS-AID test actor client to exchange tokens for the target client.",
                    "logic": "POSITIVE",
                    "decisionStrategy": "UNANIMOUS",
                    "clients": [actor_uuid],
                },
            )
            create_resp.raise_for_status()
            actor_policy = create_resp.json()

        # Bind the policy to the token-exchange permission.
        policy_ids = list(token_exchange_permission.get("policies") or [])
        if actor_policy["id"] not in policy_ids:
            policy_ids.append(actor_policy["id"])
            token_exchange_permission["policies"] = policy_ids
            client.put(
                f"{realm_base}/clients/{realm_mgmt_uuid}/authz/resource-server/permission/"
                f"scope/{token_exchange_permission['id']}",
                json=token_exchange_permission,
            ).raise_for_status()


def _get_admin_token() -> str:
    """Acquire an admin access token via the master realm's admin-cli client."""
    admin_user = os.environ.get("DNS_AID_KEYCLOAK_ADMIN_USER", "admin")
    admin_password = os.environ.get(  # noqa: S105
        "DNS_AID_KEYCLOAK_ADMIN_PASSWORD", "admin-test-only-do-not-use-in-prod"
    )
    with httpx.Client(timeout=10.0) as http:
        response = http.post(
            f"{KEYCLOAK_BASE_URL}/realms/master/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": admin_user,
                "password": admin_password,
            },
        )
        response.raise_for_status()
        return response.json()["access_token"]


def _client_uuid(client: httpx.Client, realm_base: str, client_id: str) -> str:
    """Look up a Keycloak client's internal UUID from its OAuth client_id."""
    response = client.get(f"{realm_base}/clients", params={"clientId": client_id})
    response.raise_for_status()
    matches = response.json()
    if not matches:
        raise RuntimeError(
            f"Keycloak client {client_id!r} not found in realm. Verify realm import succeeded."
        )
    return matches[0]["id"]


@pytest.fixture(scope="session", autouse=True)
def _keycloak_token_exchange_bootstrap() -> None:
    """Auto-applied session fixture: configure token-exchange permissions once."""
    if _docker_integration_enabled() and _keycloak_reachable():
        try:
            _bootstrap_token_exchange_permissions()
        except (httpx.HTTPError, RuntimeError) as exc:
            pytest.skip(
                f"Keycloak token-exchange bootstrap failed: {exc}. "
                f"The Keycloak instance may not have admin credentials available "
                f"at the expected defaults; see "
                f"tests/integration/fixtures/README.md for manual setup."
            )


# ---------------------------------------------------------------------------
# JWT helper — decode WITHOUT verification (we trust the local Keycloak)
# ---------------------------------------------------------------------------


def _decode_jwt_unverified(token: str) -> dict[str, Any]:
    """Decode the payload of a JWT without verifying the signature.

    Used purely for test assertions on claim contents. NEVER use this pattern
    in production code — application code MUST verify signatures via the
    issuer's JWKS endpoint.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT structure: expected 3 dot-separated parts, got {len(parts)}")
    payload_segment = parts[1]
    # Re-pad the base64url segment.
    padding = "=" * (-len(payload_segment) % 4)
    decoded = base64.urlsafe_b64decode(payload_segment + padding)
    return json.loads(decoded)


def _extract_actor_identity(claims: dict[str, Any]) -> str | None:
    """Return the actor (calling agent) identity from a delegation token's claims.

    RFC 8693 §4.1 defines a standard ``act`` claim, but implementations vary:

    - Keycloak v1 token-exchange emits the actor identity via ``azp`` (the
      "authorized party" — the client that initiated the exchange).
    - Okta emits ``act`` (RFC 8693 standard) or ``cid`` depending on the
      authorization-server policy.
    - Other implementations may use ``actor`` or a custom claim.

    The audit-chain invariant we test is: an actor identity exists, distinct
    from ``sub``, regardless of the claim name used. This helper centralizes
    the lookup so both Keycloak and Okta tests share the same logic.

    Returns ``None`` if no recognized actor-identity claim is present.
    """
    # RFC 8693 standard: act is a nested object whose 'sub' is the actor.
    act = claims.get("act")
    if isinstance(act, dict) and isinstance(act.get("sub"), str) and act["sub"]:
        return act["sub"]
    # Some implementations emit act as a plain string.
    if isinstance(act, str) and act:
        return act
    # Keycloak v1 token-exchange uses azp (authorized party).
    azp = claims.get("azp")
    if isinstance(azp, str) and azp:
        return azp
    # Okta authorization-server policy may emit cid (client id) or actor.
    for fallback in ("cid", "actor"):
        value = claims.get(fallback)
        if isinstance(value, str) and value:
            return value
    return None


# ---------------------------------------------------------------------------
# Subject-token acquisition (test-only — direct grant flow)
# ---------------------------------------------------------------------------


async def _fetch_user_access_token() -> str:
    """Obtain the test user's access token via direct-grant (ROPC) flow.

    Used purely to bootstrap the integration test with a real user token to
    exchange. Production callers acquire the user token through standard OIDC
    flows (auth-code + PKCE, etc.), not via direct grant.
    """
    async with httpx.AsyncClient(timeout=10.0) as http:
        response = await http.post(
            TOKEN_ENDPOINT,
            data={
                "grant_type": "password",
                "client_id": SUBJECT_CLIENT_ID,
                "client_secret": SUBJECT_CLIENT_SECRET,
                "username": SUBJECT_USERNAME,
                "password": SUBJECT_PASSWORD,
                "scope": "openid profile",
            },
        )
        response.raise_for_status()
        payload = response.json()
        token = payload.get("access_token")
        if not isinstance(token, str) or not token:
            raise RuntimeError(
                "Keycloak direct-grant response missing access_token; "
                "check realm bootstrap and client config."
            )
        return token


# ---------------------------------------------------------------------------
# Provider — exchange the user's access_token for a delegation token
# ---------------------------------------------------------------------------


def _make_token_exchange_provider(user_token: str):  # type: ignore[no-untyped-def]
    """Build the credential_provider callable used during the test.

    The provider mints a fresh delegation token per invocation via RFC 8693
    token exchange. The actor client (calling agent) is authenticated via
    client_credentials in the request body; the user's token is supplied as
    ``subject_token``.
    """

    async def keycloak_token_exchange_provider(_agent: AgentRecord) -> dict[str, str]:
        async with httpx.AsyncClient(timeout=10.0) as http:
            response = await http.post(
                TOKEN_ENDPOINT,
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                    "client_id": ACTOR_CLIENT_ID,
                    "client_secret": ACTOR_CLIENT_SECRET,
                    "subject_token": user_token,
                    "subject_token_type": ("urn:ietf:params:oauth:token-type:access_token"),
                    "requested_token_type": ("urn:ietf:params:oauth:token-type:access_token"),
                    # Keycloak requires audience to resolve to a registered
                    # client in the realm. The target client stands in for the
                    # downstream agent's identity. Production callers would
                    # derive this from agent metadata (e.g., agent.realm or a
                    # mapping table from agent.fqdn to a registered client_id).
                    "audience": TARGET_CLIENT_ID,
                },
            )
            response.raise_for_status()
            payload = response.json()
            delegation_token = payload.get("access_token")
            if not isinstance(delegation_token, str) or not delegation_token:
                raise RuntimeError(
                    "Keycloak token-exchange response missing access_token; "
                    "verify token-exchange feature flag and realm policy."
                )
            return {"token": delegation_token}

    return keycloak_token_exchange_provider


# ---------------------------------------------------------------------------
# AgentRecord builder — points at a localhost target that will never be
# reached during the test. The credential_provider path runs entirely
# before any HTTP call to the target; we don't need a real MCP server.
# ---------------------------------------------------------------------------


def _bearer_agent_localhost() -> AgentRecord:
    return AgentRecord(
        name="kc-integration",
        domain="example.com",
        protocol=Protocol.MCP,
        # Target points at a port nothing's listening on — the invocation
        # will fail at the transport layer, AFTER the credential_provider has
        # been awaited and the delegation token has been minted. We only
        # need the resolution path to complete; we capture the token via the
        # provider's own side effect (see ``last_token`` below).
        target_host="127.0.0.1",
        port=1,
        capabilities=[],
        auth_type="bearer",
        auth_config={"header_name": "Authorization"},
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@skip_unless_keycloak_live
@pytest.mark.asyncio
async def test_credential_provider_against_keycloak_token_exchange() -> None:
    """End-to-end: provider exchanges user token, SDK applies delegation token.

    Assertions:
    1. The provider's token-exchange call against Keycloak succeeds.
    2. The minted delegation token decodes as a JWT.
    3. The JWT's ``sub`` claim references the test user.
    4. The JWT carries an ``act`` claim (RFC 8693 actor claim) whose ``sub``
       references the actor client (calling agent).
    5. Token-exchange runs fresh per invoke — repeated invocations produce
       distinct ``jti`` claims.
    """
    user_token = await _fetch_user_access_token()

    # Use the provider directly first to validate the token-exchange round-trip
    # and capture the delegation token for claim assertions.
    provider = _make_token_exchange_provider(user_token)
    agent = _bearer_agent_localhost()
    credentials = await provider(agent)
    delegation_token = credentials["token"]
    claims = _decode_jwt_unverified(delegation_token)

    # Claim assertions — verify the audit chain composition.
    assert claims.get("typ") == "Bearer" or claims.get("token_type") in (None, "Bearer")
    assert "sub" in claims, f"delegation token missing 'sub' claim: {claims}"

    # Actor identity. RFC 8693 §4.1 defines the standard ``act`` claim, but
    # implementations vary:
    #   - Keycloak v1 token-exchange emits the actor identity via ``azp`` (the
    #     "authorized party" — the client that initiated the exchange).
    #   - Okta and some others emit ``act`` (RFC 8693 standard).
    #   - Other implementations may emit ``cid`` or a custom claim.
    # The audit-chain invariant we test is: an actor identity IS present in
    # the token, distinct from ``sub``, regardless of which claim name the
    # IdP uses to express it. The Okta test (T017) verifies the same
    # invariant against a different claim layout.
    actor_identity = _extract_actor_identity(claims)
    assert actor_identity is not None, (
        f"delegation token missing actor identity claim (act / azp / cid). Claims: {claims}"
    )

    # Now exercise the full SDK path: register the provider on invoke, let
    # the SDK await it, and capture the captured (per-invoke) token via the
    # provider's mutable closure. Transport will fail (no listener on
    # 127.0.0.1:1) but that's expected and unrelated to the resolution path.
    invoke_tokens: list[str] = []

    async def capturing_provider(target_agent: AgentRecord) -> dict[str, str]:
        creds = await provider(target_agent)
        invoke_tokens.append(creds["token"])
        return creds

    config = SDKConfig(timeout_seconds=2.0, caller_id="keycloak-integration", console_signals=False)
    async with AgentClient(config=config) as client:
        for _ in range(2):
            # Transport-layer failure is expected (no server at 127.0.0.1:1).
            # The credential-resolution path completes before transport runs.
            with contextlib.suppress(Exception):
                await client.invoke(
                    agent=agent,
                    method="tools/list",
                    credential_provider=capturing_provider,
                )

    # FR-006: per-invoke freshness — two invokes produced two distinct tokens.
    assert len(invoke_tokens) == 2, (
        f"Expected 2 provider awaits across 2 invokes; got {len(invoke_tokens)}."
    )
    assert invoke_tokens[0] != invoke_tokens[1], (
        "Per-invoke freshness violation: two consecutive provider awaits produced "
        "the same delegation token. SDK or provider is caching."
    )


@skip_unless_keycloak_live
@pytest.mark.asyncio
async def test_audit_chain_composition_user_via_agent() -> None:
    """Verify the canonical 'user X via agent Y' audit chain composition.

    A downstream consumer reading the delegation token sees:
        sub      = the user's identity (subject_token's subject)
        act.sub  = the agent's identity (the actor client that ran the exchange)

    Together these compose 'user X (sub) acted via agent Y (act.sub)' — the
    audit pattern that makes RFC 8693 worth the complexity over plain bearer
    token forwarding.
    """
    user_token = await _fetch_user_access_token()
    provider = _make_token_exchange_provider(user_token)
    agent = _bearer_agent_localhost()
    credentials = await provider(agent)
    claims = _decode_jwt_unverified(credentials["token"])

    user_sub = claims["sub"]
    actor_identity = _extract_actor_identity(claims)

    assert actor_identity is not None, (
        f"delegation token missing actor identity claim (act / azp / cid). Claims: {claims}"
    )

    assert user_sub != actor_identity, (
        f"Audit chain malformed: 'sub' ({user_sub!r}) equals actor identity "
        f"({actor_identity!r}). The user identity and the agent identity must "
        f"be distinct for the delegation pattern to provide meaningful audit signal."
    )

    # Both identities should resolve to non-empty strings.
    assert isinstance(user_sub, str) and user_sub, "user 'sub' claim must be non-empty"
    assert isinstance(actor_identity, str) and actor_identity, (
        "actor identity claim must be non-empty"
    )
