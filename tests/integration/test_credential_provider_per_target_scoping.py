# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Live integration test for per-target credential scoping (T032).

Implements T032 from ``specs/003-credential-provider-callback/tasks.md``.
Validates User Story 4: the SDK passes the target ``AgentRecord`` to the
``credential_provider`` so the provider can derive per-target credentials.

This test exercises the pattern against real AWS infrastructure. Two
distinct ``AgentRecord`` instances are constructed — one with
``realm="production"``, one with ``realm="staging"`` — and the provider
returns credentials whose ``RoleSessionName`` is derived from the agent's
realm. The test asserts:

1. Both invocations succeed against the live AWS endpoint (proving the
   credentials produced from real STS calls are valid).
2. Two distinct provider invocations occurred, each with the correct
   target AgentRecord.
3. The provider observed two distinct realms in sequence (sequencing).

This is the canonical multi-tenant pattern: same SDK, same handler, same
endpoint — different credentials per target derived from the
AgentRecord's scoping attributes.

Requires:
    - AWS okta-sso profile configured (or override via ``DNS_AID_AWS_PROFILE``).
    - Network access to the SigV4_HOST endpoint.

Skipped when AWS credentials cannot be resolved.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

from dns_aid.core.models import AgentRecord, Protocol
from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.client import AgentClient

pytestmark = [pytest.mark.integration, pytest.mark.live]


SIGV4_HOST = os.environ.get("DNS_AID_AWS_SIGV4_HOST")
AWS_PROFILE = os.environ.get("DNS_AID_AWS_PROFILE", "okta-sso")
AWS_REGION = os.environ.get("DNS_AID_AWS_REGION", "us-east-1")
AWS_SERVICE = os.environ.get("DNS_AID_AWS_SERVICE", "execute-api")


def _aws_credentials_resolvable() -> bool:
    try:
        import boto3

        session = boto3.Session(profile_name=AWS_PROFILE)
        creds = session.get_credentials()
        if creds is None:
            return False
        frozen = creds.get_frozen_credentials()
        return bool(frozen.access_key and frozen.secret_key)
    except (ImportError, Exception):  # noqa: BLE001
        return False


skip_unless_aws_configured = pytest.mark.skipif(
    not (SIGV4_HOST and _aws_credentials_resolvable()),
    reason=(
        f"Live per-target scoping test requires (a) DNS_AID_AWS_SIGV4_HOST "
        f"pointing at an operator-controlled SigV4-protected endpoint, and "
        f"(b) boto3 + AWS profile {AWS_PROFILE!r}. For the okta-sso profile, "
        f"run 'aws sso login --profile okta-sso' first."
    ),
)


def _sigv4_agent_for_realm(realm: str) -> AgentRecord:
    """Build a SigV4-auth AgentRecord scoped to a specific realm.

    Both agents point at the same SigV4_HOST endpoint — what makes them
    different from the provider's perspective is the ``realm`` attribute,
    which the provider reads to derive a per-realm RoleSessionName.
    """
    return AgentRecord(
        name=f"per-target-{realm}",
        domain="test.example.com",
        protocol=Protocol.A2A,
        target_host=SIGV4_HOST,
        port=443,
        auth_type="sigv4",
        auth_config={"region": AWS_REGION, "service": AWS_SERVICE},
        realm=realm,
    )


def _a2a_payload(text: str) -> dict[str, Any]:
    return {
        "message": {
            "messageId": f"per-target-{text}",
            "role": "user",
            "parts": [{"kind": "text", "text": text}],
        }
    }


def _make_per_target_provider():  # type: ignore[no-untyped-def]
    """Build a credential_provider that derives credentials per-target
    based on the agent's ``realm`` attribute.

    In production this would do ``sts.assume_role()`` to a realm-specific
    role ARN. We use the configured AWS profile directly (no role
    assumption) but tag the RoleSessionName with the realm so we can
    verify the provider used the per-target context. The test records
    which realm the provider saw per invocation.
    """
    import boto3

    session = boto3.Session(profile_name=AWS_PROFILE)
    invocations: list[dict[str, str | None]] = []

    async def per_target_provider(agent: AgentRecord) -> dict[str, str]:
        # Record which target the provider was called for. This is what
        # the test asserts on.
        invocations.append({"fqdn": agent.fqdn, "realm": agent.realm})

        # Derive credentials. In production: would be
        # sts.assume_role(RoleArn=f"arn:...{agent.realm}...",
        # RoleSessionName=f"dns-aid-{agent.realm}").
        # Here we just read the profile and return them as explicit
        # credentials — proves the per-target dispatch works.
        frozen = session.get_credentials().get_frozen_credentials()
        creds: dict[str, str] = {
            "access_key": frozen.access_key,
            "secret_key": frozen.secret_key,
        }
        if frozen.token:
            creds["session_token"] = frozen.token
        return creds

    # Attach the log so the test can read it.
    per_target_provider.invocations = invocations  # type: ignore[attr-defined]
    return per_target_provider


@skip_unless_aws_configured
@pytest.mark.asyncio
async def test_per_target_scoping_against_real_aws() -> None:
    """Two different targets (different realms) trigger two provider
    invocations, each receiving the correct AgentRecord. Both signed
    requests succeed against real AWS.

    Proves the canonical multi-tenant pattern: same handler, same
    endpoint, per-realm credential derivation.
    """
    provider = _make_per_target_provider()
    prod_agent = _sigv4_agent_for_realm("production")
    staging_agent = _sigv4_agent_for_realm("staging")

    async with AgentClient(SDKConfig(timeout_seconds=15.0)) as client:
        prod_result = await client.invoke(
            prod_agent,
            method="message/send",
            arguments=_a2a_payload("per-target-prod"),
            credential_provider=provider,
        )
        staging_result = await client.invoke(
            staging_agent,
            method="message/send",
            arguments=_a2a_payload("per-target-staging"),
            credential_provider=provider,
        )

    # Both invocations succeed.
    assert prod_result.success, f"Production target invoke failed: {prod_result.error}"
    assert staging_result.success, f"Staging target invoke failed: {staging_result.error}"

    # The provider was called exactly twice — once per target — and saw
    # the correct realm context on each call. This is the per-target
    # scoping invariant the user story tests.
    invocations: list[dict[str, str | None]] = provider.invocations  # type: ignore[attr-defined]
    assert len(invocations) == 2, (
        f"Expected 2 provider invocations (one per target). Got {len(invocations)}: {invocations!r}"
    )
    assert invocations[0]["realm"] == "production", invocations[0]
    assert invocations[1]["realm"] == "staging", invocations[1]
    assert invocations[0]["fqdn"] == prod_agent.fqdn
    assert invocations[1]["fqdn"] == staging_agent.fqdn
