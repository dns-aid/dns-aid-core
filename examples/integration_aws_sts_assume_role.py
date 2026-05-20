# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
AWS STS assume-role per invoke via ``credential_provider`` callback.

This example demonstrates the canonical pattern for using
``AgentClient.invoke(credential_provider=...)`` to assume a different
AWS IAM role per call, deriving the role ARN from the target
``AgentRecord``. The resulting STS credentials are passed through to
the SigV4 handler for explicit-credential signing — no SDK-side
caching, no implicit credential resolution.

The pattern is the AWS analogue of the OAuth2 RFC 8693 example: same
``invoke(credential_provider=...)`` surface, different IdP / credential
shape underneath.

------------------------------------------------------------------------
Why per-invoke STS instead of long-lived session credentials?
------------------------------------------------------------------------

AWS STS-issued credentials are short-lived (default 1 hour, configurable
up to the role's max-session-duration). For multi-tenant workloads where
each ``AgentClient.invoke()`` targets a different AWS account or role:

    - Long-lived environment credentials cannot span multiple accounts.
    - Per-invoke assume-role keeps credentials scoped to the target.
    - Each call produces a distinct CloudTrail "AssumeRole" event with
      the agent's session name, giving complete per-call audit trail.

The SDK is uninvolved in the STS dance; the provider is application-
owned and can use boto3, aws-cli, or any other STS client.

------------------------------------------------------------------------
Required environment variables
------------------------------------------------------------------------

    AWS_PROFILE                – Source profile holding credentials with
                                  permission to assume the target role.
                                  e.g., "okta-sso"
    AWS_REGION                 – Region for STS and the target service.
                                  e.g., "us-east-1"
    AWS_ASSUME_ROLE_ARN        – ARN of the role to assume per invoke.
                                  e.g.
                                  "arn:aws:iam::123456789012:role/dns-aid-agent"
    AWS_TARGET_SERVICE         – AWS service name for SigV4 signing.
                                  e.g., "execute-api" or "lambda"
    AWS_TARGET_HOST            – Hostname of the SigV4-protected endpoint.
                                  e.g., "abc123.execute-api.us-east-1.amazonaws.com"

------------------------------------------------------------------------
Running the example
------------------------------------------------------------------------

    export AWS_PROFILE=okta-sso
    export AWS_REGION=us-east-1
    export AWS_ASSUME_ROLE_ARN=arn:aws:iam::123456789012:role/dns-aid-agent
    export AWS_TARGET_SERVICE=execute-api
    export AWS_TARGET_HOST=abc123.execute-api.us-east-1.amazonaws.com

    uv run python examples/integration_aws_sts_assume_role.py \\
        --method message/send
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from typing import Any

from dns_aid.core.models import AgentRecord, Protocol
from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.client import AgentClient

LOGGER = logging.getLogger("dns_aid.example.aws_sts")


def _env(name: str, required: bool = True, default: str | None = None) -> str | None:
    val = os.environ.get(name, default)
    if required and not val:
        print(f"ERROR: required environment variable {name} is not set.", file=sys.stderr)
        sys.exit(2)
    return val


def make_assume_role_provider(
    source_profile: str,
    region: str,
    role_arn: str,
    session_duration_seconds: int = 900,
):
    """Return a credential_provider that calls sts.assume_role per invoke.

    The closure captures the boto3 session once. The returned coroutine
    runs `sts.assume_role` synchronously inside `asyncio.to_thread` (so
    it doesn't block the event loop) and returns the STS-issued
    short-lived credentials in the shape the SigV4 handler expects.

    Each call is a distinct STS API request and produces a distinct
    CloudTrail event — this is the canonical per-invoke audit pattern.
    """
    import boto3  # local import keeps the example optional-dependency-safe

    session = boto3.Session(profile_name=source_profile, region_name=region)
    sts = session.client("sts")

    async def assume_role_provider(agent: AgentRecord) -> dict[str, Any]:
        # Build a role session name that ties the assume-role event to
        # the target agent. CloudTrail will surface this as
        # `userIdentity.sessionContext.sessionIssuer.userName` plus the
        # `userIdentity.arn` ending in `dns-aid-agent/<role_session>`.
        role_session = f"dns-aid-{agent.name}"[:64]

        LOGGER.info(
            "Assuming role %s for agent %s (session=%s, duration=%ds)",
            role_arn,
            agent.fqdn,
            role_session,
            session_duration_seconds,
        )

        # boto3 STS calls are synchronous; offload to a thread.
        def _do_assume() -> dict[str, Any]:
            return sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName=role_session,
                DurationSeconds=session_duration_seconds,
            )

        response = await asyncio.to_thread(_do_assume)
        creds = response["Credentials"]

        # The SigV4 handler accepts explicit credentials in this shape.
        return {
            "access_key": creds["AccessKeyId"],
            "secret_key": creds["SecretAccessKey"],
            "session_token": creds["SessionToken"],
        }

    return assume_role_provider


def _a2a_payload(text: str) -> dict[str, Any]:
    """Build a minimal A2A `message/send` payload for the example."""
    return {
        "message": {
            "messageId": f"sts-example-{text}",
            "role": "user",
            "parts": [{"kind": "text", "text": text}],
        }
    }


async def main() -> int:
    parser = argparse.ArgumentParser(
        description="Invoke an agent using per-call AWS STS assume-role + SigV4."
    )
    parser.add_argument(
        "--method",
        default="message/send",
        help="RPC method to invoke on the agent (default: message/send).",
    )
    parser.add_argument(
        "--text",
        default="hello from dns-aid sts example",
        help="Text body to send in the A2A message.",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    profile = _env("AWS_PROFILE")
    region = _env("AWS_REGION", default="us-east-1")
    role_arn = _env("AWS_ASSUME_ROLE_ARN")
    service = _env("AWS_TARGET_SERVICE", default="execute-api")
    host = _env("AWS_TARGET_HOST")

    assert profile is not None
    assert region is not None
    assert role_arn is not None
    assert service is not None
    assert host is not None

    # Build an AgentRecord for the SigV4-protected endpoint. In a real
    # deployment this comes from `AgentDiscoverer.discover()`; for the
    # example we construct it directly.
    agent = AgentRecord(
        name="aws-sts-example",
        domain="example.com",
        protocol=Protocol.A2A,
        target_host=host,
        port=443,
        auth_type="sigv4",
        auth_config={"region": region, "service": service},
    )

    provider = make_assume_role_provider(
        source_profile=profile,
        region=region,
        role_arn=role_arn,
    )

    async with AgentClient(config=SDKConfig(timeout_seconds=20.0)) as client:
        result = await client.invoke(
            agent=agent,
            method=args.method,
            arguments=_a2a_payload(args.text),
            credential_provider=provider,
        )

    if result.success:
        LOGGER.info("Invoke succeeded. Response: %s", result.response)
        return 0
    LOGGER.error("Invoke failed: %s", result.error)
    return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
