# AWS STS Assume-Role per Invoke Example

This example demonstrates how to use the `credential_provider` callback parameter on `AgentClient.invoke()` to perform `sts.assume_role()` once per call, then sign the outbound request with SigV4 using the resulting short-lived credentials.

## What this example does

1. Reads a source AWS profile (e.g., `okta-sso`) that has permission to assume a target role.
2. Builds an async credential provider that calls `sts.assume_role()` on every invoke, with a role session name derived from the target `AgentRecord`.
3. Invokes a SigV4-protected endpoint (Lambda Function URL, API Gateway, VPC Lattice, etc.) using the STS-issued credentials. The SigV4 handler signs the request with `access_key` + `secret_key` + `session_token` from the dict the provider returned — no implicit boto3 default-chain resolution at signing time.

## Why per-invoke STS

| Long-lived env credentials | Per-invoke assume-role |
|---|---|
| Single AWS account | Multi-account / multi-tenant |
| Single role | Per-target role ARN derivation |
| No per-call audit context | Each invoke → distinct CloudTrail `AssumeRole` event |
| Credentials live in env or files | Credentials minted just-in-time, scoped to the call |

The STS session name (default `dns-aid-<agent.name>`) ties each CloudTrail event back to the agent that triggered it. This is the AWS-native analogue of the RFC 8693 `act` claim — it gives operators full attribution without proprietary header conventions.

## Quickstart

Configure your source profile (Okta SSO is a common pattern):

```bash
aws sso login --profile okta-sso
```

Set the example's environment variables:

```bash
export AWS_PROFILE=okta-sso
export AWS_REGION=us-east-1
export AWS_ASSUME_ROLE_ARN=arn:aws:iam::123456789012:role/dns-aid-agent
export AWS_TARGET_SERVICE=execute-api
export AWS_TARGET_HOST=abc123.execute-api.us-east-1.amazonaws.com
```

Run:

```bash
uv run python examples/integration_aws_sts_assume_role.py --method message/send
```

## Required environment variables

| Variable | Description |
|---|---|
| `AWS_PROFILE` | Source profile holding credentials with `sts:AssumeRole` permission on the target role. |
| `AWS_REGION` | Region for STS and the target SigV4 endpoint. |
| `AWS_ASSUME_ROLE_ARN` | ARN of the role the provider will assume per invoke. |
| `AWS_TARGET_SERVICE` | AWS service name for SigV4 (e.g., `execute-api`, `lambda`, `vpc-lattice-svcs`). |
| `AWS_TARGET_HOST` | Hostname of the SigV4-protected endpoint. |

## IAM trust policy requirements

The role at `AWS_ASSUME_ROLE_ARN` must trust the source identity. Minimal trust policy for IAM-identity-based source (e.g., an SSO role or IAM user):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::ACCOUNT_ID:role/source-identity-role"},
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringLike": {"sts:RoleSessionName": "dns-aid-*"}
      }
    }
  ]
}
```

The `StringLike` condition on `RoleSessionName` is recommended — it scopes the trust to sessions the example actually creates and lets CloudTrail filtering reliably identify DNS-AID-originated activity.

## Per-target role derivation (multi-tenant)

The example uses a single `AWS_ASSUME_ROLE_ARN`. For genuinely multi-tenant deployments, derive the role ARN from `agent.realm` (or any other attribute on the `AgentRecord`) inside the provider:

```python
async def assume_role_provider(agent: AgentRecord) -> dict[str, str]:
    role_arn = f"arn:aws:iam::123456789012:role/dns-aid-{agent.realm}"
    response = await asyncio.to_thread(
        sts.assume_role,
        RoleArn=role_arn,
        RoleSessionName=f"dns-aid-{agent.name}",
    )
    creds = response["Credentials"]
    return {
        "access_key": creds["AccessKeyId"],
        "secret_key": creds["SecretAccessKey"],
        "session_token": creds["SessionToken"],
    }
```

This is the canonical pattern from the live integration test at `tests/integration/test_credential_provider_per_target_scoping.py` — same provider, different `AgentRecord`s, different roles assumed per call.

## Production hardening

- **Cache STS credentials in the caller layer** with a TTL of `min(role_max_duration, 50_minutes)` to avoid hitting the STS API on every invoke under load.
- **Refresh proactively** (e.g., when remaining lifetime < 5 minutes) to absorb STS latency.
- **Set `DurationSeconds` to the minimum your workload needs.** The example uses 900s; shorter is better when token reuse is bounded by the invoke loop.
- **Use `ExternalId`** in the assume-role trust policy when the source and target accounts are owned by different organizations. The provider must include `ExternalId=...` in the `assume_role` call.
- **Restrict the session policy.** Pass `Policy=...` to `assume_role` with an inline policy that grants only the permissions the specific invoke needs. This implements least-privilege at the call site.

## SigV4 explicit credentials — what the SDK does with the dict

The SigV4 handler accepts the credential dict the provider returned in this exact shape:

```python
{
  "access_key":    "AKIA...",
  "secret_key":    "...",
  "session_token": "...",  # required for STS-issued, omit for IAM user keys
}
```

The handler:

1. Constructs a `botocore.credentials.ReadOnlyCredentials` from those values.
2. Wraps `botocore.auth.SigV4Auth` around them.
3. Suppresses the `botocore.auth` logger during signing — `botocore` emits the canonical request at DEBUG level, which would include `x-amz-security-token`. The SDK's reference-counted suppression prevents this leak even under concurrent invokes.
4. Discards the credentials immediately after signing. Nothing is cached.

If the provider omits `session_token`, the handler signs without one (correct for IAM user access keys). If the provider omits `access_key` or `secret_key` (but not both), construction fails with `ValueError` — partial credential supply is a programming error and surfaces synchronously.

## See also

- `examples/integration_oauth2_token_exchange.py` — sibling example for RFC 8693 OAuth 2.0 token exchange.
- `tests/integration/test_credential_provider_aws_sts.py` — live integration test against real AWS API Gateway.
- `tests/integration/test_credential_provider_per_target_scoping.py` — per-target multi-tenant pattern test.
- `docs/security-credentials.md` — full security posture, including the SigV4 botocore log-suppression mechanism.
