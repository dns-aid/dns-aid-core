# RFC 8693 OAuth 2.0 Token Exchange Example

This example demonstrates how to use the `credential_provider` callback parameter on `AgentClient.invoke()` to perform RFC 8693 OAuth 2.0 token exchange. The pattern lets agents obtain short-lived access tokens per invocation with full `sub` (user) / `act` (agent) claim chains for audit trails.

## What this example does

1. Discovers a DNS-AID agent via SVCB/TXT lookup.
2. Builds an async credential provider that performs RFC 8693 token exchange against any OAuth 2.0 authorization server.
3. Invokes the discovered agent — the SDK calls the provider once per invoke, exchanges the user's subject token for a fresh actor-scoped access token, and presents the resulting bearer to the target.

The pattern is identical across Keycloak, Okta, Auth0, Microsoft Entra ID, and any other RFC 8693-compliant IdP — only the endpoint URLs and client credentials change.

## Audit trail

The actor-vs-subject claim chain in RFC 8693 enables end-to-end audit logging without proprietary header conventions:

```
sub  = end user (the human on whose behalf the agent is acting)
act  = agent (the workload identity making the call)
azp  = the client that requested the exchange
```

Downstream services can log "user U via agent A called tool T" by parsing the standard JWT claims on the inbound bearer token.

## Quickstart against Keycloak (Docker)

The simplest reproducible IdP is Keycloak via Docker Compose. The fixtures at `tests/integration/fixtures/keycloak-compose.yml` and `tests/integration/fixtures/keycloak-realm.json` spin up a Keycloak instance with token-exchange + admin-fine-grained-authz features enabled.

```bash
# Spin up Keycloak
docker compose -f tests/integration/fixtures/keycloak-compose.yml up -d

# Fetch a subject token for the test user (resource-owner password grant
# is fine for local dev; production should use auth-code + PKCE).
SUBJECT_TOKEN=$(curl -s \
  -d "client_id=dns-aid-test-source" \
  -d "client_secret=test-source-secret" \
  -d "grant_type=password" \
  -d "username=test-user" \
  -d "password=test-password" \
  http://localhost:8080/realms/dns-aid-test/protocol/openid-connect/token \
  | jq -r .access_token)

# Run the example
export OAUTH2_TOKEN_URL=http://localhost:8080/realms/dns-aid-test/protocol/openid-connect/token
export OAUTH2_CLIENT_ID=dns-aid-test-actor
export OAUTH2_CLIENT_SECRET=test-actor-secret
export OAUTH2_SUBJECT_TOKEN=$SUBJECT_TOKEN
export OAUTH2_AUDIENCE=dns-aid-test-target

uv run python examples/integration_oauth2_token_exchange.py \
    --domain example.com --agent-name network-specialist
```

## Required environment variables

| Variable | Description |
|---|---|
| `OAUTH2_TOKEN_URL` | RFC 8693 token endpoint (e.g., `https://keycloak.example.com/realms/myrealm/protocol/openid-connect/token`) |
| `OAUTH2_CLIENT_ID` | OAuth client representing the agent (the "actor") |
| `OAUTH2_CLIENT_SECRET` | Confidential client secret. Omit for public clients using PKCE. |
| `OAUTH2_SUBJECT_TOKEN` | Token representing the end user — typically a session JWT or refresh token from your existing user authentication flow |
| `OAUTH2_AUDIENCE` | Optional. The audience claim for the resulting token. Defaults to `urn:dns-aid:agent:<agent.name>` |

## IdP-specific notes

### Keycloak
- Requires features `token-exchange:v1` and `admin-fine-grained-authz` enabled.
- Per-client token-exchange permissions must be granted via Admin REST API (see `tests/integration/fixtures/README.md`).
- Keycloak emits `azp` (authorized party) rather than the RFC-canonical `act` — both convey actor identity; the SDK is agnostic.

### Okta
- Requires Workforce Identity Cloud with the Cross-App Access (XAA) feature licensed on the tenant.
- DPoP can be required by app policy; the example does not include DPoP. Disable DPoP on the actor client for this example to work.
- Okta requires an explicit `actor_token` in some flows even though RFC 8693 allows it to be implicit.

### Auth0 / Microsoft Entra ID
- Both support token-exchange via custom grant or OBO (on-behalf-of) flows. Adapt the grant type and parameter names per their docs; the structure of the provider closure stays the same.

## Production hardening

The example shows the minimal working pattern. For production:

- **Cache the access token in the caller layer** with a TTL just below the IdP's `expires_in`, so high-throughput agents don't hit the token endpoint on every invoke. The SDK deliberately does not cache — it stays uninvolved in the credential lifecycle.
- **Refresh proactively** before expiry to absorb IdP latency spikes.
- **Handle 4xx from the IdP** distinctly from 5xx — 4xx usually means revoked or expired subject token (user must re-auth), 5xx means transient IdP unavailability (retry with backoff).
- **Apply the principle of least privilege** to the audience claim. Per-target audiences (derived from `agent.fqdn` or `agent.realm`) prevent token reuse across services.

## See also

- `examples/integration_aws_sts_assume_role.py` — sibling example for AWS STS per-invoke assume-role with SigV4.
- `docs/security-credentials.md` — full security posture document, including the audit trail flow and per-handler security matrix.
- RFC 8693 — OAuth 2.0 Token Exchange specification.
