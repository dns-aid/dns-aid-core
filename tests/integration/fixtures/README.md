# Integration Test Fixtures

Self-hosted infrastructure fixtures for `tests/integration/` live tests. Each
fixture is opt-in (gated by env vars or marker), so the unit-test loop is
unaffected.

---

## Keycloak (RFC 8693 token exchange)

Used by `tests/integration/test_credential_provider_oauth_keycloak.py` to
exercise the `credential_provider` callback against a real RFC 8693-compliant
identity provider. Spins up Keycloak in a Docker container with the
`token-exchange` preview feature enabled and bootstraps a pre-configured realm
(`dns-aid-test`) with two OAuth clients and one test user.

### Bring it up

```bash
docker compose -f tests/integration/fixtures/keycloak-compose.yml up -d
```

Wait ~30 seconds for the bootstrap, then verify:

```bash
curl -sS http://localhost:18080/realms/dns-aid-test/.well-known/openid-configuration | jq .issuer
# Expected: "http://localhost:18080/realms/dns-aid-test"
```

### Realm contents (pre-configured in `keycloak-realm.json`)

| Resource | Identifier | Role |
|---|---|---|
| Realm | `dns-aid-test` | Isolated namespace for this test |
| User | `dns-aid-test-user` | Subject — represents the human caller. Password: `test-user-password-not-for-prod` |
| Client | `dns-aid-test-agent` | Subject token issuer — used by the test to obtain the user's access token via direct-grant flow |
| Client | `dns-aid-test-actor` | Actor — represents the calling agent; service-account credentials initiate the RFC 8693 exchange |

### Environment variables consumed by the integration test

| Variable | Default | Purpose |
|---|---|---|
| `DNS_AID_KEYCLOAK_BASE_URL` | `http://localhost:18080` | Keycloak base URL |
| `DNS_AID_KEYCLOAK_REALM` | `dns-aid-test` | Realm name |
| `DNS_AID_KEYCLOAK_SUBJECT_CLIENT_ID` | `dns-aid-test-agent` | Client used to acquire the user's subject_token |
| `DNS_AID_KEYCLOAK_SUBJECT_CLIENT_SECRET` | `agent-client-secret-not-for-prod` | Secret for the subject client |
| `DNS_AID_KEYCLOAK_SUBJECT_USERNAME` | `dns-aid-test-user` | Test user's username |
| `DNS_AID_KEYCLOAK_SUBJECT_PASSWORD` | `test-user-password-not-for-prod` | Test user's password |
| `DNS_AID_KEYCLOAK_ACTOR_CLIENT_ID` | `dns-aid-test-actor` | Client representing the calling agent |
| `DNS_AID_KEYCLOAK_ACTOR_CLIENT_SECRET` | `actor-client-secret-not-for-prod` | Secret for the actor client |
| `DNS_AID_INTEGRATION_DOCKER` | unset | Set to `1` to enable Docker-dependent tests; tests skip otherwise |

### Tear it down

```bash
docker compose -f tests/integration/fixtures/keycloak-compose.yml down -v
```

The `-v` flag removes the named volume so the next bring-up reseeds the realm
cleanly.

---

## Okta (RFC 8693 token exchange against a real tenant)

Used by `tests/integration/test_credential_provider_oauth_okta.py`.

### Tenant

No default tenant is bundled with the test. Set `OKTA_TENANT_DOMAIN` to
your own Okta tenant (e.g., `your-org.okta.com`). The integration test
is skipped when this variable is unset.

### Required Okta admin setup (one-time)

1. **Authorization server**: use the `default` custom authorization server
   (path `/oauth2/default`) or create a dedicated one for the integration
   test.
2. **Subject app** (represents the user): create an OIDC web application with
   the **Resource Owner Password Credentials** grant enabled so the test can
   obtain a user access token via direct grant. (For production use, the
   subject token would come from a real user session — direct grant is purely
   for test automation.)
3. **Actor app** (represents the calling agent): create an OIDC service-to-
   service application with:
   - Grant types: `client_credentials`, **`urn:ietf:params:oauth:grant-type:token-exchange`** (Workforce Identity Cloud token-exchange grant)
   - Scopes: any scopes the test target requires
4. **Token-exchange policy**: per Okta documentation, enable token exchange
   between the subject client and the actor client on the chosen authorization
   server.

### Environment variables consumed by the integration test

| Variable | Default | Purpose |
|---|---|---|
| `OKTA_TENANT_DOMAIN` | (unset; required for live run) | Okta tenant domain (e.g. `your-org.okta.com`) |
| `OKTA_AUTH_SERVER_ID` | `default` | Path segment under `/oauth2/` |
| `OKTA_SUBJECT_CLIENT_ID` | (unset; required for live run) | Client representing the user |
| `OKTA_SUBJECT_CLIENT_SECRET` | (unset; required) | Secret for the subject client |
| `OKTA_SUBJECT_USERNAME` | (unset; required) | Test user's username |
| `OKTA_SUBJECT_PASSWORD` | (unset; required) | Test user's password |
| `OKTA_ACTOR_CLIENT_ID` | (unset; required) | Client representing the calling agent |
| `OKTA_ACTOR_CLIENT_SECRET` | (unset; required) | Secret for the actor client |
| `OKTA_TARGET_AUDIENCE` | unset | Optional audience claim for the exchanged token |

When any required variable is missing, the live Okta test is skipped with a
clear message naming what's missing.

### Known tenant requirement: Workforce Identity Cloud — Cross-App Access (XAA)

Empirically confirmed during feature 003 integration validation:

Okta's token-exchange grant (`urn:ietf:params:oauth:grant-type:token-exchange`)
is part of the **Workforce Identity Cloud — Cross-App Access / Identity
Propagation** feature set. On tenants where this feature is NOT licensed:

* The OAuth client config UI will let you check "Token Exchange" as an
  allowed grant type for the app.
* The authorization-server access-policy rule will let you check "Token
  Exchange" under Advanced > Non-interactive grants.
* The token endpoint will accept and validate the request shape
  (subject_token, actor_token, audience, scope, grant_type).
* But the authorization-server `.well-known/oauth-authorization-server`
  metadata will NOT list `urn:ietf:params:oauth:grant-type:token-exchange`
  under `grant_types_supported`.
* Every exchange call returns HTTP 403 `access_denied` with no specific
  reason in the System Log's `debugContext.debugData`.

If your tenant has the feature enabled, this test runs end-to-end. If your
tenant does NOT have the feature enabled, the SDK code under test is
validated by the parallel Keycloak Docker test, which exercises the same
RFC 8693 token-exchange path against a reproducible local Keycloak instance
(see the Keycloak section above).

To check whether your Okta tenant has XAA enabled, inspect the
authorization server's metadata:

```bash
curl -sS "https://${OKTA_TENANT_DOMAIN}/oauth2/${OKTA_AUTH_SERVER_ID}/.well-known/oauth-authorization-server" \
  | jq '.grant_types_supported | map(select(contains("token-exchange")))'
```

A non-empty result means XAA is enabled; an empty result means it isn't.

---

## Running the live tests

```bash
# All live integration tests (with env vars / Docker set up):
uv run pytest tests/integration/ -m live -x -q

# Specific test files:
uv run pytest tests/integration/test_credential_provider_oauth_keycloak.py -v
uv run pytest tests/integration/test_credential_provider_oauth_okta.py -v
```

Live tests are gated by the `live` pytest marker. The default `uv run pytest`
collection excludes them unless `-m live` is specified.
