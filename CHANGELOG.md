# Changelog

All notable changes to DNS-AID will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.21.2] - 2026-05-22

### Fixed

- **Route 53 backend ignored `ROUTE53_ZONE_ID` env var**: `Route53Backend.__init__`
  read `AWS_REGION` from the environment but silently dropped `ROUTE53_ZONE_ID`,
  even though `dns_aid/cli/backends.py` advertised the variable as "auto-detected
  if omitted." The CLI (`dns-aid publish`) and the MCP server both construct the
  backend via `create_backend("route53")`, which calls `Route53Backend()` with no
  keyword arguments — so callers who set only the env var always fell through to
  a `ListHostedZones` paginated API call, requiring the broader
  `route53:ListHostedZones` IAM permission and adding an avoidable round-trip to
  every publish.

  Route 53 was the only backend with this gap — every other backend
  (`Cloudflare`, `NS1`, `Cloud DNS`, `BloxOne`, `NIOS`, `DDNS`) already used the
  `kwarg or os.environ.get(VAR)` pattern. The fix brings Route 53 into line.

  **Fix**: `self._zone_id = zone_id or os.environ.get("ROUTE53_ZONE_ID")` in
  `src/dns_aid/backends/route53.py`. Explicit `zone_id=` kwarg continues to take
  precedence; env var is consulted only when the kwarg is unset. No API change,
  no behavior change for callers who already passed `zone_id` explicitly.

  **Operational benefit**: callers who set `ROUTE53_ZONE_ID` can now scope their
  IAM policy to `route53:ChangeResourceRecordSets` on the specific zone and skip
  the `route53:ListHostedZones` grant. The fallback path (no kwarg, no env var)
  still works unchanged — `_get_zone_id()` discovers the zone via API when
  `self._zone_id` is unset.

### Tests

- New `tests/unit/test_route53_backend.py` cases pin the contract:
  `test_init_no_zone_id_no_env`, `test_init_zone_id_from_env`,
  `test_init_kwarg_wins_over_env` (precedence), plus a new test class
  `TestRoute53GetZoneIdEnvShortCircuit::test_get_zone_id_short_circuits_on_env_var`
  that asserts no boto3 client is constructed when the env var alone supplies
  the zone ID.
- `TestRoute53FactoryWiring::test_factory_with_env_var` /
  `test_factory_without_env_var` cover the `create_backend("route53")` factory
  path the CLI and MCP server both use.
- `TestRoute53AdvertisedEnvContract::test_route53_zone_id_in_optional_env_registry`
  pins the docs/code contract — if a future change drops `ROUTE53_ZONE_ID` from
  `BACKEND_REGISTRY` or stops honoring it, the test fails.
- Live integration verified against AWS Route 53: CLI (`dns-aid publish`), MCP
  server (`publish_agent_to_dns` tool), and direct SDK use all honor the env
  var; control case without the env var still falls through to API discovery.

## [0.21.1] - 2026-05-20

### Fixed

- **DDNS backend `list_records()` yield shape ([#137](https://github.com/infobloxopen/dns-aid-core/issues/137))**:
  `DDNSBackend.list_records()` previously yielded one dict per rdata with a
  singular `data: str(rdata)` key, diverging from every other backend
  (Route53, Cloudflare, NS1, Cloud DNS, BloxOne, NIOS, Mock) which yield
  one dict per RRset with a `values: list[str]` key per the documented
  contract. `core.indexer.read_index()` reads `values` per the contract,
  so the divergent shape made existing index entries invisible to
  DDNS-backed zones — each `publish_agent()` call overwrote the index TXT
  record with only its own entry instead of merging.

  Discovered and diagnosed by external contributor
  [@yiyuandao](https://github.com/yiyuandao). The DDNS multi-agent +
  `read_index()` scenario was never exercised by the existing BIND9
  integration test, which only published single agents.

  Fix: DDNS now groups all rdata at a `(name, type)` tuple into a single
  yielded dict with `values: list[str]`, matching the contract.

### Tests

- Two new unit tests in
  `tests/unit/test_ddns_backend.py::TestDDNSBackendListRecords`:
  `test_list_records_yields_values_list_not_data_string` (pins the
  yield-shape contract) and `test_list_records_groups_multiple_rdata_into_one_dict`
  (pins the grouping behavior — N rdata at one (name, type) → 1 yielded
  dict, not N).
- New live integration test
  `tests/integration/test_ddns.py::TestDDNSBackend::test_multi_agent_index_merging`
  publishes two agents through DDNS and asserts the merged index TXT
  record contains both. Closes the test-matrix hole that allowed #137 to
  ship in the first commit (2026-01-16) and survive every release since.

## [0.21.0] - 2026-05-19

> Lazy credential resolution via `credential_provider` callback — enables RFC 8693
> token exchange, AWS STS assume-role, and other per-invoke credential minting
> patterns through a single opt-in callback. Extends `SigV4AuthHandler` with
> explicit AWS credentials so the same SDK contract works uniformly across all
> six authentication handlers. Strictly additive — every existing call site
> continues to function unchanged.

### Added

- **`credential_provider` keyword parameter** on `AgentClient.invoke()` — an
  opt-in async callable that takes the target `AgentRecord` and returns a
  credentials dict, awaited lazily at invoke time. Suited for short-lived
  delegation tokens (RFC 8693 token exchange against Keycloak, Okta, Auth0,
  Ping Identity, and any other RFC 8693-compliant IdP), AWS STS assume-role
  per invocation, HashiCorp Vault dynamic secrets, and HSM/KMS-backed
  signing keys. Precedence:
  `auth_handler > credentials > credential_provider > no_auth`.
- **`CredentialProviderError` exception class** in `dns_aid.sdk.exceptions` —
  wraps provider-side failures with the original exception preserved via
  `__cause__` for debugging. The wrapper's serialised surface (`str`,
  `repr`, `args`) contains no credential values from the provider's return
  dict, guaranteed by sentinel-based regression tests.
- **`SigV4AuthHandler` explicit-credentials extension** — three new optional
  keyword arguments (`access_key`, `secret_key`, `session_token`) on the
  constructor enable per-invoke STS credentials supplied directly by the
  application instead of the boto3 default credential chain. The existing
  boto3 chain remains the fallback when explicit credentials are not
  supplied (backward-compatible default behavior preserved).
- **`SDKConfig.credential_provider_timeout`** — bounds the await on the
  `credential_provider` callback. Default 30 seconds; configurable via env
  var `DNS_AID_CREDENTIAL_PROVIDER_TIMEOUT`. Hanging providers surface as
  `CredentialProviderError` with the underlying `TimeoutError` preserved as
  `__cause__`.
- **`docs/security-credentials.md`** — first-class security posture
  document with a per-handler security matrix covering all six auth
  handlers. Reviewers can answer the eight standard credential-handling
  questions (logging, caching, exception sanitisation, concurrency, opt-in
  compatibility, audit trail, air-gapped operation, FIPS / FedRAMP
  alignment) in under one hour of code inspection.
- **`docs/architecture.md` — "Caller-side credential application" section**
  documenting the three resolution paths and the SDK's credential-handling
  boundary.

### Changed

- `AgentClient._resolve_auth()` is now async and accepts the new
  `credential_provider` parameter. Backward-compatible: existing callers
  going through `AgentClient.invoke()` are unaffected.
- `SigV4AuthHandler` constructor accepts three new optional keyword
  arguments (`access_key`, `secret_key`, `session_token`) — additive.
  Every pre-existing constructor call pattern continues to work without
  source change. Verified by `tests/unit/sdk/test_sigv4_backward_compat.py`.

### Security

- **botocore.auth DEBUG-level session-token leak suppressed** during SigV4
  signing. botocore's `SigV4Auth.add_auth()` logs the canonical request at
  DEBUG level, which includes the `x-amz-security-token` header value (the
  STS session token). Any application running with botocore at DEBUG level
  would otherwise leak session tokens. The SDK temporarily disables the
  `botocore.auth` logger for the duration of the signing call, using a
  reference-counted thread-safe suppression so concurrent SigV4 signings
  cannot corrupt the logger state. Verified by sentinel-based regression
  tests.
- **Provider exception sanitisation**: when the `credential_provider`
  callback raises, the SDK wraps the exception in `CredentialProviderError`
  with the original exception preserved as `__cause__`. The wrapper's
  serialised surface contains no credential values from the provider's
  return dict.
- **Provider return-shape validation**: a `credential_provider` that
  returns a non-dict value (raw string, list, etc.) surfaces a clear
  `CredentialProviderError` naming the wrong type — instead of a cryptic
  downstream failure in the auth registry.
- **Cancellation passthrough**: `asyncio.CancelledError` from the provider
  is propagated cleanly without being wrapped in
  `CredentialProviderError`, preserving cooperative cancellation patterns
  at the caller.
- **`SigV4AuthHandler` validation messages credential-clean**: partial
  credential supply (e.g., `access_key` without `secret_key`) raises
  `ValueError` with a static message; supplied credential values never
  appear in the error.
- **`SigV4AuthHandler` empty / whitespace credentials rejected at
  construction**: supplying `access_key=""`, `secret_key=""`, or
  `session_token=""` (or whitespace-only equivalents) raises `ValueError`
  with a credential-clean message instead of producing a confusing
  botocore canonical-request error at signing time. Field name is named
  in the error; supplied value never appears.
- **Generic provider-failure observability log**: when the
  `credential_provider` callback raises a non-timeout exception, the SDK
  now emits a `sdk.credential_provider_failed` debug log carrying the
  exception **type name only** (never the message or args, which a buggy
  provider could populate with credential material). Symmetric with the
  existing `sdk.credential_provider_timeout` log so operators get
  per-handler debug traces for any provider failure mode.
- **Documented disputed CVE-2025-45768** (`pyjwt 2.12.1`). This CVE is
  disputed by the pyjwt maintainer per the
  [NVD entry](https://nvd.nist.gov/vuln/detail/CVE-2025-45768) ("Analyzed"
  status, with the supplier's note that the key length is chosen by the
  application, not the library). The maintainer's own pyjwt Security
  Advisories list does not include CVE-2025-45768; Snyk's vulnerability
  database does not list it either. DNS-AID does not generate JWTs in
  the SDK path. Suppressed in `pip-audit` per the established repo
  pattern with a per-CVE rationale comment; publicly acknowledged in
  `SECURITY.md` "Accepted dependency vulnerabilities" section with the
  full dispute context. Re-evaluation tracked at
  [#141](https://github.com/infobloxopen/dns-aid-core/issues/141).

### Tests

- 70 new unit tests across `tests/unit/sdk/` covering precedence,
  per-handler security regressions, error sanitisation, concurrency,
  hardening invariants, SigV4 explicit-credentials behavior selection
  table, and backward-compatibility locks.
- Live integration tests:
  - **Keycloak Docker**
    (`tests/integration/test_credential_provider_oauth_keycloak.py`):
    end-to-end RFC 8693 token exchange against a locally-spun-up
    Keycloak. Bundled `docker-compose.yml` makes the test reproducible
    without a paid SaaS tenant.
  - **Okta tenant**
    (`tests/integration/test_credential_provider_oauth_okta.py`): RFC 8693
    token exchange against a real Okta Custom Authorization Server.
    Documented tenant-licensing requirement (Workforce Identity Cloud
    Cross-App Access).
  - **AWS STS**
    (`tests/integration/test_credential_provider_aws_sts.py`): live
    validation against real AWS API Gateway with IAM auth. Three passing
    tests verify explicit-credentials signing, per-invoke freshness, and
    log-suppression non-interference with real signing.
  - **Per-target scoping**
    (`tests/integration/test_credential_provider_per_target_scoping.py`):
    live multi-tenant test that constructs two `AgentRecord`s with
    distinct `realm` values and asserts the provider is invoked exactly
    once per target with the corresponding agent context. Proves the
    multi-tenant invariant against real AWS.
- 3 new unit tests in
  `tests/unit/sdk/test_credential_provider_per_target.py` covering
  provider receives the correct `AgentRecord`, per-target derivation
  from agent attributes, and sequencing across multiple targets without
  state contamination.
- 6 new unit tests in `tests/unit/sdk/test_sigv4_explicit_credentials.py`
  covering empty / whitespace credential rejection (access_key,
  secret_key, session_token) plus a sentinel-based credential-clean
  invariant for the ValueError messages.
- 1 new unit test in `tests/unit/sdk/test_credential_provider_hardening.py`
  covering the `sdk.credential_provider_failed` debug log: asserts the
  exception type name is logged but the exception's args (which the test
  populates with a sentinel) never appear in any captured log event.

### Chore

- Lint sweep across `tests/` and `examples/` — resolved 52 pre-existing
  ruff findings (35 auto-fixed; 17 manual: 10 `E741` `l → line` renames
  in policy zone tests, 4 `F841` unused-locals, 2 `N805` deliberate
  `inner_self` nested-handler exceptions with `noqa`, 1 `B017` narrowed
  to `pydantic.ValidationError`). Mandatory CI gate (`ruff check src/`)
  was already clean.

### Documentation

- New: `docs/security-credentials.md` (centrepiece security posture
  document). Includes a Mermaid sequence diagram of the RFC 8693
  token-exchange flow, a decoded delegation-JWT payload showing the
  actor / subject claim chain (`sub` / `act` / `azp` / `aud`), and a
  "Known limitations" subsection naming proof-of-possession bindings
  (RFC 9449 DPoP, mTLS, FAPI PAR) that require a custom `auth_handler`
  override today.
- New: `examples/integration_oauth2_token_exchange.py` and its
  companion `.README.md` — canonical RFC 8693 token-exchange pattern
  with audit-trail explanation and per-IdP notes (Keycloak / Okta /
  Auth0 / Microsoft Entra ID).
- New: `examples/integration_aws_sts_assume_role.py` and its companion
  `.README.md` — canonical per-invoke STS assume-role pattern with SigV4
  signing, multi-tenant role derivation, and production-hardening
  guidance.
- New: `tests/integration/fixtures/keycloak-compose.yml`,
  `keycloak-realm.json`, and `README.md` documenting bring-up flow and
  per-IdP setup requirements.
- Updated: `docs/architecture.md` adds a "Caller-side credential
  application" section.
- New: `scripts/audit_credential_handling.py` — static analysis sweep
  for credential-shaped attribute names in `structlog` calls. Zero
  findings against the SDK source; suitable for use as a CI safety
  gate.

## [0.20.0] - 2026-05-09

### Security

- **DCV verifier hardened to fail-closed**: `verify()` now requires an explicit `expiry=` field; missing, malformed, or `"never"` expiry values return `verified=False` instead of silently passing. Bare-string tokens (no `token=` prefix) are no longer accepted. All five confirmed exploits from the security review are closed.
- **`bnd-req` enforcement**: `verify()` accepts a new `expected_bnd_req` parameter; when supplied, the record's `bnd-req` field must match exactly, preventing cross-vendor token reuse (DCV hazard H2). CLI and MCP tool updated accordingly.
- **`agent_name` injection prevented**: `issue()` now validates `agent_name` through `validate_agent_name()` before embedding it in the `bnd-req` field, blocking space-separated RDATA injection.
- **Constant-time token comparison**: Token matching in `verify()` uses `hmac.compare_digest()` to mitigate timing side-channel attacks.
- **Nameserver validated as IP address**: `verify()` rejects non-IP nameserver values and returns a `DCVVerifyResult` with an error instead of raising an unhandled exception.
- **`nameserver` removed from MCP tool**: `dcv_verify_challenge` no longer exposes the nameserver parameter to LLMs (SSRF risk); it remains in the Python API for testbed use.
- **MCP tools hardened**: All four DCV tools now wrap exceptions and return `{"success": False, "error": <safe message>}`; backend errors are logged server-side and never returned as raw `str(e)`. `success` key added to all responses. `readOnlyHint` and `idempotentHint` corrected.
- **`revoke()` scoped to token**: `revoke()` now requires a `token` parameter and confirms the token is present in DNS before deleting, reducing the risk of racing a concurrent challenger's record.
- **DoS guard**: `verify()` limits TXT record iteration to `MAX_CHALLENGE_RECORDS = 10` and sets `resolver.lifetime = 4.0`.
- **OS DNS cache bypassed**: `resolver.cache = None` in `verify()` prevents stale cached positives from surviving after `revoke()`.

### Fixed

- **Cloudflare TXT quoting bug**: `CloudflareBackend.create_txt_record()` was wrapping content in literal `"..."` characters, causing verification to always fail on Cloudflare zones. Content is now passed raw.
- **Async resolver**: `verify()` was calling the synchronous `dns.resolver.Resolver`, blocking the event loop. Switched to `dns.asyncresolver.Resolver` with `await`, consistent with `discoverer.py`.
- **`_parse_txt_value` quote stripping**: Strips one layer of RFC-1035-style outer quotes (Cloudflare's wrapping) before parsing. First-wins semantics for duplicate keys (was: last-wins). Bare-value token fallback removed.
- **Library-level input validation**: `issue()`, `place()`, and `revoke()` now call `validate_domain()` / `validate_ttl()` / token shape check internally; direct Python API callers get the same protection as CLI and MCP callers.
- **DCV TTL cap**: Maximum challenge validity capped at `MAX_DCV_TTL_SECONDS = 86400` (24 h) in `issue()` and `place()`, separate from the general 7-day DNS TTL cap.
- **Namespace collision**: `issue`, `place`, `revoke` exported from `core/__init__.py` as `dcv_issue`, `dcv_place`, `dcv_revoke` (matching the existing `dcv_verify` alias) to avoid collision with future top-level names.
- **All failed verifications now logged at WARNING** with domain, fqdn, and reason.
- **`--port` always validated** in `dns-aid dcv verify`, even without `--nameserver`.
- **`--json` output** added to `dns-aid dcv place` and `dns-aid dcv revoke`.
- **`dns-aid dcv revoke`** now accepts a required `TOKEN` argument.
- **`expiry=` datetime normalization**: `_build_txt_value` calls `.astimezone(UTC)` defensively to reject naive datetimes. Python 3.11 native `fromisoformat()` used for parsing (no `.replace("Z", "+00:00")` workaround).

### Tests

- 46 unit tests (was: 25) — added regression test for every confirmed exploit and every previously untested code path: missing expiry, malformed expiry, `expiry=never`, bare-string token, invalid nameserver, Cloudflare-quoted records, bnd-req enforcement, `MAX_CHALLENGE_RECORDS` guard, multi-string TXT records, multi-record iteration (expired-then-valid), backend raise on `place()` and `revoke()`, token shape validation.
- All `verify()` tests updated from `dns.resolver.Resolver` patch to `dns.asyncresolver.Resolver` with `AsyncMock`.

## [0.19.0] - 2026-05-11

> SDK Search Wrapper — extends the SDK with two coherent search surfaces: in-memory
> filters on Path A `discover()` for already-fetched agents, and a new opt-in Path B
> `AgentClient.search()` for cross-domain queries against a configured directory backend.

### Added

#### Path B (new) — cross-domain search via opt-in directory backend

- **`AgentClient.search(...)` method**: GET `{directory_api_url}/api/v1/search` and return a typed
  `SearchResponse`. Supports filters `q`, `protocol`, `domain`, `capabilities`, `min_security_score`,
  `verified_only`, `intent`, `auth_type`, `transport`, `realm`, `limit`, `offset`. Maps every
  failure mode to a typed exception so callers can dispatch on `DirectoryConfigError`,
  `DirectoryAuthError`, `DirectoryRateLimitedError`, `DirectoryUnavailableError`.
- **New typed models** in `dns_aid.sdk.search`:
  - `SearchResponse` — query echo, ranked results, pagination state, `has_more` /
    `next_offset` helpers.
  - `SearchResult` — agent + relevance score + trust attestation + optional provenance.
  - `TrustAttestation` — `security_score` / `trust_score` / `popularity_score` /
    `trust_tier` / `safety_status` / per-signal verification flags
    (`dnssec_valid` / `dane_valid` / `svcb_valid` / `endpoint_reachable` /
    `protocol_verified`) / `threat_flags` / `breakdown` / `badges`.
  - `Provenance` — `discovery_level`, `first_seen`, `last_seen`, `last_verified`,
    `company`. All faithful mirrors of the directory's
    `dns_aid_directory.api.schemas.AgentResponse` flat shape.
- **`dns-aid search` CLI subcommand**: every Path B filter as a flag with
  human-readable + `--json` output, exit codes per BSD `sysexits.h` (75 transient,
  77 auth, 78 config).
- **`search_agents` MCP tool**: structured `success: true/false` envelope (never raises
  to the transport); error classes `directory_not_configured`,
  `directory_unavailable`, `directory_rate_limited`, `directory_auth_failed`,
  `invalid_arguments` map 1:1 with SDK exceptions.
- **Wire-shape adapter** (`dns_aid.sdk.client._adapt_search_payload`): translates the
  directory's flat `AgentResponse` into the SDK's typed nested objects. Lifts trust +
  provenance signals, derives `target_host` from `endpoint_url`, splits comma-separated
  `bap` strings into lists, strips explicit nulls so Pydantic defaults apply. Localizes
  every wire-shape quirk in one place — directory schema drift only requires updating
  this helper.
- **`SDKConfig.directory_api_url`** field + `DNS_AID_SDK_DIRECTORY_API_URL` env var.
  Existing `telemetry_api_url` continues to work as a deprecation alias and emits one
  `DeprecationWarning` per process; when both are set, `directory_api_url` wins.
- **`SDKConfig.resolved_directory_url`** property — single source of truth that
  `search()`, `fetch_rankings()`, and the telemetry signal push all read from.

#### Path A (extension) — in-memory filters on already-fetched agents

- **`discover(...)` filter kwargs** (all keyword-only, all default `None`/`False`,
  no behavior change for existing callers): `capabilities`, `capabilities_any`,
  `auth_type`, `intent`, `transport`, `realm`, `min_dnssec`, `text_match`,
  `require_signed`, `require_signature_algorithm`. Implementation in
  `dns_aid.core.filters.apply_filters` — pure-function predicates over already-enriched
  `AgentRecord` lists. Path A's per-domain agent set is small (<50 typical), so
  list-comprehension filtering is the right tool over a query language or DSL.
- **`dns-aid discover` CLI flags** for every filter kwarg: `--capabilities`,
  `--capabilities-any`, `--auth-type`, `--intent`, `--transport`, `--realm`,
  `--min-dnssec`, `--text-match`, `--require-signed`, `--require-signature-algorithm`.
- **`discover_agents_via_dns` MCP tool** extended with the same filter args.
- **AgentRecord fields**: `dnssec_validated: bool`, `signature_verified: bool | None`,
  `signature_algorithm: str | None` populated by the discoverer's existing JWS
  verification path so the new `--require-signed` and `--min-dnssec` filters have a
  record-level signal to evaluate.

#### Composition pattern (zero-trust)

- **`search()` (Path B) → `discover(domain, name=, require_signed=True)` (Path A)**:
  documented in API reference and demonstrated end-to-end against the live
  `api.example.com` + `highvelocitynetworking.com` fixtures. Path B is opt-in
  convenience; Path A re-verification is the authoritative trust gate.

### Changed

- **`dns-aid discover --name X`** now case-insensitive (DNS labels are case-insensitive
  per RFC 1035). Previously a no-op when used without `--protocol` because the substrate
  fall-through would full-zone-walk and the post-filter never ran. Both bugs fixed.
- **`SearchResponse.query`** is `str | None` (the directory's echoed `q` string), not
  a structured object. The previously-planned `SearchQuery` echo class was removed —
  the directory just echoes a string.
- **`SearchResult.score`** drops the `<= 1.0` ceiling. Directory uses raw scores
  (e.g. 39.2) — no client-side normalization.

### Security

- **`validate_fetch_url` rejects URLs with userinfo** (`https://user:pass@host`).
  Prevents accidental credential leaks via logs / error messages. New
  `redact_url_for_log` helper in `dns_aid.utils.url_safety` for defense-in-depth on
  any code path that logs the raw user-supplied URL.
- **`AgentClient.search()` disables HTTP redirects** (`follow_redirects=False`).
  Closes a redirect-based SSRF: without this guard, a directory returning
  `Location: https://internal.local` would have bypassed the SSRF check on the
  initial URL. 3xx responses now surface as `DirectoryUnavailableError(UnexpectedRedirect)`.
- **Response size guard** in `AgentClient.search()`: caps response body at 10 MiB.
  A misbehaving directory (forgot pagination, returned an oversized page) is rejected
  with `DirectoryUnavailableError(ResponseTooLarge)` before reaching the JSON parser.
- **`AgentClient.search()` skip-and-log adapter**: directory records lacking a
  derivable `target_host` (no `endpoint_url`, no pre-set `target_host`) are dropped
  rather than synthesized. The SDK never invents endpoint data a caller might invoke.
  Drops are logged at WARN with full agent identity (`fqdn`, `name`, `domain`); the
  `total` field is adjusted so paginators stay arithmetically consistent.

### Deferred

- **SDK auth on outbound directory calls** — `search()`, `fetch_rankings()`, and the
  telemetry signal push currently make anonymous requests. Phase 5.6's `AuthHandler`
  infrastructure is not yet wired into directory-side calls. Tracked in
  `docs/impl/phase-5.6.1-sdk-directory-auth.md` in the main DNS-AID repo. The live
  directory at `api.example.com` does not currently require auth, so this is
  non-blocking; landing it before private/internal-tenant search filters (per
  Phase 10) becomes a hard requirement.
- **Path B JWS / signature filtering** — directory does not yet expose per-agent
  `sig` / `key_algorithms` columns. Out of scope for this slice; Path A
  `--require-signed` is fully functional today.

### Notes

- 1484 unit + parity + integration tests pass on this branch.
- `mypy` clean across 79 source files; ruff + ruff-format clean on all touched
  files; `bandit` reports 0 new findings.
- Live integration verified end-to-end against `https://api.example.com/api/v1/search`
  and the `highvelocitynetworking.com` Route 53 zone — SDK / CLI / MCP / Path B → Path A
  composition all green.
- Backwards compatibility preserved: every existing `discover()`, `dns-aid discover`,
  and `discover_agents_via_dns` MCP-tool caller produces identical results when no
  new filter kwargs are passed.

## [0.18.6] - 2026-05-08

### Security

- **`python-multipart` floor raised to `>=0.0.27`** in both `[project.optional-dependencies] api` and the `all` extra. Patches **CVE-2026-42561 / GHSA-pp6c-gr5w-3c5g** (high severity) — "Denial of Service via unbounded multipart part headers". Upstream fix landed in `python-multipart 0.0.27` (PR #267 "Add multipart header limits"). The previous floor (`>=0.0.26`) only covered CVE-2026-40347; the new floor supersedes it. `uv.lock` regenerated to pull the patched version. Closes Dependabot alert #11.

### Notes

- No public API surface changes; no source code logic changes.
- PyPI users with fresh `pip install dns-aid` were already getting the patched version (since `>=0.0.26` resolves to latest). This release closes the gap for downstream consumers of this repo's `uv.lock` and prevents future lockfile regression.
- 1267 unit tests pass on the bumped version.

## [0.18.5] - 2026-05-08

### Changed

- **`src/dns_aid/core/discoverer.py`** — `_discover_via_http_index` now parallelizes per-agent SVCB walks the same way `_discover_agents_in_zone` does. Replaced the sequential `for http_agent in http_agents` loop with an `asyncio.Semaphore(20)` + `asyncio.gather(..., return_exceptions=True)` pattern, reusing the existing `_collect_agent_results` filter helper. End-state: HTTP-index-mode discovery completes in roughly `max(per-agent latency)` instead of `sum(per-agent latency)`, matching the latency profile of the DNS-zone-walk path. No behavior change for callers — every existing `TestDiscoverViaHttpIndex` case passes unchanged.

### Notes

- No public API surface changes; concurrency cap (20) intentionally matches the DNS-zone-walk ceiling so a single domain cannot fan out beyond what the existing path already permits.
- 1267 unit tests pass on the bumped version.

## [0.18.4] - 2026-04-25

### Changed

- **`README.md` DNS Backends table corrected and expanded.** Marked Infoblox NIOS as `✅ Production` (it had been listed as `🚧 Planned` despite being one of the most production-complete backends — 887 lines, 30 methods, full WAPI 2.13.7 integration). Added missing rows for **NS1** (now IBM Managed DNS) and **Google Cloud DNS**, both shipped as production backends. Added an "Install Extra" column showing the exact `pip install dns-aid[<extra>]` invocation for every backend. End-state: the README table now matches the actual `pyproject.toml` `[project.optional-dependencies]` declarations and the `src/dns_aid/backends/` directory.
- **`src/dns_aid/cli/init.py`** — `dns-aid init` first-run welcome examples switched from a project lead's personal demo zone to `example.com`, so the first command a new user sees is generic and not vendor-specific.
- **`src/dns_aid/mcp/server.py`** — MCP tool `domain` parameter docstring switched to `example.com` for the same reason. The docstring ships in the `.mcpb` bundle and surfaces in Claude Desktop's tool catalog.

### Added

- **PyPI `Programming Language :: Python :: 3.13` classifier.** CI already tests on 3.13 and the README badge declares 3.13 support; the PyPI Trove classifier list now reflects this so PyPI search and downstream tooling see the full version-support range.
- **PyPI `[project.urls]`: Issues + Security entries.** PyPI surfaces these as labeled links in the project sidebar (`Issues = .../issues`, `Security = .../security/policy`).
- **`CODEOWNERS` updated for two-maintainer reality.** Now distributes review responsibility between the two current maintainers per subsystem: core protocol engine and governance docs require both; `src/dns_aid/sdk/policy/` is led by the policy/standards maintainer.

### Notes

- No public API surface changes, no source code logic changes; all changes are docstrings, package metadata, examples, and ownership/governance.
- 1267 unit tests pass on the bumped version. Manifest passes `npx @anthropic-ai/mcpb validate`.

## [0.18.3] - 2026-04-25

### Added

- **`NOTICE` file** — Apache 2.0 attribution notice listing copyright holders and Infoblox as the original developing organization.

### Changed

- **`MAINTAINERS.md`** — corrected project lead name (Ivan → Igor) and affiliation (Independent → Infoblox) for accurate CLA/DCO traceability ahead of Linux Foundation contribution filing.
- **Sanitized example domains** — replaced `nordstrom.com` / `nordstrom.net` / `rpz.nordstrom.com` with generic `example.com` / `example.net` / `rpz.example.com` across CLI usage examples (`dns_aid.cli.main`), MCP tool docstrings (`dns_aid.mcp.server`), policy compiler/snapshot docstrings (`dns_aid.sdk.policy.compiler`, `dns_aid.sdk.policy.snapshot`), policy unit tests (`tests/unit/sdk/policy/`), and `README.md` enforcement examples. No public API or behavior changes — generic example domains better suit a public open-source reference implementation.
- **`docs/getting-started.md`** — removed dead reference to the previously deleted `nordstrom-poc.md` document.
- **`.mcpbignore`** — pruned stale `docs/nordstrom-poc.md` and `docs/demo-talking-points.md` exclusion entries (those files no longer exist in the working tree).

### Removed

- **`tests/fixtures/nordstrom-agent-governance.json`** — unused enterprise governance fixture removed (no test loaded it).

### Notes

- No public API surface changes; no source code logic changes. 254 unit tests pass across `tests/unit/sdk/policy/`, `tests/unit/cli/`, `tests/unit/mcp/`. Manifest passes `npx @anthropic-ai/mcpb validate`.
- Linux Foundation readiness work — preparatory cleanup for upstream contribution filing.

## [0.18.2] - 2026-04-25

### Added

- **Manifest privacy disclosures** — `manifest.json` now declares a `privacy_policies` array (linking to `PRIVACY.md`) and a populated `license: "Apache-2.0"` field. Required by the Anthropic MCP Directory listing review (issue #83, items 1 and 4).
- **Manifest `user_config` block** — declares 17 backend configuration entries (DNS_AID_BACKEND, DNS_AID_POLICY_MODE, Infoblox NIOS, Cloudflare, NS1, Google Cloud DNS, AWS Route 53, RFC 2136 DDNS) with `title`, `description`, `required: false`, and `sensitive: true` flags as appropriate. All entries are referenced from `server.mcp_config.env` via `${user_config.*}` so Claude Desktop prompts users for the relevant credentials at install time and stores secrets via the OS keychain. Closes Anthropic MCP Directory review item 2.
- **In-response telemetry disclosure in `PRIVACY.md`** — new "In-response telemetry field" section documents the exact `{latency_ms: float, status: str}` dict returned by `call_agent_tool` and `send_a2a_message` when the optional Infoblox SDK is installed. Distinguished from the opt-in remote telemetry channels (`DNS_AID_SDK_HTTP_PUSH_URL`, `DNS_AID_SDK_OTEL_ENDPOINT`, `DNS_AID_SDK_TELEMETRY_API_URL`), which remain off by default. Closes Anthropic MCP Directory review item 3.

### Changed

- **`.mcpb` bundle composition tightened** — `.mcpbignore` now restricts the bundle to runtime code plus user-facing documentation. Development tooling, IDE/agent metadata (`.specify/`, `.claude/`, `CLAUDE.md`, `GEMINI.md`, `AGENTS.md`), and Spec Kit planning artifacts (`specs/`) are excluded. Bundle size: 101 files / 339 KB (was 168 / 490 KB).

### Removed

- **`docs/nordstrom-poc.md`** — internal customer POC document removed from the public open-source repository.

### Internal

- `*.mcpb` added to `.gitignore` so build artifacts no longer surface in `git status`.

### Notes

- No public API surface changes; no source code changes. Manifest passes `npx @anthropic-ai/mcpb validate`. 1267 unit tests pass on the bumped version.

## [0.18.1] - 2026-04-25

### Security

Patch release rolling up the security work landed since v0.18.0. Closes 9 Dependabot pip-ecosystem alerts and 3 high-severity GitHub code-scanning findings. No public API changes.

#### Dependabot — direct dep bumps (PR #85)

- `python-dotenv>=1.2.2` — closes CVE-2026-28684 (medium) — symlink follow in `set_key`
- `cryptography>=46.0.7` — closes CVE-2026-39892 (medium) — buffer overflow on non-contiguous buffers, AND CVE-2026-34073 (low) — incomplete DNS name constraint enforcement
- `requests>=2.33.0` — closes CVE-2026-25645 (medium) — insecure temp file in `extract_zipped_paths()`
- `pytest>=9.0.3` — closes CVE-2025-71176 (medium) — vulnerable tmpdir handling

#### Dependabot — transitive dep floors (this PR)

Explicit version floors added to our `pyproject.toml` because upstream parents (`mcp`, `cyclonedx-bom`, `rich`) still pin loose constraints that include the vulnerable versions:

- `pyjwt>=2.12.0` (in `[mcp]`) — closes CVE-2026-32597 (high) — accepts unknown `crit` header extensions; pulled by `mcp[crypto]`
- `lxml>=6.1.0` (in `[dev]`) — closes CVE-2026-41066 (high) — XXE in `iterparse()`/`ETCompatXMLParser()`; pulled by `cyclonedx-bom` for SBOM generation
- `python-multipart>=0.0.26` (in `[mcp]`) — closes CVE-2026-40347 (medium) — DoS via large multipart preamble; pulled by `mcp`
- `pygments>=2.20.0` (in `[dev]`) — closes CVE-2026-4539 (low) — ReDoS in GUID regex; pulled by `rich`/`pytest`/`common-expression-language`

#### Code-scanning — high-severity findings (PR #86)

- `src/dns_aid/core/http_index.py` — fixed real defect: the `verify_ssl=False` opt-out path silently disabled TLS cert verification because the surrounding `if not verify_ssl: ssl_context = ...` block built an `ssl_context` that was never passed to httpx (dead code AND insecure). Now passes `verify=verify_ssl` directly and emits a structured warning (`http_index.tls_verification_disabled`) on every invocation that takes the opt-out, so operators can audit insecure usage. Drops the unused `import ssl`.
- `.github/workflows/release.yml` — narrowed workflow-scope `GITHUB_TOKEN` to `contents: read` (principle of least privilege); the `build` job escalates to `contents: write` + `id-token: write` only as needed for GitHub Release creation and Sigstore keyless OIDC signing.
- `.github/workflows/codeql.yml` — narrowed workflow-scope `GITHUB_TOKEN` to `contents: read`; the `analyze` job escalates to `security-events: write` only as needed for CodeQL findings upload.

### Notes

- No public API surface changes — `call_mcp_tool`, `list_mcp_tools`, `AgentClient.invoke`, `MCPProtocolHandler.invoke`, `RawResponse`, `InvocationResult`, `InvocationStatus`, `AuthHandler` all unchanged.
- 1283 unit tests pass on the bumped versions; mypy strict clean across 76 source files.
- The 6 `py/incomplete-url-substring-sanitization` code-scanning alerts in test/example files were dismissed via the code-scanning API as false positives (substring assertions used for output verification, not URL security boundary checks). The 3 NOTE-level CodeQL alerts on `mcp.py` introduced by v0.18.0 (catch-base-exception, 2× empty-except) were dismissed as `won't fix` — intentional patterns documented in source with `noqa` comments.
- A separate follow-up will address the ~50 Scorecard `Pinned-Dependencies` alerts (workflows using `actions/X@vN` instead of SHA-pinned references) — that's a strategic mass migration handled outside this release.

## [0.18.0] - 2026-04-25

### Added
- **MCP Streamable HTTP transport** (spec revision 2025-03-26 and later) — the SDK's MCP client now delegates transport to the official `mcp` Python SDK's `streamablehttp_client` and `ClientSession`, replacing the hand-rolled plain JSON-RPC POST. Modern MCP servers (AWS Bedrock AgentCore, Anthropic MCP Connector Directory listings, agentgateway-fronted servers, and other 2025-03-26+ spec-compliant targets) are now reachable end-to-end via `call_mcp_tool`, `list_mcp_tools`, and `AgentClient.invoke`.
- **Transparent legacy transport fallback** — if a target server signals it does not support the modern transport (HTTP 405/406, refused initialize via JSON-RPC -32601), the handler automatically falls back to the legacy plain JSON-RPC POST path so on-premise and pre-2025-03-26 servers keep working. Fallback decisions are logged as structured warnings (`transport.legacy_fallback`) with endpoint, reason, and modern-attempt latency so operators can track which targets need migration.
- **`dns_aid.sdk.auth._httpx_adapter`** — internal bridge that wraps existing `AuthHandler` implementations as `httpx.Auth` so they plug into the official MCP SDK without any handler-side changes. Bearer, OAuth2, mTLS, and API Key handlers continue to work unchanged.
- **`dns_aid.sdk.protocols._mcp_telemetry`** — internal per-invocation telemetry capture using `httpx` event hooks. Records latency, TTFB, response size, cost headers, TLS version, status code, and response headers across both the modern and legacy transports.
- **Public API surface contract test** (`tests/unit/sdk/test_public_api_contract.py`) — programmatic guard that asserts the signatures and return-type field sets of `MCPProtocolHandler.invoke`, `call_mcp_tool`, `list_mcp_tools`, `AgentClient.invoke`, `RawResponse`, `InvokeResult`, `InvocationStatus`, and `AuthHandler` are unchanged. Fails CI loudly on any unintentional drift.

### Fixed
- **`X-DNS-AID-Caller-Domain` header silent drop on the SDK code path** — the previous SDK transport built requests via `client.build_request(...)` with only `Content-Type` set; the dns-aid Layer 2 caller-identity header was added only on the legacy raw-httpx path and never on the SDK path. Layer 2 target middleware therefore could not enforce caller-identity-based policy for any user invoking through the SDK. The new transport propagates the header on every request in the session lifecycle (initialize handshake AND every subsequent tool call) on BOTH the modern and legacy fallback paths whenever `DNS_AID_CALLER_DOMAIN` is set. The header is omitted entirely (not sent as empty string) when the env var is unset or empty.
- **Opaque HTTP 406 errors against modern MCP servers** — calls to modern Streamable HTTP MCP servers (AWS Bedrock AgentCore, agentgateway-fronted targets, Anthropic Connector Directory listings) previously failed with `HTTP 406: Not Acceptable` and no remediation hint, because the SDK was sending plain `Content-Type: application/json` without `Accept: application/json, text/event-stream`. The new transport handles content negotiation correctly via the official SDK; targets that still reject negotiation get a structured error message identifying the lifecycle phase that failed and naming the remediation (legacy fallback already attempted).
- **Missing `[mcp]` extra produces a clear remediation message** — instead of an opaque `ImportError` at first use, the handler returns `RawResponse(success=False, error_type="ImportError", error_message="Missing 'mcp' extra: install dns-aid[mcp] ...")` so developers can self-serve fix the install.

### Changed
- **`dns_aid.core.invoke._invoke_raw_mcp` removed** — the legacy plain-POST helper was duplicate code after the unification; its behavior now lives inside `MCPProtocolHandler` as the transparent legacy fallback. The `_sdk_available` toggle no longer gates MCP (the modern path is always tried first; legacy fallback handles servers that need the old shape). The `_sdk_available` flag remains in place for the A2A no-SDK fallback path (out of scope for this change).
- **Existing MCP unit tests** (`tests/unit/sdk/test_mcp_handler.py` plus the AgentClient/auth/top-level tests that mock MCP via `httpx.MockTransport`) now exercise the legacy fallback path via a shared `force_legacy_mcp_fallback` fixture in `tests/unit/sdk/conftest.py`. They continue to verify the legacy path's behavior unchanged. New unit coverage for the modern path lives at `tests/unit/sdk/protocols/test_mcp_streamable.py`, fallback decision logic at `tests/unit/sdk/protocols/test_mcp_fallback.py`, and error remediation messages at `tests/unit/sdk/protocols/test_mcp_errors.py`.

### Notes
- Public API surface preserved verbatim: `call_mcp_tool`, `list_mcp_tools`, `AgentClient.invoke`, `MCPProtocolHandler.invoke`, `RawResponse`, `InvocationResult`, `InvocationStatus`, `AuthHandler` all unchanged.
- 1283 unit tests pass (mypy strict clean across 76 source files).

## [0.17.3] - 2026-04-14

### Added
- **MCP Registry listing** — added `mcp-name: io.github.infobloxopen/dns-aid` tag to README for MCP Registry ownership verification.
- **MCP bundle files** — `manifest.json`, `server.json`, `.mcpbignore` for `.mcpb` packaging and registry publishing.

## [0.17.2] - 2026-04-14

### Added
- **MCP tool annotations** — all 15 MCP tools now declare `ToolAnnotations` with `readOnlyHint`, `destructiveHint`, `idempotentHint`, and `openWorldHint` hints per MCP spec. Helps clients (Claude Desktop, Cursor, etc.) determine permission levels for each tool. 9 tools marked read-only, 5 write (non-destructive), 1 destructive (`delete_agent_from_dns`).
- **MCP tool titles** — all 15 tools include human-readable `title` parameter for directory listings (e.g., "Discover Agents via DNS", "Publish Agent to DNS").
- **Privacy policy** (`PRIVACY.md`) — documents data handling for Anthropic MCP Directory submission. Covers DNS query routing, opt-in SDK telemetry, credential handling, and third-party backend interactions.
- **Directory listing reference** (`docs/mcp-directory-listing.md`) — submission notes, demo prompts, and category/tag metadata for the Anthropic MCP Connector Directory.

## [0.17.1] - 2026-04-07

### Added
- **RPZ blast-radius guard** — compiler rejects broad wildcards (e.g., `*.nordstrom.net`) outside the `_agents.*` namespace by default. Prevents accidental DNS outages from overly broad RPZ rules. Override with `--allow-broad-rpz` flag on CLI commands or `allow_broad_rpz=True` on `PolicyCompiler.compile()`.
- **RPZ rollback mechanism** — `dns-aid policy rollback` command restores previous RPZ zone state from timestamped snapshots. Snapshots are automatically saved to `.dns-aid/snapshots/` before each enforce push. Supports `--dry-run` for preview.
- **Inventory report output** — `dns-aid enforce --report inventory.json` writes a JSON or CSV report of discovered agents, compiled RPZ rules, skipped rules, and warnings. Useful for auditing and compliance.
- **RPZ snapshot module** (`sdk/policy/snapshot.py`) — save, load, and list RPZ zone snapshots with zone-level filtering.
- **Shadow mode zero-WAPI-calls test** — explicit verification that shadow mode makes zero backend calls.

### Changed
- **DROP→NXDOMAIN docstring** (`nios.py`) — documents that NIOS WAPI silently converts DROP to NXDOMAIN for `record:rpz:cname` objects.
- **Shadow mode docstring** (`rpz_publisher.py`) — documents that shadow mode makes zero WAPI calls and is safe to run at any time.

## [0.17.0] - 2026-03-29

### Added
- **Policy-to-RPZ compiler** (`PolicyCompiler`) — transforms `PolicyDocument` JSON into RPZ directives (standard CNAME-based) and bind-aid directives (TXT-based with `ACTION:` and `key654xx=op:value` syntax). Supports all 16 native policy rules + CEL custom rules. Domain-based CEL patterns (endsWith, ==, !=) compile to DNS zone entries; complex CEL (trust scores, tool restrictions) is skipped at Layer 0 with documented reasons and enforced at Layer 1/2 by the CEL evaluator.
- **RPZ zone writer** (`write_rpz_zone()`) — renders compilation results to standard RFC 8010 RPZ zone files with SOA, NS, and CNAME records. Includes audit comments and source rule tracking.
- **bind-aid zone writer** (`write_bindaid_zone()`) — renders compilation results to bind-aid policy zone files per Ingmar's BIND 9 fork format. Uses `$ORIGIN` directive, separate TXT records for ACTION and SvcParam operations.
- **SvcParam policy operations** (`svcparam_ops`) — new policy rule type for bind-aid rdata enforcement: `strip`, `require`, `validate`, `enforce`, `whitelist`, `blacklist` operations on SVCB keys.
- **Infoblox BloxOne Threat Defense integration** — full TD API support:
  - `create_or_update_named_list()` — push blocked domains as TD named lists via `/api/atcfw/v1/named_lists`
  - `bind_named_list_to_policy()` — bind named lists to security policies with action support (`action_block`, `action_log`, `action_allow`, `action_redirect`). Handles action switching (removes old rule, adds new one) without duplicates.
  - `unbind_named_list_from_policy()` — remove named list rules from policies
  - `list_security_policies()` / `get_security_policy()` — query TD policies
  - `list_named_lists()` / `delete_named_list()` — manage named lists
- **Infoblox NIOS RPZ support** — WAPI methods for on-prem RPZ:
  - `create_rpz_cname_record()` — create/update `record:rpz:cname` entries
  - `delete_rpz_cname_record()` / `list_rpz_cname_records()` — manage RPZ records
  - `ensure_rpz_zone()` — create RPZ zones (`zone_rp`) if needed
- **CLI `policy` sub-app** — `dns-aid policy compile` (generate RPZ/bind-aid zone files), `dns-aid policy show` (compilation report with tables)
- **CLI `enforce` command** — full pipeline: discover agents → compile policy → generate zones → push to Infoblox TD. Supports `--mode shadow` (dry run), `--mode enforce` (live push), `--td-action` (block/log/allow/redirect), `--td-policy-id` (target specific policy), `--auto-policy` (fetch policy_uri from discovered agents' SVCB records), `--output-dir` (write zone files).
- **MCP tools** — 4 new tools:
  - `compile_policy_to_rpz` — compile policy JSON to RPZ + bind-aid zone content
  - `publish_rpz_zone` — compile + push to TD with security policy binding, supports `td_action` and `td_policy_id` params
  - `list_rpz_rules` — query TD named lists and security policies
  - `list_td_security_policies` — list all TD security policies
- **RPZ deduplication** — compiler removes duplicate directives (same owner+action from native rules + CEL) with warnings
- **Test fixtures** — `sample-policy.json` (general) and `nordstrom-agent-governance.json` (enterprise governance scenario with CEL rules and SvcParam ops)
- **Nordstrom POC documentation** (`docs/nordstrom-poc.md`) — end-to-end deployment guide with dual MCP server architecture, CEL enforcement diagrams, TD action options, and before/after framing

### Changed
- **CEL compiler patterns** — now recognizes both evaluator-convention (`!endsWith`, `!=`) and positive forms (`endsWith`, `==`) for domain-based CEL rules. Both produce the same RPZ output.
- **`__init__.py` exports** — `dns_aid.sdk.policy` now exports all compiler types: `PolicyCompiler`, `CompilationResult`, `RPZDirective`, `RPZAction`, `BindAidDirective`, `BindAidAction`, `BindAidParamOp`, `SkippedRule`, `write_rpz_zone`, `write_bindaid_zone`

## [0.16.0] - 2026-03-28

### Added
- **NS1 (IBM) DNS backend** — new `NS1Backend` for the NS1 REST API v1 with API key authentication (`X-NSONE-Key`). Supports SVCB + TXT record CRUD with PUT/POST upsert semantics, zone caching, `list_zones`, and efficient single-record lookup. Native private-use SVCB key support (no demotion to TXT). Configured via `NS1_API_KEY` and optional `NS1_BASE_URL` env vars. 48 unit tests.

### Changed
- **Base class `supports_private_svcb_keys` property** — three-state: `True` (native support, NS1/NIOS), `False` (demote to TXT, Route53/Cloudflare/CloudDNS/BloxOne), `None` (auto-detect, DDNS — tries native first, falls back to demotion if server rejects). Eliminates duplicated `publish_agent()` overrides.

## [0.15.0] - 2026-03-24

### Added
- **Tool-level CEL context** — `request.tool_name` field in PolicyContext enables CEL rules that distinguish MCP tools (e.g., block `delete_user` but allow `read_user`). For MCP, extracted from `arguments["name"]` on `tools/call`; for A2A, the method itself is the tool name; for HTTPS, empty string.
- **Agent-aware circuit breaker** — tracks consecutive failures per agent FQDN with a CLOSED → OPEN → HALF_OPEN → CLOSED state machine. Configurable via `DNS_AID_CIRCUIT_BREAKER`, `DNS_AID_CIRCUIT_BREAKER_THRESHOLD` (default 5), `DNS_AID_CIRCUIT_BREAKER_COOLDOWN` (default 60s). Disabled by default.
- **Circuit state in CEL** — `request.target_circuit_state` field enables policy rules like `request.target_circuit_state != "open"` to combine circuit health with trust/identity checks.
- **Middleware tool_name extraction** — Layer 2 middleware (`DnsAidPolicyMiddleware`) extracts `tool_name` from JSON-RPC body for MCP `tools/call` requests, enabling target-side tool-level governance.

## [0.14.5] - 2026-03-23

### Fixed
- **Version drift eliminated** — `__version__` now derived from `importlib.metadata.version("dns-aid")` instead of a hardcoded string. Single source of truth is `pyproject.toml`. Fixes the 0.14.3→0.14.4 sync miss where `__init__.py` was stale while pyproject.toml and CITATION.cff were correct.

### Improved
- **CEL evaluator: missing context fields** — `caller_id`, `intent`, and `tls_version` from PolicyContext are now exposed to CEL expressions as `request.caller_id`, `request.intent`, `request.tls_version`.
- **CEL evaluator: negative compilation cache** — invalid expressions are cached after first failure, preventing repeated compile errors and log spam on every request from attacker-crafted policy documents.
- **CEL schema: `Literal` type for effect** — `CELRule.effect` uses `Literal["deny", "warn"]` instead of `str` + validator for better type safety and cleaner Pydantic error messages.
- **CEL evaluator: `backend_name` property** — exposes which CEL backend is active (`_RustBackend` or `_PythonBackend`) for telemetry and debugging.

## [0.14.4] - 2026-03-22

### Added
- **CEL custom rules in PolicyEvaluator** — policy documents can now include `cel_rules` with Common Expression Language expressions for flexible access control (HTTP method rules, trust score thresholds, geo-sanctions, etc.) without hardcoding. Policy version `"1.1"` support.
- **Dual CEL backend** — Rust-based `common-expression-language` (~2µs/eval, 93x faster) with automatic fallback to pure-Python `cel-python` (~200µs/eval). Optional dependency: `pip install dns-aid[cel]`.
- **CEL security hardening** — bounded compilation cache (256 entries FIFO), max 64 rules per document, regex-validated rule IDs, 2048-char expression limit, non-boolean return type warnings. Both backends use RE2 (linear-time regex, ReDoS-safe). Fail-open on all error paths.
- **CELRuleEvaluator** — thread-safe evaluator with per-instance compilation cache, backend abstraction protocol, and `request.*` namespace for PolicyContext field access with None→zero-value coercion.

## [0.14.3] - 2026-03-22

### Fixed
- **Auth bypass in invoke.py** — MCP server and CLI invocation paths now thread auth_type, auth_config, credentials, and policy_uri through to AgentClient.invoke(). Previously, invoke.py built synthetic AgentRecords that discarded all auth/policy metadata from DNS discovery, causing requests to go out unsigned.
- **ResolvedAgent preserves AgentRecord** — DNS discovery results now carry the full AgentRecord through the resolution chain, preserving auth and policy metadata for the SDK invocation path.
- **Raw httpx path sends X-DNS-AID-Caller-Domain** — the fallback path (SDK not installed) now sends the caller domain header from DNS_AID_CALLER_DOMAIN env var, enabling Layer 2 target-side domain matching.

## [0.14.2] - 2026-03-22

### Added
- **DnsAidPolicyMiddleware** — target-side ASGI middleware (Layer 2) for mandatory policy enforcement. Extracts method from JSON-RPC body (not spoofable header), verifies mTLS cert domain against claimed caller, sliding-window rate limiting with LRU eviction. Returns `X-DNS-AID-Policy-Result` header on every response.
- **MCP server policy guard** — `check_target_policy()` pre-invocation check for `call_agent_tool` and `send_a2a_message`. Accepts `policy_uri` parameter from discovery flow.
- **`policy/guard.py`** — standalone policy guard module for MCP server with module-level evaluator (shared cache).
- **E2E integration tests** — 12 tests against real HTTP policy server covering Layer 1 strict/permissive/disabled, Layer 2 allow/deny/permissive/rate-limit/mTLS/method-from-body, and MCP guard.

## [0.14.1] - 2026-03-22

### Added
- **PolicyEvaluator** — fetch, cache, and evaluate all 16 policy rules with layer-aware filtering. SSRF-safe fetch (64KB max, 3s timeout, content-type validation). TTL-based cache with asyncio.Lock.
- **SDKConfig policy extensions** — `policy_mode` (disabled/permissive/strict), `policy_cache_ttl`, `caller_domain` with env var support
- **InvocationSignal policy fields** — 7 new fields for bidirectional enforcement visibility: `policy_enforced`, `policy_mode`, `policy_result`, `policy_violations`, `policy_version`, `policy_fetch_time_ms`, `target_policy_result`
- **AgentClient.invoke() policy gate** — Layer 1 pre-flight check between auth resolution and handler.invoke(). Strict mode raises `PolicyViolationError`. Permissive mode logs warning. Disabled skips with zero overhead. Captures `X-DNS-AID-Policy-Result` response header.

### Fixed
- **RULE_ENFORCEMENT_LAYERS** — `rate_limits` now includes CALLER (L1=warn per spec). `geo_restrictions` now includes CALLER (L1=partial per spec).

## [0.14.0] - 2026-03-22

### Added
- **Phase 6 Policy Foundation** — new `dns_aid.sdk.policy` package with:
  - `PolicyDocument` Pydantic schema with all 16 policy rule types
  - `PolicyRules`, `RateLimitConfig`, `AvailabilityConfig` models
  - `RULE_ENFORCEMENT_LAYERS` mapping with bind-aid compilation annotations (Layer 0/1/2)
  - `PolicyContext` (13 fields for caller identity and request context)
  - `PolicyResult` with violations/warnings lists
  - `PolicyViolation` model for structured rule violation reporting
  - `PolicyViolationError` exception for strict mode enforcement
  - `PolicyEnforcementLayer` enum (DNS, CALLER, TARGET)
- **Granular DNSSEC validation** — `DNSSECDetail` model with algorithm, strength rating, chain depth, NSEC3 presence, AD flag
- **Granular TLS validation** — `TLSDetail` model with TLS version, cipher suite, cert validity, days remaining, HSTS
- **`_check_dnssec_detail()`** — extracts algorithm from DNSKEY records, walks DNS tree for chain depth and NSEC3
- **`_check_tls()`** — probes endpoint for TLS version, cipher suite, certificate properties, HSTS header

## [0.13.6] - 2026-03-22

### Security
- **Streaming size guards** — replaced post-buffer `len(resp.content)` checks with true streaming byte-counted reads via `safe_fetch_bytes()`. Oversized payloads are now aborted mid-stream — they never fully land in memory. Applies to `fetch_agent_card` (1MB), `fetch_cap_document` (256KB), and `_fetch_agent_json_auth` (100KB). `Content-Length` is checked as fast-path reject; stream byte count is the authoritative guard.
- **Credential rotation** — Cognito test client rotated. Old client `17gid5tgiv7634o57kvo9ph6mm` deleted and invalidated. Integration tests now read from `DNS_AID_TEST_COGNITO_CLIENT_ID` / `DNS_AID_TEST_COGNITO_CLIENT_SECRET` environment variables. Tests skip gracefully when env vars are absent (CI-safe).

### Added
- **`safe_fetch_bytes()`** in `dns_aid.utils.url_safety` — reusable async streaming fetch with byte-counted size enforcement, `Content-Length` fast-path, and `ResponseTooLargeError`.

## [0.13.5] - 2026-03-22

### Security
- **HTTP Message Signature bypass fixed** — `_build_signature_base()` silently signed empty strings for missing covered components. An attacker could forge requests without required headers and still produce valid signatures. Now raises `ValueError` for non-`@` components absent from the request.
- **OAuth2 SSRF protection** — `_get_token()`, `_discover_token_url()`, and the discovered `token_endpoint` from OIDC responses are now validated via `validate_fetch_url()`. Prevents credential exfiltration to internal hosts (e.g., cloud metadata at `169.254.169.254`).
- **Auth type allowlist** — `_apply_auth_from_metadata()` now validates `auth_type` against the registry before setting it on `AgentRecord`. Unknown types from malicious `agent-card.json` are rejected at discovery time with a warning.
- **Response size limits** — `fetch_agent_card()` (1MB), `fetch_cap_document()` (256KB), and `_fetch_agent_json_auth()` (100KB) now reject oversized responses before JSON parsing.

### Fixed
- **Auth error context** — `resolve_auth_handler()` failures now include the agent FQDN and `auth_type` in the error message for multi-agent debugging.
- **Telemetry push logging** — HTTP push failures in the daemon thread are now logged at `warning` level with `exc_info=True` instead of silently swallowed at `debug` level.

### Added
- **`InvocationSignal.auth_type` and `auth_applied`** — Telemetry signals now capture whether auth was applied and which type, enabling auth observability across invocations.
- **`dns_aid.invoke()` auth support** — Top-level convenience API now accepts `credentials` and `auth_handler` parameters, matching `AgentClient.invoke()`.
- **`dns_aid.AuthHandler` and `dns_aid.resolve_auth_handler`** — Auth types exported from the top-level package for discoverability.
- **`__repr__` on all auth handlers** — Useful for debugging; never includes secrets. Shows config metadata only (region, key_id, header_name, etc.).
- 21 new tests: adversarial auth type injection, SSRF to cloud metadata, signature bypass, oversized response rejection, secret leak prevention in `__repr__`, signal auth metadata propagation.

### Verified
- 870 unit tests, 28 live integration tests against AWS API Gateway (IAM/SigV4), AWS Cognito (OAuth2), httpbin.org (Bearer/API key)
- `ruff check`, `ruff format`, `mypy` — all clean

## [0.13.4] - 2026-03-20

### Fixed
- **SigV4 handler signs only content headers** — API Gateway rejects signatures when transport headers (`accept-encoding`, `connection`, `user-agent`) are in `SignedHeaders` because proxies may strip or modify them. Now only signs `Host`, `Content-Type`, `Content-Length`, and `X-Amz-Target`. Verified live against API Gateway with IAM auth.

### Verified
- Full E2E pipeline tested live: DNS discovery → `/.well-known/agent.json` fetch (unauthenticated) → `auth_type=sigv4` auto-populated → `SigV4AuthHandler` resolved → signed request → API Gateway IAM → Lambda → HTTP 200

## [0.13.3] - 2026-03-20

### Added
- **Auth metadata enrichment during discovery** — `auth_type` and `auth_config` are now automatically populated on `AgentRecord` from `.well-known/agent-card.json` (A2A authentication schemes) and `.well-known/agent.json` (DNS-AID native AuthSpec with `oauth_discovery`, `header_name`, `location`, etc.)
- **AWS SigV4 auth handler** — `SigV4AuthHandler` signs requests with AWS Signature Version 4 for agents behind VPC Lattice (`connect-class=lattice`) or API Gateway with IAM auth. Credentials resolved via standard boto3 chain. Default service: `vpc-lattice-svcs`, also supports `execute-api`.
- **Auth enrichment priority chain** — Existing auth (manual) > DNS-AID native AuthSpec > A2A authentication schemes. Never overwrites.
- **`_fetch_agent_json_auth()`** — Fetches `/.well-known/agent.json`, discriminates DNS-AID native (has `aid_version`) from A2A, extracts auth section. SSRF-protected via `validate_fetch_url()`.
- 12 auth enrichment tests, 8 SigV4 tests

### Changed
- **`_apply_agent_card()` extended** — Now extracts auth from A2A `authentication.schemes` (first scheme → `auth_type`) and from DNS-AID native `auth` in card metadata
- **`_enrich_agents_with_endpoint_paths()` extended** — Falls back to `agent.json` for richer auth when `agent-card.json` doesn't provide it
- **Registry** — `sigv4` added to auth handler factory, `http_msg_sig` now passes `algorithm` from credentials

## [0.13.2] - 2026-03-20

### Added
- **SDK auth handlers (Phase 5.6)** — Automatic authentication for agent invocations. SDK reads `auth_type` + `auth_config` from discovery metadata and applies credentials to outgoing requests.
  - `AuthHandler` ABC with `apply(request)` interface
  - `NoopAuthHandler` — pass-through (auth_type=none)
  - `ApiKeyAuthHandler` — header or query parameter injection
  - `BearerAuthHandler` — `Authorization: Bearer <token>` header
  - `OAuth2AuthHandler` — client-credentials flow with token caching, asyncio lock, OIDC discovery, `OAuth2TokenError`
  - `HttpMsgSigAuthHandler` — RFC 9421 HTTP Message Signatures with Ed25519 and **ML-DSA-65** (post-quantum, FIPS 204)
  - `resolve_auth_handler()` factory with ZTAIP canonical name aliases
- **ML-DSA-65 post-quantum signing** — `HttpMsgSigAuthHandler(algorithm="ml-dsa-65")` produces 3,309-byte FIPS 204 signatures via `pqcrypto` package. Sign+verify round-trip tested. DNS-AID is the first agent discovery protocol with PQC-ready request signing.
- **`[pqc]` optional dependency** — `pip install dns-aid[pqc]` for ML-DSA-65 support
- **`AgentRecord.auth_type` and `auth_config` fields** — Populated from agent metadata during discovery enrichment
- **Protocol handler auth integration** — MCP, A2A, HTTPS handlers use `build_request → apply → send` pattern for auth injection
- **`AgentClient.invoke()` auth support** — Accepts `credentials` dict or explicit `auth_handler` override
- 43 unit tests, 7 integration tests against AWS Cognito, httpbin.org, Google OIDC

## [0.13.1] - 2026-03-20

### Added
- **A2A card conversion helpers** — `A2AAgentCard.from_agent_record()` converts discovered DNS-AID agents to A2A cards, `to_publish_params()` builds `dns_aid.publish()` kwargs, `publish_agent_card()` one-liner publishes A2A cards to DNS. DNS label sanitization with 63-char truncation.

## [0.13.0] - 2026-03-20

### Added
- **Connection mediation SVCB params** — `connect-class` (`key65406`), `connect-meta` (`key65407`), and `enroll-uri` (`key65408`) are now first-class DNS-AID wire parameters for AppHub PSC and VPC Lattice bootstrap flows.
- **Google Cloud DNS backend** — New `CloudDNSBackend` for managing SVCB and TXT records via the Cloud DNS REST API.
- **CLI connect params** — `--connect-class`, `--connect-meta`, `--enroll-uri` flags added to `dns-aid publish`.
- **MCP connect params** — `connect_class`, `connect_meta`, `enroll_uri` added to the `publish_agent_to_dns` MCP tool.
- **Quoted-string-safe SVCB parser** — Discoverer uses `shlex.split()` for correct handling of values with spaces.

### Changed
- **Centralized SVCB private-use key demotion** — `DNSBackend` base class handles demotion of private-use keys (key65280–key65534) to TXT as `dnsaid_keyNNNNN=value`. Route 53, Cloudflare, Cloud DNS, and DDNS inherit this safe default. NIOS overrides to pass all params natively since it supports private-use keys. Adding support to a new backend only requires overriding `publish_agent()`.
- **TTL floor lowered to 30s** — Minimum TTL reduced from 60s to 30s for dynamically provisioned services.

### Fixed
- **Missing `requests` dependency** — Added `requests>=2.28.0` to the `cloud-dns` extra (required by `google-auth` transport).
- **Duplicate demotion code eliminated** — Route 53 and Cloudflare `publish_agent` overrides replaced with base class inheritance.

### Notes
- **Republish required** — Zones adopting connection mediation must republish affected records so `key65406`, `key65407`, and `key65408` appear on the wire.
- **Backend support** — NIOS: native private-use SVCB keys (intended backend for connect-* publishing). Cloud DNS, Route 53, Cloudflare, DDNS: automatic TXT demotion for private-use keys.
- **Verified against real infrastructure** — NIOS (native SVCB), Route 53 (TXT demotion), Cloud DNS (TXT demotion).
- See `docs/adr/0001-connect-mediation-wire-format.md` for the wire format decision.

## [0.12.1] - 2026-03-12

### Added
- **MCP endpoint path resolution** — DNS SVCB records provide only host:port, but MCP agents serve their JSON-RPC handler at sub-paths (e.g., `/mcp`). New `resolve_mcp_endpoint()` discovers the correct path via `/.well-known/agent.json` with `/mcp` convention fallback. Applied automatically in `call_mcp_tool()` and `list_mcp_tools()`.

### Fixed
- **MCP tool invocations failing on DNS-discovered agents** — `call_mcp_tool` and `list_mcp_tools` posted to the root URL (`/`) instead of the MCP handler path (`/mcp`), causing 404 errors for agents discovered via DNS.
- **Default A2A timeout too short** — `send_a2a_message` MCP tool default timeout increased from 30s to 60s. Agents performing multi-step analysis (DNS lookups, DNSSEC checks, TLS probing) need more than 30s.
- **LLM tool selection confusion** — Improved `list_published_agents` and `discover_agents_via_dns` tool descriptions to clarify when each should be used (managed domains with credentials vs. any public domain).

## [0.12.0] - 2026-03-12

### Added
- **`core/invoke.py` module** — Single source of truth for agent invocation (A2A messaging + MCP tool calling). CLI and MCP server now delegate to `invoke.py` instead of duplicating protocol logic. Public API: `send_a2a_message()`, `call_mcp_tool()`, `list_mcp_tools()`, `resolve_a2a_endpoint()`.
- **Discover-first invocation flow** — `send_a2a_message()` and MCP tools accept `domain` + `name` instead of requiring a raw endpoint URL. Resolution chain: DNS discovery → agent card fetch → invoke.
- **Agent card prefetch** — Before invoking, fetches `/.well-known/agent-card.json` for canonical endpoint URL and metadata (name, description, skills). Includes host mismatch protection: if the agent card's `url` hostname differs from the DNS endpoint, the DNS endpoint is used and a warning is logged.
- **`dns-aid message --domain --name` options** — Discover-first CLI flow: `dns-aid message --domain ai.infoblox.com --name security-analyzer "hello"`. Existing `--endpoint` option still supported for direct invocation.

### Changed
- **CLI commands delegate to `core/invoke.py`** — `dns-aid message`, `dns-aid call`, and `dns-aid list-tools` now call the shared invoke module instead of inlining httpx/SDK logic. Reduces code duplication and ensures consistent behavior across CLI and MCP server.
- **MCP `send_a2a_message` tool enhanced** — Now accepts `domain` + `name` parameters for discover-first invocation from Claude Desktop, in addition to the existing `endpoint` parameter.

### Fixed
- **Hardcoded 30s timeout in `_run_async()`** — The thread pool wrapper used `future.result(timeout=30)`, which killed long-running requests regardless of the user-specified timeout. Now passes the actual timeout value through.
- **Empty error strings in SDK path** — `InvokeResult.error` could be an empty string on failure. All exceptions are now wrapped in `InvokeResult` with meaningful error messages.
- **Type guards on A2A response parsing** — Response body is now validated before accessing nested fields, preventing `KeyError` and `TypeError` on unexpected A2A responses.

## [0.11.0] - 2026-03-12

### Added
- **`send_a2a_message` MCP tool** — Send messages to A2A agents directly from Claude Desktop or any MCP client. Sends standard A2A JSON-RPC `message/send` requests with automatic text extraction from response artifacts. Routes through SDK for telemetry capture when available, falls back to raw httpx.
- **`dns-aid message` CLI command** — Send a message to an A2A agent from the command line. Supports `--json` output and configurable `--timeout`.
- **`dns-aid call` CLI command** — Call a tool on a remote MCP agent via JSON-RPC `tools/call`. Accepts `--arguments` as JSON string.
- **`dns-aid list-tools` CLI command** — List available tools on a remote MCP agent via JSON-RPC `tools/list`.

### Fixed
- **A2A protocol handler JSON-RPC 2.0 compliance** — Standard A2A methods (`message/send`, `message/stream`, `tasks/get`, `tasks/cancel`, etc.) are now wrapped in a proper JSON-RPC 2.0 envelope with `jsonrpc`, `id`, and `params` fields. Previously, all methods used a flat generic payload which real A2A agents rejected. Non-standard methods retain the generic format for backward compatibility.

### Changed
- **Full agent communication parity** — All three interfaces (CLI, MCP server, Python SDK) now support both MCP tool calling and A2A messaging. Previously, only the MCP server and SDK could communicate with remote agents.

## [0.10.1] - 2026-03-06

### Fixed
- **Capability resolution priority inversion** — Agent Card skills now correctly override TXT fallback capabilities. Previously, TXT capabilities were set first in `_query_single_agent`, preventing the higher-priority `agent_card` source from taking effect during endpoint enrichment. The 4-tier chain (`cap_uri` > `agent_card` > `http_index` > `txt_fallback`) now works as documented.

## [0.10.0] - 2026-03-06

### Added
- **`ipv4_hint` / `ipv6_hint` publish parameters** — `publish()`, CLI (`--ipv4hint`, `--ipv6hint`), and MCP server now accept address hints for SVCB records (RFC 9460 SvcParamKey 4 and 6), reducing follow-up A/AAAA query round trips
- **4-tier capability resolution chain** — Capabilities now resolve with priority: SVCB `cap` URI → A2A Agent Card skills (`.well-known/agent-card.json`) → HTTP Index → TXT record fallback. New `capability_source` values: `agent_card`, `http_index`
- **Multi-format capability document parsing** — `cap_fetcher` handles three JSON formats: DNS-AID native string list, non-standard object list (`[{"name": "..."}]`), and A2A skills array (`[{"id": "...", "name": "..."}]`)
- **Single-fetch optimization** — When a `cap` URI points to an A2A Agent Card, the document is parsed once and reused as `agent_card` — no redundant HTTP fetch for `.well-known/agent-card.json`

### Changed
- **A2A Agent Card well-known path** — Changed from `/.well-known/agent.json` to `/.well-known/agent-card.json` per the A2A specification
- **`capability_source` expanded** — Now a 5-value Literal: `cap_uri`, `agent_card`, `http_index`, `txt_fallback`, `none`
- **HTTP Index capabilities** — `Capability` dataclass now carries a `capabilities: list[str]` field, merged into agent records during HTTP index discovery

## [0.9.0] - 2026-02-24

### Changed
- **SVCB key numbers moved to RFC 9460 Private Use range** — All custom SvcParamKeys migrated from the Expert Review range (65001–65010) to the Private Use range (65280–65534) per RFC 9460 Section 14.3. New mapping: cap=key65400, cap-sha256=key65401, bap=key65402, policy=key65403, realm=key65404, sig=key65405. **Breaking:** existing DNS records using the old key numbers will need re-publishing.

## [0.8.0] - 2026-02-21

### Added
- **SVCB AliasMode handling** — Discoverer follows SVCB priority-0 (AliasMode) records to resolve the canonical ServiceMode target, per RFC 9460 and IETF draft Section 4.4.2
- **SVCB ipv4hint/ipv6hint extraction** — Discoverer reads SvcParamKey 4 (ipv4hint) and 6 (ipv6hint) from SVCB records to reduce follow-up A/AAAA queries, per IETF draft Section 4.4.2
- **DANE dynamic verification notes** — `verify()` now returns context-aware `dane_note` messages: advisory-only vs full certificate matching, with DNSSEC coupling warning when DANE is present but DNSSEC is not validated
- **DANE/DNSSEC security documentation** — README now includes "Security: DNSSEC and DANE" section with TLSA 3 1 1 recommendation, security score table, and verification code examples

### Changed
- **BANDAID → DNS-AID rename** — All references to "BANDAID" and `bandaid_` updated to "DNS-AID" and `dnsaid_` across source, tests, docs, and metadata files. IETF draft reference updated from `draft-mozleywilliams-dnsop-bandaid-02` to `draft-mozleywilliams-dnsop-dnsaid-01`
- **`bap` SvcParamKey number** — Changed from `key65003` to `key65010` to match IETF draft Section 4.4.3 example. **Breaking:** existing DNS records with `key65003` for bap will need re-publishing (further updated to `key65402` in v0.9.0)

## [0.7.3] - 2026-02-19

### Added
- **`--domain` option for `dns-aid doctor`** — Explicit domain parameter across all three interfaces: CLI (`--domain`), Python (`run_checks(domain=...)`), MCP (`diagnose_environment(domain=...)`)
- Falls back to `DNS_AID_DOCTOR_DOMAIN` env var; agent discovery check is skipped if neither is set

### Changed
- **Removed hardcoded default domain** from doctor's agent discovery check — users must explicitly specify their domain

## [0.7.2] - 2026-02-18

### Fixed
- **Doctor version comparison** — Used `packaging.version.Version` for proper PEP 440 comparison instead of string `!=`, which incorrectly suggested downgrades (e.g., `0.7.1 → 0.7.0 available`)

## [0.7.1] - 2026-02-18

### Fixed
- **Rich markup escaping** — `pip install "dns-aid[mcp]"` hints in doctor output were silently consumed as Rich markup tags. Fixed with `rich.markup.escape()`
- **Shell-safe install hints** — Changed single quotes to double quotes in pip install hints for zsh/bash compatibility

## [0.7.0] - 2026-02-18

### Added
- **Structured diagnostics API** (`dns_aid.doctor`) — `run_checks()` returns `DiagnosticReport` with `CheckResult` dataclass, consumed by CLI (Rich), MCP (JSON dict), and Python
- **`diagnose_environment` MCP tool** — 10th MCP tool, returns environment diagnostics as structured dict
- **PyPI version check** — Doctor checks latest version on PyPI and warns if outdated
- **`_get_module_version()` helper** — Falls back to `importlib.metadata` for packages without `__version__` (e.g., rich)

### Changed
- **CLI doctor refactored** — Thin Rich renderer over `dns_aid.doctor.run_checks()` instead of monolithic function

## [0.6.9] - 2026-02-18

### Fixed
- **`zone_exists()` pre-flight checks** — All interfaces (CLI, Python API, MCP) now validate zone existence before destructive or listing operations. Previously, specifying a non-existent zone produced raw Python tracebacks or cryptic backend errors
- **Indexer error logging** — Changed `logger.exception` to `logger.error` in `sync_index()` for cleaner output

## [0.6.8] - 2026-02-18

### Changed
- **Centralized backend dispatch** — Single `create_backend()` factory in `backends/__init__.py` replaces 4 scattered if-elif chains in `publisher.py`, `cli/main.py`, `mcp/server.py`, and inline MCP tools. Adding a new backend now requires updating ONE place instead of four
- **`VALID_BACKEND_NAMES` frozenset** — Derived from the factory registry, used by `validate_backend()` instead of a hardcoded tuple. Impossible for backend names to drift out of sync

### Fixed
- **`validate_backend()` missing "nios"** — Hardcoded backend tuple in `utils/validation.py` did not include "nios", causing validation to reject a valid backend name. Now uses `VALID_BACKEND_NAMES` from the factory registry

## [0.6.7] - 2026-02-18

### Added
- **Infoblox NIOS WAPI backend** — Full on-premise Infoblox support via WAPI v2.13.7+ with SVCB and TXT record management, zone caching, upsert semantics, and `get_record()` override for efficient lookups. Contributed by @IngmarVG-IB (#22)
- **NIOS in CLI tooling** — `dns-aid doctor` checks NIOS credentials, `dns-aid init` offers NIOS as a backend option, `detect_backend()` auto-detects NIOS from env vars
- **NIOS pip extra** — `pip install dns-aid[nios]` for explicit dependency declaration
- **46 unit tests** for NIOS backend covering init, helpers, SVC parameter mapping, async CRUD, zone caching, error handling, and publisher integration
- **Live integration test harness** for NIOS (env-var gated with `NIOS_HOST`)

### Fixed
- **`zone_exists()` hardened across all backends** — All backends now return `False` (never raise) on any error: network failures, auth issues, misconfigured DNS views. Documented as a must-not-raise contract in `DNSBackend` base class
- **NIOS WAPI upsert** — PUT requests correctly exclude immutable fields (`name`, `view`) that WAPI rejects on update

## [0.6.6] - 2026-02-16

### Fixed
- **`dns-aid init` steps formatting** — Route 53 setup steps now read as proper standalone instructions instead of heading + indented sub-items

## [0.6.5] - 2026-02-16

### Fixed
- **Route 53 auto-detect** — Uses boto3 credential chain (`~/.aws/credentials`, IAM roles, SSO) instead of requiring `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` env vars
- **`dns-aid doctor`** — Route 53 credential check now respects boto3 session credentials
- **`detect_backend()`** — Route 53 detected via `boto3.Session().get_credentials()` for all credential sources

## [0.6.4] - 2026-02-16

### Added
- **`dns-aid init`** — Interactive setup wizard guides backend selection, shows required env vars, generates `.env` snippets
- **`dns-aid doctor`** — Non-interactive environment diagnostics (Python, deps, DNS resolution, backend credentials, optional features, `.env` config)
- **Backend registry** — Single source of truth for backend metadata (`BackendInfo` dataclass), used by CLI, MCP server, init, and doctor
- **Auto-detect backend** — `_get_backend()` now auto-detects configured backend from environment variables when no `--backend` flag or `DNS_AID_BACKEND` is set

### Changed
- **Improved `_get_backend()` error handling** — Missing deps show `pip install` hint; missing env vars show which vars + setup steps; no backend configured suggests `dns-aid init`
- **MCP server `_get_dns_backend()`** — Uses backend registry, returns clear error dicts, supports auto-detect

### Fixed
- **mypy type errors** in `_get_backend()` backend class assignment
- **bandit B105 false positives** on backend description strings

## [0.6.3] - 2026-02-16

### Added
- **PyPI Publishing** — Release workflow now publishes to PyPI via OIDC trusted publisher (no API tokens)
- **Cloudflare & DDNS install extras** — `pip install dns-aid[cloudflare]` and `pip install dns-aid[ddns]`

### Changed
- **pip-audit** — Kept non-strict until first PyPI publish lands
- **Release artifacts** — Updated RELEASE.md to document Sigstore signatures, SBOM, and PyPI package

## [0.6.2] - 2026-02-12

### Changed
- **Documentation Cleanup** — Removed references to server-side modules not present in dns-aid-core: Agent Directory submission, crawler pipeline, Kubernetes controller, database schema, and production telemetry endpoints
- **SDK Telemetry Docs** — Clarified HTTP push and community rankings as optional client-side features with user-configured endpoints

### Notes
- No functional code changes — documentation-only release aligning docs with actual dns-aid-core scope

## [0.6.1] - 2026-02-12

### Added
- **SPDX License Headers** — All 88 Python source and test files carry `SPDX-License-Identifier: Apache-2.0`
- **DCO File** — Developer Certificate of Origin text at repository root
- **GitHub Templates** — PR template with checklist, issue templates for bug reports and feature requests
- **Changelog URL** — Added to `[project.urls]` in pyproject.toml

### Changed
- **Neutral Branding** — Removed all personal domain references (`example.com`, `highvelocitynetworking.com`) from source, docs, and examples; replaced with `example.com` (RFC 2606)
- **Repository URLs** — All URLs now point to `infobloxopen/dns-aid-core` (pyproject.toml, Dockerfile, CHANGELOG, docs)
- **Telemetry Push URL** — MCP server default is now `None`; configured via `DNS_AID_SDK_HTTP_PUSH_URL` env var
- **AWS Zone ID** — Docstring examples use `ZEXAMPLEZONEID` placeholder instead of real zone ID

### Notes
- No functional code changes — this release is purely governance, compliance, and branding cleanup for Linux Foundation submission

## [0.6.0] - 2026-02-12

### Added
- **DNSSEC Enforcement** — `discover(require_dnssec=True)` checks the AD flag and raises `DNSSECError` if the response is unsigned
- **DANE Full Certificate Matching** — `verify(verify_dane_cert=True)` connects via TLS and compares the peer certificate against TLSA record data (SHA-256/SHA-512, full cert or SPKI selector)
- **Sigstore Release Signing** — Wheels, tarballs, and SBOMs are signed with Sigstore cosign (keyless OIDC) in the release workflow; `.sig` and `.pem` attestation files attached to GitHub Releases
- **Environment Variables Reference** — Documented all env vars (core, SDK, backend-specific) in `docs/getting-started.md`
- **Experimental Models Documentation** — Marked `agent_metadata` and `capability_model` modules as experimental with status docstrings

### Fixed
- **Route53 SVCB custom params** — Route53 rejects private-use SvcParamKeys (`key65400`–`key65405`). The Route53 backend now demotes custom DNS-AID params to TXT records with `dnsaid_` prefix, keeping the publish working without data loss
- **Cloudflare SVCB custom params** — Same demotion applied to the Cloudflare backend
- **CLI `--backend` help text** — Now lists all five backends (route53, cloudflare, infoblox, ddns, mock) instead of just "route53, mock"
- **SECURITY.md contact** — Updated from placeholder LF mailing list to interim maintainer email
- **Bandit config** — Migrated from `.bandit` INI to `pyproject.toml` `[tool.bandit]` for newer bandit compatibility
- **CLI ANSI escape codes** — Stripped Rich/Typer ANSI codes in test assertions for Python 3.13 compatibility

### Notes
- BIND/DDNS backends natively support custom SVCB params (`key65400`–`key65405`) — no demotion needed
- DNSSEC enforcement defaults to `False` (backwards compatible)
- DANE cert matching defaults to `False` (advisory TLSA existence check remains the default)

## [0.5.1] - 2026-02-05

### Fixed
- **Security scan compliance** — Replaced AWS example key patterns in tests for Wiz/SonarQube compatibility
- **Code quality** — Removed unused imports flagged by static analysis

### Added
- **Dependabot** — Automated dependency updates for pip and GitHub Actions
- **Pre-commit hooks** — Ruff linting/formatting + MyPy type checking on commit
- **Makefile** — Standard development commands (`make test`, `make lint`, etc.)
- **requirements.lock** — Reproducible builds with pinned dependencies

## [0.5.0] - 2026-02-05

### Added
- **A2A Agent Card Support** (`src/dns_aid/core/a2a_card.py`)
  - Typed dataclasses: `A2AAgentCard`, `A2ASkill`, `A2AAuthentication`, `A2AProvider`
  - `fetch_agent_card()` — fetches from `/.well-known/agent-card.json`
  - `fetch_agent_card_from_domain()` — convenience wrapper
  - `card.to_capabilities()` — converts A2A skills to DNS-AID capability format
  - Discovery automatically attaches `agent_card` to discovered agents

- **JWS Signatures** (`src/dns_aid/core/jwks.py`)
  - Application-layer verification alternative to DNSSEC (~70% of domains lack DNSSEC)
  - `generate_keypair()` — creates EC P-256 (ES256) key pairs
  - `export_jwks()` — exports public key as JWKS for `.well-known/dns-aid-jwks.json`
  - `sign_record()` — signs SVCB record payload, adds `sig` parameter
  - `verify_record_signature()` — fetches JWKS and verifies signature
  - CLI: `dns-aid keys generate`, `dns-aid keys export-jwks`
  - Optional `[jws]` extra: `pip install dns-aid[jws]`

- **SDK Package** (`src/dns_aid/sdk/`)
  - `AgentClient` — discover + invoke agents with automatic protocol handling
  - Protocol handlers: `A2AProtocolHandler`, `MCPProtocolHandler`, `HTTPSProtocolHandler`
  - Ranking: `AgentRanker` with pluggable strategies (latency, success rate, round-robin)
  - Signals: `SignalCollector` tracks invocation metrics (latency, errors, retries)
  - Telemetry: OpenTelemetry integration via optional `[otel]` extra

### Changed
- `Protocol` enum now uses `StrEnum` (Python 3.11+) instead of `(str, Enum)`
- `AgentRecord` now has `agent_card` field (populated during discovery enrichment)
- Discovery enrichment uses typed `fetch_agent_card()` instead of raw dict parsing
- Development status upgraded to "Beta" in package classifiers

### Dependencies
- New optional `[jws]` extra: `cryptography>=41.0.0`
- New optional `[otel]` extra: `opentelemetry-api>=1.20.0`, `opentelemetry-sdk>=1.20.0`
- New optional `[sdk]` extra: (no additional deps, uses core httpx)

## [0.4.9] - 2026-02-02

### Fixed
- **Discovery now uses TXT index instead of hardcoded name probing**
  - `dns-aid discover` queries `_index._agents.{domain}` TXT record via DNS to find all agents
  - Falls back to hardcoded common name probing only when no TXT index exists
  - Previously only found agents whose names matched a hardcoded list (missed most agents)

- **`dns-aid index list` works without AWS credentials**
  - Falls back to direct DNS TXT query when Route 53 backend API is unavailable
  - Previously silently returned "No index record found" without backend credentials

### Added
- `read_index_via_dns()` function in `indexer.py` — reads TXT index via dnspython resolver (no backend needed)

## [0.4.8] - 2026-01-27

### Added
- **DNS-AID Custom SVCB Parameters (IETF Draft Alignment)**
  - `cap` — URI to capability document (HTTPS endpoint for rich capability metadata)
  - `cap-sha256` — Base64url-encoded SHA-256 digest of capability descriptor for integrity checks
  - `bap` — Supported bulk agent protocols with versioning (e.g., `mcp/1,a2a/1`)
  - `policy` — URI to agent policy document (jurisdiction/compliance signaling)
  - `realm` — Multi-tenant scope identifier for federated agent environments
  - New `AgentRecord` fields: `cap_uri`, `cap_sha256`, `bap`, `policy_uri`, `realm`
  - Updated `to_svcb_params()` to include custom params when present (backwards compatible)
  - CLI options: `--cap-uri`, `--cap-sha256`, `--bap`, `--policy-uri`, `--realm`
  - MCP server: publish and discover tools support all DNS-AID custom params
  - Discovery priority: SVCB `cap` URI → fetch capability document → TXT fallback

- **Capability Document Fetcher** (`src/dns_aid/core/cap_fetcher.py`)
  - Fetch and parse agent capability documents from `cap` URI
  - Returns structured `CapabilityDocument` with capabilities, version, description, use_cases
  - Graceful fallback to TXT record capabilities on fetch failure
  - 12 unit tests covering success, failure, timeout, and malformed responses

- **Discovery Capability Source Transparency**
  - `capability_source` field on discovered agents: `cap_uri`, `txt_fallback`, or `none`
  - JSON output includes `cap_uri`, `cap_sha256`, `bap`, `policy_uri`, `realm` when present

- **HTTP Index Capabilities + Capability Document Endpoint**
  - HTTP index now includes `capabilities` list inline per agent (e.g., `["travel", "booking", "reservations"]`)
  - New `/cap/{agent-name}` endpoint serves per-agent capability documents as JSON
  - Flow Visualizer HTTP Index tab now shows capabilities in step cards and summary table
  - Capability document format: capabilities, version, description, protocols, modality

### Changed
- Discovery flow now tries SVCB `cap` URI first, falls back to TXT capabilities
- `bap` field uses versioned protocol identifiers (`mcp/1` instead of bare `mcp`)
- HTTP Index discovery now extracts and displays agent capabilities from index JSON
- Flow Visualizer summary table for HTTP mode includes Capabilities column

## [0.4.1] - 2026-01-20

### Added
- **HTTP Index Discovery (ANS-Compatible)**
  - New `use_http_index` parameter for `discover()` function
  - Supports ANS-style HTTP index endpoint: `https://_index._aiagents.{domain}/index-wellknown`
  - Falls back to well-known paths: `/.well-known/agents-index.json`, `/.well-known/agents.json`
  - Richer metadata support: descriptions, model cards, modality, costs
  - CLI flag: `dns-aid discover example.com --use-http-index`
  - MCP tool parameter: `discover_agents_via_dns(..., use_http_index=True)`
  - New core module: `src/dns_aid/core/http_index.py`
  - 29 unit tests for HTTP index functionality
  - Demo Lambda handler for workshop demonstrations

- **DDNS Backend (RFC 2136)**
  - New `DDNSBackend` for universal DNS server support
  - Works with BIND9, Windows DNS, PowerDNS, Knot DNS, and any RFC 2136 compliant server
  - TSIG authentication support with multiple algorithms (hmac-sha256, sha384, sha512, sha224, md5)
  - Key file loading support (BIND key file format)
  - Full DNS-AID compliance with ServiceMode SVCB records
  - Docker-based BIND9 integration tests
  - Documentation and examples for on-premise DNS deployments

## [0.3.1] - 2026-01-16

### Fixed
- **httpx Client Event Loop Bug** (Cloudflare & Infoblox backends)
  - Fixed "Event loop is closed" error when CLI runs sequential async operations
  - Affects `publish` → auto-index update and `delete` → auto-index update flows
  - Root cause: httpx.AsyncClient cached across multiple `asyncio.run()` calls
  - Fix: Track event loop ID and recreate client when loop changes

## [0.3.0] - 2026-01-16

### Added
- **Agent Index Management** (`_index._agents.*` TXT records)
  - New `dns-aid index list <domain>` command to view agents in a domain's index
  - New `dns-aid index sync <domain>` command to sync index with actual DNS records
  - Automatic index updates on `publish` (creates/updates index record)
  - Automatic index removal on `delete` (removes agent from index)
  - `--no-update-index` flag for publish/delete to skip index updates
  - RFC draft Section 3.2 compliant: enables single-query discovery
  - Index format: `_index._agents.{domain}. TXT "agents=name1:proto1,name2:proto2,..."`

- **MCP Server Index Tools**
  - New `list_agent_index` tool to view domain's agent index
  - New `sync_agent_index` tool to rebuild index from DNS records
  - Added `update_index` parameter to `publish_agent_to_dns` (default: true)
  - Added `update_index` parameter to `delete_agent_from_dns` (default: true)

- **New Core Module** (`src/dns_aid/core/indexer.py`)
  - `read_index()` - Read `_index._agents.*` TXT record
  - `update_index()` - Add/remove agents from index (read-modify-write)
  - `delete_index()` - Remove entire index record
  - `sync_index()` - Scan DNS and rebuild index from actual records
  - `IndexEntry` dataclass for agent entries
  - `IndexResult` dataclass for operation results

### Changed
- `publish` command now auto-creates/updates the domain's agent index by default
- `delete` command now auto-removes the agent from the domain's index by default
- MockBackend now returns `values` at top level (consistent with Route53 backend)
- Test suite expanded to 607 unit tests (34 new indexer tests)

### Fixed
- MockBackend `list_records` now uses substring matching (consistent with Route53)

## [0.2.1] - 2026-01-15

### Added
- **Cloudflare DNS Backend**
  - New `CloudflareBackend` for Cloudflare DNS API v4
  - Free tier support - ideal for demos and workshops
  - Full DNS-AID compliance with ServiceMode SVCB records
  - Zone auto-discovery from domain name
  - 32 unit tests with mocked API responses

### Changed
- CLI `--backend` option now accepts "cloudflare"
- Updated getting-started.md with Cloudflare setup instructions
- README updated with Cloudflare examples

## [0.2.0] - 2026-01-13

### Added
- **DNS-AID Compliance**
  - Added `mandatory="alpn,port"` parameter to SVCB records per IETF draft
  - Ensures proper agent discovery signaling

- **Top-Level API Improvements**
  - Exported `unpublish()` and `delete()` (alias) to top-level API
  - Simpler imports: `from dns_aid import publish, unpublish, delete`

- **MCP E2E Test Script** (`scripts/test_mcp_e2e.py`)
  - Automated testing of all MCP tools via HTTP transport
  - Auto-start capability for MCP server
  - Full publish/discover/verify/list/delete cycle

- **Demo Guide** (`docs/demo-guide.md`)
  - Step-by-step demonstration guide for conferences
  - Quick Checklist for pre-demo verification
  - ngrok integration with `ngrok-skip-browser-warning` header
  - Python library E2E script example

- **Infoblox BloxOne Backend**
  - Full support for BloxOne Cloud API
  - DNS view configuration support
  - SVCB and TXT record creation/deletion
  - Zone listing and verification
  - Integration tests with real API

- **E2E Integration Tests** (`tests/integration/test_e2e.py`)
  - Full publish → discover → verify → delete workflow test
  - Multi-protocol discovery test (MCP + A2A)
  - Security scoring verification
  - Capabilities roundtrip test

- **Documentation**
  - CODE_OF_CONDUCT.md (Contributor Covenant 2.1)
  - Comprehensive Infoblox setup guide
  - Troubleshooting guide for both backends

### Changed
- Test suite expanded to 126 unit tests + 19 integration tests (from 108 in v0.1.0)

### Planned
- Cloudflare DNS backend
- Infoblox NIOS backend (on-prem)
- Agent capability negotiation
- Multi-region discovery

## [0.1.0] - 2026-01-13

### Added
- **Core Protocol Implementation**
  - SVCB record support per RFC 9460
  - TXT record metadata for capabilities and versioning
  - DNS-AID naming convention: `_{agent}._{protocol}._agents.{domain}`
  - Support for MCP (Model Context Protocol) and A2A (Agent-to-Agent) protocols

- **Python Library**
  - `publish()` - Publish agents to DNS
  - `discover()` - Discover agents at a domain
  - `verify()` - Verify DNS-AID records with security scoring
  - Pydantic models with full validation
  - Async/await throughout

- **CLI Interface** (`dns-aid`)
  - `dns-aid publish` - Publish agent records
  - `dns-aid discover` - Find agents at a domain
  - `dns-aid verify` - Check DNS record validity
  - `dns-aid list` - List all agents in a zone
  - `dns-aid delete` - Remove agent records
  - `dns-aid zones` - List available DNS zones
  - Rich terminal output with tables and colors

- **MCP Server** (`dns-aid-mcp`)
  - 5 MCP tools for AI agent integration
  - Stdio transport for Claude Desktop
  - HTTP transport with health endpoints
  - `/health`, `/ready`, `/` endpoints for orchestration

- **DNS Backends**
  - AWS Route 53 backend (production-ready)
  - Mock backend for testing

- **Security Features**
  - Comprehensive input validation (RFC 1035 compliant)
  - DNSSEC validation support
  - DANE/TLSA advisory checking
  - Security scoring (0-100) for agents
  - Default localhost binding for HTTP transport

- **Developer Experience**
  - Type hints throughout
  - Structured logging with structlog
  - Comprehensive test suite (108 tests)
  - GitHub Actions CI/CD pipeline
  - Docker support with multi-stage builds

### Security
- All inputs validated against DNS naming standards
- No hardcoded credentials
- Bandit security scanning in CI
- Dependency vulnerability checking with pip-audit

### Documentation
- Comprehensive README with examples
- Getting Started guide with AWS setup
- Security policy and vulnerability reporting
- Contributing guidelines

## References

- [IETF draft-mozleywilliams-dnsop-dnsaid-01](https://datatracker.ietf.org/doc/draft-mozleywilliams-dnsop-dnsaid/)
- [RFC 9460 - SVCB and HTTPS Resource Records](https://www.rfc-editor.org/rfc/rfc9460.html)
- [RFC 4033-4035 - DNSSEC](https://www.rfc-editor.org/rfc/rfc4033.html)

[Unreleased]: https://github.com/infobloxopen/dns-aid-core/compare/v0.13.4...HEAD
[0.13.4]: https://github.com/infobloxopen/dns-aid-core/compare/v0.13.3...v0.13.4
[0.13.3]: https://github.com/infobloxopen/dns-aid-core/compare/v0.13.2...v0.13.3
[0.13.2]: https://github.com/infobloxopen/dns-aid-core/compare/v0.13.1...v0.13.2
[0.13.1]: https://github.com/infobloxopen/dns-aid-core/compare/v0.13.0...v0.13.1
[0.13.0]: https://github.com/infobloxopen/dns-aid-core/compare/v0.12.1...v0.13.0
[0.12.1]: https://github.com/infobloxopen/dns-aid-core/compare/v0.12.0...v0.12.1
[0.12.0]: https://github.com/infobloxopen/dns-aid-core/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/infobloxopen/dns-aid-core/compare/v0.10.1...v0.11.0
[0.10.1]: https://github.com/infobloxopen/dns-aid-core/compare/v0.10.0...v0.10.1
[0.10.0]: https://github.com/infobloxopen/dns-aid-core/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/infobloxopen/dns-aid-core/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/infobloxopen/dns-aid-core/compare/v0.7.3...v0.8.0
[0.7.3]: https://github.com/infobloxopen/dns-aid-core/compare/v0.7.2...v0.7.3
[0.7.2]: https://github.com/infobloxopen/dns-aid-core/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/infobloxopen/dns-aid-core/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/infobloxopen/dns-aid-core/compare/v0.6.9...v0.7.0
[0.6.9]: https://github.com/infobloxopen/dns-aid-core/compare/v0.6.8...v0.6.9
[0.6.8]: https://github.com/infobloxopen/dns-aid-core/compare/v0.6.7...v0.6.8
[0.6.7]: https://github.com/infobloxopen/dns-aid-core/compare/v0.6.6...v0.6.7
[0.6.6]: https://github.com/infobloxopen/dns-aid-core/compare/v0.6.5...v0.6.6
[0.6.5]: https://github.com/infobloxopen/dns-aid-core/compare/v0.6.4...v0.6.5
[0.6.4]: https://github.com/infobloxopen/dns-aid-core/compare/v0.6.3...v0.6.4
[0.6.3]: https://github.com/infobloxopen/dns-aid-core/compare/v0.6.2...v0.6.3
[0.6.2]: https://github.com/infobloxopen/dns-aid-core/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/infobloxopen/dns-aid-core/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/infobloxopen/dns-aid-core/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/infobloxopen/dns-aid-core/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/infobloxopen/dns-aid-core/compare/v0.4.9...v0.5.0
[0.4.9]: https://github.com/infobloxopen/dns-aid-core/compare/v0.4.8...v0.4.9
[0.4.8]: https://github.com/infobloxopen/dns-aid-core/compare/v0.3.1...v0.4.8
[0.3.1]: https://github.com/infobloxopen/dns-aid-core/compare/v0.3.1...v0.3.1
[0.3.0]: https://github.com/infobloxopen/dns-aid-core/releases/tag/v0.3.1
[0.2.1]: https://github.com/infobloxopen/dns-aid-core/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/infobloxopen/dns-aid-core/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/infobloxopen/dns-aid-core/releases/tag/v0.1.0
