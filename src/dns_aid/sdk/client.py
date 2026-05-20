# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
AgentClient — main entry point for the DNS-AID Tier 1 SDK.

Wraps agent invocations with protocol handlers, captures telemetry
signals, and exports them according to configuration.
"""

from __future__ import annotations

import asyncio
import threading
import time as _time
from collections.abc import Awaitable, Callable
from types import TracebackType
from typing import Any, Literal

import httpx
import structlog

from dns_aid.core.models import AgentRecord
from dns_aid.sdk._circuit_breaker import CircuitBreaker
from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.auth import resolve_auth_handler
from dns_aid.sdk.auth.base import AuthHandler
from dns_aid.sdk.exceptions import (
    CredentialProviderError,
    DirectoryAuthError,
    DirectoryConfigError,
    DirectoryRateLimitedError,
    DirectoryUnavailableError,
)
from dns_aid.sdk.models import InvocationResult, InvocationSignal, InvocationStatus
from dns_aid.sdk.policy.evaluator import PolicyEvaluator
from dns_aid.sdk.policy.models import PolicyContext, PolicyViolationError
from dns_aid.sdk.policy.schema import PolicyEnforcementLayer
from dns_aid.sdk.protocols.a2a import A2AProtocolHandler
from dns_aid.sdk.protocols.base import ProtocolHandler
from dns_aid.sdk.protocols.https import HTTPSProtocolHandler
from dns_aid.sdk.protocols.mcp import MCPProtocolHandler
from dns_aid.sdk.search import SearchResponse
from dns_aid.sdk.signals.collector import SignalCollector
from dns_aid.utils.url_safety import UnsafeURLError, redact_url_for_log, validate_fetch_url

logger = structlog.get_logger(__name__)

# Type alias for the credential_provider callback. Application supplies an
# async callable that takes the target AgentRecord and returns a credentials
# dict whose shape matches the agent's declared auth_type. The SDK awaits the
# callable lazily at invoke time (FR-001).
CredentialProvider = Callable[[AgentRecord], Awaitable[dict[str, Any] | None]]

# Protocol handler registry
_HANDLERS: dict[str, type[ProtocolHandler]] = {
    "mcp": MCPProtocolHandler,
    "a2a": A2AProtocolHandler,
    "https": HTTPSProtocolHandler,
}


class AgentClient:
    """
    DNS-AID SDK client for invoking agents and collecting telemetry.

    Usage::

        async with AgentClient() as client:
            result = await client.invoke(agent, method="tools/list")
            print(result.signal.invocation_latency_ms)

    Supports MCP agents out of the box. A2A and HTTPS handlers
    are registered in Phase F.
    """

    def __init__(self, config: SDKConfig | None = None) -> None:
        self._config = config or SDKConfig.from_env()
        self._http_client: httpx.AsyncClient | None = None
        self._collector = SignalCollector(
            console=self._config.console_signals,
            caller_id=self._config.caller_id,
        )
        self._handlers: dict[str, ProtocolHandler] = {}
        self._policy_evaluator: PolicyEvaluator | None = None
        self._circuit_breaker = CircuitBreaker(
            enabled=self._config.circuit_breaker_enabled,
            threshold=self._config.circuit_breaker_threshold,
            cooldown=self._config.circuit_breaker_cooldown,
        )

    async def __aenter__(self) -> AgentClient:
        self._http_client = httpx.AsyncClient(
            timeout=self._config.timeout_seconds,
            follow_redirects=True,
        )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None

    def _get_handler(self, protocol: str) -> ProtocolHandler:
        """Get or create a protocol handler for the given protocol."""
        if protocol not in self._handlers:
            handler_cls = _HANDLERS.get(protocol)
            if handler_cls is None:
                raise ValueError(
                    f"Unsupported protocol: {protocol}. Available: {', '.join(_HANDLERS.keys())}"
                )
            self._handlers[protocol] = handler_cls()
        return self._handlers[protocol]

    async def _resolve_auth(
        self,
        agent: AgentRecord,
        credentials: dict | None,
        credential_provider: CredentialProvider | None = None,
    ) -> AuthHandler | None:
        """Resolve an auth handler from agent metadata, credentials, or provider.

        Precedence (FR-002): the first non-empty source wins; subsequent
        sources are not consulted.

            1. ``credentials`` dict (explicit pre-fetched credentials)
            2. ``credential_provider`` callback (awaited lazily at invoke time)
            3. No-auth fallback (when both are absent or empty)

        The ``auth_handler`` explicit override is handled by the caller of this
        method (see ``invoke()``); when set, this method is not called.

        Returns *None* when the agent requires no auth, when no credentials
        are supplied, or when the provider returns ``None`` / empty dict.

        Raises:
            CredentialProviderError: When the provider callable itself raises.
                The original exception is preserved as ``__cause__`` for
                debugging. The wrapper's serialized surface does not contain
                credential values (FR-004).
            ValueError: When the resolved credentials dict lacks required keys
                for the declared ``auth_type``. The provider's return value is
                NOT included in the error message (FR-005).
        """
        auth_type = getattr(agent, "auth_type", None)
        # FR-008: short-circuit before the provider is awaited when the target
        # declares no authentication.
        if not auth_type or auth_type == "none":
            return None

        # FR-013: conflict-detection debug log when both sources supplied.
        # Emitted before the precedence check so developers can observe the
        # bypass without source-changing.
        if credentials and credential_provider is not None:
            logger.debug(
                "sdk.credential_provider_bypassed",
                agent_fqdn=agent.fqdn,
                auth_type=auth_type,
                winner="credentials",
                bypassed="credential_provider",
                reason="explicit credentials dict supplied alongside credential_provider",
            )

        # Precedence step 1: explicit credentials dict (existing behavior).
        if credentials:
            return self._build_handler_from_credentials(agent, auth_type, credentials)

        # Precedence step 2: lazy credential_provider callback.
        if credential_provider is not None:
            # Hardening: bound the provider call with a timeout so a hanging
            # provider (network stall, blocked socket, slow IdP) does not
            # block invoke indefinitely. The credential_provider_timeout
            # default is 30 seconds; configurable via SDKConfig or the env
            # var DNS_AID_CREDENTIAL_PROVIDER_TIMEOUT.
            provider_timeout = self._config.credential_provider_timeout
            try:
                provider_credentials = await asyncio.wait_for(
                    credential_provider(agent),
                    timeout=provider_timeout,
                )
            except TimeoutError as exc:
                # Wrap with sanitization. The wrapper carries the agent FQDN
                # and the timeout duration as safe context; the original
                # TimeoutError is preserved via __cause__ but does not contain
                # credential material (TimeoutError carries no credentials).
                # Python 3.11+ unified ``asyncio.TimeoutError`` with the
                # builtin ``TimeoutError`` (PEP 678 / 657 era cleanup).
                logger.debug(
                    "sdk.credential_provider_timeout",
                    agent_fqdn=agent.fqdn,
                    auth_type=auth_type,
                    timeout_seconds=provider_timeout,
                )
                raise CredentialProviderError(agent_fqdn=agent.fqdn) from exc
            except asyncio.CancelledError:
                # Propagate cancellation cleanly — do NOT wrap. asyncio.CancelledError
                # is a BaseException in Python 3.11+; this except clause is defensive
                # in case a provider raises it from inside (it should not).
                raise
            except Exception as exc:
                # FR-004: wrap with sanitization. The original exception is
                # preserved as __cause__ via `raise ... from exc`. The wrapper's
                # serialized form does not contain credential values.
                #
                # Hardening: log the exception TYPE NAME (never the value or
                # args) so operators get a per-handler debug trace symmetric
                # with the timeout case above. The exception's message and
                # args may contain credential material from a buggy provider,
                # so we deliberately omit them.
                logger.debug(
                    "sdk.credential_provider_failed",
                    agent_fqdn=agent.fqdn,
                    auth_type=auth_type,
                    exception_type=type(exc).__name__,
                )
                raise CredentialProviderError(agent_fqdn=agent.fqdn) from exc

            # FR-003: None or empty dict from provider == no credentials.
            if provider_credentials is None or provider_credentials == {}:
                logger.debug(
                    "sdk.auth_skipped",
                    agent_fqdn=agent.fqdn,
                    auth_type=auth_type,
                    reason="credential_provider returned None or empty dict",
                )
                return None

            # Hardening: validate return shape. A misbehaving provider that
            # returns a non-dict (string, list, int, etc.) would otherwise
            # surface a cryptic error from deep in the registry. Catching it
            # here gives the caller a clear actionable message.
            if not isinstance(provider_credentials, dict):
                # Note: we deliberately include only the TYPE NAME of the
                # return value in the error, never the value itself — the
                # offending value could contain credential material from a
                # buggy provider implementation.
                raise CredentialProviderError(agent_fqdn=agent.fqdn) from TypeError(
                    f"credential_provider must return dict or None, "
                    f"got {type(provider_credentials).__name__}"
                )

            return self._build_handler_from_credentials(agent, auth_type, provider_credentials)

        # Precedence step 3: no source supplied — skip auth (existing behavior).
        logger.debug(
            "sdk.auth_skipped",
            agent_fqdn=agent.fqdn,
            auth_type=auth_type,
            reason="no credentials provided",
        )
        return None

    def _build_handler_from_credentials(
        self,
        agent: AgentRecord,
        auth_type: str,
        credentials: dict,
    ) -> AuthHandler:
        """Build the auth handler for the agent's declared auth_type from the
        supplied credentials dict.

        Raises ``ValueError`` if the registry factory rejects the dict shape
        (e.g., missing required keys for the declared auth_type). The error
        message includes ``auth_type`` and the underlying factory's error
        message — never the credentials dict's values.
        """
        auth_config = getattr(agent, "auth_config", None) or {}
        try:
            return resolve_auth_handler(
                auth_type=str(auth_type),
                auth_config=auth_config if isinstance(auth_config, dict) else {},
                credentials=credentials,
            )
        except ValueError as exc:
            raise ValueError(
                f"Auth resolution failed for agent {agent.fqdn!r} (auth_type={auth_type!r}): {exc}"
            ) from exc

    async def invoke(
        self,
        agent: AgentRecord,
        *,
        method: str | None = None,
        arguments: dict | None = None,
        timeout: float | None = None,
        credentials: dict | None = None,
        credential_provider: CredentialProvider | None = None,
        auth_handler: AuthHandler | None = None,
    ) -> InvocationResult:
        """
        Invoke an agent and capture a telemetry signal.

        Args:
            agent: The AgentRecord from dns_aid.discover().
            method: Protocol-specific method (e.g., "tools/call" for MCP).
            arguments: Method arguments / payload.
            timeout: Override timeout for this call (seconds).
            credentials: Caller-supplied secrets (tokens, client_id/secret)
                for automatic auth resolution from agent metadata.
            credential_provider: Optional async callable taking the target
                ``AgentRecord`` and returning a credentials dict. The SDK
                awaits it lazily at invoke time when no explicit
                ``credentials`` dict is supplied. Suited for short-lived
                delegation tokens (RFC 8693 token exchange), per-target
                credential scoping, and dynamic secret stores (Vault, KMS,
                AWS STS). See
                ``specs/003-credential-provider-callback/contracts/
                credential_provider_contract.md`` for the full contract.
            auth_handler: Explicit auth handler override. When provided,
                ``credentials``, ``credential_provider``, and agent metadata
                are ignored.

        Returns:
            InvocationResult with the response data and attached signal.

        Raises:
            CredentialProviderError: When ``credential_provider`` was used and
                the callable itself raised. The original exception is
                preserved via ``__cause__``; the wrapper's serialized surface
                does NOT contain credential values.

        Precedence (FR-002): ``auth_handler`` > ``credentials`` >
        ``credential_provider`` > no_auth. The first non-empty source wins;
        subsequent sources are not consulted. When both ``credentials`` and
        ``credential_provider`` are supplied, the explicit dict wins, the
        provider is NOT awaited, and a debug-level log notes the bypass
        (FR-013).
        """
        if self._http_client is None:
            raise RuntimeError(
                "AgentClient must be used as an async context manager: "
                "async with AgentClient() as client: ..."
            )

        protocol = agent.protocol.value if hasattr(agent.protocol, "value") else str(agent.protocol)
        handler = self._get_handler(protocol)
        effective_timeout = timeout or self._config.timeout_seconds

        # Resolve auth handler from agent metadata or explicit override.
        # Precedence (FR-002): auth_handler explicit override is the highest
        # priority; otherwise delegate to _resolve_auth, which handles the
        # credentials > credential_provider > no_auth order.
        if auth_handler is not None:
            # FR-013 (extended): when auth_handler is the winning source AND
            # the caller also supplied a credential_provider, log the bypass
            # so developers can detect misconfiguration without behavior
            # surprise. We log only metadata about the bypass — never the
            # provider's identity or any other reference that could be
            # captured in closures over credential material.
            if credential_provider is not None:
                logger.debug(
                    "sdk.credential_provider_bypassed",
                    agent_fqdn=agent.fqdn,
                    winner="auth_handler",
                    bypassed="credential_provider",
                    reason="explicit auth_handler supplied alongside credential_provider",
                )
            resolved_auth: AuthHandler | None = auth_handler
        else:
            resolved_auth = await self._resolve_auth(
                agent,
                credentials,
                credential_provider=credential_provider,
            )

        logger.debug(
            "sdk.invoke",
            agent_fqdn=agent.fqdn,
            endpoint=agent.endpoint_url,
            protocol=protocol,
            method=method,
            auth_type=resolved_auth.auth_type if resolved_auth else None,
        )

        # --- Tool name extraction (Phase 6.6) ---
        tool_name: str | None = None
        if method == "tools/call" and isinstance(arguments, dict):
            tool_name = arguments.get("name")
        elif protocol == "a2a":
            tool_name = method  # A2A method IS the "tool"

        # --- Circuit breaker pre-check (Phase 6.6) ---
        circuit_state = self._circuit_breaker.get_state(agent.fqdn)
        if circuit_state == "open":
            logger.warning(
                "sdk.circuit_open",
                agent_fqdn=agent.fqdn,
                threshold=self._config.circuit_breaker_threshold,
            )
            signal = InvocationSignal(
                agent_fqdn=agent.fqdn,
                agent_endpoint=agent.endpoint_url,
                protocol=protocol,
                method=method,
                invocation_latency_ms=0.0,
                status=InvocationStatus.REFUSED,
                error_type="circuit_open",
                error_message=f"Circuit open for {agent.fqdn}",
                caller_id=self._config.caller_id,
            )
            return InvocationResult(
                success=False,
                data={"error": "circuit_open", "agent_fqdn": agent.fqdn},
                signal=signal,
            )

        # --- Policy enforcement (Phase 6 §3.20) --- Layer 1: caller-side ---
        policy_result_data = None
        policy_doc = None
        policy_fetch_ms = None
        if self._config.policy_mode != "disabled" and getattr(agent, "policy_uri", None):
            if self._policy_evaluator is None:
                self._policy_evaluator = PolicyEvaluator(
                    cache_ttl=self._config.policy_cache_ttl,
                )
            try:
                _t0 = _time.monotonic()
                policy_doc = await self._policy_evaluator.fetch(agent.policy_uri)
                policy_fetch_ms = (_time.monotonic() - _t0) * 1000

                ctx = PolicyContext(
                    caller_id=self._config.caller_id,
                    caller_domain=self._config.caller_domain,
                    protocol=protocol,
                    method=method,
                    auth_type=resolved_auth.auth_type if resolved_auth else None,
                    dnssec_validated=getattr(agent, "dnssec_validated", False),
                    tool_name=tool_name,
                    target_circuit_state=circuit_state,
                )
                policy_result_data = self._policy_evaluator.evaluate(
                    policy_doc,
                    ctx,
                    layer=PolicyEnforcementLayer.CALLER,
                )
                if policy_result_data.denied and self._config.policy_mode == "strict":
                    raise PolicyViolationError(policy_result_data)
                if policy_result_data.denied:
                    logger.warning(
                        "sdk.policy_violation",
                        agent_fqdn=agent.fqdn,
                        mode=self._config.policy_mode,
                        violations=[f"{v.rule}:{v.detail}" for v in policy_result_data.violations],
                    )
            except PolicyViolationError:
                raise
            except Exception as exc:
                logger.warning(
                    "sdk.policy_fetch_failed",
                    error=str(exc),
                    policy_uri=agent.policy_uri,
                )
        # --- end policy enforcement ---

        raw = await handler.invoke(
            client=self._http_client,
            endpoint=agent.endpoint_url,
            method=method,
            arguments=arguments,
            timeout=effective_timeout,
            auth_handler=resolved_auth,
        )

        # --- Circuit breaker post-update (Phase 6.6) ---
        if raw.status == InvocationStatus.SUCCESS:
            self._circuit_breaker.record_success(agent.fqdn)
        else:
            self._circuit_breaker.record_failure(agent.fqdn)

        # Capture target-side policy result (Layer 2) from response header
        target_policy_result = None
        if hasattr(raw, "headers") and raw.headers:
            target_policy_result = raw.headers.get("X-DNS-AID-Policy-Result")

        signal = self._collector.record(
            agent_fqdn=agent.fqdn,
            agent_endpoint=agent.endpoint_url,
            protocol=protocol,
            method=method,
            raw=raw,
            auth_type=resolved_auth.auth_type if resolved_auth else None,
            auth_applied=resolved_auth is not None,
        )

        # Enrich signal with policy data
        if policy_result_data is not None or target_policy_result:
            signal.policy_enforced = True
            signal.policy_mode = self._config.policy_mode
            if policy_result_data:
                signal.policy_result = "allowed" if policy_result_data.allowed else "denied"
                signal.policy_violations = (
                    [f"{v.rule}:{v.detail}" for v in policy_result_data.violations]
                    if policy_result_data.violations
                    else None
                )
                signal.policy_version = policy_doc.version if policy_doc else None
                signal.policy_fetch_time_ms = policy_fetch_ms
            signal.target_policy_result = target_policy_result

        # HTTP push to telemetry API if configured (true fire-and-forget via thread).
        # Resolution order:
        #   1. Explicit ``http_push_url`` override (back-compat: full URL).
        #   2. Derived from ``resolved_directory_url`` + signals path (preferred new path).
        #   3. None: push is disabled.
        push_url = self._config.http_push_url
        if push_url is None:
            base = self._config.resolved_directory_url
            if base is not None:
                push_url = f"{base.rstrip('/')}/api/v1/telemetry/signals"
        if push_url:
            thread = threading.Thread(
                target=self._push_signal_http_sync,
                args=(signal, push_url),
                daemon=True,
            )
            thread.start()

        return InvocationResult(
            success=raw.success,
            data=raw.data,
            signal=signal,
        )

    @staticmethod
    def _push_signal_http_sync(signal: InvocationSignal, push_url: str) -> None:
        """POST a signal to the telemetry API. Runs in a daemon thread, fire-and-forget."""
        try:
            payload = signal.model_dump(mode="json")
            payload.pop("id", None)
            if hasattr(signal.status, "value"):
                payload["status"] = signal.status.value
            resp = httpx.post(push_url, json=payload, timeout=5.0)
            if resp.status_code in (200, 201, 202):
                logger.debug("sdk.http_push_ok", signal_id=str(signal.id), url=push_url)
            else:
                logger.warning(
                    "sdk.http_push_rejected",
                    signal_id=str(signal.id),
                    status_code=resp.status_code,
                    body=resp.text[:200],
                )
        except Exception as e:
            logger.warning(
                "sdk.http_push_failed",
                signal_id=str(signal.id),
                url=push_url,
                error=str(e),
                exc_info=True,
            )

    def rank(
        self,
        agent_fqdns: list[str] | None = None,
        strategy: object | None = None,
    ) -> list:
        """
        Rank agents by their telemetry signals.

        Args:
            agent_fqdns: FQDNs to rank. If None, ranks all agents with signals.
            strategy: Optional RankingStrategy to use.

        Returns:
            List of RankedAgent sorted by composite score.
        """
        from dns_aid.sdk.ranking.ranker import AgentRanker
        from dns_aid.sdk.ranking.strategies import RankingStrategy

        strat = strategy if isinstance(strategy, RankingStrategy) else None
        ranker = AgentRanker(self._collector, strategy=strat)
        return ranker.rank(agent_fqdns)

    @property
    def collector(self) -> SignalCollector:
        """Access the signal collector for querying signals and scorecards."""
        return self._collector

    async def fetch_rankings(
        self,
        fqdns: list[str] | None = None,
        limit: int = 50,
    ) -> list[dict]:
        """
        Fetch community-wide rankings from the central telemetry API.

        This retrieves aggregated rankings based on telemetry data from all
        SDK users, providing a global view of agent reliability and performance.

        Args:
            fqdns: Optional list of agent FQDNs to filter rankings.
                   If provided, only returns rankings for these agents.
            limit: Maximum number of rankings to fetch (default: 50).

        Returns:
            List of ranking dicts, each containing:
            - agent_fqdn: The agent's fully qualified domain name
            - composite_score: Overall score (0-100)
            - reliability_score: Uptime/success rate score
            - latency_score: Response time score
            - invocation_count: Total invocations tracked

        Example::

            async with AgentClient() as client:
                # Get top 10 rankings for specific agents
                fqdns = [a.fqdn for a in discovered_agents]
                rankings = await client.fetch_rankings(fqdns=fqdns, limit=10)
                best = rankings[0] if rankings else None
        """
        if self._http_client is None:
            raise RuntimeError(
                "AgentClient must be used as an async context manager: "
                "async with AgentClient() as client: ..."
            )

        directory_base = self._config.resolved_directory_url
        if not directory_base:
            logger.debug(
                "sdk.fetch_rankings_skipped",
                reason="directory_api_url not configured",
            )
            return []

        url = f"{directory_base.rstrip('/')}/api/v1/telemetry/rankings"
        params = {"limit": limit}

        logger.debug("sdk.fetch_rankings", url=url, limit=limit, fqdns=fqdns)

        try:
            resp = await self._http_client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()
            rankings = data.get("rankings", [])

            # Filter by FQDNs if provided
            if fqdns:
                fqdn_set = set(fqdns)
                rankings = [r for r in rankings if r.get("agent_fqdn") in fqdn_set]

            logger.debug("sdk.fetch_rankings_ok", count=len(rankings))
            return rankings

        except httpx.HTTPStatusError as e:
            logger.warning(
                "sdk.fetch_rankings_failed",
                status_code=e.response.status_code,
                detail=e.response.text[:200],
            )
            return []
        except Exception:
            logger.warning("sdk.fetch_rankings_error", exc_info=True)
            return []

    async def search(
        self,
        q: str | None = None,
        *,
        protocol: Literal["mcp", "a2a", "https"] | None = None,
        domain: str | None = None,
        capabilities: list[str] | None = None,
        min_security_score: int | None = None,
        verified_only: bool = False,
        intent: str | None = None,
        auth_type: str | None = None,
        transport: str | None = None,
        realm: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> SearchResponse:
        """
        Cross-domain agent search via the configured DNS-AID directory backend (Path B).

        Issues ``GET {resolved_directory_url}/api/v1/search`` and returns a typed
        :class:`SearchResponse`. Path B is **opt-in**: invoking ``search()`` without
        ``directory_api_url`` configured raises :class:`DirectoryConfigError` immediately,
        before any network work. Failures are mapped to the structured exception hierarchy
        in :mod:`dns_aid.sdk.exceptions` so callers can dispatch on type.

        Args:
            q: Free-text query, or ``None`` for browse-all-with-filters mode.
            protocol: Restrict to ``mcp`` / ``a2a`` / ``https``.
            domain: Restrict to a single domain.
            capabilities: All-of capability match — every entry must be present.
            min_security_score: Minimum security score (0–100).
            verified_only: Restrict to DCV-verified domains.
            intent: Action intent filter (query / command / transaction / subscription).
            auth_type: Auth type filter.
            transport: Transport filter.
            realm: Multi-tenant realm filter.
            limit: Page size (1–10000). Default 20.
            offset: Pagination offset.

        Returns:
            :class:`SearchResponse` with ranked results, trust attestations, optional
            crawler provenance, and pagination state.

        Raises:
            DirectoryConfigError: ``directory_api_url`` is not configured.
            DirectoryAuthError: Directory rejected credentials (HTTP 401/403).
            DirectoryRateLimitedError: Directory rate-limited the call (HTTP 429); the
                ``retry_after_seconds`` detail mirrors the ``Retry-After`` header.
            DirectoryUnavailableError: Transient failure — connect refused, timeout, 5xx,
                404 (wrong URL), or response shape the SDK can't validate.
            RuntimeError: ``AgentClient`` is not in an async context manager.

        Example::

            async with AgentClient() as client:
                response = await client.search(
                    "payment processing",
                    protocol="mcp",
                    capabilities=["payment-processing"],
                    min_security_score=70,
                )
                for result in response.results:
                    print(result.score, result.agent.fqdn, result.trust.trust_tier)
        """
        if self._http_client is None:
            raise RuntimeError(
                "AgentClient must be used as an async context manager: "
                "async with AgentClient() as client: ..."
            )

        directory_base = self._config.resolved_directory_url
        if directory_base is None:
            logger.debug("sdk.search_skipped", reason="directory_api_url_not_configured")
            raise DirectoryConfigError(
                "AgentClient.search() requires a configured directory backend; "
                "set SDKConfig.directory_api_url or DNS_AID_SDK_DIRECTORY_API_URL.",
                details={
                    "missing_field": "directory_api_url",
                    "env_var": "DNS_AID_SDK_DIRECTORY_API_URL",
                },
            )

        try:
            validated_base = validate_fetch_url(directory_base)
        except UnsafeURLError as exc:
            # The URL failed validation — it might be ``https://user:pass@host``,
            # malformed scheme, or pointing at a private IP. Whatever the reason,
            # strip userinfo before logging or surfacing in the error so we never
            # leak credentials a misconfigured caller might have stuffed into the URL.
            redacted = redact_url_for_log(directory_base)
            logger.warning(
                "sdk.search_failed",
                directory_url=redacted,
                error_class="UnsafeURLError",
                underlying="UnsafeURLError",
            )
            raise DirectoryUnavailableError(
                f"Configured directory URL failed safety validation: {exc}",
                details={
                    "directory_url": redacted,
                    "status_code": None,
                    "underlying": "UnsafeURLError",
                },
            ) from exc

        url = f"{validated_base.rstrip('/')}/api/v1/search"
        params = _build_search_params(
            q=q,
            protocol=protocol,
            domain=domain,
            capabilities=capabilities,
            min_security_score=min_security_score,
            verified_only=verified_only,
            intent=intent,
            auth_type=auth_type,
            transport=transport,
            realm=realm,
            limit=limit,
            offset=offset,
        )

        logger.debug(
            "sdk.search_started",
            directory_url=validated_base,
            q=q,
            protocol=protocol,
            limit=limit,
            offset=offset,
        )
        started = _time.monotonic()

        try:
            # ``follow_redirects=False`` is intentional: validate_fetch_url ran the
            # SSRF check on the *initial* URL only. If the directory (or any host
            # in a redirect chain) returns ``Location: https://internal.local``,
            # following it would bypass the SSRF guard. The directory contract
            # is a single-shot HTTPS request to ``/api/v1/search``; redirects
            # are never legitimate here.
            resp = await self._http_client.get(url, params=params, follow_redirects=False)
        except httpx.HTTPError as exc:
            logger.warning(
                "sdk.search_failed",
                directory_url=validated_base,
                error_class=type(exc).__name__,
                underlying=type(exc).__name__,
            )
            raise DirectoryUnavailableError(
                f"Directory request failed: {exc}",
                details={
                    "directory_url": validated_base,
                    "status_code": None,
                    "underlying": type(exc).__name__,
                },
            ) from exc

        latency_ms = (_time.monotonic() - started) * 1000.0

        # ── Reject 3xx (no auto-redirect — see follow_redirects=False above). ──
        # A directory that responds with a redirect is misconfigured; surfacing
        # that as DirectoryUnavailableError is more useful than letting the body
        # parse fail with a cryptic "expected JSON, got HTML" message.
        if 300 <= resp.status_code < 400:
            logger.warning(
                "sdk.search_failed",
                directory_url=validated_base,
                status_code=resp.status_code,
                redirect_target=resp.headers.get("Location"),
            )
            raise DirectoryUnavailableError(
                f"Directory responded with HTTP {resp.status_code} redirect; "
                "redirects are not followed (SSRF guard). Reconfigure the "
                "``directory_api_url`` to point at the canonical endpoint.",
                details={
                    "directory_url": validated_base,
                    "status_code": resp.status_code,
                    "underlying": "UnexpectedRedirect",
                },
            )

        if resp.status_code == 429:
            retry_after = _parse_retry_after(resp.headers.get("Retry-After"))
            logger.warning(
                "sdk.search_failed",
                directory_url=validated_base,
                status_code=429,
                retry_after_seconds=retry_after,
            )
            raise DirectoryRateLimitedError(
                "Directory rate-limited the search request.",
                details={
                    "directory_url": validated_base,
                    "status_code": 429,
                    "underlying": "HTTPStatusError",
                    "retry_after_seconds": retry_after,
                },
            )

        if resp.status_code in (401, 403):
            logger.warning(
                "sdk.search_failed",
                directory_url=validated_base,
                status_code=resp.status_code,
            )
            raise DirectoryAuthError(
                f"Directory rejected credentials (HTTP {resp.status_code}).",
                details={
                    "directory_url": validated_base,
                    "status_code": resp.status_code,
                    "auth_handler_class": None,
                },
            )

        if resp.status_code >= 400:
            logger.warning(
                "sdk.search_failed",
                directory_url=validated_base,
                status_code=resp.status_code,
                body=resp.text[:200],
            )
            raise DirectoryUnavailableError(
                f"Directory returned HTTP {resp.status_code}.",
                details={
                    "directory_url": validated_base,
                    "status_code": resp.status_code,
                    "underlying": "HTTPStatusError",
                },
            )

        # ── Response size guard. ──
        # The directory contract is small JSON (~1KB per result × <=10000 results
        # max). Bound the body at 10 MB to defend against a misbehaving directory
        # that forgot pagination or returned an oversized page. The body is
        # already buffered by httpx at this point — the guard rejects parsing
        # rather than ingestion. Streaming-with-byte-cap is future work tracked
        # in :doc:`phase-5.6.1-sdk-directory-auth`'s sibling work.
        body_size = len(resp.content)
        if body_size > _SEARCH_MAX_RESPONSE_BYTES:
            logger.warning(
                "sdk.search_failed",
                directory_url=validated_base,
                status_code=resp.status_code,
                body_bytes=body_size,
                max_bytes=_SEARCH_MAX_RESPONSE_BYTES,
            )
            raise DirectoryUnavailableError(
                f"Directory response exceeded {_SEARCH_MAX_RESPONSE_BYTES} bytes "
                f"({body_size} received); refusing to parse.",
                details={
                    "directory_url": validated_base,
                    "status_code": resp.status_code,
                    "underlying": "ResponseTooLarge",
                    "body_bytes": body_size,
                },
            )

        try:
            adapted = _adapt_search_payload(resp.json())
            response = SearchResponse.model_validate(adapted)
        except ValueError as exc:
            logger.warning(
                "sdk.search_failed",
                directory_url=validated_base,
                error_class="ValidationError",
                underlying=type(exc).__name__,
            )
            raise DirectoryUnavailableError(
                f"Directory response failed schema validation: {exc}",
                details={
                    "directory_url": validated_base,
                    "status_code": resp.status_code,
                    "underlying": type(exc).__name__,
                },
            ) from exc

        logger.debug(
            "sdk.search_completed",
            directory_url=validated_base,
            result_count=len(response.results),
            total=response.total,
            latency_ms=round(latency_ms, 2),
        )
        return response

    @classmethod
    def register_handler(cls, protocol: str, handler_cls: type[ProtocolHandler]) -> None:
        """Register a custom protocol handler."""
        _HANDLERS[protocol] = handler_cls


def _build_search_params(
    *,
    q: str | None,
    protocol: str | None,
    domain: str | None,
    capabilities: list[str] | None,
    min_security_score: int | None,
    verified_only: bool,
    intent: str | None,
    auth_type: str | None,
    transport: str | None,
    realm: str | None,
    limit: int,
    offset: int,
) -> list[tuple[str, str | int | float | bool | None]]:
    """Serialize search kwargs to HTTP query parameters; ``None`` values are omitted."""
    params: list[tuple[str, str | int | float | bool | None]] = []
    if q is not None:
        params.append(("q", q))
    if protocol is not None:
        params.append(("protocol", protocol))
    if domain is not None:
        params.append(("domain", domain.lower()))
    if capabilities is not None:
        for cap in capabilities:
            params.append(("capabilities", cap))
    if min_security_score is not None:
        params.append(("min_security_score", str(min_security_score)))
    if verified_only:
        params.append(("verified_only", "true"))
    if intent is not None:
        params.append(("intent", intent))
    if auth_type is not None:
        params.append(("auth_type", auth_type))
    if transport is not None:
        params.append(("transport", transport))
    if realm is not None:
        params.append(("realm", realm))
    params.append(("limit", str(limit)))
    params.append(("offset", str(offset)))
    return params


def _parse_retry_after(value: str | None) -> int | None:
    """Parse an HTTP ``Retry-After`` header to integer seconds; ``None`` if unparseable."""
    if not value:
        return None
    try:
        return int(value.strip())
    except ValueError:
        # Retry-After can also be an HTTP-date — surface as None and let caller back off
        # using their own policy. Date parsing is intentionally not implemented here.
        return None


# ---------------------------------------------------------------------------
# Wire-shape adapter (Path B)
# ---------------------------------------------------------------------------
#
# The directory backend (`dns_aid_directory.api.schemas.AgentResponse`) exposes
# trust + provenance signals as flat fields *on the agent object*, plus a
# couple of small shape quirks vs the SDK's typed models:
#
#   * ``agent.target_host`` is absent — the directory only emits ``endpoint_url``;
#     the SDK's :class:`AgentRecord` requires ``target_host``.
#   * ``agent.bap`` is a comma-separated string (e.g. ``"mcp/1,a2a/1"``); the SDK
#     types it as ``list[str]``.
#   * Trust signals (``security_score``, ``trust_score``, ``popularity_score``,
#     ``trust_tier``, ``safety_status``, ``dnssec_valid``, ``dane_valid``,
#     ``svcb_valid``, ``endpoint_reachable``, ``protocol_verified``,
#     ``threat_flags``, ``trust_breakdown``, ``trust_badges``) live flat on the
#     agent; the SDK exposes them via :class:`TrustAttestation` nested under
#     ``SearchResult.trust``.
#   * Provenance signals (``discovery_level``, ``first_seen``, ``last_seen``,
#     ``last_verified``, ``company``) live flat on the agent; the SDK exposes
#     them via :class:`Provenance` nested under ``SearchResult.provenance``.
#
# This adapter is the *only* place in the SDK that knows about the directory's
# wire shape. If the directory schema changes, only this function needs an
# update — the typed SDK contract stays stable for callers.


# AgentRecord fields where the directory may write explicit ``None`` but the SDK
# types them as non-Optional with a default. The adapter removes these keys when
# the directory wrote ``null`` so Pydantic applies the field's declared default
# instead of failing validation.
_AGENT_FIELDS_STRIP_IF_NONE = ("capabilities", "version", "bap", "use_cases")

# Hard cap on /api/v1/search response size. The directory contract is small JSON
# (a single ``limit=10000`` page is bounded above by ~10 MB at directory's
# documented field set). Set the SDK guard at the same level so an honest
# maximum-page response still parses, but any further excess is rejected
# without invoking the JSON parser.
_SEARCH_MAX_RESPONSE_BYTES = 10 * 1024 * 1024  # 10 MiB


def _adapt_search_payload(raw: dict[str, Any]) -> dict[str, Any]:
    """Translate the directory's raw ``/api/v1/search`` JSON into the SDK's typed shape.

    This is purely structural. No values are invented — fields the directory does
    not provide are left absent so the typed models can use their declared defaults.
    The function mutates ``raw`` in place for efficiency (no need to deep-copy a
    response we are about to discard) and returns it for chaining.

    Three independent concerns:

    1. **Lift flat trust + provenance signals** off the agent into nested objects.
    2. **Coerce wire-shape quirks**: ``bap`` string → list, ``target_host`` from
       ``endpoint_url``.
    3. **Strip explicit nulls** for AgentRecord fields where the directory writes
       ``None`` but the SDK type is non-Optional. Pydantic will then use the
       declared default (e.g. ``capabilities: list = []``, ``version: str = "1.0.0"``).

    **Skip-and-log on insufficient data**: when the directory returns an agent
    with no derivable ``target_host`` (no ``endpoint_url`` and no pre-set
    ``target_host``), the record is dropped and logged at WARN with the
    directory URL + agent fqdn. The search response then carries only records
    the directory could fully describe; the caller never sees a fabricated
    endpoint. ``total`` is reduced accordingly so the page count stays honest.
    """
    from urllib.parse import urlparse

    results = raw.get("results")
    if not isinstance(results, list):
        return raw

    kept: list[Any] = []
    for result in results:
        if not isinstance(result, dict):
            kept.append(result)  # leave malformed entries for the validator to reject
            continue
        agent = result.get("agent")
        if not isinstance(agent, dict):
            kept.append(result)
            continue

        # ── Lift trust signals: pop from agent, place under result["trust"]. ──
        # ``setdefault`` preserves any caller-supplied trust block (used by tests).
        result.setdefault(
            "trust",
            {
                "security_score": agent.pop("security_score", 0),
                "trust_score": agent.pop("trust_score", 0),
                "popularity_score": agent.pop("popularity_score", 0),
                "trust_tier": agent.pop("trust_tier", 0),
                "safety_status": agent.pop("safety_status", "active"),
                "dnssec_valid": agent.pop("dnssec_valid", None),
                "dane_valid": agent.pop("dane_valid", None),
                "svcb_valid": agent.pop("svcb_valid", None),
                "endpoint_reachable": agent.pop("endpoint_reachable", None),
                "protocol_verified": agent.pop("protocol_verified", None),
                "threat_flags": agent.pop("threat_flags", {}),
                "breakdown": agent.pop("trust_breakdown", None),
                "badges": agent.pop("trust_badges", None),
            },
        )

        # ── Lift provenance signals only if the directory supplied first_seen/last_seen. ──
        # Provenance is optional in the SDK contract; we only build it when there are
        # actual signals to populate it with.
        if "first_seen" in agent or "last_seen" in agent:
            result.setdefault(
                "provenance",
                {
                    "discovery_level": agent.pop("discovery_level", 0),
                    "first_seen": agent.pop("first_seen", None),
                    "last_seen": agent.pop("last_seen", None),
                    "last_verified": agent.pop("last_verified", None),
                    "company": agent.pop("company", None),
                },
            )

        # ── Adapt agent shape: split comma-separated ``bap`` string into list. ──
        # Done before the ``_AGENT_FIELDS_STRIP_IF_NONE`` pass so ``bap=None`` still
        # gets stripped.
        bap = agent.get("bap")
        if isinstance(bap, str):
            agent["bap"] = [item.strip() for item in bap.split(",") if item.strip()]

        # ── Adapt agent shape: derive ``target_host`` from ``endpoint_url`` only. ──
        # If neither field is set, drop the record and log — never fabricate. The
        # directory's data quality issue surfaces via the WARN log; the caller
        # gets a smaller-but-honest result set.
        if not agent.get("target_host"):
            endpoint_url = agent.get("endpoint_url")
            if isinstance(endpoint_url, str) and endpoint_url:
                hostname = urlparse(endpoint_url).hostname
                if hostname:
                    agent["target_host"] = hostname

        if not agent.get("target_host"):
            logger.warning(
                "sdk.search_record_skipped",
                reason="no_derivable_target_host",
                fqdn=agent.get("fqdn"),
                name=agent.get("name"),
                domain=agent.get("domain"),
            )
            continue  # drop the record from the result set

        # ── Strip explicit nulls for AgentRecord fields with non-None types + defaults. ──
        for key in _AGENT_FIELDS_STRIP_IF_NONE:
            if key in agent and agent[key] is None:
                del agent[key]

        kept.append(result)

    # Adjust ``total`` to reflect the records actually returned. The directory's
    # original total is meaningless to the caller once we've filtered locally:
    # paginating with the directory's total would loop forever.
    dropped = len(results) - len(kept)
    if dropped:
        original_total = raw.get("total")
        if isinstance(original_total, int):
            raw["total"] = max(0, original_total - dropped)
        logger.info(
            "sdk.search_filter_summary",
            kept=len(kept),
            dropped=dropped,
            adjusted_total=raw.get("total"),
        )
    raw["results"] = kept

    return raw
