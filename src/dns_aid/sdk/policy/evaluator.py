# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
DNS-AID Policy Evaluator.

Fetches policy documents from policy_uri with SSRF protection,
caches them with TTL, and evaluates all 16 rules with layer-aware filtering.
"""

from __future__ import annotations

import asyncio
import fnmatch
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

import httpx
import structlog

from dns_aid.sdk.policy.models import PolicyContext, PolicyResult, PolicyViolation
from dns_aid.sdk.policy.schema import (
    RULE_ENFORCEMENT_LAYERS,
    PolicyDocument,
    PolicyEnforcementLayer,
    PolicyRules,
)
from dns_aid.utils.url_safety import validate_fetch_url_async

if TYPE_CHECKING:
    from dns_aid.sdk.policy.cel_evaluator import CELRuleEvaluator

logger = structlog.get_logger(__name__)

_MAX_POLICY_BYTES = 65536  # 64 KB
_FETCH_TIMEOUT = 3.0  # seconds


@dataclass
class _CacheEntry:
    """TTL-based cache entry for a fetched PolicyDocument."""

    doc: PolicyDocument
    fetched_at: float
    ttl: float

    @property
    def expired(self) -> bool:
        """Return True if this cache entry has exceeded its TTL."""
        return (time.monotonic() - self.fetched_at) >= self.ttl


class PolicyEvaluator:
    """Fetches, caches, and evaluates policy documents for DNS-AID agents."""

    def __init__(self, cache_ttl: int = 300) -> None:
        self._cache_ttl = cache_ttl
        self._cache: dict[str, _CacheEntry] = {}
        self._lock = asyncio.Lock()
        self._cel_evaluator: CELRuleEvaluator | None = None

    # ── Fetch with SSRF protection + TTL cache ───────────────

    async def fetch(self, policy_uri: str) -> PolicyDocument:
        """Fetch a policy document from *policy_uri* with caching.

        - SSRF protection via :func:`validate_fetch_url`
        - 64 KB max response size
        - 3 s timeout
        - ``application/json`` content-type enforcement
        - TTL cache with double-check locking to prevent stampede

        Args:
            policy_uri: HTTPS URL of the policy document.

        Returns:
            Parsed :class:`PolicyDocument`.

        Raises:
            ValueError: On SSRF, oversized, or wrong content-type.
        """
        # Fast path: cache hit (no lock needed for read)
        entry = self._cache.get(policy_uri)
        if entry and not entry.expired:
            return entry.doc

        async with self._lock:
            # Double-check after acquiring lock
            entry = self._cache.get(policy_uri)
            if entry and not entry.expired:
                return entry.doc

            # Validate URL is safe (blocks SSRF)
            await validate_fetch_url_async(policy_uri)

            # Fetch with size + timeout + content-type guards
            async with httpx.AsyncClient(timeout=_FETCH_TIMEOUT) as client:
                resp = await client.get(policy_uri)

            ct = resp.headers.get("content-type", "")
            if "application/json" not in ct:
                raise ValueError(
                    f"Policy document has unexpected content-type '{ct}', "
                    f"expected application/json: {policy_uri}"
                )

            if len(resp.content) > _MAX_POLICY_BYTES:
                raise ValueError(
                    f"Policy document exceeds {_MAX_POLICY_BYTES} bytes "
                    f"({len(resp.content)} bytes): {policy_uri}"
                )

            doc = PolicyDocument.model_validate_json(resp.content)

            self._cache[policy_uri] = _CacheEntry(
                doc=doc, fetched_at=time.monotonic(), ttl=self._cache_ttl
            )
            return doc

    # ── Evaluate all 16 rules ────────────────────────────────

    def evaluate(
        self,
        doc: PolicyDocument,
        ctx: PolicyContext,
        *,
        layer: PolicyEnforcementLayer = PolicyEnforcementLayer.CALLER,
    ) -> PolicyResult:
        """Evaluate a policy document against a request context.

        Args:
            doc: The policy document to evaluate.
            ctx: The caller/request context.
            layer: Which enforcement layer is calling (filters rules).

        Returns:
            :class:`PolicyResult` with violations and warnings.
        """
        violations: list[PolicyViolation] = []
        warnings: list[PolicyViolation] = []
        rules = doc.rules

        def _applicable(rule_name: str) -> bool:
            """Check if a rule applies to the current enforcement layer."""
            layers = RULE_ENFORCEMENT_LAYERS.get(rule_name, [])
            return layer in layers

        def _violation(rule: str, detail: str) -> None:
            violations.append(PolicyViolation(rule=rule, detail=detail, layer=layer.value))

        def _warning(rule: str, detail: str) -> None:
            warnings.append(PolicyViolation(rule=rule, detail=detail, layer=layer.value))

        # 1. required_protocols
        if rules.required_protocols and _applicable("required_protocols"):
            if not ctx.protocol or ctx.protocol not in rules.required_protocols:
                _violation(
                    "required_protocols",
                    f"protocol '{ctx.protocol}' not in {rules.required_protocols}",
                )

        # 2. required_auth_types
        if rules.required_auth_types and _applicable("required_auth_types"):
            if not ctx.auth_type or ctx.auth_type not in rules.required_auth_types:
                _violation(
                    "required_auth_types",
                    f"auth_type '{ctx.auth_type}' not in {rules.required_auth_types}",
                )

        # 3. require_dnssec
        if rules.require_dnssec and _applicable("require_dnssec"):
            if not ctx.dnssec_validated:
                _violation("require_dnssec", "DNSSEC validation required but not present")

        # 4. require_mutual_tls
        if rules.require_mutual_tls and _applicable("require_mutual_tls"):
            if not ctx.has_mutual_tls:
                _violation("require_mutual_tls", "mutual TLS required but not present")

        # 5. min_tls_version
        if rules.min_tls_version and _applicable("min_tls_version"):
            if not ctx.tls_version:
                _violation(
                    "min_tls_version",
                    f"TLS {rules.min_tls_version} required, got None",
                )
            elif ctx.tls_version < rules.min_tls_version:
                _violation(
                    "min_tls_version",
                    f"TLS {rules.min_tls_version} required, got {ctx.tls_version}",
                )

        # 6. required_caller_trust_score
        if rules.required_caller_trust_score is not None and _applicable(
            "required_caller_trust_score"
        ):
            if (
                ctx.caller_trust_score is None
                or ctx.caller_trust_score < rules.required_caller_trust_score
            ):
                _violation(
                    "required_caller_trust_score",
                    f"trust score {ctx.caller_trust_score} below "
                    f"required {rules.required_caller_trust_score}",
                )

        # 7. rate_limits (structural only — actual enforcement in middleware)
        if rules.rate_limits and _applicable("rate_limits"):
            _warning(
                "rate_limits",
                f"rate limits defined: {rules.rate_limits.max_per_minute}/min, "
                f"{rules.rate_limits.max_per_hour}/hr (enforcement in middleware)",
            )

        # 8. max_payload_bytes
        if rules.max_payload_bytes is not None and _applicable("max_payload_bytes"):
            if ctx.payload_bytes is not None and ctx.payload_bytes > rules.max_payload_bytes:
                _violation(
                    "max_payload_bytes",
                    f"payload {ctx.payload_bytes} bytes exceeds limit {rules.max_payload_bytes}",
                )

        # 9. allowed_caller_domains
        if rules.allowed_caller_domains and _applicable("allowed_caller_domains"):
            if not ctx.caller_domain:
                _violation("allowed_caller_domains", "caller_domain is required but not set")
            elif not any(
                fnmatch.fnmatch(ctx.caller_domain, pattern)
                for pattern in rules.allowed_caller_domains
            ):
                _violation(
                    "allowed_caller_domains",
                    f"domain '{ctx.caller_domain}' not in allowed list",
                )

        # 10. blocked_caller_domains
        if rules.blocked_caller_domains and _applicable("blocked_caller_domains"):
            if ctx.caller_domain and any(
                fnmatch.fnmatch(ctx.caller_domain, pattern)
                for pattern in rules.blocked_caller_domains
            ):
                _violation(
                    "blocked_caller_domains",
                    f"domain '{ctx.caller_domain}' is blocked",
                )

        # 11. allowed_methods
        if rules.allowed_methods and _applicable("allowed_methods"):
            if not ctx.method or ctx.method not in rules.allowed_methods:
                _violation(
                    "allowed_methods",
                    f"method '{ctx.method}' not in {rules.allowed_methods}",
                )

        # 12. allowed_intents
        if rules.allowed_intents and _applicable("allowed_intents"):
            if not ctx.intent or ctx.intent not in rules.allowed_intents:
                _violation(
                    "allowed_intents",
                    f"intent '{ctx.intent}' not in {rules.allowed_intents}",
                )

        # 13. geo_restrictions
        if rules.geo_restrictions and _applicable("geo_restrictions"):
            if not ctx.geo_country or ctx.geo_country not in rules.geo_restrictions:
                _violation(
                    "geo_restrictions",
                    f"geo '{ctx.geo_country}' not in {rules.geo_restrictions}",
                )

        # 14. availability
        if rules.availability and _applicable("availability"):
            self._check_availability(rules, ctx, _violation, _warning)

        # 15. data_classification (informational — warning only)
        if rules.data_classification and _applicable("data_classification"):
            _warning(
                "data_classification",
                f"data classification: {rules.data_classification}",
            )

        # 16. consent_required
        if rules.consent_required and _applicable("consent_required"):
            if not ctx.consent_token:
                _violation("consent_required", "consent token required but not provided")

        # ── CEL custom rules (optional, requires cel backend) ────
        if rules.cel_rules:
            try:
                from dns_aid.sdk.policy.cel_evaluator import CELRuleEvaluator

                if self._cel_evaluator is None:
                    self._cel_evaluator = CELRuleEvaluator()
                cel_violations, cel_warnings = self._cel_evaluator.evaluate(
                    rules.cel_rules,
                    ctx,
                    layer.value,
                )
                violations.extend(cel_violations)
                warnings.extend(cel_warnings)
            except ImportError:
                logger.warning(
                    "policy.cel_unavailable",
                    rule_count=len(rules.cel_rules),
                    hint="Install CEL backend: pip install dns-aid[cel]",
                )

        return PolicyResult(
            allowed=len(violations) == 0,
            violations=violations,
            warnings=warnings,
        )

    @staticmethod
    def _check_availability(
        rules: PolicyRules,
        ctx: PolicyContext,
        _violation: Callable[[str, str], None],
        _warning: Callable[[str, str], None],
    ) -> None:
        """Check time-of-day availability with midnight-wrap support.

        Fails open on parse errors (logs warning).
        """
        if rules.availability is None:
            return
        try:
            from datetime import datetime
            from zoneinfo import ZoneInfo

            tz = ZoneInfo(rules.availability.timezone)
            now = datetime.now(tz)
            now_minutes = now.hour * 60 + now.minute

            parts = rules.availability.hours.split("-")
            if len(parts) != 2:
                raise ValueError(f"Expected HH:MM-HH:MM, got '{rules.availability.hours}'")

            start_parts = parts[0].strip().split(":")
            end_parts = parts[1].strip().split(":")
            if len(start_parts) != 2 or len(end_parts) != 2:
                raise ValueError(f"Expected HH:MM-HH:MM, got '{rules.availability.hours}'")

            start_minutes = int(start_parts[0]) * 60 + int(start_parts[1])
            end_minutes = int(end_parts[0]) * 60 + int(end_parts[1])

            if start_minutes <= end_minutes:
                # Normal window: 08:00-22:00
                in_window = start_minutes <= now_minutes <= end_minutes
            else:
                # Midnight wrap: 22:00-06:00
                in_window = now_minutes >= start_minutes or now_minutes <= end_minutes

            if not in_window:
                _violation(
                    "availability",
                    f"current time {now.strftime('%H:%M')} outside "
                    f"window {rules.availability.hours} ({rules.availability.timezone})",
                )

        except Exception as exc:
            logger.warning(
                "policy.availability_parse_error",
                hours=rules.availability.hours,
                timezone=rules.availability.timezone,
                error=str(exc),
            )
            # Fail open — don't block on parse errors
