# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
OpenTelemetry integration for DNS-AID SDK (spec 005 production rewrite).

Provides span and metric export for agent invocations. Opt-in via
``SDKConfig.otel_enabled``; works as a no-op when ``opentelemetry`` is
not installed.

Production-grade hardening (per specs/005-otel-production/):

- Provider-join detection: never clobbers an integrator's globally-set
  ``TracerProvider`` / ``MeterProvider`` (FR-008).
- Dynamic ``service.version`` from ``dns_aid.__version__`` (FR-009;
  fixes the prior hardcoded "0.4.9" bug).
- Sampler resolution honoring OTEL standard env vars first (FR-010).
- ``BatchSpanProcessor`` for production-grade async batching (R1).
- ``force_flush()`` on shutdown — invokes never lose their last batch
  of spans (FR-024, hardening H3).
- Thread-safe singleton initialization (Q2 hardening note).
- Rate-limited WARN logs for all OTEL events — a chronically-down
  collector cannot fill the log stream (FR-025, hardening H4).
- Span attribute sanitization for credentials embedded in URLs
  (FR-019, FR-020, hardening H1 — security release-blocker).
- All OTEL exceptions caught and logged via the rate-limiter; never
  propagate to the caller (FR-011).
"""

from __future__ import annotations

import contextlib
import os
import re
import threading
import time
from typing import Any

import structlog

from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.models import InvocationSignal
from dns_aid.utils.url_safety import redact_url_for_log

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# OTEL availability detection (must succeed without opentelemetry installed)
# ---------------------------------------------------------------------------

_otel_available = False
try:
    from opentelemetry import metrics, trace
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import (
        ConsoleMetricExporter,
        PeriodicExportingMetricReader,
    )
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import (
        BatchSpanProcessor,
        ConsoleSpanExporter,
    )
    from opentelemetry.sdk.trace.sampling import (
        ALWAYS_OFF,
        ALWAYS_ON,
        ParentBased,
        Sampler,
        TraceIdRatioBased,
    )
    from opentelemetry.trace import SpanKind, StatusCode

    _otel_available = True
except ImportError:
    Sampler = Any  # type: ignore[assignment,misc]

# ---------------------------------------------------------------------------
# Span attribute names — stable contract per contracts/span-attributes.md
# ---------------------------------------------------------------------------

ATTR_AGENT_NAME = "dns_aid.agent.name"
ATTR_AGENT_DOMAIN = "dns_aid.agent.domain"
ATTR_AGENT_PROTOCOL = "dns_aid.agent.protocol"
ATTR_AGENT_ENDPOINT = "dns_aid.agent.endpoint"
ATTR_AGENT_FQDN = "dns_aid.agent.fqdn"  # opt-in high-cardinality label only
ATTR_INVOCATION_METHOD = "dns_aid.invocation.method"
ATTR_INVOCATION_STATUS = "dns_aid.invocation.status"
ATTR_INVOCATION_LATENCY = "dns_aid.invocation.latency_ms"
ATTR_INVOCATION_COST = "dns_aid.invocation.cost_units"
ATTR_SECURITY_DNSSEC = "dns_aid.security.dnssec"

# ---------------------------------------------------------------------------
# Rate-limited WARN helper (FR-025, hardening H4)
# ---------------------------------------------------------------------------

_WARN_RATE_WINDOW_SECONDS = 60.0


class _OTELWarnRateLimiter:
    """Per-(event_name, instance_id) rate limiter for OTEL WARN logs.

    Suppresses repeat events within a 60-second window. When the window
    expires, emits a single summary log with the suppressed count, then
    resets.

    Thread-safe — the lock is held only for the brief decision step,
    not while logging.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # key = (event_name, instance_id); value = (window_start, suppressed_count)
        self._windows: dict[tuple[str, int], tuple[float, int]] = {}

    def emit(self, event_name: str, instance_id: int, **fields: Any) -> None:
        """Emit *event_name* WARN log if outside the rate window; otherwise count.

        ``instance_id`` is typically ``id(self)`` of the calling object so
        each AgentClient instance gets its own rate budget.
        """
        now = time.monotonic()
        key = (event_name, instance_id)
        emit_now = False
        summary_to_emit: tuple[float, int] | None = None
        with self._lock:
            window = self._windows.get(key)
            if window is None:
                # First time we've seen this event for this instance.
                self._windows[key] = (now, 0)
                emit_now = True
            else:
                start, suppressed = window
                if now - start >= _WARN_RATE_WINDOW_SECONDS:
                    # Window expired — emit summary if anything was suppressed,
                    # then start a fresh window with the current event.
                    if suppressed > 0:
                        summary_to_emit = (start, suppressed)
                    self._windows[key] = (now, 0)
                    emit_now = True
                else:
                    # Inside window — suppress and bump count.
                    self._windows[key] = (start, suppressed + 1)

        if summary_to_emit is not None:
            start, suppressed = summary_to_emit
            logger.warning(
                "sdk.otel_warn_summary",
                event_name=event_name,
                suppressed_count=suppressed,
                window_start=start,
                window_seconds=_WARN_RATE_WINDOW_SECONDS,
            )
        if emit_now:
            logger.warning(event_name, **fields)

    def reset(self) -> None:
        """Clear all rate-limiter state (test hook)."""
        with self._lock:
            self._windows.clear()


# Module-level singleton — shared across all TelemetryManager instances and
# the propagation module. Tests can call ``_warn_rate_limiter.reset()`` via
# the conftest fixture.
_warn_rate_limiter = _OTELWarnRateLimiter()


def _otel_warn_rate_limited(event_name: str, instance_id: int = 0, **fields: Any) -> None:
    """Module-level shortcut to the singleton rate-limiter."""
    _warn_rate_limiter.emit(event_name, instance_id, **fields)


# ---------------------------------------------------------------------------
# Sanitization helpers (FR-019, FR-020, hardening H1 — security release-blocker)
# ---------------------------------------------------------------------------

# Pattern matching ``scheme://user:pass@host`` substrings inside arbitrary
# text (e.g., error messages that echo a request URL). Conservative — only
# matches when both ``://`` and ``@`` are present with userinfo characters
# between them.
_URL_WITH_USERINFO_RE = re.compile(
    r"(?P<scheme>https?|grpc[s]?|ftp[s]?|ssh)://[^\s/@]+:[^\s/@]+@(?P<rest>[^\s]+)"
)


def _sanitize_endpoint_url(url: str | None) -> str | None:
    """Strip ``user:pass@`` from a URL before it lands on a span attribute.

    Delegates to ``dns_aid.utils.url_safety.redact_url_for_log`` which is
    already battle-tested by the SDK's HTTP-push and search code paths.
    Returns ``None`` unchanged so optional fields stay optional.
    """
    if url is None:
        return None
    try:
        return redact_url_for_log(url)
    except Exception:
        # Belt-and-suspenders: if the helper raises (it shouldn't), do not
        # leak the original URL to the span — return a clearly redacted
        # marker instead.
        return "<redacted: sanitization failed>"


def _sanitize_error_message(msg: str | None) -> str | None:
    """Redact ``scheme://user:pass@host`` substrings from arbitrary text.

    Error messages from httpx, MCP SDK, and OS-level errors sometimes echo
    the request URL — including any embedded credentials. Substituting the
    matched substring with the same URL minus userinfo preserves the
    debugging value while eliminating the credential leak (FR-020).
    """
    if msg is None:
        return None

    def _replace(match: re.Match[str]) -> str:
        scheme = match.group("scheme")
        rest = match.group("rest")
        return f"{scheme}://{rest}"

    return _URL_WITH_USERINFO_RE.sub(_replace, msg)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_signal_fqdn(fqdn: str) -> tuple[str | None, str | None]:
    """Parse ``agent_name`` and ``domain`` from ``_name._proto._agents.domain``."""
    parts = fqdn.split("._agents.")
    if len(parts) == 2:
        name_parts = parts[0].lstrip("_").split("._")
        agent_name = name_parts[0] if name_parts else None
        return agent_name, parts[1]
    return None, None


def _resolve_sampler(config: SDKConfig) -> Sampler | None:
    """Resolve OTEL sampler per FR-010 precedence.

    Order (highest first):
        1. ``OTEL_TRACES_SAMPLER`` env var (standard OTEL — operator wins)
        2. ``DNS_AID_SDK_OTEL_SAMPLER`` env var (project-specific)
        3. ``SDKConfig.otel_sampler`` field
        4. None — TracerProvider() picks the OTEL SDK default
           (``parentbased_always_on``)

    Returns ``None`` to let the OTEL SDK use its default. Raising on
    unknown values would interfere with operator's standard env var; the
    OTEL SDK itself handles unknown ``OTEL_TRACES_SAMPLER`` values with a
    fallback to default.
    """
    if not _otel_available:
        return None

    # Standard OTEL env var first — operators expect this to win.
    if os.environ.get("OTEL_TRACES_SAMPLER"):
        # Let the OTEL SDK handle parsing the env var (it does this when
        # the TracerProvider is constructed without an explicit sampler).
        return None

    sampler_name = os.environ.get("DNS_AID_SDK_OTEL_SAMPLER") or config.otel_sampler
    if sampler_name is None:
        return None

    arg_raw = os.environ.get("OTEL_TRACES_SAMPLER_ARG")
    arg_float: float | None = None
    if arg_raw is not None:
        try:
            arg_float = float(arg_raw)
        except ValueError:
            arg_float = None

    if sampler_name == "always_on":
        return ALWAYS_ON
    if sampler_name == "always_off":
        return ALWAYS_OFF
    if sampler_name == "traceidratio":
        return TraceIdRatioBased(arg_float if arg_float is not None else 1.0)
    if sampler_name == "parentbased_always_on":
        return ParentBased(root=ALWAYS_ON)
    if sampler_name == "parentbased_always_off":
        return ParentBased(root=ALWAYS_OFF)
    if sampler_name == "parentbased_traceidratio":
        ratio = arg_float if arg_float is not None else 1.0
        return ParentBased(root=TraceIdRatioBased(ratio))

    # Unknown value — SDKConfig validator should have rejected this earlier,
    # but defensive fallback.
    return None


def _is_default_tracer_provider() -> bool:
    """True when no integrator has set their own ``TracerProvider``.

    Uses isinstance against the SDK's proxy type when available, falling
    back to a class-name check for OTEL SDK version compatibility
    (FR-008 / R4).
    """
    if not _otel_available:
        return True
    provider = trace.get_tracer_provider()
    with contextlib.suppress(ImportError):
        from opentelemetry.trace import ProxyTracerProvider

        if isinstance(provider, ProxyTracerProvider):
            return True
    # Class-name fallback — survives OTEL SDK refactors.
    return type(provider).__name__ in {"ProxyTracerProvider", "_DefaultTracerProvider"}


def _is_default_meter_provider() -> bool:
    """True when no integrator has set their own ``MeterProvider`` (FR-008)."""
    if not _otel_available:
        return True
    provider = metrics.get_meter_provider()
    # ProxyMeterProvider is private in some OTEL versions — class-name fallback only.
    return type(provider).__name__ in {
        "ProxyMeterProvider",
        "_ProxyMeterProvider",
        "_DefaultMeterProvider",
    }


# ---------------------------------------------------------------------------
# TelemetryManager — singleton, thread-safe, production-hardened
# ---------------------------------------------------------------------------


class TelemetryManager:
    """Manages OTEL ``TracerProvider`` and ``MeterProvider`` for the DNS-AID SDK.

    Singleton per process — matches OTEL convention (providers are global).
    First AgentClient with ``otel_enabled=True`` wins; subsequent ones with
    different configs emit a one-time rate-limited WARN and inherit the
    existing setup.

    Thread-safe initialization via ``threading.Lock`` (hardening Q2).

    All public methods (``record_signal``, ``force_flush``, ``shutdown``)
    are no-ops when OTEL is not available or initialization failed — the
    caller's invoke path is never broken by OTEL issues (FR-011).
    """

    _instance: TelemetryManager | None = None
    _instance_lock = threading.Lock()

    def __init__(self, config: SDKConfig) -> None:
        self._config = config
        self._initialized = False
        self._tracer: Any = None
        self._tracer_provider: Any = None
        self._meter_provider: Any = None
        self._duration_histogram: Any = None
        self._invocation_counter: Any = None
        self._error_counter: Any = None
        self._cost_counter: Any = None
        # Snapshot of opt-in metric labels for cardinality decisions.
        self._metric_labels_opts: frozenset[str] = frozenset(config.otel_metric_labels)

    @classmethod
    def get_or_create(cls, config: SDKConfig) -> TelemetryManager:
        """Get or create the singleton ``TelemetryManager``.

        Idempotent. First caller's config wins. Subsequent callers with
        *different* OTEL settings get a rate-limited WARN — we do not
        re-initialize because OTEL providers are global state.

        Thread-safe via ``_instance_lock``.
        """
        # Fast path without lock.
        existing = cls._instance
        if existing is not None:
            cls._maybe_warn_singleton_conflict(existing, config)
            return existing

        with cls._instance_lock:
            # Re-check under lock.
            if cls._instance is None:
                instance = cls(config)
                if config.otel_enabled:
                    instance._initialize()
                cls._instance = instance
            else:
                cls._maybe_warn_singleton_conflict(cls._instance, config)
            return cls._instance

    @classmethod
    def _maybe_warn_singleton_conflict(
        cls, existing: TelemetryManager, new_config: SDKConfig
    ) -> None:
        """WARN once (rate-limited) when a new caller has a divergent config."""
        if (
            existing._config.otel_endpoint != new_config.otel_endpoint
            or existing._config.otel_export_format != new_config.otel_export_format
            or existing._config.otel_sampler != new_config.otel_sampler
        ):
            _otel_warn_rate_limited(
                "sdk.otel_singleton_conflict",
                instance_id=id(cls),
                existing_endpoint=existing._config.otel_endpoint,
                new_endpoint=new_config.otel_endpoint,
            )

    @classmethod
    def reset(cls) -> None:
        """Shut down providers and clear the singleton (test hook).

        Production code never calls this; the per-test fixture
        ``reset_otel_singleton`` (in ``tests/unit/sdk/conftest.py``) uses
        it for isolation (hardening H5 / FR-026).
        """
        with cls._instance_lock:
            if cls._instance is not None:
                with contextlib.suppress(Exception):
                    cls._instance.shutdown()
            cls._instance = None
        # Also clear rate-limiter state so tests don't see suppressed events.
        _warn_rate_limiter.reset()

    @property
    def is_available(self) -> bool:
        return _otel_available and self._initialized

    def _initialize(self) -> None:
        """Initialize OTEL providers per the production spec.

        Wrapped end-to-end in try/except — failure emits one WARN via the
        rate-limiter and leaves ``_initialized=False``, causing all
        subsequent ``record_signal`` / ``force_flush`` calls to be no-ops
        (FR-011 — invoke path never breaks).
        """
        if not _otel_available:
            _otel_warn_rate_limited(
                "sdk.otel_unavailable",
                instance_id=id(self),
                reason="opentelemetry package not installed; pip install 'dns-aid[otel]'",
            )
            return

        try:
            # Lazy import — keep dns_aid.__version__ off the cold path of
            # users who never enable OTEL.
            import dns_aid

            # ----- Resource -----
            default_attrs: dict[str, Any] = {
                "service.name": "dns-aid-sdk",
                "service.version": dns_aid.__version__,  # FR-009 — fixes the 0.4.9 bug
            }
            if self._config.otel_environment:
                default_attrs["deployment.environment"] = self._config.otel_environment

            # Resource.create() reads OTEL_RESOURCE_ATTRIBUTES env var and
            # merges with our defaults. Per OTEL spec, user env values
            # WIN over our defaults — that's the documented behavior we
            # want (FR-009b, hardening Q6 decision).
            resource = Resource.create(default_attrs)

            export_format = self._config.otel_export_format
            sampler = _resolve_sampler(self._config)

            # ----- Tracer Provider -----
            tracer_provider_kwargs: dict[str, Any] = {"resource": resource}
            if sampler is not None:
                tracer_provider_kwargs["sampler"] = sampler
            tracer_provider = TracerProvider(**tracer_provider_kwargs)

            span_exporter = self._build_span_exporter(export_format)
            if span_exporter is not None:
                # BatchSpanProcessor — production async batching (R1).
                tracer_provider.add_span_processor(BatchSpanProcessor(span_exporter))

            # Provider-join safety (FR-008) — never clobber an integrator's
            # globally-set provider.
            if _is_default_tracer_provider():
                trace.set_tracer_provider(tracer_provider)
                self._tracer_provider = tracer_provider
            else:
                # Integrator owns the global provider; we join via the global API
                # and do not retain a reference to a provider we did not set.
                self._tracer_provider = None
            self._tracer = trace.get_tracer("dns-aid-sdk")

            # ----- Meter Provider -----
            metric_reader = self._build_metric_reader(export_format)
            if metric_reader is not None:
                meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
                if _is_default_meter_provider():
                    metrics.set_meter_provider(meter_provider)
                    self._meter_provider = meter_provider
                else:
                    self._meter_provider = None
            meter = metrics.get_meter("dns-aid-sdk")

            # ----- Instruments -----
            self._duration_histogram = meter.create_histogram(
                name="dns_aid.invocation.duration",
                description="Agent invocation duration in milliseconds",
                unit="ms",
            )
            self._invocation_counter = meter.create_counter(
                name="dns_aid.invocation.count",
                description="Number of agent invocations by status",
            )
            self._error_counter = meter.create_counter(
                name="dns_aid.invocation.error_count",
                description="Number of failed agent invocations",
            )
            self._cost_counter = meter.create_counter(
                name="dns_aid.invocation.cost",
                description="Cumulative invocation cost in cost_units",
            )

            self._initialized = True
            logger.info(
                "sdk.otel_initialized",
                export_format=export_format,
                endpoint=self._config.otel_endpoint,
                sampler=self._config.otel_sampler,
                provider_joined=self._tracer_provider is None,
            )
        except Exception as exc:
            self._initialized = False
            _otel_warn_rate_limited(
                "sdk.otel_init_failed",
                instance_id=id(self),
                error=type(exc).__name__,
                detail=str(exc)[:200],
            )

    def _build_span_exporter(self, export_format: str) -> Any:
        """Return a configured span exporter, or None to skip exporter."""
        if export_format == "console":
            return ConsoleSpanExporter()
        if export_format == "noop":
            return None
        # otlp (default)
        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                OTLPSpanExporter,
            )

            return OTLPSpanExporter(**self._otlp_exporter_kwargs())
        except ImportError:
            _otel_warn_rate_limited(
                "sdk.otel_otlp_exporter_unavailable",
                instance_id=id(self),
                detail=(
                    "opentelemetry-exporter-otlp-proto-grpc not installed; "
                    "falling back to console. Install dns-aid[otel] to fix."
                ),
            )
            return ConsoleSpanExporter()

    def _build_metric_reader(self, export_format: str) -> Any:
        """Return a configured metric reader, or None to skip metrics."""
        if export_format == "console":
            return PeriodicExportingMetricReader(
                ConsoleMetricExporter(), export_interval_millis=10000
            )
        if export_format == "noop":
            return None
        # otlp (default)
        try:
            from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
                OTLPMetricExporter,
            )

            return PeriodicExportingMetricReader(OTLPMetricExporter(**self._otlp_exporter_kwargs()))
        except ImportError:
            return PeriodicExportingMetricReader(
                ConsoleMetricExporter(), export_interval_millis=60000
            )

    def _otlp_exporter_kwargs(self) -> dict[str, Any]:
        """Build OTLP exporter kwargs honoring URL scheme for TLS vs plaintext.

        The OTEL Python OTLP gRPC exporter uses TLS by default; passing
        ``insecure=True`` switches to plaintext. Naïvely passing an
        endpoint like ``grpc://localhost:4317`` fails with a confusing
        TLS handshake error against a plaintext collector (e.g., the
        default Jaeger OTLP ingest port).

        This helper interprets the user-supplied endpoint:

        - ``http://host:port`` → plaintext (insecure=True), endpoint
          stripped of scheme so the exporter receives ``host:port``
        - ``https://host:port`` → TLS (insecure=False, the default)
        - ``grpc://host:port`` → plaintext (legacy alias for ``http://``),
          stripped of scheme — we accept this because it appears in
          tutorials and docs in the OTEL ecosystem
        - ``grpcs://host:port`` → TLS, stripped of scheme
        - bare ``host:port`` or empty → use OTEL SDK default (TLS) and
          let standard env vars (``OTEL_EXPORTER_OTLP_INSECURE``,
          ``OTEL_EXPORTER_OTLP_CERTIFICATE``) take over
        """
        kwargs: dict[str, Any] = {}
        endpoint = self._config.otel_endpoint
        if not endpoint:
            return kwargs
        plaintext_schemes = ("http://", "grpc://")
        tls_schemes = ("https://", "grpcs://")
        for scheme in plaintext_schemes:
            if endpoint.startswith(scheme):
                kwargs["endpoint"] = endpoint[len(scheme) :]
                kwargs["insecure"] = True
                return kwargs
        for scheme in tls_schemes:
            if endpoint.startswith(scheme):
                kwargs["endpoint"] = endpoint[len(scheme) :]
                kwargs["insecure"] = False
                return kwargs
        # No recognized scheme — pass through as-is (OTEL SDK defaults
        # apply: TLS unless OTEL_EXPORTER_OTLP_INSECURE=true env var).
        kwargs["endpoint"] = endpoint
        return kwargs

    def force_flush(self, timeout_millis: int = 5000) -> bool:
        """Flush pending spans and metrics. Returns True on success.

        Safe to call when OTEL is not available — returns True (no-op).
        Defensive — exporter failures are logged via the rate-limiter and
        do not raise to the caller (FR-024).
        """
        if not self.is_available:
            return True
        ok = True
        try:
            if self._tracer_provider is not None and hasattr(self._tracer_provider, "force_flush"):
                ok = bool(self._tracer_provider.force_flush(timeout_millis)) and ok
            if self._meter_provider is not None and hasattr(self._meter_provider, "force_flush"):
                ok = bool(self._meter_provider.force_flush(timeout_millis)) and ok
        except Exception as exc:
            _otel_warn_rate_limited(
                "sdk.otel_flush_failed",
                instance_id=id(self),
                error=type(exc).__name__,
                detail=str(exc)[:200],
            )
            ok = False
        return ok

    def shutdown(self) -> None:
        """Flush + shut down providers. Idempotent."""
        if not self.is_available:
            self._initialized = False
            return
        # Flush before shutdown so pending spans drain.
        self.force_flush(timeout_millis=5000)
        with contextlib.suppress(Exception):
            if self._tracer_provider is not None and hasattr(self._tracer_provider, "shutdown"):
                self._tracer_provider.shutdown()
        with contextlib.suppress(Exception):
            if self._meter_provider is not None and hasattr(self._meter_provider, "shutdown"):
                self._meter_provider.shutdown()
        self._tracer = None
        self._tracer_provider = None
        self._meter_provider = None
        self._initialized = False

    # ----- Span attribute building -----

    @staticmethod
    def _build_span_start_attributes(agent: Any) -> dict[str, Any]:
        """Attributes set when the span is opened (before handler runs).

        Sanitizes the endpoint URL per FR-019 to prevent credential leakage
        if a caller constructed an AgentRecord with embedded userinfo.
        """
        fqdn = getattr(agent, "fqdn", "")
        endpoint = getattr(agent, "endpoint_url", "") or ""
        protocol_val = getattr(agent, "protocol", None)
        protocol_str = protocol_val.value if hasattr(protocol_val, "value") else str(protocol_val)
        attrs: dict[str, Any] = {
            ATTR_AGENT_PROTOCOL: protocol_str,
            ATTR_AGENT_ENDPOINT: _sanitize_endpoint_url(endpoint) or "",
        }
        agent_name, agent_domain = _parse_signal_fqdn(fqdn)
        if agent_name:
            attrs[ATTR_AGENT_NAME] = agent_name
        if agent_domain:
            attrs[ATTR_AGENT_DOMAIN] = agent_domain
        return attrs

    @staticmethod
    def _build_span_end_attributes(signal: InvocationSignal) -> dict[str, Any]:
        """Attributes set at span end from the recorded signal."""
        attrs: dict[str, Any] = {
            ATTR_INVOCATION_STATUS: signal.status.value,
            ATTR_INVOCATION_LATENCY: signal.invocation_latency_ms,
            ATTR_SECURITY_DNSSEC: signal.dnssec_validated,
        }
        if signal.method:
            attrs[ATTR_INVOCATION_METHOD] = signal.method
        if signal.cost_units is not None:
            attrs[ATTR_INVOCATION_COST] = signal.cost_units
        return attrs

    @classmethod
    def _build_span_attributes(cls, signal: InvocationSignal) -> dict[str, Any]:
        """Backward-compatible shim for pre-v0.23.0 callers and tests.

        Combines start-time attributes (which previously took an agent or
        signal) with end-time attributes (from the signal). New code should
        prefer the explicit ``_build_span_start_attributes(agent)`` and
        ``_build_span_end_attributes(signal)`` helpers so attributes can be
        set at the correct phase of the span lifecycle (Story 3).
        """
        attrs: dict[str, Any] = {
            ATTR_AGENT_ENDPOINT: _sanitize_endpoint_url(signal.agent_endpoint) or "",
            ATTR_AGENT_PROTOCOL: signal.protocol,
        }
        attrs.update(cls._build_span_end_attributes(signal))
        agent_name, agent_domain = _parse_signal_fqdn(signal.agent_fqdn)
        if agent_name:
            attrs[ATTR_AGENT_NAME] = agent_name
        if agent_domain:
            attrs[ATTR_AGENT_DOMAIN] = agent_domain
        return attrs

    def build_metric_labels(self, signal: InvocationSignal) -> dict[str, Any]:
        """Build the label dict for metric instruments per the cardinality
        contract (contracts/metrics.md)."""
        labels: dict[str, Any] = {
            "protocol": signal.protocol,
            "status": signal.status.value,
        }
        if "fqdn" in self._metric_labels_opts:
            labels[ATTR_AGENT_FQDN] = signal.agent_fqdn
        if "caller" in self._metric_labels_opts and signal.caller_id:
            labels["dns_aid.caller.id"] = signal.caller_id
        # NOTE: the "tool" opt-in label is accepted by SDKConfig for
        # forward-compatibility, but InvocationSignal does not currently
        # carry the per-call tool name, so no `dns_aid.tool.name` label is
        # emitted here yet. Populating it requires threading the tool name
        # from the MCP tools/call arguments into the signal — tracked as a
        # follow-up. Until then, opting into "tool" is a no-op for metrics.
        return labels

    def record_signal(self, signal: InvocationSignal) -> None:
        """Record metric instrument data for a completed invoke.

        Spans are NOT recorded here — they're managed by the context
        manager in ``AgentClient.invoke()`` so the span is the active
        context during the handler call (Story 3 / FR-001).

        Metrics are recorded on every invoke regardless of span sampling
        (FR-004).
        """
        if not self.is_available:
            return
        try:
            labels = self.build_metric_labels(signal)
            if self._duration_histogram is not None:
                self._duration_histogram.record(signal.invocation_latency_ms, labels)
            if self._invocation_counter is not None:
                self._invocation_counter.add(1, labels)
            if signal.status.value in ("error", "timeout", "refused") and (
                self._error_counter is not None
            ):
                self._error_counter.add(1, labels)
            if signal.cost_units is not None and self._cost_counter is not None:
                self._cost_counter.add(signal.cost_units, {"protocol": signal.protocol})
        except Exception as exc:
            _otel_warn_rate_limited(
                "sdk.otel_error",
                instance_id=id(self),
                op="record_signal",
                error=type(exc).__name__,
                detail=str(exc)[:200],
            )

    def set_span_outcome(self, span: Any, signal: InvocationSignal) -> None:
        """Apply end-of-span attributes + status from a recorded signal.

        Short-circuits when the span is not recording (sampler dropped it
        OR span is None) — saves the cost of building the attribute dict
        when the data won't be exported (hardening H10).

        Sanitizes ``signal.error_message`` (FR-020) before setting it as
        the span status description.
        """
        if span is None:
            return
        # Avoid wasted work when the sampler dropped this span.
        is_recording = getattr(span, "is_recording", None)
        if callable(is_recording) and not is_recording():
            return
        if not _otel_available:
            return
        try:
            attrs = self._build_span_end_attributes(signal)
            for k, v in attrs.items():
                span.set_attribute(k, v)
            status = signal.status.value
            if status == "success":
                span.set_status(StatusCode.OK)
            else:
                description = _sanitize_error_message(signal.error_message) or ""
                span.set_status(StatusCode.ERROR, description)
        except Exception as exc:
            _otel_warn_rate_limited(
                "sdk.otel_error",
                instance_id=id(self),
                op="set_span_outcome",
                error=type(exc).__name__,
                detail=str(exc)[:200],
            )

    def start_invoke_span(self, agent: Any, method: str | None) -> Any:
        """Return a context manager that opens a span for one invoke.

        Returns ``None`` (suitable for use with ``contextlib.nullcontext``
        wrapping at the call site) when OTEL is not available — but for
        ergonomics, AgentClient uses its own ``_maybe_otel_span`` wrapper
        that handles the None case.

        The span name is ``dns-aid.invoke {agent_fqdn}``; SpanKind=CLIENT
        per contracts/span-attributes.md.
        """
        if not self.is_available or self._tracer is None:
            return None
        try:
            fqdn = getattr(agent, "fqdn", "unknown")
            attrs = self._build_span_start_attributes(agent)
            return self._tracer.start_as_current_span(
                name=f"dns-aid.invoke {fqdn}",
                kind=SpanKind.CLIENT,
                attributes=attrs,
            )
        except Exception as exc:
            _otel_warn_rate_limited(
                "sdk.otel_error",
                instance_id=id(self),
                op="start_invoke_span",
                error=type(exc).__name__,
                detail=str(exc)[:200],
            )
            return None
