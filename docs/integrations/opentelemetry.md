# OpenTelemetry Integration (v0.23.0+)

The DNS-AID SDK ships first-class OpenTelemetry support for distributed
tracing, metrics, and structured-log correlation. This page covers how to
enable it, what gets emitted on the wire, how to configure sampling and
collectors, and how to operate it in production.

## TL;DR

```bash
pip install 'dns-aid[otel]>=0.23.0'

export DNS_AID_SDK_OTEL_ENABLED=true
export DNS_AID_SDK_OTEL_ENDPOINT=http://your-collector:4317   # use http:// for plaintext, https:// for TLS
```

Every `AgentClient.invoke()` now produces a span and metric data points.
Outbound MCP/A2A/HTTPS requests carry `traceparent` so downstream agents
can link spans into one end-to-end trace.

## Quick start

See `examples/integration_otel_collector/` for a runnable demo:

```bash
cd examples/integration_otel_collector/
docker-compose up -d        # Jaeger UI on :16686, OTLP gRPC on :4317
python downstream_agent.py &  # OTEL-instrumented FastAPI
python caller.py              # AgentClient with otel_enabled=True
open http://localhost:16686
```

You should see a trace with the caller's span as parent of the downstream
agent's span. Total elapsed: under 10 minutes from clone.

## What gets emitted

### Spans

- Name: `dns-aid.invoke {agent_fqdn}` (e.g., `dns-aid.invoke chat.example.com`)
- Kind: `SpanKind.CLIENT`
- Attributes (set at span open): `dns_aid.agent.name`, `dns_aid.agent.domain`,
  `dns_aid.agent.protocol`, `dns_aid.agent.endpoint` (credentials in URL
  are sanitized before they reach this attribute — H1 / FR-019).
- Attributes (set at span close): `dns_aid.invocation.method`,
  `dns_aid.invocation.status`, `dns_aid.invocation.latency_ms`,
  `dns_aid.invocation.cost_units` (when present), `dns_aid.security.dnssec`.
- Status: `OK` on success; `ERROR` with the (sanitized) error message
  otherwise.

### Metrics

| Instrument | Type | Default labels |
|---|---|---|
| `dns_aid.invocation.duration` | Histogram (ms) | `protocol`, `status` |
| `dns_aid.invocation.count` | Counter | `protocol`, `status` |
| `dns_aid.invocation.error_count` | Counter | `protocol`, `status` |
| `dns_aid.invocation.cost` | Counter | `protocol` |

Metrics are recorded on **every** invoke regardless of sampling — turning
off traces (`OTEL_TRACES_SAMPLER=always_off`) still records full metric
data points. This is OTEL-standard behavior.

### Propagation headers

When an OTEL span is active on the caller, outbound HTTP requests carry:

| Header | Always? |
|---|---|
| `traceparent` | Yes when span active |
| `tracestate` | When current context carries tracestate values |
| `baggage` | When `OTEL_PROPAGATORS` includes `baggage` AND baggage is set |

A downstream agent that participates in OTEL (e.g., uses
`opentelemetry-instrumentation-fastapi`) extracts the headers and starts
a child span — producing a linked end-to-end trace.

When `otel_enabled=False` OR no current span exists, NO header is added.
Outbound wire format is byte-identical to v0.21.x.

### Structlog trace correlation

Every structlog event emitted from any `dns_aid.*` logger while an OTEL
span is active automatically carries `trace_id` and `span_id` matching
the span. Example:

```
sdk.invoke           agent_fqdn=...  trace_id=4bf92...  span_id=00f06...
mcp.policy_denied    policy_uri=...  trace_id=4bf92...  span_id=00f06...
```

This works whether YOUR SDK started the span or an integrator's own OTEL
setup did — the processor is always-on. Cost when no span is active:
~100 nanoseconds.

## Authenticating to a managed collector

Most managed observability backends (Honeycomb, Grafana Cloud, Datadog,
New Relic, Lightstep) require an `Authorization` header on OTLP requests.
Use the OTEL-standard env var `OTEL_EXPORTER_OTLP_HEADERS`:

### Honeycomb

```bash
export DNS_AID_SDK_OTEL_ENABLED=true
export DNS_AID_SDK_OTEL_ENDPOINT=grpc://api.honeycomb.io:443
export OTEL_EXPORTER_OTLP_HEADERS="x-honeycomb-team=YOUR_API_KEY,x-honeycomb-dataset=dns-aid"
```

### Grafana Cloud (Tempo + Mimir)

```bash
export DNS_AID_SDK_OTEL_ENABLED=true
export DNS_AID_SDK_OTEL_ENDPOINT=grpc://your-grafana-cloud-otlp-endpoint:443
export OTEL_EXPORTER_OTLP_HEADERS="Authorization=Basic $(echo -n USER_ID:API_TOKEN | base64)"
```

### Datadog (via OTLP)

```bash
export DNS_AID_SDK_OTEL_ENABLED=true
export DNS_AID_SDK_OTEL_ENDPOINT=grpc://otlp.datadoghq.com:443
export OTEL_EXPORTER_OTLP_HEADERS="dd-api-key=YOUR_API_KEY"
```

### mTLS

For collectors that require client certificates:

```bash
export OTEL_EXPORTER_OTLP_CERTIFICATE=/path/to/client-cert.pem
export OTEL_EXPORTER_OTLP_CLIENT_KEY=/path/to/client-key.pem
```

These env vars are read by the OTEL Python SDK directly — DNS-AID does
not need to know about them.

## Sampler configuration

### Production: trace-id ratio sampling

```bash
export OTEL_TRACES_SAMPLER=traceidratio
export OTEL_TRACES_SAMPLER_ARG=0.1   # 10% of traces
```

This is the OTEL-standard env var; it wins over any SDK-specific config.

### Project-specific sampler env var (lower precedence)

```bash
export DNS_AID_SDK_OTEL_SAMPLER=always_off   # ignored if OTEL_TRACES_SAMPLER is set
```

### Via SDKConfig field (lowest precedence)

```python
SDKConfig(otel_sampler="traceidratio", ...)
```

Supported sampler names: `always_on`, `always_off`, `traceidratio`,
`parentbased_always_on`, `parentbased_always_off`,
`parentbased_traceidratio`. Unknown values raise `ValueError` at SDKConfig
construction.

## Resource attributes

The SDK sets these by default:

| Attribute | Source |
|---|---|
| `service.name` | `"dns-aid-sdk"` |
| `service.version` | `dns_aid.__version__` (matches your installed version) |
| `deployment.environment` | `SDKConfig.otel_environment` or `DNS_AID_SDK_OTEL_ENVIRONMENT` env |
| `telemetry.sdk.{name,version,language}` | OTEL SDK auto-populated |

**User overrides via `OTEL_RESOURCE_ATTRIBUTES` env var WIN** over the
defaults — per OTEL spec convention. Example:

```bash
export OTEL_RESOURCE_ATTRIBUTES="service.name=billing-agent-caller,service.version=2.0.0,deployment.environment=production"
```

## High-cardinality metric labels (opt-in)

Default label set is intentionally low-cardinality (`protocol`, `status`).
For richer dashboards, opt in to additional labels:

```bash
export DNS_AID_SDK_OTEL_METRIC_LABELS=fqdn,caller,tool
```

| Label | Added to | Source |
|---|---|---|
| `dns_aid.agent.fqdn` | duration, count, error_count | `signal.agent_fqdn` |
| `dns_aid.caller.id` | duration, count, error_count, cost | `SDKConfig.caller_id` |
| `dns_aid.tool.name` | duration, count, error_count | MCP `tools/call` tool name |

**Cardinality cost example**: with 100 unique agent FQDNs × 10 caller IDs
× 20 tool names, the default 12 series per instrument multiplies to up to
240,000 series. Most observability backends handle this but some have
strict quotas. Enable per-label as needed.

## Joining an existing OTEL setup

If your application already configures OpenTelemetry (e.g., FastAPI
auto-instrumentation, manual tracer provider setup), the DNS-AID SDK
detects this and joins your providers rather than overwriting them:

```python
# Your application already does this somewhere:
from opentelemetry import trace
trace.set_tracer_provider(my_custom_provider)

# Then later in your code:
from dns_aid.sdk import AgentClient, SDKConfig
async with AgentClient(config=SDKConfig(otel_enabled=True)) as client:
    # The SDK uses YOUR tracer provider — never overwrites it.
    await client.invoke(agent, method="probe")
```

The SDK calls `trace.get_tracer("dns-aid-sdk")` against your existing
provider. Your dashboard naming and exporter setup are preserved.

## Failure modes

| Symptom | Cause | Behavior |
|---|---|---|
| `opentelemetry` not installed but `otel_enabled=True` | Missing `dns-aid[otel]` extra | One `sdk.otel_unavailable` WARN, invokes proceed without OTEL |
| OTLP collector unreachable | Network failure, wrong endpoint | At most one `sdk.otel_error` WARN per minute, invokes still succeed |
| Propagator misconfigured (`OTEL_PROPAGATORS=bogus`) | Unsupported propagator name | At most one `sdk.otel_propagation_failed` WARN per minute, request continues without the header |
| Provider init failure | Malformed exporter config | One `sdk.otel_init_failed` WARN, OTEL disabled for this AgentClient's lifetime |
| Multiple AgentClients with conflicting OTEL configs | Singleton behavior | First config wins, one-time `sdk.otel_singleton_conflict` WARN |

All OTEL failures are caught defensively — your invoke path is never
broken because the observability backend is down.

## Flush on close

`AgentClient.__aexit__` calls `TelemetryManager.force_flush(5000ms)`
before closing the httpx client. Short-lived processes (CI jobs,
serverless functions, scripts) do not lose their last batch of spans.

If you manage the AgentClient lifetime manually (not via `async with`),
call `TelemetryManager.get_or_create(config).force_flush()` explicitly
before your process exits.

## Performance

- Per-invoke overhead with `otel_enabled=True` + no-op exporter: < 1 ms.
- p99 latency overhead with OTLP gRPC + healthy local collector: < 50 ms.
- Cost when `otel_enabled=False`: zero — no new threads, no new imports.
- Cost of the always-on structlog correlation processor when no span is
  active: ~100 ns per log event (thread-local span context lookup).

## History

OpenTelemetry support was scaffolded in v0.5.0 (Feb 2026) as a 245-line
`TelemetryManager` class with full unit-test coverage in isolation — but
the wiring step (calling `record_signal` from `AgentClient.invoke()`)
was never landed. Five SDK feature releases shipped between v0.5.0 and
v0.21.x without anyone catching or closing the gap; the architecture
doc described emitting spans that the code never actually emitted.
v0.23.0 closes that gap with a production-grade implementation including
the four release-blocker hardening items (credential sanitization,
cancellation propagation, flush on close, rate-limited warnings) that
the original scaffold did not address. Full design rationale in
`specs/005-otel-production/`.
