# DNS-AID SDK + OpenTelemetry — Linked Trace Demo

End-to-end demonstration of distributed tracing across an agent mesh
using DNS-AID's v0.23.0 OpenTelemetry support. The caller emits a span
via DNS-AID SDK, propagates W3C trace context to a downstream agent over
the wire, and you see both spans linked in the Jaeger UI.

**Time**: under 10 minutes from clone to seeing a linked trace.

## Prerequisites

- Docker (for the Jaeger all-in-one container)
- Python 3.11+
- `pip install 'dns-aid[otel]>=0.23.0'`
- For the downstream agent only: `pip install -r requirements.txt`

## Run

### 1. Start Jaeger

```bash
docker-compose up -d
```

Jaeger UI is now on `http://localhost:16686`, OTLP gRPC ingest on `:4317`.

### 2. Start the downstream agent

```bash
pip install -r requirements.txt
python downstream_agent.py &
```

FastAPI listens on `:9000`. The agent uses
`opentelemetry-instrumentation-fastapi` to auto-extract the incoming
`traceparent` header.

### 3. Run the caller

```bash
python caller.py
```

You'll see three invokes execute successfully.

### 4. View the linked trace

Open `http://localhost:16686`. In the Service dropdown:

- Select **`dns-aid-sdk`** → click "Find Traces" → click any trace.
  - Top span: `dns-aid.invoke {agent_fqdn}` — the caller's span.
  - Child: `POST /invoke` — the downstream agent's FastAPI-instrumented span.
  - Grandchild: `downstream.process` — the custom span the downstream
    explicitly started.
- All three share the same `trace_id` — proving W3C trace context
  propagated correctly across the wire.

## What's happening

```
[caller.py]
   AgentClient.invoke()
      ├─ opens span "dns-aid.invoke _echo._https._agents.demo.local"
      ├─ HTTPS protocol handler builds POST request
      ├─ inject_otel_context() event hook writes `traceparent` header
      ├─ httpx sends request to http://localhost:9000/invoke
      └─ span ends with status=OK, latency=...

[downstream_agent.py]
   FastAPI receives the request
      ├─ FastAPIInstrumentor reads `traceparent` from headers
      ├─ starts server span as CHILD of caller's span
      └─ /invoke endpoint starts "downstream.process" span explicitly

[jaeger]
   collects spans via OTLP gRPC from both services
   UI renders the three spans as one connected trace
```

## Cleanup

```bash
# Stop the downstream agent
kill %1   # or pkill -f downstream_agent.py

# Stop Jaeger
docker-compose down
```

## Try it in production

This example uses HTTP for simplicity. For production:

- Use HTTPS — the SDK's propagation works identically over TLS.
- Use a managed OTEL collector — set `OTEL_EXPORTER_OTLP_HEADERS` for
  auth (see `docs/integrations/opentelemetry.md`).
- Pin the Jaeger image by SHA digest (see comment in `docker-compose.yml`).
- Configure sampling — set `OTEL_TRACES_SAMPLER=traceidratio` and
  `OTEL_TRACES_SAMPLER_ARG=0.1` to sample 10% of traces.
