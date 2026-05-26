"""Tiny OTEL-instrumented downstream agent for the linked-trace demo.

Listens on http://localhost:9000/invoke. Receives requests from the
caller, extracts the incoming W3C `traceparent`, starts a child span,
returns a JSON response.

Run BEFORE caller.py:

    pip install fastapi uvicorn opentelemetry-api opentelemetry-sdk \
        opentelemetry-exporter-otlp-proto-grpc \
        opentelemetry-instrumentation-fastapi
    python downstream_agent.py &
"""

from __future__ import annotations

import os

import uvicorn
from fastapi import FastAPI, Request
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor


def configure_otel() -> None:
    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "grpc://localhost:4317")
    resource = Resource.create(
        {"service.name": "demo-downstream-agent", "service.version": "0.1.0"}
    )
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    trace.set_tracer_provider(provider)


configure_otel()
app = FastAPI(title="DNS-AID OTEL Demo Downstream Agent")
FastAPIInstrumentor.instrument_app(app)
tracer = trace.get_tracer("demo-downstream-agent")


@app.post("/invoke")
async def invoke(request: Request) -> dict:
    """Receive an invoke from the caller, return a response.

    FastAPI auto-instrumentation extracts the incoming `traceparent` and
    starts a server span as a child of the caller's span. The explicit
    span below adds a custom annotation on top, demonstrating that
    custom spans inherit context too.
    """
    payload = await request.json()
    with tracer.start_as_current_span("downstream.process") as span:
        span.set_attribute("demo.payload_iteration", payload.get("iteration", -1))
        span.set_attribute("demo.payload_message", payload.get("message", ""))
        # Simulate some processing time
        import asyncio

        await asyncio.sleep(0.01)
        return {"ok": True, "echo": payload}


@app.get("/health")
async def health() -> dict:
    return {"status": "healthy"}


if __name__ == "__main__":
    uvicorn.run("downstream_agent:app", host="0.0.0.0", port=9000, log_level="info")
