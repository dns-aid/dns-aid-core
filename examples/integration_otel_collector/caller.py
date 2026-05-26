"""DNS-AID SDK caller — sends one invoke with OTEL enabled.

Run AFTER `docker-compose up -d` (Jaeger ready on :4317) AND
`python downstream_agent.py &` (FastAPI listening on :9000).

Then open http://localhost:16686 — search for service `dns-aid-sdk` and
you'll see a trace with this caller's `dns-aid.invoke` span as parent of
the downstream agent's HTTP server span (linked via W3C traceparent).
"""

from __future__ import annotations

import asyncio
import os
import sys

from dns_aid.core.models import AgentRecord, Protocol
from dns_aid.sdk import AgentClient, SDKConfig


async def main() -> None:
    # Configure OTEL to ship to the local Jaeger OTLP endpoint.
    os.environ.setdefault("DNS_AID_SDK_OTEL_ENABLED", "true")
    # Use http:// scheme for plaintext gRPC (Jaeger all-in-one default).
    # For TLS use https:// or grpcs:// scheme. See URL-scheme handling
    # in docs/integrations/opentelemetry.md.
    os.environ.setdefault("DNS_AID_SDK_OTEL_ENDPOINT", "http://localhost:4317")
    os.environ.setdefault("DNS_AID_SDK_OTEL_ENVIRONMENT", "demo")

    config = SDKConfig.from_env()
    config.caller_id = "otel-demo-caller"

    # Build an AgentRecord pointing at the local downstream agent.
    agent = AgentRecord(
        name="echo",
        domain="demo.local",
        protocol=Protocol.HTTPS,
        target_host="localhost",
        port=9000,
        endpoint_override="http://localhost:9000/invoke",
    )

    async with AgentClient(config=config) as client:
        for i in range(3):
            result = await client.invoke(
                agent,
                method="probe",
                arguments={"iteration": i, "message": "hello from demo caller"},
            )
            status = "ok" if result.success else "FAIL"
            print(f"[caller] invoke {i + 1}: {status} latency={result.signal.invocation_latency_ms:.1f}ms")

    print("\nFlush complete. Open http://localhost:16686 and search service=dns-aid-sdk")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(130)
