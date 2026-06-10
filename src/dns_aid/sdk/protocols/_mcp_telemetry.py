# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Telemetry capture for the MCP Streamable HTTP transport.

The official MCP Python SDK exposes ``httpx_client_factory`` as the seam
for replacing the underlying HTTP client. We pass a factory that creates
an ``httpx.AsyncClient`` with event hooks attached, capturing the same
signals dns-aid's existing ``RawResponse`` carries: TTFB, total latency,
response size, cost headers, TLS version, status code, headers.

Each ``streamablehttp_client`` invocation may issue multiple HTTP
requests (initialize handshake, then one or more tool calls). The
capture records the LAST request's signals — the tool call's response —
matching the semantics of the previous one-shot transport.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import httpx

from dns_aid.sdk.telemetry.propagation import inject_otel_context

if TYPE_CHECKING:
    # `mcp` is an optional dependency (the `mcp` extra). It is referenced here
    # only as a return-type annotation, which `from __future__ import
    # annotations` keeps lazy — so importing this module (and therefore the
    # whole `dns_aid` package and CLI) must not require `mcp` to be installed.
    from mcp.shared._httpx_utils import McpHttpClientFactory


@dataclass
class _TelemetryCapture:
    """Per-invocation transport-layer signal record.

    Fields are populated by httpx event hooks during request/response
    flow. Translated into the public ``RawResponse`` shape after the
    session completes.
    """

    start_perf: float | None = None
    ttfb_perf: float | None = None
    total_perf: float | None = None
    response_size_bytes: int = 0
    cost_units: float | None = None
    cost_currency: str | None = None
    tls_version: str | None = None
    http_status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)

    async def on_request(self, request: httpx.Request) -> None:
        """httpx event hook: called when a request is about to be sent."""
        self.start_perf = time.perf_counter()
        # Reset per-request fields so the LAST request's signals win
        self.ttfb_perf = None
        self.total_perf = None
        self.response_size_bytes = 0
        self.cost_units = None
        self.cost_currency = None
        self.tls_version = None
        self.http_status_code = None
        self.headers = {}

    async def on_response(self, response: httpx.Response) -> None:
        """httpx event hook: called when response headers are received."""
        now = time.perf_counter()
        self.ttfb_perf = now
        self.http_status_code = response.status_code
        # Lowercase keys for case-insensitive lookup downstream
        self.headers = {k.lower(): v for k, v in response.headers.items()}

        cost_units_raw = self.headers.get("x-cost-units")
        if cost_units_raw is not None:
            try:
                self.cost_units = float(cost_units_raw)
            except (TypeError, ValueError):
                self.cost_units = None

        self.cost_currency = self.headers.get("x-cost-currency")

        # Read response body to measure size and finalize total_perf.
        # SSE streams are consumed by the SDK; this hook fires once headers
        # arrive, so we cannot measure full body here for streaming responses.
        # For non-streaming JSON responses, content is already buffered.
        try:
            self.response_size_bytes = len(response.content)
        except (httpx.ResponseNotRead, RuntimeError):
            # Streaming response — size will be tracked separately if needed.
            self.response_size_bytes = 0

        self.total_perf = time.perf_counter()

        # TLS version extraction — best-effort, may not be available on all platforms.
        try:
            extensions = response.extensions
            network_stream = extensions.get("network_stream") if extensions else None
            if network_stream is not None:
                ssl_object = network_stream.get_extra_info("ssl_object")
                if ssl_object is not None:
                    self.tls_version = ssl_object.version()
        except (AttributeError, KeyError):
            self.tls_version = None

    @property
    def invocation_latency_ms(self) -> float | None:
        """Total latency in milliseconds, or None if not yet completed."""
        if self.start_perf is None or self.total_perf is None:
            return None
        return (self.total_perf - self.start_perf) * 1000

    @property
    def ttfb_ms(self) -> float | None:
        """Time to first byte in milliseconds, or None if not yet measured."""
        if self.start_perf is None or self.ttfb_perf is None:
            return None
        return (self.ttfb_perf - self.start_perf) * 1000


def _make_telemetry_factory(capture: _TelemetryCapture) -> McpHttpClientFactory:
    """Build an ``httpx_client_factory`` that records signals into *capture*.

    The returned factory matches the signature expected by
    ``streamablehttp_client(httpx_client_factory=...)`` — see
    ``mcp.shared._httpx_utils.create_mcp_http_client``.
    """

    def factory(
        headers: dict[str, str] | None = None,
        timeout: httpx.Timeout | None = None,
        auth: httpx.Auth | None = None,
    ) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers=headers,
            timeout=timeout if timeout is not None else httpx.Timeout(30.0),
            auth=auth,
            follow_redirects=True,
            event_hooks={
                # Spec 005 / FR-005: inject_otel_context runs AFTER capture
                # so the active span is read at the latest moment before the
                # request goes on the wire. Captures + propagation are
                # independent; ordering is for clarity.
                "request": [capture.on_request, inject_otel_context],
                "response": [capture.on_response],
            },
        )

    return factory
