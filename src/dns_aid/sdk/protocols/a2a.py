# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
A2A (Agent-to-Agent) protocol handler.

Implements Google's A2A protocol (https://google.github.io/A2A/) using
JSON-RPC 2.0 over HTTP POST.

Standard A2A methods (message/send, message/stream, tasks/get, etc.) are
wrapped in a proper JSON-RPC 2.0 envelope with jsonrpc version and request ID.
Non-standard methods use a simpler generic payload for backward compatibility.

Example standard A2A request:
    {
        "jsonrpc": "2.0",
        "method": "message/send",
        "params": {
            "message": {
                "messageId": "...",
                "role": "user",
                "parts": [{"kind": "text", "text": "Hello"}]
            }
        },
        "id": "unique-request-id"
    }
"""

from __future__ import annotations

import json
import time
import uuid
from typing import TYPE_CHECKING

import httpx

from dns_aid.sdk.models import InvocationStatus
from dns_aid.sdk.protocols.base import ProtocolHandler, RawResponse
from dns_aid.sdk.telemetry.propagation import inject_otel_context

if TYPE_CHECKING:
    from dns_aid.sdk.auth.base import AuthHandler

# Standard A2A JSON-RPC methods per the Google A2A specification.
# These get wrapped in a proper JSON-RPC 2.0 envelope automatically.
_A2A_JSONRPC_METHODS = frozenset(
    {
        "message/send",
        "message/stream",
        "tasks/get",
        "tasks/cancel",
        "tasks/pushNotificationConfig/set",
        "tasks/pushNotificationConfig/get",
        "tasks/resubscribe",
    }
)


class A2AProtocolHandler(ProtocolHandler):
    """Handles A2A agent invocations over HTTPS.

    Supports two modes:

    1. **Standard A2A** (recommended): When ``method`` is a recognized A2A
       JSON-RPC method (e.g., ``message/send``), the request is wrapped in a
       proper JSON-RPC 2.0 envelope with ``jsonrpc``, ``id``, and ``params``.
       Arguments are placed inside ``params``.

    2. **Generic**: For non-standard methods, arguments are spread into the
       payload directly for backward compatibility with custom agents.
    """

    @property
    def protocol_name(self) -> str:
        return "a2a"

    async def invoke(
        self,
        client: httpx.AsyncClient,
        endpoint: str,
        method: str | None,
        arguments: dict | None,
        timeout: float,
        auth_handler: AuthHandler | None = None,
    ) -> RawResponse:
        """
        Send an A2A request to an agent.

        For standard A2A methods (message/send, tasks/get, etc.), builds a
        JSON-RPC 2.0 envelope. For other methods, sends a generic payload.

        Args:
            client: httpx async client for making the request.
            endpoint: Agent's A2A endpoint URL.
            method: A2A method name (e.g., "message/send").
            arguments: Method parameters (placed in "params" for JSON-RPC).
            timeout: Request timeout in seconds.

        Returns:
            RawResponse with success/failure status, response data, and telemetry.
        """
        resolved_method = method or "message/send"

        if resolved_method in _A2A_JSONRPC_METHODS:
            # Standard A2A: proper JSON-RPC 2.0 envelope
            payload = {
                "jsonrpc": "2.0",
                "method": resolved_method,
                "params": arguments or {},
                "id": str(uuid.uuid4()),
            }
        else:
            # Generic/legacy: flat payload for backward compatibility
            payload = {
                "method": resolved_method,
                **(arguments or {}),
            }

        start = time.perf_counter()

        try:
            request = client.build_request(
                "POST",
                endpoint,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=timeout,
            )
            if auth_handler:
                request = await auth_handler.apply(request)
            # Spec 005 / FR-005: inject W3C trace context headers into the
            # outbound request when an OTEL span is active on the caller.
            # No-op when otel_enabled=False or no current span — header is
            # not added in those cases (FR-006).
            await inject_otel_context(request)
            response = await client.send(request)
            elapsed = (time.perf_counter() - start) * 1000

        except httpx.TimeoutException:
            elapsed = (time.perf_counter() - start) * 1000
            return RawResponse(
                success=False,
                status=InvocationStatus.TIMEOUT,
                error_type="TimeoutError",
                error_message=f"Timeout after {timeout}s connecting to {endpoint}",
                invocation_latency_ms=elapsed,
            )
        except httpx.ConnectError as e:
            elapsed = (time.perf_counter() - start) * 1000
            return RawResponse(
                success=False,
                status=InvocationStatus.REFUSED,
                error_type="ConnectError",
                error_message=str(e),
                invocation_latency_ms=elapsed,
            )
        except httpx.HTTPError as e:
            elapsed = (time.perf_counter() - start) * 1000
            return RawResponse(
                success=False,
                status=InvocationStatus.ERROR,
                error_type=type(e).__name__,
                error_message=str(e),
                invocation_latency_ms=elapsed,
            )

        response_size = len(response.content)
        cost_units = _parse_float_header(response.headers, "x-cost-units")
        cost_currency = response.headers.get("x-cost-currency")

        if response.status_code >= 400:
            return RawResponse(
                success=False,
                status=InvocationStatus.ERROR,
                http_status_code=response.status_code,
                error_type="HTTPError",
                error_message=f"HTTP {response.status_code}: {response.text[:200]}",
                invocation_latency_ms=elapsed,
                ttfb_ms=elapsed,
                response_size_bytes=response_size,
                cost_units=cost_units,
                cost_currency=cost_currency,
                headers=dict(response.headers),
            )

        try:
            data = response.json()
        except json.JSONDecodeError:
            data = response.text

        return RawResponse(
            success=True,
            status=InvocationStatus.SUCCESS,
            data=data,
            http_status_code=response.status_code,
            invocation_latency_ms=elapsed,
            ttfb_ms=elapsed,
            response_size_bytes=response_size,
            cost_units=cost_units,
            cost_currency=cost_currency,
            headers=dict(response.headers),
        )


def _parse_float_header(headers: httpx.Headers, name: str) -> float | None:
    value = headers.get(name)
    if value is None:
        return None
    try:
        return float(value)
    except (ValueError, TypeError):
        return None
