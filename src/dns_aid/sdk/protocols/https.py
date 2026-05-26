# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
HTTPS protocol handler.

Generic handler for agents reachable via plain HTTPS endpoints.
Sends HTTP POST with JSON payload, returns parsed response.
"""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING

import httpx

from dns_aid.sdk.models import InvocationStatus
from dns_aid.sdk.protocols.base import ProtocolHandler, RawResponse
from dns_aid.sdk.telemetry.propagation import inject_otel_context

if TYPE_CHECKING:
    from dns_aid.sdk.auth.base import AuthHandler


class HTTPSProtocolHandler(ProtocolHandler):
    """Handles plain HTTPS agent invocations."""

    @property
    def protocol_name(self) -> str:
        return "https"

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
        Send an HTTPS request to an agent.

        Uses POST with JSON body by default. Method is appended to the endpoint path
        if provided (e.g., endpoint=/api, method=invoke -> POST /api/invoke).
        """
        url = endpoint
        if method:
            url = f"{endpoint.rstrip('/')}/{method.lstrip('/')}"

        payload = arguments or {}
        start = time.perf_counter()

        try:
            request = client.build_request(
                "POST",
                url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=timeout,
            )
            if auth_handler:
                request = await auth_handler.apply(request)
            # Spec 005 / FR-005: inject W3C trace context headers. No-op
            # when otel_enabled=False or no current span (FR-006).
            await inject_otel_context(request)
            response = await client.send(request)
            elapsed = (time.perf_counter() - start) * 1000

        except httpx.TimeoutException:
            elapsed = (time.perf_counter() - start) * 1000
            return RawResponse(
                success=False,
                status=InvocationStatus.TIMEOUT,
                error_type="TimeoutError",
                error_message=f"Timeout after {timeout}s",
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
