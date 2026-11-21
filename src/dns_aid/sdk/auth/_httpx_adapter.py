# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Bridge dns-aid AuthHandler implementations to httpx.Auth.

The official MCP Python SDK's `streamablehttp_client` accepts
``auth: httpx.Auth | None``. dns-aid's existing AuthHandler interface
(in ``base.py``) exposes an async ``apply(request)`` method instead.
This adapter wraps the latter so it can be passed to the former.

mcp 2.x talks HTTP through httpx2, which only accepts an ``httpx2.Auth``.
``to_httpx2_auth`` builds the same wrapper on that base class. The handlers
only touch ``request.headers``, ``request.url`` and ``request.content``, which
httpx2 requests expose the same way.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Any

import httpx

from dns_aid.sdk.auth.base import AuthHandler


class _DnsAidHttpxAuth(httpx.Auth):
    """Wrap a dns-aid ``AuthHandler`` so it satisfies the ``httpx.Auth`` protocol."""

    requires_request_body = False  # httpx.Auth instance attribute (overridden per-class)

    def __init__(self, handler: AuthHandler) -> None:
        self._handler = handler

    async def async_auth_flow(
        self, request: httpx.Request
    ) -> AsyncGenerator[httpx.Request, httpx.Response]:
        """Apply credentials to *request* and yield it once.

        dns-aid AuthHandlers are stateless per-request (no challenge/response
        flow). A single yield is correct; httpx will not re-enter for retries.
        """
        request = await self._handler.apply(request)
        yield request


def to_httpx_auth(handler: AuthHandler | None) -> httpx.Auth | None:
    """Convert a dns-aid ``AuthHandler`` (or ``None``) into an ``httpx.Auth``.

    Returns ``None`` when *handler* is ``None`` so callers can pass the
    result directly to ``streamablehttp_client(auth=...)``.
    """
    return _DnsAidHttpxAuth(handler) if handler is not None else None


def to_httpx2_auth(handler: AuthHandler | None) -> Any:
    """Like ``to_httpx_auth``, but returns an ``httpx2.Auth`` for mcp 2.x.

    httpx2 is imported lazily: it is only installed alongside mcp 2.x.
    """
    if handler is None:
        return None

    import httpx2

    class _DnsAidHttpx2Auth(httpx2.Auth):
        requires_request_body = False

        async def async_auth_flow(self, request: Any) -> AsyncGenerator[Any, Any]:
            yield await handler.apply(request)

    return _DnsAidHttpx2Auth()
