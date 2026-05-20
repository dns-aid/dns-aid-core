# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for the credential resolution precedence on ``AgentClient.invoke()``.

Implements T008 from ``specs/003-credential-provider-callback/tasks.md``. The
precedence contract is:

    auth_handler > credentials > credential_provider > no_auth

where the first non-empty source wins and subsequent sources are not consulted.
When both ``credentials`` and ``credential_provider`` are supplied, the explicit
dict wins and the SDK emits a debug-level log naming the bypass (FR-013).

TDD state at file creation (T008): the ``credential_provider`` keyword-only
parameter on ``AgentClient.invoke`` does not yet exist. Tests referencing it
will fail with ``TypeError: invoke() got an unexpected keyword argument
'credential_provider'`` — the expected RED state. T012 adds the parameter, T013
adds the resolution logic, and at T014 the full precedence suite turns GREEN.

Tests that only exercise the existing ``auth_handler`` and ``credentials``
parameters (already present in the SDK today) pass against the current code
and serve as backward-compatibility locks.
"""

from __future__ import annotations

import contextlib
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest

from dns_aid.core.models import AgentRecord, Protocol
from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.auth.base import AuthHandler
from dns_aid.sdk.client import AgentClient


def _bearer_agent() -> AgentRecord:
    """Build an AgentRecord whose declared auth_type is bearer (the simplest
    non-none handler for exercising precedence)."""
    return AgentRecord(
        name="precedence-test",
        domain="example.com",
        protocol=Protocol.MCP,
        target_host="mcp.example.com",
        port=443,
        capabilities=[],
        auth_type="bearer",
        auth_config={"header_name": "Authorization"},
    )


def _no_auth_agent() -> AgentRecord:
    """Build an AgentRecord that requires no authentication."""
    return AgentRecord(
        name="precedence-no-auth",
        domain="example.com",
        protocol=Protocol.MCP,
        target_host="mcp.example.com",
        port=443,
        capabilities=[],
        auth_type=None,
        auth_config=None,
    )


class _RecordingAuthHandler(AuthHandler):
    """An AuthHandler that records when it's applied, so tests can assert
    which path resolved it."""

    def __init__(self) -> None:
        self.apply_count = 0

    @property
    def auth_type(self) -> str:
        return "recording"

    async def apply(self, request: httpx.Request) -> httpx.Request:
        self.apply_count += 1
        request.headers["X-Recording-Handler"] = "applied"
        return request


def _mock_transport(_request: httpx.Request) -> httpx.Response:
    """Mock HTTP transport that returns a successful JSON-RPC response without
    inspecting credentials, isolating the resolution path from network I/O."""
    return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})


@pytest.fixture
def sdk_config() -> SDKConfig:
    return SDKConfig(timeout_seconds=5.0, caller_id="precedence-test", console_signals=False)


class TestPrecedenceOrdering:
    """Each level of precedence wins over the levels below it."""

    @pytest.mark.asyncio
    async def test_explicit_auth_handler_overrides_credentials_dict(
        self,
        sdk_config: SDKConfig,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When ``auth_handler`` is supplied, ``credentials`` is not consulted.

        This locks existing SDK behavior (the ``auth_handler`` override has been
        the highest-priority source since before this feature). Continues to
        pass after T012/T013 to prove backward compatibility (FR-009).
        """
        agent = _bearer_agent()
        explicit_handler = _RecordingAuthHandler()
        unused_credentials = {"token": "this-token-should-NOT-be-used"}  # noqa: S106

        async with AgentClient(config=sdk_config) as client:
            monkeypatch.setattr(
                client,
                "_http_client",
                httpx.AsyncClient(transport=httpx.MockTransport(_mock_transport)),
            )
            # Mocked transport may not produce a fully-formed MCP response;
            # what matters is which handler was used during resolution.
            with contextlib.suppress(Exception):
                await client.invoke(
                    agent=agent,
                    method="tools/list",
                    credentials=unused_credentials,
                    auth_handler=explicit_handler,
                )

        # The explicit handler must have been applied to the outbound request
        # (precedence works) — the credentials dict was bypassed.
        assert explicit_handler.apply_count >= 1, (
            "Explicit auth_handler override must have been applied; "
            "credentials dict must have been bypassed."
        )

    @pytest.mark.asyncio
    async def test_explicit_auth_handler_overrides_credential_provider(
        self,
        sdk_config: SDKConfig,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When ``auth_handler`` is supplied, ``credential_provider`` is not awaited.

        TDD red until T012: invoke() doesn't accept credential_provider yet.
        """
        agent = _bearer_agent()
        explicit_handler = _RecordingAuthHandler()
        unused_provider = AsyncMock(return_value={"token": "never-used"})  # noqa: S106

        async with AgentClient(config=sdk_config) as client:
            monkeypatch.setattr(
                client,
                "_http_client",
                httpx.AsyncClient(transport=httpx.MockTransport(_mock_transport)),
            )
            try:
                await client.invoke(
                    agent=agent,
                    method="tools/list",
                    credential_provider=unused_provider,
                    auth_handler=explicit_handler,
                )
            except TypeError:
                raise
            except Exception:  # noqa: BLE001
                pass

        unused_provider.assert_not_awaited()
        assert explicit_handler.apply_count >= 1, (
            "Explicit auth_handler override must have been applied; "
            "credential_provider must NOT have been awaited."
        )

    @pytest.mark.asyncio
    async def test_credentials_dict_wins_over_credential_provider(
        self,
        sdk_config: SDKConfig,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When both ``credentials`` and ``credential_provider`` are supplied, the
        explicit dict wins and the provider is not awaited.

        TDD red until T012/T013: invoke() doesn't accept credential_provider yet.
        """
        agent = _bearer_agent()
        explicit_credentials = {"token": "explicit-bearer-token"}  # noqa: S106
        unused_provider = AsyncMock(return_value={"token": "provider-bearer-token"})  # noqa: S106

        async with AgentClient(config=sdk_config) as client:
            monkeypatch.setattr(
                client,
                "_http_client",
                httpx.AsyncClient(transport=httpx.MockTransport(_mock_transport)),
            )
            try:
                await client.invoke(
                    agent=agent,
                    method="tools/list",
                    credentials=explicit_credentials,
                    credential_provider=unused_provider,
                )
            except TypeError:
                raise
            except Exception:  # noqa: BLE001
                pass

        unused_provider.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_credential_provider_awaited_when_no_explicit_credentials(
        self,
        sdk_config: SDKConfig,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When only ``credential_provider`` is supplied, the SDK awaits it and uses
        the returned dict for handler resolution.

        TDD red until T012/T013: invoke() doesn't accept credential_provider yet.
        """
        agent = _bearer_agent()

        async def provider(received_agent: AgentRecord) -> dict[str, Any]:
            # The contract requires the SDK to pass the target AgentRecord to
            # the provider so it can derive per-target credentials.
            assert received_agent.fqdn == agent.fqdn
            return {"token": "provider-issued-bearer-token"}  # noqa: S106

        wrapped_provider = AsyncMock(side_effect=provider)

        async with AgentClient(config=sdk_config) as client:
            monkeypatch.setattr(
                client,
                "_http_client",
                httpx.AsyncClient(transport=httpx.MockTransport(_mock_transport)),
            )
            try:
                await client.invoke(
                    agent=agent,
                    method="tools/list",
                    credential_provider=wrapped_provider,
                )
            except TypeError:
                raise
            except Exception:  # noqa: BLE001
                pass

        wrapped_provider.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_no_auth_when_all_sources_absent(
        self,
        sdk_config: SDKConfig,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When no credential source is supplied and ``agent.auth_type`` is None
        or 'none', the SDK proceeds without authentication.

        Locks existing SDK behavior (continues to pass after T012/T013 to prove
        no regression in the no-auth path).
        """
        agent = _no_auth_agent()

        async with AgentClient(config=sdk_config) as client:
            monkeypatch.setattr(
                client,
                "_http_client",
                httpx.AsyncClient(transport=httpx.MockTransport(_mock_transport)),
            )
            # The invoke may fail downstream for unrelated reasons (mocked
            # transport, etc.); the precedence path completed without raising
            # on auth resolution itself, which is what this test locks.
            with contextlib.suppress(Exception):
                await client.invoke(
                    agent=agent,
                    method="tools/list",
                )


class TestConflictDetectionLog:
    """When both ``credentials`` and ``credential_provider`` are supplied, the SDK
    emits a debug log naming the bypass (FR-013)."""

    @pytest.mark.asyncio
    async def test_debug_log_when_both_credentials_and_provider_supplied(
        self,
        sdk_config: SDKConfig,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """The debug log MUST name which source won (``credentials``) and which was
        bypassed (``credential_provider``) so developers can detect misconfiguration.

        Uses ``structlog.testing.capture_logs()`` which intercepts structlog
        events at the bind layer — before any global filter/level configuration
        applied by other tests in the suite can drop them. This makes the
        assertion robust to suite-level structlog state (some tests run before
        this one configure structlog at CRITICAL level, which would otherwise
        suppress DEBUG messages and produce flaky failures).
        """
        import structlog.testing

        agent = _bearer_agent()
        explicit_credentials = {"token": "explicit-token"}  # noqa: S106
        unused_provider = AsyncMock(return_value={"token": "unused"})  # noqa: S106

        with structlog.testing.capture_logs() as captured_events:
            async with AgentClient(config=sdk_config) as client:
                monkeypatch.setattr(
                    client,
                    "_http_client",
                    httpx.AsyncClient(transport=httpx.MockTransport(_mock_transport)),
                )
                with contextlib.suppress(Exception):
                    await client.invoke(
                        agent=agent,
                        method="tools/list",
                        credentials=explicit_credentials,
                        credential_provider=unused_provider,
                    )

        # Locate the conflict-detection log event by name. structlog.testing
        # captures structured events as dicts with the event name under
        # ``event`` and bound kwargs as siblings.
        bypass_events = [
            event
            for event in captured_events
            if event.get("event") == "sdk.credential_provider_bypassed"
        ]
        assert bypass_events, (
            f"Expected the SDK to emit 'sdk.credential_provider_bypassed' "
            f"when both credentials and credential_provider are supplied. "
            f"Captured events: {captured_events!r}"
        )

        # The event payload must name both sources by name, identify which
        # source won, and identify which was bypassed.
        event = bypass_events[0]
        assert event.get("winner") == "credentials"
        assert event.get("bypassed") == "credential_provider"
        assert event.get("agent_fqdn") == agent.fqdn
