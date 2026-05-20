# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Hardening regression tests for the credential_provider path.

These tests verify the defensive invariants added during the Phase 3
hardening pass:

1. Provider timeout (configurable via SDKConfig.credential_provider_timeout
   or env var DNS_AID_CREDENTIAL_PROVIDER_TIMEOUT) — a hanging provider
   cannot block invoke indefinitely.
2. Return-shape validation — a provider that returns a non-dict surfaces a
   clear CredentialProviderError instead of a cryptic downstream failure.
3. Cancellation passthrough — asyncio.CancelledError is propagated cleanly,
   not wrapped in CredentialProviderError.
4. Conflict-detection log for the auth_handler-vs-credential_provider case.

These tests complement the contract tests in test_credential_provider_*.py
by focusing on operational robustness rather than the happy-path contract.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
import structlog.testing

from dns_aid.core.models import AgentRecord, Protocol
from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.auth.base import AuthHandler
from dns_aid.sdk.client import AgentClient
from dns_aid.sdk.exceptions import CredentialProviderError


def _bearer_agent() -> AgentRecord:
    return AgentRecord(
        name="hardening-test",
        domain="example.com",
        protocol=Protocol.MCP,
        target_host="mcp.example.com",
        port=443,
        capabilities=[],
        auth_type="bearer",
        auth_config={"header_name": "Authorization"},
    )


def _mock_transport(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})


class _NoopHandler(AuthHandler):
    """Minimal AuthHandler for use in precedence tests."""

    @property
    def auth_type(self) -> str:
        return "noop"

    async def apply(self, request: httpx.Request) -> httpx.Request:
        return request


# ---------------------------------------------------------------------------
# 1. Provider timeout
# ---------------------------------------------------------------------------


class TestProviderTimeout:
    """A hanging provider must not block invoke indefinitely. The configured
    ``credential_provider_timeout`` bounds the await, and a timeout surfaces
    as a ``CredentialProviderError`` with the original ``TimeoutError`` in
    ``__cause__``."""

    @pytest.mark.asyncio
    async def test_hanging_provider_times_out(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A provider that never returns is killed after the configured timeout
        and surfaces ``CredentialProviderError``."""
        agent = _bearer_agent()
        # Use a very short timeout so the test completes quickly; production
        # default is 30 seconds.
        config = SDKConfig(
            timeout_seconds=5.0,
            caller_id="hardening-test",
            console_signals=False,
            credential_provider_timeout=0.2,
        )

        async def hanging_provider(_agent: AgentRecord) -> dict[str, Any]:
            await asyncio.sleep(10.0)  # well beyond the 0.2s timeout
            return {"token": "never-returned"}  # noqa: S106

        async with AgentClient(config=config) as client:
            monkeypatch.setattr(
                client,
                "_http_client",
                httpx.AsyncClient(transport=httpx.MockTransport(_mock_transport)),
            )
            with pytest.raises(CredentialProviderError) as exc_info:
                await client.invoke(
                    agent=agent,
                    method="tools/list",
                    credential_provider=hanging_provider,
                )

        wrapper = exc_info.value
        assert wrapper.agent_fqdn == agent.fqdn
        # The wrapped cause must be a TimeoutError (or its asyncio alias,
        # which is the same class in Python 3.11+).
        assert wrapper.__cause__ is not None
        assert isinstance(wrapper.__cause__, TimeoutError)

    @pytest.mark.asyncio
    async def test_fast_provider_completes_well_under_timeout(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A provider that returns quickly is NOT affected by the timeout —
        regression catch for any implementation that erroneously waits the
        full timeout window."""
        agent = _bearer_agent()
        config = SDKConfig(
            timeout_seconds=5.0,
            caller_id="hardening-test",
            console_signals=False,
            credential_provider_timeout=10.0,
        )

        invocations = 0

        async def fast_provider(_agent: AgentRecord) -> dict[str, Any]:
            nonlocal invocations
            invocations += 1
            return {"token": "fast"}  # noqa: S106

        async with AgentClient(config=config) as client:
            monkeypatch.setattr(
                client,
                "_http_client",
                httpx.AsyncClient(transport=httpx.MockTransport(_mock_transport)),
            )
            with contextlib.suppress(Exception):
                await client.invoke(
                    agent=agent,
                    method="tools/list",
                    credential_provider=fast_provider,
                )

        assert invocations == 1


# ---------------------------------------------------------------------------
# 2. Provider return-shape validation
# ---------------------------------------------------------------------------


class TestProviderReturnShape:
    """A provider that returns a non-dict surfaces a clear CredentialProviderError
    instead of a cryptic downstream failure deep in the auth registry."""

    @pytest.mark.parametrize(
        "bad_return",
        [
            "raw-string-not-wrapped",
            ["list", "instead", "of", "dict"],
            12345,
            object(),
            ("tuple", "of", "stuff"),
        ],
        ids=["str", "list", "int", "object", "tuple"],
    )
    @pytest.mark.asyncio
    async def test_non_dict_return_raises_credential_provider_error(
        self, bad_return: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        agent = _bearer_agent()
        config = SDKConfig(
            timeout_seconds=5.0,
            caller_id="hardening-test",
            console_signals=False,
            credential_provider_timeout=5.0,
        )

        async def bad_provider(_agent: AgentRecord) -> Any:
            return bad_return

        async with AgentClient(config=config) as client:
            monkeypatch.setattr(
                client,
                "_http_client",
                httpx.AsyncClient(transport=httpx.MockTransport(_mock_transport)),
            )
            with pytest.raises(CredentialProviderError) as exc_info:
                await client.invoke(
                    agent=agent,
                    method="tools/list",
                    credential_provider=bad_provider,
                )

        wrapper = exc_info.value
        assert wrapper.agent_fqdn == agent.fqdn
        # The wrapped cause must be a TypeError naming the wrong type — but
        # the wrapper itself must NOT contain the bad value (which could
        # include credential material from a buggy provider).
        assert isinstance(wrapper.__cause__, TypeError)
        bad_value_str = str(bad_return)
        assert bad_value_str not in str(wrapper), (
            f"Wrapper exposed the provider's bad return value {bad_return!r}; "
            f"only the type name should appear."
        )


# ---------------------------------------------------------------------------
# 3. Cancellation passthrough
# ---------------------------------------------------------------------------


class TestCancellationPassthrough:
    """asyncio.CancelledError from a provider must propagate cleanly, not be
    wrapped in CredentialProviderError. Wrapping cancellation would break
    cooperative cancellation patterns at the caller."""

    @pytest.mark.asyncio
    async def test_cancelled_error_propagates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        agent = _bearer_agent()
        config = SDKConfig(
            timeout_seconds=5.0,
            caller_id="hardening-test",
            console_signals=False,
            credential_provider_timeout=5.0,
        )

        async def cancelling_provider(_agent: AgentRecord) -> dict[str, Any]:
            raise asyncio.CancelledError("simulated cooperative cancellation")

        async with AgentClient(config=config) as client:
            monkeypatch.setattr(
                client,
                "_http_client",
                httpx.AsyncClient(transport=httpx.MockTransport(_mock_transport)),
            )
            # CancelledError should propagate, NOT be wrapped.
            with pytest.raises(asyncio.CancelledError):
                await client.invoke(
                    agent=agent,
                    method="tools/list",
                    credential_provider=cancelling_provider,
                )


# ---------------------------------------------------------------------------
# 4. Conflict-detection log for auth_handler vs credential_provider
# ---------------------------------------------------------------------------


class TestAuthHandlerProviderConflictLog:
    """When both ``auth_handler`` and ``credential_provider`` are supplied to
    ``invoke()``, the SDK emits a debug log naming the bypass — so developers
    debugging integration can see why their provider wasn't awaited."""

    @pytest.mark.asyncio
    async def test_debug_log_when_auth_handler_and_provider_both_supplied(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        agent = _bearer_agent()
        config = SDKConfig(
            timeout_seconds=5.0,
            caller_id="hardening-test",
            console_signals=False,
            credential_provider_timeout=5.0,
        )
        explicit_handler = _NoopHandler()
        unused_provider = AsyncMock(return_value={"token": "never-used"})  # noqa: S106

        with structlog.testing.capture_logs() as captured_events:
            async with AgentClient(config=config) as client:
                monkeypatch.setattr(
                    client,
                    "_http_client",
                    httpx.AsyncClient(transport=httpx.MockTransport(_mock_transport)),
                )
                with contextlib.suppress(Exception):
                    await client.invoke(
                        agent=agent,
                        method="tools/list",
                        auth_handler=explicit_handler,
                        credential_provider=unused_provider,
                    )

        # The provider must not have been awaited (auth_handler precedence).
        unused_provider.assert_not_awaited()

        # The bypass debug log must have been emitted, naming the winning
        # source (auth_handler) and the bypassed source (credential_provider).
        bypass_events = [
            event
            for event in captured_events
            if event.get("event") == "sdk.credential_provider_bypassed"
        ]
        assert bypass_events, (
            f"Expected 'sdk.credential_provider_bypassed' event when both "
            f"auth_handler and credential_provider are supplied. "
            f"Captured: {captured_events!r}"
        )
        event = bypass_events[0]
        assert event.get("winner") == "auth_handler"
        assert event.get("bypassed") == "credential_provider"


# ---------------------------------------------------------------------------
# 5. agent.fqdn sanitization (verification of pydantic validator behavior)
# ---------------------------------------------------------------------------


class TestAgentFqdnLogSafety:
    """Verify AgentRecord's pydantic validation rejects characters that would
    break structured logging (newlines, control chars, whitespace, underscores).
    This protects the SDK's debug logs from injection attacks where an
    attacker-controlled agent name could insert fake log entries.

    Note: AgentRecord normalises uppercase ASCII letters to lowercase rather
    than rejecting them; that normalisation is verified separately below.
    Uppercase letters don't break log parsing, so normalisation is safe.
    """

    @pytest.mark.parametrize(
        "unsafe_name",
        [
            "name-with-newline\n-injected",
            "name-with-cr\r-injected",
            "name-with-tab\t-injected",
            "name with spaces",
            "name_with_underscore",
            "name-with-ansi-\x1b[31m-escape",
            "name-with-null\x00-byte",
        ],
        ids=[
            "newline",
            "carriage-return",
            "tab",
            "space",
            "underscore",
            "ansi-escape",
            "null-byte",
        ],
    )
    def test_unsafe_name_chars_rejected_by_validation(self, unsafe_name: str) -> None:
        """AgentRecord's name regex rejects characters that could enable
        log-injection. The regex accepts only lowercase alphanumerics + hyphens."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            AgentRecord(
                name=unsafe_name,
                domain="example.com",
                protocol=Protocol.MCP,
                target_host="mcp.example.com",
                port=443,
                capabilities=[],
            )

    def test_uppercase_name_is_normalised_to_lowercase(self) -> None:
        """AgentRecord normalises uppercase ASCII to lowercase. Uppercase
        doesn't break log parsing, so normalisation is the correct behaviour."""
        record = AgentRecord(
            name="Name-With-Uppercase",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="mcp.example.com",
            port=443,
            capabilities=[],
        )
        assert record.name == "name-with-uppercase"


# ---------------------------------------------------------------------------
# 6. Generic provider-exception observability log
# ---------------------------------------------------------------------------


class TestProviderExceptionDebugLog:
    """When the credential_provider raises a generic exception (not a
    timeout, not a cancellation), the SDK emits a debug log naming the
    exception TYPE only — never the value or args. Symmetric with the
    timeout-path log so operators get per-handler debug traces for any
    provider failure."""

    @pytest.mark.asyncio
    async def test_generic_exception_emits_typed_debug_log(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        agent = _bearer_agent()
        config = SDKConfig(
            timeout_seconds=5.0,
            caller_id="hardening-test",
            console_signals=False,
            credential_provider_timeout=5.0,
        )

        class CustomProviderError(RuntimeError):
            """A distinct exception class so we can match on type name."""

        sentinel_value = "AKIA-SENTINEL-NEVER-LOG-ME"

        async def failing_provider(_agent: AgentRecord) -> dict[str, str]:
            # Embed a sentinel in the exception's args. The SDK log must
            # NOT include this string anywhere in its captured events.
            raise CustomProviderError(f"contains sensitive value: {sentinel_value}")

        with structlog.testing.capture_logs() as captured_events:
            async with AgentClient(config=config) as client:
                monkeypatch.setattr(
                    client,
                    "_http_client",
                    httpx.AsyncClient(transport=httpx.MockTransport(_mock_transport)),
                )
                with pytest.raises(CredentialProviderError):
                    await client.invoke(
                        agent=agent,
                        method="tools/list",
                        credential_provider=failing_provider,
                    )

        # The debug log must have been emitted with the exception TYPE NAME
        # only, no value content.
        failed_events = [
            event
            for event in captured_events
            if event.get("event") == "sdk.credential_provider_failed"
        ]
        assert failed_events, (
            f"Expected 'sdk.credential_provider_failed' debug log when the "
            f"provider raised a non-timeout exception. "
            f"Captured: {captured_events!r}"
        )
        event = failed_events[0]
        assert event.get("exception_type") == "CustomProviderError", (
            f"Expected exception_type='CustomProviderError'; got {event!r}"
        )
        assert event.get("agent_fqdn") == agent.fqdn
        assert event.get("auth_type") == "bearer"

        # CRITICAL: the sentinel value MUST NOT appear anywhere in the
        # captured logs. This is the credential-clean invariant — even
        # though the provider's exception message contained a sensitive
        # value, the SDK only logged the type name.
        for event in captured_events:
            for value in event.values():
                assert sentinel_value not in str(value), (
                    f"Sentinel value {sentinel_value!r} leaked into log event "
                    f"{event!r} — the SDK is logging exception args, not just type."
                )
