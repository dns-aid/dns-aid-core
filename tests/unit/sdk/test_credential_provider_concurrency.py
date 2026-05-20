# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for concurrent invocation safety of the credential_provider path.

Implements T009 from ``specs/003-credential-provider-callback/tasks.md``.
Verifies FR-007 (no SDK-side synchronization around provider invocation) and
the concurrency contract in
``contracts/credential_provider_contract.md`` (concurrent invokes await the
provider concurrently; provider exception in one invoke does not contaminate
another).

TDD state at file creation: the ``credential_provider`` keyword-only parameter
on ``AgentClient.invoke`` does not yet exist. Both tests in this file fail
with ``TypeError: invoke() got an unexpected keyword argument
'credential_provider'`` — the expected RED state. T012/T013 implement the
parameter and resolution logic; T014 confirms these tests turn GREEN.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest

from dns_aid.core.models import AgentRecord, Protocol
from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.client import AgentClient


def _bearer_agent(name_suffix: str) -> AgentRecord:
    """Build a bearer-auth AgentRecord with a distinct name per concurrent test."""
    return AgentRecord(
        name=f"concur-{name_suffix}",
        domain="example.com",
        protocol=Protocol.MCP,
        target_host="mcp.example.com",
        port=443,
        capabilities=[],
        auth_type="bearer",
        auth_config={"header_name": "Authorization"},
    )


def _mock_transport(_request: httpx.Request) -> httpx.Response:
    """Mock HTTP transport that succeeds without inspecting credentials."""
    return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})


@pytest.fixture
def sdk_config() -> SDKConfig:
    return SDKConfig(timeout_seconds=5.0, caller_id="concurrency-test", console_signals=False)


class TestProviderConcurrentInvocation:
    """The SDK awaits the provider without serialization — concurrent invokes
    trigger the provider concurrently (FR-007)."""

    @pytest.mark.asyncio
    async def test_concurrent_invokes_call_provider_concurrently(
        self,
        sdk_config: SDKConfig,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Two concurrent invocations with the same provider function trigger
        two concurrent provider awaits.

        The provider blocks on an internal asyncio.Event until BOTH calls are
        in flight. If the SDK serialized provider invocations (which it must
        not, per FR-007), the second call would never enter the provider and
        the event would never be set — the test would time out instead of
        completing.
        """
        agent_a = _bearer_agent("concurrent-a")
        agent_b = _bearer_agent("concurrent-b")

        both_in_flight = asyncio.Event()
        in_flight_count = 0
        max_concurrent_observed = 0

        async def overlapping_provider(_agent: AgentRecord) -> dict[str, Any]:
            nonlocal in_flight_count, max_concurrent_observed
            in_flight_count += 1
            max_concurrent_observed = max(max_concurrent_observed, in_flight_count)
            if in_flight_count >= 2:
                both_in_flight.set()
            try:
                # Wait up to 1s for the peer call to enter the provider.
                # If the SDK serializes provider invocations, this wait times
                # out — and that timeout is the test signal.
                await asyncio.wait_for(both_in_flight.wait(), timeout=1.0)
            finally:
                in_flight_count -= 1
            return {"token": f"concurrent-token-{_agent.name}"}  # noqa: S106

        async with AgentClient(config=sdk_config) as client:
            monkeypatch.setattr(
                client,
                "_http_client",
                httpx.AsyncClient(transport=httpx.MockTransport(_mock_transport)),
            )
            # Drive two invocations concurrently and gather. Any TypeError
            # (missing credential_provider kwarg) propagates as the TDD red
            # signal.
            results: list[Any] = await asyncio.gather(
                client.invoke(
                    agent=agent_a,
                    method="tools/list",
                    credential_provider=overlapping_provider,
                ),
                client.invoke(
                    agent=agent_b,
                    method="tools/list",
                    credential_provider=overlapping_provider,
                ),
                return_exceptions=True,
            )

        # Confirm any TypeError surfaced (TDD red until T012). Once T012 lands,
        # results contain InvocationResult or transport-related exceptions —
        # never TypeError.
        for result in results:
            if isinstance(result, TypeError):
                raise result

        # The actual concurrency assertion: both provider calls overlapped.
        assert max_concurrent_observed >= 2, (
            f"Expected at least 2 concurrent provider invocations; observed max "
            f"of {max_concurrent_observed}. This indicates the SDK is serializing "
            f"provider calls — a violation of FR-007."
        )


class TestProviderConcurrentFailureIsolation:
    """A provider exception in one invocation does not contaminate a concurrent
    invocation. Each invoke's resolution path is independent."""

    @pytest.mark.asyncio
    async def test_provider_raise_in_one_invoke_does_not_affect_concurrent_invoke(
        self,
        sdk_config: SDKConfig,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Two concurrent invocations share a provider that raises only for one
        target. The failing invoke surfaces ``CredentialProviderError``; the
        succeeding invoke completes its resolution path independently.
        """
        failing_agent = _bearer_agent("failing-target")
        succeeding_agent = _bearer_agent("succeeding-target")

        async def selective_provider(agent: AgentRecord) -> dict[str, Any]:
            if agent.fqdn == failing_agent.fqdn:
                # Simulate a real provider failure (e.g., IdP token endpoint
                # returned 500 for this specific target).
                raise RuntimeError("simulated provider failure for one target")
            return {"token": f"good-token-{agent.name}"}  # noqa: S106

        # Import locally so the test file remains importable in TDD red state
        # before T005 had implemented the class. (T005 is already complete;
        # this import simply documents the symbol used below.)
        from dns_aid.sdk.exceptions import CredentialProviderError

        async with AgentClient(config=sdk_config) as client:
            monkeypatch.setattr(
                client,
                "_http_client",
                httpx.AsyncClient(transport=httpx.MockTransport(_mock_transport)),
            )

            results: list[Any] = await asyncio.gather(
                client.invoke(
                    agent=failing_agent,
                    method="tools/list",
                    credential_provider=selective_provider,
                ),
                client.invoke(
                    agent=succeeding_agent,
                    method="tools/list",
                    credential_provider=selective_provider,
                ),
                return_exceptions=True,
            )

        # TypeError from missing kwarg means TDD red — propagate for clarity.
        for result in results:
            if isinstance(result, TypeError):
                raise result

        # The first result corresponds to the failing target; it MUST be a
        # CredentialProviderError. The wrapper preserves __cause__ for
        # debugging but its own surface MUST NOT contain credential material
        # (verified separately in test_credential_provider_errors.py — this
        # test only verifies isolation, not sanitization).
        failing_result = results[0]
        assert isinstance(failing_result, CredentialProviderError), (
            f"Expected CredentialProviderError for the failing target, got "
            f"{type(failing_result).__name__}: {failing_result!r}"
        )
        assert failing_result.agent_fqdn == failing_agent.fqdn

        # The second result corresponds to the succeeding target. The
        # succeeding invoke's resolution MUST NOT have been contaminated by
        # the peer's failure. The downstream transport may produce its own
        # error (mocked MCP may not validate the full response shape), but
        # the resolution path itself must have completed without raising a
        # CredentialProviderError for the succeeding target.
        succeeding_result = results[1]
        if isinstance(succeeding_result, CredentialProviderError):
            raise AssertionError(
                f"Concurrent invocation contamination detected: the succeeding "
                f"target {succeeding_agent.fqdn!r} surfaced "
                f"CredentialProviderError {succeeding_result!r}, indicating the "
                f"failing peer's exception leaked into the independent invoke. "
                f"This violates the concurrency-isolation contract."
            )

    @pytest.mark.asyncio
    async def test_provider_failure_preserves_cause_chain(
        self,
        sdk_config: SDKConfig,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """When the provider raises, the resulting CredentialProviderError carries
        the original exception via __cause__ for deliberate debugging access.

        This complements the sanitization tests in test_credential_provider_errors.py
        by verifying the cause-chain preservation specifically through the SDK's
        wrapping mechanism at invoke time.
        """
        agent = _bearer_agent("cause-chain")

        async def raising_provider(_agent: AgentRecord) -> dict[str, Any]:
            raise ValueError("specific provider failure type")

        from dns_aid.sdk.exceptions import CredentialProviderError

        async with AgentClient(config=sdk_config) as client:
            monkeypatch.setattr(
                client,
                "_http_client",
                httpx.AsyncClient(transport=httpx.MockTransport(_mock_transport)),
            )
            with pytest.raises(CredentialProviderError) as exc_info:
                await client.invoke(
                    agent=agent,
                    method="tools/list",
                    credential_provider=raising_provider,
                )

        wrapper = exc_info.value
        assert wrapper.agent_fqdn == agent.fqdn
        # The original ValueError MUST be preserved via __cause__ for debug
        # access. The wrapper's own surface remains sanitized (verified in
        # test_credential_provider_errors.py).
        assert wrapper.__cause__ is not None
        assert isinstance(wrapper.__cause__, ValueError)
        assert "specific provider failure type" in str(wrapper.__cause__)
