# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Per-target credential scoping tests for ``credential_provider``.

Implements T031 from ``specs/003-credential-provider-callback/tasks.md``.
Verifies User Story 4: the SDK passes the target ``AgentRecord`` to the
provider so the provider can derive per-target credentials (different
audience claim per IdP target, different STS role ARN per AWS account,
different bearer token per tenant, etc.).

The contract is exercised in two ways:

1. **Identity** — the provider receives an ``AgentRecord`` whose ``fqdn``
   exactly matches the agent being invoked.
2. **Derivation surface** — the provider can read every public attribute
   on the ``AgentRecord`` (``fqdn``, ``realm``, ``connect_class``,
   ``connect_meta``, etc.) to derive credentials.
3. **Sequencing** — invoking N different targets in sequence triggers N
   provider invocations, each with the corresponding ``AgentRecord``
   (no caching, no state contamination).
"""

from __future__ import annotations

import contextlib
from typing import Any

import httpx
import pytest

from dns_aid.core.models import AgentRecord, Protocol
from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.client import AgentClient


def _bearer_agent(
    name: str,
    domain: str = "example.com",
    realm: str | None = None,
    connect_class: str | None = None,
    connect_meta: str | None = None,
) -> AgentRecord:
    """Build a bearer-auth AgentRecord with configurable scoping attributes."""
    kwargs: dict[str, Any] = {
        "name": name,
        "domain": domain,
        "protocol": Protocol.MCP,
        "target_host": f"{name}.{domain}",
        "port": 443,
        "capabilities": [],
        "auth_type": "bearer",
        "auth_config": {"header_name": "Authorization"},
    }
    if realm is not None:
        kwargs["realm"] = realm
    if connect_class is not None:
        kwargs["connect_class"] = connect_class
    if connect_meta is not None:
        kwargs["connect_meta"] = connect_meta
    return AgentRecord(**kwargs)


def _mock_transport(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})


@pytest.fixture
def sdk_config() -> SDKConfig:
    return SDKConfig(timeout_seconds=5.0, caller_id="per-target-test", console_signals=False)


class TestProviderReceivesCorrectAgentRecord:
    """The ``AgentRecord`` passed to the provider matches the target being
    invoked — by identity, not just by value."""

    @pytest.mark.asyncio
    async def test_provider_receives_agent_with_matching_fqdn(
        self, sdk_config: SDKConfig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        agent = _bearer_agent("alpha")
        received_agents: list[AgentRecord] = []

        async def recording_provider(received: AgentRecord) -> dict[str, str]:
            received_agents.append(received)
            return {"token": "alpha-token"}  # noqa: S106

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
                    credential_provider=recording_provider,
                )

        assert len(received_agents) == 1
        # Identity check — same object passed through.
        assert received_agents[0] is agent
        # Value sanity — fqdn matches.
        assert received_agents[0].fqdn == agent.fqdn


class TestProviderCanDeriveFromAgentAttributes:
    """The provider can read ``realm``, ``connect_class``, ``connect_meta``,
    and other public attributes on the ``AgentRecord`` to derive
    per-target credentials."""

    @pytest.mark.asyncio
    async def test_provider_reads_realm_and_connect_meta(
        self, sdk_config: SDKConfig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Multi-tenant pattern: provider mints credentials scoped to the
        target's realm + connection-mediation metadata."""
        agent = _bearer_agent(
            "multi-tenant-agent",
            realm="production",
            connect_class="lattice",
            connect_meta="arn:aws:vpc-lattice:us-east-1:123456789012:service/svc-test",
        )

        derived_scopes: list[str] = []

        async def realm_scoped_provider(received: AgentRecord) -> dict[str, str]:
            # The provider derives an audience claim from the agent's
            # public attributes — exactly the per-target scoping pattern
            # this user story validates.
            scope = (
                f"realm={received.realm};"
                f"connect_class={received.connect_class};"
                f"connect_meta={received.connect_meta}"
            )
            derived_scopes.append(scope)
            return {"token": f"token-for-{received.fqdn}"}

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
                    credential_provider=realm_scoped_provider,
                )

        assert len(derived_scopes) == 1
        scope = derived_scopes[0]
        assert "realm=production" in scope
        assert "connect_class=lattice" in scope
        assert "connect_meta=arn:aws:vpc-lattice:us-east-1:123456789012:service/svc-test" in scope


class TestProviderSequencingAcrossMultipleTargets:
    """Invoking N different targets triggers N provider invocations, each
    with the corresponding ``AgentRecord``. No caching, no contamination
    between provider calls."""

    @pytest.mark.asyncio
    async def test_three_invokes_yield_three_distinct_provider_calls(
        self, sdk_config: SDKConfig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        agents = [
            _bearer_agent("agent-a", domain="tenant-1.example.com", realm="tenant-1"),
            _bearer_agent("agent-b", domain="tenant-2.example.com", realm="tenant-2"),
            _bearer_agent("agent-c", domain="tenant-3.example.com", realm="tenant-3"),
        ]
        provider_call_log: list[tuple[str, str | None]] = []

        async def tenant_provider(received: AgentRecord) -> dict[str, str]:
            provider_call_log.append((received.fqdn, received.realm))
            # In production: provider would use realm to look up the right
            # tenant-specific credentials. We just return a token marked
            # with the realm so the test can verify per-target derivation.
            return {"token": f"token-{received.realm}"}  # noqa: S106

        async with AgentClient(config=sdk_config) as client:
            monkeypatch.setattr(
                client,
                "_http_client",
                httpx.AsyncClient(transport=httpx.MockTransport(_mock_transport)),
            )
            for agent in agents:
                with contextlib.suppress(Exception):
                    await client.invoke(
                        agent=agent,
                        method="tools/list",
                        credential_provider=tenant_provider,
                    )

        assert len(provider_call_log) == 3, (
            f"Expected 3 provider invocations (one per target). "
            f"Got {len(provider_call_log)}: {provider_call_log!r}"
        )

        # Each invocation must have received the corresponding agent's
        # fqdn + realm — proving the provider sees per-target context, not
        # cached or shared state.
        recorded_fqdns = [call[0] for call in provider_call_log]
        recorded_realms = [call[1] for call in provider_call_log]
        expected_fqdns = [a.fqdn for a in agents]
        expected_realms = [a.realm for a in agents]
        assert recorded_fqdns == expected_fqdns, (
            f"Provider calls did not match the target sequence. "
            f"Expected fqdns {expected_fqdns!r}, got {recorded_fqdns!r}"
        )
        assert recorded_realms == expected_realms, (
            f"Provider did not see per-target realm values. "
            f"Expected {expected_realms!r}, got {recorded_realms!r}"
        )
