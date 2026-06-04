# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
DNS-AID: DNS-based Agent Identification and Discovery

Reference implementation for IETF draft-mozleywilliams-dnsop-dnsaid-02.
Enables AI agents to discover each other via DNS using SVCB records.

Example:
    >>> import dns_aid
    >>>
    >>> # Discover agents at a domain
    >>> result = await dns_aid.discover("example.com")
    >>>
    >>> # Invoke an agent and capture telemetry
    >>> resp = await dns_aid.invoke(result.agents[0], method="tools/list")
    >>> print(resp.signal.invocation_latency_ms)
    >>>
    >>> # Publish an agent to DNS
    >>> await dns_aid.publish(
    ...     name="my-agent",
    ...     domain="example.com",
    ...     protocol="mcp",
    ...     endpoint="agent.example.com"
    ... )
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from dns_aid.core import dcv
from dns_aid.core.discoverer import discover
from dns_aid.core.models import (
    AgentRecord,
    DiscoveryResult,
    DNSSECError,
    Protocol,
    PublishResult,
    SvcbRecord,
)
from dns_aid.core.publisher import publish, unpublish

# Tier 0: DNS validation
from dns_aid.core.validator import verify

# Tier 1: Execution Telemetry SDK
from dns_aid.sdk import AgentClient, InvocationResult, InvocationSignal, SDKConfig

# Auth handlers
from dns_aid.sdk.auth import AuthHandler, resolve_auth_handler

if TYPE_CHECKING:
    from dns_aid.sdk.ranking.ranker import RankedAgent

# Alias for convenience
delete = unpublish

try:
    from importlib.metadata import version as _pkg_version

    __version__ = _pkg_version("dns-aid")
except (ImportError, ModuleNotFoundError, ValueError):
    __version__ = "0.0.0-dev"  # Fallback for editable installs without metadata
__all__ = [
    # Core functions (Tier 0)
    "publish",
    "unpublish",
    "delete",
    "discover",
    "verify",
    # DCV
    "dcv",
    # SDK functions (Tier 1)
    "invoke",
    "rank",
    # SDK classes
    "AgentClient",
    "SDKConfig",
    "InvocationResult",
    "InvocationSignal",
    # Auth
    "AuthHandler",
    "resolve_auth_handler",
    # Models
    "AgentRecord",
    "DiscoveryResult",
    "PublishResult",
    "SvcbRecord",
    "Protocol",
    # Exceptions
    "DNSSECError",
    # Version
    "__version__",
]


async def invoke(
    agent: AgentRecord,
    *,
    method: str | None = None,
    arguments: dict | None = None,
    timeout: float | None = None,
    config: SDKConfig | None = None,
    credentials: dict | None = None,
    auth_handler: AuthHandler | None = None,
) -> InvocationResult:
    """
    Invoke an agent and capture telemetry — convenience wrapper.

    Creates a one-shot AgentClient, calls the agent, and returns the result
    with an attached telemetry signal. For multiple calls or connection reuse,
    use ``AgentClient`` directly.

    Args:
        agent: An AgentRecord from ``dns_aid.discover()``.
        method: Protocol-specific method (e.g., ``"tools/list"`` for MCP).
        arguments: Method arguments / payload.
        timeout: Request timeout in seconds (default: 30).
        config: Optional SDKConfig. Defaults to ``SDKConfig.from_env()``.
        credentials: Caller-supplied secrets (tokens, client_id/secret)
            for automatic auth resolution from agent metadata.
        auth_handler: Explicit auth handler override. When provided,
            *credentials* and agent metadata are ignored.

    Returns:
        InvocationResult with the response data and telemetry signal.

    Example::

        import dns_aid

        result = await dns_aid.discover("example.com", protocol="mcp")
        agent = result.agents[0]

        resp = await dns_aid.invoke(agent, method="tools/list")
        print(f"Latency: {resp.signal.invocation_latency_ms}ms")
        print(f"Status:  {resp.signal.status}")
        print(f"Data:    {resp.data}")
    """
    async with AgentClient(config=config) as client:
        return await client.invoke(
            agent,
            method=method,
            arguments=arguments,
            timeout=timeout,
            credentials=credentials,
            auth_handler=auth_handler,
        )


async def rank(
    agents: list[AgentRecord],
    *,
    method: str | None = None,
    arguments: dict | None = None,
    config: SDKConfig | None = None,
) -> list[RankedAgent]:
    """
    Invoke multiple agents and rank them by telemetry performance.

    Calls each agent, collects signals, and returns agents sorted by
    composite score (reliability, latency, cost, freshness).

    Args:
        agents: List of AgentRecords from ``dns_aid.discover()``.
        method: Protocol-specific method to invoke on each agent.
        arguments: Method arguments / payload.
        config: Optional SDKConfig.

    Returns:
        List of RankedAgent sorted best-to-worst.

    Example::

        import dns_aid

        result = await dns_aid.discover("example.com", protocol="mcp")
        ranked = await dns_aid.rank(result.agents, method="tools/list")

        for r in ranked:
            print(f"{r.agent_fqdn}: score={r.composite_score:.1f}")
    """
    async with AgentClient(config=config) as client:
        for agent in agents:
            await client.invoke(
                agent,
                method=method,
                arguments=arguments,
            )
        return client.rank()
