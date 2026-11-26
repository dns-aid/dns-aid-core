# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""SDK freshness re-verification (verify_freshness_seconds).

Adapted from nicknacnic's tests in #132. A stale AgentRecord is re-resolved
before invoke; a changed record, or one that lost DNSSEC/DANE verification
it originally had, refuses the call.
"""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, patch

import pytest

from dns_aid.core.models import AgentRecord, DiscoveryResult, DNSSECError, Protocol
from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.client import AgentClient, _reverify_agent
from dns_aid.sdk.models import InvocationStatus

pytestmark = pytest.mark.asyncio


def _agent(discovered_at: float | None = None, **overrides: object) -> AgentRecord:
    base: dict[str, object] = {
        "name": "network",
        "domain": "example.com",
        "protocol": Protocol.MCP,
        "target_host": "mcp.example.com",
        "port": 443,
        "capabilities": ["ipam"],
        "cap_sha256": "abc",
        "discovered_at": discovered_at,
    }
    base.update(overrides)
    return AgentRecord(**base)  # type: ignore[arg-type]


def _result(*agents: AgentRecord) -> DiscoveryResult:
    return DiscoveryResult(query="network.example.com", domain="example.com", agents=list(agents))


def _raw():
    from dns_aid.sdk.protocols.base import RawResponse

    return RawResponse(
        success=True,
        status=InvocationStatus.SUCCESS,
        data={},
        http_status_code=200,
        invocation_latency_ms=1.0,
        ttfb_ms=1.0,
        response_size_bytes=0,
        headers={},
    )


# --- _reverify_agent ------------------------------------------------------


async def test_matching_record_is_returned() -> None:
    fresh = _agent(discovered_at=time.time())
    with patch("dns_aid.core.discoverer.discover", AsyncMock(return_value=_result(fresh))):
        got, reason = await _reverify_agent(_agent(discovered_at=1.0), require_dnssec=False)
    assert got is fresh
    assert reason is None


@pytest.mark.parametrize(
    "change", [{"target_host": "evil.example.net"}, {"port": 8443}, {"cap_sha256": "rotated"}]
)
async def test_changed_record_is_refused(change: dict) -> None:
    with patch(
        "dns_aid.core.discoverer.discover", AsyncMock(return_value=_result(_agent(**change)))
    ):
        got, reason = await _reverify_agent(_agent(), require_dnssec=False)
    assert got is None
    assert next(iter(change)) in (reason or "")


async def test_missing_agent_is_refused() -> None:
    with patch("dns_aid.core.discoverer.discover", AsyncMock(return_value=_result())):
        got, reason = await _reverify_agent(_agent(), require_dnssec=False)
    assert got is None
    assert "missing" in (reason or "")


async def test_resolver_error_is_refused() -> None:
    with patch("dns_aid.core.discoverer.discover", AsyncMock(side_effect=TimeoutError("slow"))):
        got, reason = await _reverify_agent(_agent(), require_dnssec=False)
    assert got is None
    assert "TimeoutError" in (reason or "")


@pytest.mark.parametrize(
    ("config_flag", "was_validated", "expected"),
    [(False, False, False), (True, False, True), (False, True, True)],
)
async def test_dnssec_is_required_by_config_or_by_the_original_record(
    config_flag: bool, was_validated: bool, expected: bool
) -> None:
    """No downgrade: a DNSSEC-validated record must re-resolve validated."""
    discover = AsyncMock(return_value=_result(_agent()))
    with patch("dns_aid.core.discoverer.discover", discover):
        await _reverify_agent(_agent(dnssec_validated=was_validated), require_dnssec=config_flag)
    assert discover.await_args.kwargs["require_dnssec"] is expected


async def test_lost_dnssec_is_refused() -> None:
    discover = AsyncMock(side_effect=DNSSECError(["network.example.com"]))
    with patch("dns_aid.core.discoverer.discover", discover):
        got, reason = await _reverify_agent(_agent(dnssec_validated=True), require_dnssec=False)
    assert got is None
    assert "DNSSECError" in (reason or "")


async def test_dane_verified_record_must_verify_again() -> None:
    discover = AsyncMock(return_value=_result(_agent(dane_verified=None)))
    with patch("dns_aid.core.discoverer.discover", discover):
        got, reason = await _reverify_agent(_agent(dane_verified=True), require_dnssec=False)
    assert discover.await_args.kwargs["verify_dane"] is True
    assert got is None
    assert "DANE" in (reason or "")


async def test_unverified_dane_is_not_requested() -> None:
    discover = AsyncMock(return_value=_result(_agent()))
    with patch("dns_aid.core.discoverer.discover", discover):
        await _reverify_agent(_agent(dane_verified=None), require_dnssec=False)
    assert discover.await_args.kwargs["verify_dane"] is False


# --- AgentClient.invoke ---------------------------------------------------


async def _invoke(agent: AgentRecord, config: SDKConfig, reverify: AsyncMock):
    with (
        patch("dns_aid.sdk.client._reverify_agent", reverify),
        patch.object(AgentClient, "_get_handler") as get_handler,
    ):
        handler = get_handler.return_value
        handler.invoke = AsyncMock(return_value=_raw())
        async with AgentClient(config=config) as client:
            result = await client.invoke(agent)
    return result, handler, reverify


@pytest.mark.parametrize(
    ("freshness", "age", "discovered"),
    [(0, 3600, True), (30, 5, True), (30, 3600, False)],
    ids=["disabled", "not-stale", "no-timestamp"],
)
async def test_reverify_is_skipped(freshness: int, age: int, discovered: bool) -> None:
    agent = _agent(discovered_at=time.time() - age if discovered else None)
    _, handler, reverify = await _invoke(
        agent, SDKConfig(verify_freshness_seconds=freshness), AsyncMock()
    )
    reverify.assert_not_called()
    handler.invoke.assert_awaited_once()


async def test_stale_match_invokes_the_fresh_record() -> None:
    fresh = _agent(discovered_at=time.time(), endpoint_override="https://mcp.example.com/v2")
    result, handler, _ = await _invoke(
        _agent(discovered_at=time.time() - 120),
        SDKConfig(verify_freshness_seconds=30),
        AsyncMock(return_value=(fresh, None)),
    )
    assert result.success is True
    assert handler.invoke.await_args.kwargs["endpoint"] == "https://mcp.example.com/v2"


async def test_auth_is_resolved_against_the_fresh_record() -> None:
    fresh = _agent(discovered_at=time.time(), auth_type="bearer")
    with patch.object(AgentClient, "_resolve_auth", AsyncMock(return_value=None)) as resolve:
        await _invoke(
            _agent(discovered_at=time.time() - 120),
            SDKConfig(verify_freshness_seconds=30),
            AsyncMock(return_value=(fresh, None)),
        )
    assert resolve.await_args.args[0] is fresh


async def test_stale_drift_refuses_without_calling_the_handler() -> None:
    result, handler, _ = await _invoke(
        _agent(discovered_at=time.time() - 120),
        SDKConfig(verify_freshness_seconds=30),
        AsyncMock(return_value=(None, "record changed since discovery: target_host")),
    )
    handler.invoke.assert_not_called()
    assert result.success is False
    assert result.signal.status == InvocationStatus.REFUSED
    assert result.signal.error_type == "stale_record"
    assert "target_host" in (result.signal.error_message or "")


def test_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DNS_AID_VERIFY_FRESHNESS_SECONDS", "45")
    monkeypatch.setenv("DNS_AID_REQUIRE_DNSSEC", "true")
    config = SDKConfig.from_env()
    assert config.verify_freshness_seconds == 45
    assert config.require_dnssec is True
