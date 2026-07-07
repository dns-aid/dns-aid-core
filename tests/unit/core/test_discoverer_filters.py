# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
End-to-end tests for ``discover()`` Path A filter kwargs.

The filter primitives are unit-tested in :mod:`tests.unit.core.test_filters`. This
module verifies the *wiring*: ``discover()`` correctly threads its new kwargs through
to :func:`apply_filters` after enrichment, and the resulting ``DiscoveryResult.agents``
reflects the filtered subset.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from dns_aid.core.discoverer import discover
from dns_aid.core.models import AgentRecord, Protocol


def _agent(
    name: str,
    *,
    capabilities: list[str] | None = None,
    auth_type: str | None = None,
    realm: str | None = None,
    description: str | None = None,
    sig: str | None = None,
    signature_verified: bool | None = None,
    signature_algorithm: str | None = None,
    dnssec_validated: bool = False,
) -> AgentRecord:
    return AgentRecord(
        name=name,
        domain="example.com",
        protocol=Protocol.MCP,
        target_host=f"{name}.example.com",
        port=443,
        capabilities=capabilities or [],
        description=description,
        auth_type=auth_type,
        realm=realm,
        sig=sig,
        signature_verified=signature_verified,
        signature_algorithm=signature_algorithm,
        dnssec_validated=dnssec_validated,
    )


@pytest.fixture
def mocked_pipeline() -> list[AgentRecord]:
    """Three agents with mixed metadata so filters can discriminate."""
    return [
        _agent(
            "payments",
            capabilities=["payment-processing", "fraud-detection"],
            auth_type="oauth2",
            realm="prod",
            description="Process card payments.",
            sig="hdr.payload.sig",
            signature_verified=True,
            signature_algorithm="ES256",
        ),
        _agent(
            "search",
            capabilities=["search"],
            auth_type="api_key",
            realm="prod",
        ),
        _agent(
            "weak",
            capabilities=["fraud-detection"],
            auth_type="oauth2",
            sig="hdr.payload.sig",
            signature_verified=True,
            signature_algorithm="HS256",
        ),
    ]


def _patch_discovery(agents: list[AgentRecord]):
    """Stub ``_execute_discovery`` and ``_apply_post_discovery`` so no DNS or HTTP fires."""
    return [
        patch(
            "dns_aid.core.discoverer._execute_discovery",
            new=AsyncMock(return_value=agents),
        ),
        patch(
            "dns_aid.core.discoverer._apply_post_discovery",
            new=AsyncMock(return_value=False),
        ),
    ]


@pytest.mark.asyncio
async def test_no_filters_returns_full_set(mocked_pipeline: list[AgentRecord]) -> None:
    patches = _patch_discovery(mocked_pipeline)
    for p in patches:
        p.start()
    try:
        result = await discover("example.com")
        assert {a.name for a in result.agents} == {"payments", "search", "weak"}
    finally:
        for p in patches:
            p.stop()


@pytest.mark.asyncio
async def test_capabilities_all_of(mocked_pipeline: list[AgentRecord]) -> None:
    patches = _patch_discovery(mocked_pipeline)
    for p in patches:
        p.start()
    try:
        result = await discover(
            "example.com",
            capabilities=["payment-processing", "fraud-detection"],
        )
        assert [a.name for a in result.agents] == ["payments"]
    finally:
        for p in patches:
            p.stop()


@pytest.mark.asyncio
async def test_capabilities_any_of(mocked_pipeline: list[AgentRecord]) -> None:
    patches = _patch_discovery(mocked_pipeline)
    for p in patches:
        p.start()
    try:
        result = await discover(
            "example.com",
            capabilities_any=["search", "fraud-detection"],
        )
        assert {a.name for a in result.agents} == {"payments", "search", "weak"}
    finally:
        for p in patches:
            p.stop()


@pytest.mark.asyncio
async def test_auth_type_filter(mocked_pipeline: list[AgentRecord]) -> None:
    patches = _patch_discovery(mocked_pipeline)
    for p in patches:
        p.start()
    try:
        result = await discover("example.com", auth_type="oauth2")
        assert {a.name for a in result.agents} == {"payments", "weak"}
    finally:
        for p in patches:
            p.stop()


@pytest.mark.asyncio
async def test_text_match_substring(mocked_pipeline: list[AgentRecord]) -> None:
    patches = _patch_discovery(mocked_pipeline)
    for p in patches:
        p.start()
    try:
        result = await discover("example.com", text_match="payment")
        assert {a.name for a in result.agents} == {"payments"}
    finally:
        for p in patches:
            p.stop()


@pytest.mark.asyncio
async def test_realm_filter(mocked_pipeline: list[AgentRecord]) -> None:
    patches = _patch_discovery(mocked_pipeline)
    for p in patches:
        p.start()
    try:
        result = await discover("example.com", realm="prod")
        assert {a.name for a in result.agents} == {"payments", "search"}
    finally:
        for p in patches:
            p.stop()


@pytest.mark.asyncio
async def test_min_dnssec_propagates_from_dnssec_validated(
    mocked_pipeline: list[AgentRecord],
) -> None:
    """When DNSSEC validation succeeds for every agent, the per-agent
    ``dnssec_validated`` flag is stamped (now inside _apply_post_discovery
    under the per-agent model, not via a blanket loop in discover())."""

    async def fake_post_discovery(
        agents,
        require_dnssec,
        enrich_endpoints,
        verify_signatures,
        domain,
        min_dnssec=False,
        verify_dane=False,
    ):
        # Simulate the per-agent stamping that the real function does
        # when the DNSSEC check runs and every per-agent check succeeds.
        for a in agents:
            a.dnssec_validated = True
        return True

    with (
        patch(
            "dns_aid.core.discoverer._execute_discovery",
            new=AsyncMock(return_value=mocked_pipeline),
        ),
        patch(
            "dns_aid.core.discoverer._apply_post_discovery",
            new=fake_post_discovery,
        ),
    ):
        result = await discover("example.com", min_dnssec=True)
        assert len(result.agents) == 3
        assert all(a.dnssec_validated for a in result.agents)


@pytest.mark.asyncio
async def test_min_dnssec_excludes_when_unvalidated(
    mocked_pipeline: list[AgentRecord],
) -> None:
    patches = _patch_discovery(mocked_pipeline)  # Returns dnssec_validated=False
    for p in patches:
        p.start()
    try:
        result = await discover("example.com", min_dnssec=True)
        assert result.agents == []
    finally:
        for p in patches:
            p.stop()


# US3 — trust filtering


@pytest.mark.asyncio
async def test_require_signed_only_returns_verified(
    mocked_pipeline: list[AgentRecord],
) -> None:
    patches = _patch_discovery(mocked_pipeline)
    for p in patches:
        p.start()
    try:
        result = await discover("example.com", require_signed=True)
        # ``payments`` and ``weak`` both have signature_verified=True; ``search`` has no sig.
        assert {a.name for a in result.agents} == {"payments", "weak"}
    finally:
        for p in patches:
            p.stop()


@pytest.mark.asyncio
async def test_require_signature_algorithm_allow_list(
    mocked_pipeline: list[AgentRecord],
) -> None:
    patches = _patch_discovery(mocked_pipeline)
    for p in patches:
        p.start()
    try:
        result = await discover(
            "example.com",
            require_signed=True,
            require_signature_algorithm=["ES256", "Ed25519"],
        )
        # Only ``payments`` has algorithm ES256; ``weak`` uses HS256.
        assert [a.name for a in result.agents] == ["payments"]
    finally:
        for p in patches:
            p.stop()


@pytest.mark.asyncio
async def test_algorithm_without_require_signed_raises_value_error(
    mocked_pipeline: list[AgentRecord],
) -> None:
    patches = _patch_discovery(mocked_pipeline)
    for p in patches:
        p.start()
    try:
        with pytest.raises(ValueError, match="require_signed=True"):
            await discover(
                "example.com",
                require_signature_algorithm=["ES256"],
            )
    finally:
        for p in patches:
            p.stop()


@pytest.mark.asyncio
async def test_text_match_empty_string_raises_value_error(
    mocked_pipeline: list[AgentRecord],
) -> None:
    patches = _patch_discovery(mocked_pipeline)
    for p in patches:
        p.start()
    try:
        with pytest.raises(ValueError, match="text_match cannot be empty"):
            await discover("example.com", text_match="")
    finally:
        for p in patches:
            p.stop()


@pytest.mark.asyncio
async def test_require_signed_implies_verify_signatures(
    mocked_pipeline: list[AgentRecord],
) -> None:
    """``require_signed=True`` must auto-enable verify_signatures (FR-023)."""
    captured: dict[str, object] = {}

    async def stub_post_discovery(
        agents: list[AgentRecord],
        require_dnssec: bool,
        enrich_endpoints: bool,
        verify_signatures: bool,
        domain: str,
        min_dnssec: bool = False,
        verify_dane: bool = False,
    ) -> bool:
        captured["verify_signatures"] = verify_signatures
        return False

    with (
        patch(
            "dns_aid.core.discoverer._execute_discovery",
            new=AsyncMock(return_value=mocked_pipeline),
        ),
        patch("dns_aid.core.discoverer._apply_post_discovery", new=stub_post_discovery),
    ):
        await discover("example.com", require_signed=True)

    assert captured["verify_signatures"] is True


@pytest.mark.asyncio
async def test_combined_filters(mocked_pipeline: list[AgentRecord]) -> None:
    """Multiple filters compose with logical AND."""
    patches = _patch_discovery(mocked_pipeline)
    for p in patches:
        p.start()
    try:
        result = await discover(
            "example.com",
            capabilities=["payment-processing"],
            auth_type="oauth2",
            require_signed=True,
            require_signature_algorithm=["ES256"],
        )
        assert [a.name for a in result.agents] == ["payments"]
    finally:
        for p in patches:
            p.stop()


# ----- name filter -----
#
# When ``name`` is passed without ``protocol``, ``_execute_discovery`` cannot
# short-circuit to a single SVCB query (no protocol means no FQDN to query). It
# falls back to a full-zone walk and returns every agent. ``discover()`` must
# then post-filter by exact name. Without the post-filter, ``--name`` would be a
# silent no-op when used alone — the kind of bug a CLI user would only catch by
# noticing a result count that's clearly wrong.


@pytest.mark.asyncio
async def test_name_alone_filters_post_substrate_walk(
    mocked_pipeline: list[AgentRecord],
) -> None:
    patches = _patch_discovery(mocked_pipeline)
    for p in patches:
        p.start()
    try:
        result = await discover("example.com", name="search")
        assert [a.name for a in result.agents] == ["search"]
    finally:
        for p in patches:
            p.stop()


@pytest.mark.asyncio
async def test_name_with_no_match_returns_empty(
    mocked_pipeline: list[AgentRecord],
) -> None:
    patches = _patch_discovery(mocked_pipeline)
    for p in patches:
        p.start()
    try:
        result = await discover("example.com", name="nonexistent")
        assert result.agents == []
    finally:
        for p in patches:
            p.stop()


@pytest.mark.asyncio
async def test_name_filter_is_case_insensitive(
    mocked_pipeline: list[AgentRecord],
) -> None:
    """DNS labels are case-insensitive (RFC 1035); the post-filter must match."""
    patches = _patch_discovery(mocked_pipeline)
    for p in patches:
        p.start()
    try:
        # Fixture has agent named ``payments``; query with mixed case.
        result = await discover("example.com", name="PaYmEnTs")
        assert [a.name for a in result.agents] == ["payments"]
    finally:
        for p in patches:
            p.stop()
