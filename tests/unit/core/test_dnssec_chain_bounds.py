# SPDX-License-Identifier: Apache-2.0
"""The chain gate must be bounded, budgeted, and fail closed when it runs out.

A walk is a DNSKEY and a DS lookup per zone cut, so an unbounded gather over a
zone advertising many agents is a query storm pointed at the resolver and the
servers behind it. The DANE and signature phases were bounded for exactly this
reason; the chain phase shipped without it.

The budget half is the security-relevant one. If a name whose walk did not
finish in time were treated as proved, an attacker would only need to be slow
to walk through a gate whose entire purpose is to refuse what it cannot prove.
"""

from __future__ import annotations

import asyncio

import pytest

import dns_aid.core.dnssec_chain as chain_mod
from dns_aid.core.discoverer import MAX_CONCURRENT_CHAIN


@pytest.mark.asyncio
async def test_a_walk_that_outruns_the_budget_does_not_count_as_proved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Slow must not read as secure."""
    from dns_aid.core import discoverer as disc

    async def _never_finishes(fqdn: str, rdtype: str = "SVCB") -> object:
        await asyncio.sleep(3600)
        raise AssertionError("unreachable")

    monkeypatch.setattr(chain_mod, "validate_chain", _never_finishes)
    monkeypatch.setattr(disc, "CHAIN_TOTAL_BUDGET_SECONDS", 0.05)

    agent = _stub_agent("slow.example.com")
    with pytest.raises(disc.DNSSECError):
        await disc._apply_post_discovery(
            [agent], False, False, False, "example.com", require_secure_chain=True
        )

    assert agent.dnssec_validated is False
    assert agent.dnssec_chain_status == "indeterminate"


@pytest.mark.asyncio
async def test_walks_do_not_all_run_at_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """Concurrency is capped, so a big zone cannot become a query storm."""
    from dns_aid.core import discoverer as disc

    live = 0
    peak = 0

    async def _counting(fqdn: str, rdtype: str = "SVCB") -> object:
        nonlocal live, peak
        live += 1
        peak = max(peak, live)
        try:
            await asyncio.sleep(0.01)
            return chain_mod.ChainResult(chain_mod.ChainStatus.SECURE, "ok")
        finally:
            live -= 1

    monkeypatch.setattr(chain_mod, "validate_chain", _counting)

    agents = [_stub_agent(f"a{i}.example.com") for i in range(MAX_CONCURRENT_CHAIN * 4)]
    await disc._apply_post_discovery(
        agents, False, False, False, "example.com", require_secure_chain=True
    )

    assert peak <= MAX_CONCURRENT_CHAIN, (
        f"{peak} walks ran at once against a cap of {MAX_CONCURRENT_CHAIN}"
    )


def _stub_agent(fqdn: str):
    from dns_aid.core.models import AgentRecord

    return AgentRecord(
        name=fqdn.split(".")[0],
        domain=fqdn.split(".", 1)[1],
        protocol="mcp",
        endpoint=f"https://{fqdn}",
        fqdn=fqdn,
        target_host=fqdn,
        port=443,
    )
