# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""DANE across many agents must be bounded in both concurrency and total time.

The loop was strictly sequential and each check opens a TLS connection worth up
to DANE_CONNECT_TIMEOUT plus teardown, so a zone with twenty agents blocked
discovery for minutes. The MCP server caps a tool call at 120s, so a wide zone
lost every result rather than just its DANE column.

An agent that could not be checked keeps dane_verified=None. Unknown, never a
failed binding.
"""

import asyncio

import pytest

from dns_aid.core.discoverer import (
    DANE_TOTAL_BUDGET_SECONDS,
    MAX_CONCURRENT_DANE,
    _verify_agents_dane,
)
from dns_aid.core.models import AgentRecord, Protocol


def _agents(n, *, dnssec=True):
    out = []
    for i in range(n):
        a = AgentRecord(
            name=f"a{i}",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host=f"e{i}.example.com",
            port=443,
        )
        a.dnssec_validated = dnssec
        out.append(a)
    return out


@pytest.mark.asyncio
async def test_checks_run_concurrently_not_one_after_another(monkeypatch):
    agents = _agents(24)

    async def slow(host, port, *, verify_cert=True):  # noqa: ARG001
        await asyncio.sleep(0.05)
        return True

    monkeypatch.setattr("dns_aid.core.validator._check_dane", slow)

    loop = asyncio.get_running_loop()
    start = loop.time()
    await _verify_agents_dane(agents)
    elapsed = loop.time() - start

    sequential = 24 * 0.05
    assert elapsed < sequential / 2, f"{elapsed:.2f}s suggests a sequential loop"
    assert all(a.dane_verified is True for a in agents)


@pytest.mark.asyncio
async def test_concurrency_is_capped(monkeypatch):
    """A wide zone must not open one socket per agent at once."""
    agents = _agents(40)
    live = 0
    peak = 0

    async def watched(host, port, *, verify_cert=True):  # noqa: ARG001
        nonlocal live, peak
        live += 1
        peak = max(peak, live)
        try:
            await asyncio.sleep(0.02)
            return True
        finally:
            live -= 1

    monkeypatch.setattr("dns_aid.core.validator._check_dane", watched)
    await _verify_agents_dane(agents)

    assert peak <= MAX_CONCURRENT_DANE, f"{peak} concurrent handshakes"


@pytest.mark.asyncio
async def test_a_hung_endpoint_does_not_hold_the_whole_call(monkeypatch):
    """Unchecked agents read as unknown, and the cap is logged not silent."""
    agents = _agents(4)

    async def hang(host, port, *, verify_cert=True):  # noqa: ARG001
        await asyncio.sleep(3600)

    monkeypatch.setattr("dns_aid.core.validator._check_dane", hang)
    monkeypatch.setattr("dns_aid.core.discoverer.DANE_TOTAL_BUDGET_SECONDS", 0.1)

    warned = []
    monkeypatch.setattr(
        "dns_aid.core.discoverer.logger",
        type(
            "L",
            (),
            {"warning": lambda self, m, **k: warned.append(k), "debug": lambda self, m, **k: None},
        )(),
    )

    loop = asyncio.get_running_loop()
    start = loop.time()
    await _verify_agents_dane(agents)
    elapsed = loop.time() - start

    assert elapsed < 5, f"budget not enforced, took {elapsed:.1f}s"
    assert all(a.dane_verified is None for a in agents), "unchecked must be unknown, not False"
    assert warned and warned[0]["unchecked"] == 4, "a capped run must say so"


@pytest.mark.asyncio
async def test_a_positive_result_is_still_demoted_without_dnssec(monkeypatch):
    """RFC 6698 section 10.1 -- the concurrency rewrite must not lose this.

    It was lost, briefly, when the TLSA-RRset DNSSEC gate was added and this one
    was removed as redundant. It is not redundant: the TLSA gate proves the pin
    was not forged, this one proves the name we dialled was not. An attacker who
    forges the SVCB answer points target at a zone they own and sign, and passes
    the first gate with a real TLSA pinning their own certificate.
    """
    agents = _agents(3, dnssec=False)

    async def ok(host, port, *, verify_cert=True):  # noqa: ARG001
        return True

    monkeypatch.setattr("dns_aid.core.validator._check_dane", ok)
    await _verify_agents_dane(agents)

    assert all(a.dane_verified is None for a in agents)


@pytest.mark.asyncio
async def test_a_verdict_is_otherwise_recorded_untouched(monkeypatch):
    """With the owner name authenticated, the concurrency layer passes through."""
    for verdict in (True, False, None):
        agents = _agents(3, dnssec=True)

        async def one(host, port, *, verify_cert=True, _v=verdict):  # noqa: ARG001
            return _v

        monkeypatch.setattr("dns_aid.core.validator._check_dane", one)
        await _verify_agents_dane(agents)

        assert all(a.dane_verified is verdict for a in agents), f"verdict {verdict} was altered"


def test_the_budget_fits_inside_the_mcp_call_cap():
    """Read the real cap. A copy of the number does not track it."""
    import inspect

    from dns_aid.mcp.server import _run_async

    cap = inspect.signature(_run_async).parameters["timeout"].default

    assert cap > DANE_TOTAL_BUDGET_SECONDS, (
        f"DANE budget {DANE_TOTAL_BUDGET_SECONDS}s does not fit inside the "
        f"{cap}s MCP per-call cap, so a wide zone loses every result"
    )
