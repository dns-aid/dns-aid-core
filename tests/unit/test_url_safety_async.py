# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Async SSRF-validation wrapper (``validate_fetch_url_async``).

The sync ``validate_fetch_url`` does a blocking ``socket.getaddrinfo``; called
directly from a coroutine it freezes the event loop and serializes concurrent
fetches. ``validate_fetch_url_async`` offloads it to a worker thread under a
bounded timeout. These tests lock in the SSRF policy (public passes; private and
timeout fail closed) and the concurrency property (a fan-out is not serialized).
"""

import asyncio
import socket
import time

import pytest

from dns_aid.utils import url_safety
from dns_aid.utils.url_safety import UnsafeURLError, validate_fetch_url_async

_PUBLIC = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]
_PRIVATE = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0))]


@pytest.mark.asyncio
async def test_async_returns_url_on_public_host(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(url_safety.socket, "getaddrinfo", lambda *a, **k: _PUBLIC)
    assert await validate_fetch_url_async("https://example.com/x") == "https://example.com/x"


@pytest.mark.asyncio
async def test_async_raises_on_private_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(url_safety.socket, "getaddrinfo", lambda *a, **k: _PRIVATE)
    with pytest.raises(UnsafeURLError):
        await validate_fetch_url_async("https://example.com/x")


@pytest.mark.asyncio
async def test_async_raises_on_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def slow(*a: object, **k: object) -> list:
        time.sleep(0.5)
        return _PUBLIC

    monkeypatch.setattr(url_safety.socket, "getaddrinfo", slow)
    with pytest.raises(UnsafeURLError, match="timed out"):
        await validate_fetch_url_async("https://example.com/x", timeout=0.2)


@pytest.mark.asyncio
async def test_concurrency_not_serialized(monkeypatch: pytest.MonkeyPatch) -> None:
    # Each resolution "costs" 0.3s. Six offloaded validations run concurrently, so
    # wall-time stays well under the serial sum (6 x 0.3 = 1.8s). Pre-fix — a direct
    # blocking getaddrinfo on the single-threaded event loop — this serialized to ~1.8s.
    def slow(*a: object, **k: object) -> list:
        time.sleep(0.3)
        return _PUBLIC

    monkeypatch.setattr(url_safety.socket, "getaddrinfo", slow)
    start = time.perf_counter()
    await asyncio.gather(*[validate_fetch_url_async(f"https://example.com/{i}") for i in range(6)])
    elapsed = time.perf_counter() - start
    assert elapsed < 1.0, f"fan-out serialized ({elapsed:.2f}s); expected concurrent (<1s)"


@pytest.mark.asyncio
async def test_concurrent_same_host_all_consistent(monkeypatch: pytest.MonkeyPatch) -> None:
    # Regression: under the previous wrapper, concurrent validations shared the event
    # loop's default thread pool (min(32, cpu+4)); a wide fan-out on a slow resolver
    # queued the excess, and the queue wait counted against the per-call timeout — so
    # the last-queued URLs for the SAME host spuriously "timed out" (surfacing as an
    # SSRF block) while their siblings passed. The dedicated resolver pool must run
    # them independently: fire more validations than a low-core default pool would
    # admit at once and assert every one resolves identically — none blocked purely
    # for losing a thread-pool slot.
    def slow(*a: object, **k: object) -> list:
        time.sleep(0.3)
        return _PUBLIC

    monkeypatch.setattr(url_safety.socket, "getaddrinfo", slow)
    n = 24
    urls = [f"https://same-host.example.com/{i}" for i in range(n)]
    results = await asyncio.gather(
        *(validate_fetch_url_async(u) for u in urls), return_exceptions=True
    )
    blocked = [r for r in results if isinstance(r, BaseException)]
    assert not blocked, f"{len(blocked)}/{n} spuriously blocked under concurrency: {blocked[:2]}"
    assert results == urls
