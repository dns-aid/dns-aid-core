# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for dns_aid.experimental.edns_cache — EdnsAwareResolver."""

from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock

from dns_aid.experimental.edns_cache import EdnsAwareResolver
from dns_aid.experimental.edns_hint import (
    AGENT_HINT_OPTION_CODE,
    AgentHint,
    AgentHintEcho,
    HintSelector,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_upstream(answer=None, echo: AgentHintEcho | None = None) -> MagicMock:
    """Build a mock upstream resolver suitable for EdnsAwareResolver.

    Uses MagicMock for the resolver instance so sync attrs (cache, use_edns,
    nameservers) don't produce coroutine warnings; only resolve is AsyncMock.
    """
    mock = MagicMock()

    response = MagicMock()
    if echo is not None:
        echo_opt = MagicMock()
        echo_opt.otype = AGENT_HINT_OPTION_CODE
        echo_opt.data = echo.encode()
        response.options = [echo_opt]
    else:
        response.options = []

    mock_answer = MagicMock()
    mock_answer.response = response

    mock.resolve = AsyncMock(return_value=answer if answer is not None else mock_answer)
    return mock


# ---------------------------------------------------------------------------
# Cache hit / miss
# ---------------------------------------------------------------------------


async def test_first_call_misses_then_caches():
    upstream = _make_upstream()
    resolver = EdnsAwareResolver(upstream=upstream)

    hint = AgentHint(realm="prod")
    result = await resolver.resolve("_chat._mcp._agents.example.com", "SVCB", agent_hint=hint)

    assert result.answer is upstream.resolve.return_value
    upstream.resolve.assert_awaited_once()


async def test_second_call_hits_cache_when_signature_matches():
    upstream = _make_upstream()
    resolver = EdnsAwareResolver(upstream=upstream)

    hint = AgentHint(realm="prod", transport="mcp")
    await resolver.resolve("_chat._mcp._agents.example.com", "SVCB", agent_hint=hint)
    await resolver.resolve("_chat._mcp._agents.example.com", "SVCB", agent_hint=hint)

    # Two calls, one upstream resolve — second was a cache hit.
    upstream.resolve.assert_awaited_once()


async def test_axis2_only_differences_still_hit_cache():
    """Two queries differing only in Axis 2 fields must share a cache entry.

    Locks in the design invariant: metering selectors (parallelism, deadline_ms,
    etc.) do not fragment the cache because they describe the request, not the
    answer set.
    """
    upstream = _make_upstream()
    resolver = EdnsAwareResolver(upstream=upstream)

    h1 = AgentHint(realm="prod", parallelism=4, deadline_ms=5000)
    h2 = AgentHint(realm="prod", parallelism=64, deadline_ms=1)
    await resolver.resolve("example.com", "SVCB", agent_hint=h1)
    await resolver.resolve("example.com", "SVCB", agent_hint=h2)

    # One upstream call — second was a cache hit even with very different metering.
    upstream.resolve.assert_awaited_once()


async def test_different_axis1_signature_misses_cache():
    upstream = _make_upstream()
    resolver = EdnsAwareResolver(upstream=upstream)

    h1 = AgentHint(realm="prod")
    h2 = AgentHint(realm="staging")
    await resolver.resolve("_x._mcp._agents.example.com", "SVCB", agent_hint=h1)
    await resolver.resolve("_x._mcp._agents.example.com", "SVCB", agent_hint=h2)

    # Different Axis 1 values → different signatures → both miss.
    assert upstream.resolve.await_count == 2


async def test_no_hint_caches_separately_from_hinted():
    """A bare call (no hint) and a hinted call cache under different keys."""
    upstream = _make_upstream()
    resolver = EdnsAwareResolver(upstream=upstream)

    await resolver.resolve("example.com", "SVCB", agent_hint=None)
    await resolver.resolve("example.com", "SVCB", agent_hint=AgentHint(realm="prod"))
    await resolver.resolve("example.com", "SVCB", agent_hint=None)

    # Bare-first, hinted, bare-third → first and third should share a key (one upstream call
    # between them). hinted is a separate key. Total: 2 upstream calls.
    assert upstream.resolve.await_count == 2


async def test_ttl_expiry_triggers_re_resolution():
    upstream = _make_upstream()
    resolver = EdnsAwareResolver(upstream=upstream, ttl_seconds=0.05)

    hint = AgentHint(realm="prod")
    await resolver.resolve("example.com", "SVCB", agent_hint=hint)
    time.sleep(0.1)  # wait past TTL (sync sleep is fine — test doesn't depend on the loop)
    await resolver.resolve("example.com", "SVCB", agent_hint=hint)

    assert upstream.resolve.await_count == 2


async def test_invalidate_drops_cache():
    upstream = _make_upstream()
    resolver = EdnsAwareResolver(upstream=upstream)

    hint = AgentHint(realm="prod")
    await resolver.resolve("example.com", "SVCB", agent_hint=hint)
    resolver.invalidate()
    await resolver.resolve("example.com", "SVCB", agent_hint=hint)

    assert upstream.resolve.await_count == 2


# ---------------------------------------------------------------------------
# Upstream wire integration
# ---------------------------------------------------------------------------


async def test_hint_passed_to_upstream_via_use_edns():
    """When a hint is supplied, the EDNS option must be attached on the upstream resolver."""
    upstream = _make_upstream()
    resolver = EdnsAwareResolver(upstream=upstream)

    hint = AgentHint(realm="prod")
    await resolver.resolve("example.com", "SVCB", agent_hint=hint)

    upstream.use_edns.assert_called()
    call = upstream.use_edns.call_args
    options = call.kwargs.get("options") or (call.args[3] if len(call.args) >= 4 else None)
    assert options is not None and len(options) == 1
    opt = options[0]
    assert opt.otype == AGENT_HINT_OPTION_CODE
    assert opt.data == hint.encode()


async def test_no_hint_clears_previous_options():
    """A bare resolve must reset use_edns options so a prior hint doesn't leak."""
    upstream = _make_upstream()
    resolver = EdnsAwareResolver(upstream=upstream)

    await resolver.resolve("a.example.com", "SVCB", agent_hint=AgentHint(realm="prod"))
    await resolver.resolve("b.example.com", "SVCB", agent_hint=None)

    # Last use_edns call (for the bare resolve) must have empty options.
    last_call = upstream.use_edns.call_args
    options = last_call.kwargs.get("options")
    assert options == []


# ---------------------------------------------------------------------------
# AgentHintEcho surfacing
# ---------------------------------------------------------------------------


async def test_upstream_echo_surfaced_on_cached_answer():
    echo = AgentHintEcho(applied_selectors=[HintSelector.REALM.value])
    upstream = _make_upstream(echo=echo)
    resolver = EdnsAwareResolver(upstream=upstream)

    result = await resolver.resolve("example.com", "SVCB", agent_hint=AgentHint(realm="prod"))

    assert result.echo is not None
    assert result.echo.applied_selectors == [HintSelector.REALM.value]


async def test_absent_echo_means_no_upstream_filtering():
    upstream = _make_upstream(echo=None)
    resolver = EdnsAwareResolver(upstream=upstream)

    result = await resolver.resolve("example.com", "SVCB", agent_hint=AgentHint(realm="prod"))
    assert result.echo is None


async def test_malformed_echo_in_response_returns_none():
    """A malformed echo option in the upstream response is silently treated as absent."""
    upstream = MagicMock()
    response = MagicMock()
    bad_opt = MagicMock()
    bad_opt.otype = AGENT_HINT_OPTION_CODE
    bad_opt.data = b"\x80"  # truncated — too short to be a valid echo
    response.options = [bad_opt]
    mock_answer = MagicMock()
    mock_answer.response = response
    upstream.resolve = AsyncMock(return_value=mock_answer)

    resolver = EdnsAwareResolver(upstream=upstream)
    result = await resolver.resolve("example.com", "SVCB", agent_hint=AgentHint(realm="prod"))
    assert result.echo is None
