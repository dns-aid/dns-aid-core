# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Experimental ``EdnsAwareResolver`` — in-process programmable hop for ``agent-hint``.

⚠ Experimental. See ``docs/experimental/edns-signaling.md``.

This is the Locus 1 reference implementation: a thin wrapper around
``dns.asyncresolver.Resolver`` that caches answers keyed by
``(qname, qtype, hint_signature)``. When a query carries an :class:`AgentHint`
that matches a previous fresh entry, the cached answer is returned without an
upstream round trip.

The cache is unconditionally per-process and in-memory. It is intentionally
simple: no eviction policy beyond TTL expiry, no concurrency guards beyond what
``asyncio`` provides natively (single event loop), no persistence. The point is
to demonstrate the warm-cache behaviour described in the design doc, not to be
a production cache.

If the upstream response carries an :class:`AgentHintEcho`, it is surfaced on
the :class:`CachedAnswer` so callers can see what filtering (if any) happened
upstream.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import dns.asyncresolver
import dns.edns
import structlog

from dns_aid.experimental.edns_hint import (
    AGENT_HINT_OPTION_CODE,
    AgentHint,
    AgentHintEcho,
    decode_agent_hint_echo,
)

if TYPE_CHECKING:
    pass

logger = structlog.get_logger(__name__)

DEFAULT_CACHE_TTL_SECONDS: float = 60.0


@dataclass
class CachedAnswer:
    """A DNS answer captured by :class:`EdnsAwareResolver`.

    Attributes:
        answer:    The underlying ``dns.resolver.Answer`` (or anything the
                   wrapped resolver returns).
        cached_at: Monotonic timestamp of capture.
        echo:      :class:`AgentHintEcho` if the upstream response carried one,
                   else ``None``. Absence is meaningful — it tells the caller no
                   upstream filtering happened.
    """

    answer: Any
    cached_at: float
    echo: AgentHintEcho | None = None


CacheKey = tuple[str, str, str | None]


class EdnsAwareResolver:
    """In-process programmable hop that caches DNS answers by hint signature.

    Usage::

        resolver = EdnsAwareResolver()
        result = await resolver.resolve(
            "_chat._mcp._agents.example.com", "SVCB",
            agent_hint=AgentHint(capabilities=["chat"]),
        )
        # result.answer is the dns answer; result.echo is the hop's applied selectors
    """

    def __init__(
        self,
        *,
        ttl_seconds: float = DEFAULT_CACHE_TTL_SECONDS,
        upstream: dns.asyncresolver.Resolver | None = None,
    ) -> None:
        self._ttl = ttl_seconds
        self._cache: dict[CacheKey, CachedAnswer] = {}
        # Construct a default upstream resolver here so tests can swap it in.
        self._upstream = upstream if upstream is not None else dns.asyncresolver.Resolver()
        # Bypass OS cache so we observe upstream hits, not stale OS positives.
        self._upstream.cache = None

    async def resolve(
        self,
        qname: str,
        qtype: str,
        *,
        agent_hint: AgentHint | None = None,
    ) -> CachedAnswer:
        """Resolve ``qname/qtype``, attaching ``agent_hint`` as an EDNS option.

        Returns a :class:`CachedAnswer` containing the answer plus, if present,
        the upstream :class:`AgentHintEcho`.
        """
        signature = agent_hint.signature() if agent_hint is not None else None
        key: CacheKey = (qname, qtype, signature)

        cached = self._cache.get(key)
        if cached is not None and (time.monotonic() - cached.cached_at) < self._ttl:
            logger.debug(
                "edns-aware cache hit",
                qname=qname,
                qtype=qtype,
                hint_signature=signature,
            )
            return cached

        # Cache miss (or expired) — go upstream.
        if agent_hint is not None:
            option = dns.edns.GenericOption(
                dns.edns.OptionType(AGENT_HINT_OPTION_CODE), agent_hint.encode()
            )
            # use_edns is sync on the resolver; options is the list of EDNS options to send.
            self._upstream.use_edns(0, 0, 4096, options=[option])
        else:
            # Reset any previously-configured options so the next bare call doesn't leak hints.
            self._upstream.use_edns(0, 0, 4096, options=[])

        logger.debug(
            "edns-aware cache miss; resolving upstream",
            qname=qname,
            qtype=qtype,
            hint_signature=signature,
        )
        answer = await self._upstream.resolve(qname, qtype)
        echo = _extract_echo(answer)

        cached = CachedAnswer(answer=answer, cached_at=time.monotonic(), echo=echo)
        self._cache[key] = cached
        return cached

    def invalidate(self) -> None:
        """Drop all cached entries."""
        self._cache.clear()


def _extract_echo(answer: Any) -> AgentHintEcho | None:
    """Return the :class:`AgentHintEcho` from a response, or ``None`` if absent.

    Looks at ``answer.response.options`` (dnspython attaches EDNS options there
    on the response message). Silently returns ``None`` for any structural
    issue — the echo is non-mandatory.
    """
    response = getattr(answer, "response", None)
    if response is None:
        return None
    options = getattr(response, "options", None) or []
    for opt in options:
        otype = getattr(opt, "otype", None)
        if otype != AGENT_HINT_OPTION_CODE:
            continue
        # dnspython GenericOption stores payload in .data
        data = getattr(opt, "data", None)
        if not isinstance(data, (bytes, bytearray)):
            return None
        try:
            return decode_agent_hint_echo(bytes(data))
        except ValueError:
            return None
    return None
