# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Internal helper: per-call EDNS(0) ``agent-hint`` plumbing for the discovery layer.

⚠ Experimental. See ``docs/experimental/edns-signaling.md``.

This module is intentionally tiny and private (leading underscore in the name)
because both ``discoverer.py`` and ``indexer.py`` need to read the same active
hint without creating an import cycle (discoverer already imports from indexer).

The contextvar is set by :func:`dns_aid.core.discoverer.discover` for the
duration of the call, then reset in ``finally``. Helpers that build a
``dns.asyncresolver.Resolver`` call :func:`apply_agent_hint_to_resolver` to
attach the EDNS option when both the contextvar and the env flag are set.
"""

from __future__ import annotations

import contextvars
import os
from typing import TYPE_CHECKING

import dns.asyncresolver
import structlog

if TYPE_CHECKING:
    from dns_aid.experimental.edns_hint import AgentHint

logger = structlog.get_logger(__name__)

_AGENT_HINT_CTX: contextvars.ContextVar[AgentHint | None] = contextvars.ContextVar(
    "dns_aid_agent_hint", default=None
)
_EDNS_HINTS_ENV_FLAG = "DNS_AID_EXPERIMENTAL_EDNS_HINTS"


def set_agent_hint(hint: AgentHint | None) -> contextvars.Token:
    """Set the active hint and return a token for reset()."""
    return _AGENT_HINT_CTX.set(hint)


def reset_agent_hint(token: contextvars.Token) -> None:
    """Restore the previous hint value."""
    _AGENT_HINT_CTX.reset(token)


def apply_agent_hint_to_resolver(resolver: dns.asyncresolver.Resolver) -> None:
    """Attach the active agent-hint EDNS option to ``resolver`` if enabled.

    No-op unless both: (a) a non-None hint is set on the contextvar, AND (b)
    the ``DNS_AID_EXPERIMENTAL_EDNS_HINTS`` environment variable is truthy.
    Import of the experimental module is lazy so non-experimental users never
    load it.
    """
    if os.environ.get(_EDNS_HINTS_ENV_FLAG, "").lower() not in ("1", "true", "yes"):
        return
    hint = _AGENT_HINT_CTX.get()
    if hint is None:
        return
    try:
        import dns.edns

        from dns_aid.experimental.edns_hint import AGENT_HINT_OPTION_CODE

        option = dns.edns.GenericOption(dns.edns.OptionType(AGENT_HINT_OPTION_CODE), hint.encode())
        resolver.use_edns(0, 0, 4096, options=[option])
        logger.debug(
            "experimental.agent_hint_attached",
            option_code=AGENT_HINT_OPTION_CODE,
            signature=hint.signature(),
        )
    except Exception as e:
        # Experimental path must never break core discovery on failure.
        logger.warning("experimental.agent_hint_attach_failed", error=str(e))
