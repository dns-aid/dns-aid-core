# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Experimental DNS-AID features.

⚠ APIs in this subpackage are unstable. They may change shape, change behaviour,
or disappear entirely in any release — including patch versions. They are NOT
covered by the semver guarantees that apply to ``dns_aid.core`` and ``dns_aid.sdk``.

By convention, experimental features are:

- Never re-exported from the top-level ``dns_aid`` package. Callers import
  explicitly: ``from dns_aid.experimental import AgentHint``.
- Gated at runtime by a per-feature environment variable
  (e.g. ``DNS_AID_EXPERIMENTAL_EDNS_HINTS=1``). Without the flag, the related
  code paths remain dormant even if the symbols are imported.
- Documented in ``docs/experimental/`` rather than ``docs/rfc/``.

Currently exported:

- :class:`AgentHint` — request-side EDNS(0) signal carrying selector filters
- :class:`AgentHintEcho` — response-side echo from a hint-aware DNS hop
- :class:`EdnsSignalingAdvertisement` — publisher advertisement model (JSON)
- :class:`EdnsAwareResolver` — in-process programmable hop with hint-keyed cache

See ``docs/experimental/edns-signaling.md`` for the design rationale and wire
format.
"""

from __future__ import annotations

from dns_aid.experimental.edns_cache import CachedAnswer, EdnsAwareResolver
from dns_aid.experimental.edns_hint import (
    AGENT_HINT_OPTION_CODE,
    AgentHint,
    AgentHintEcho,
    EdnsSignalingAdvertisement,
    HintSelector,
    decode_agent_hint,
    decode_agent_hint_echo,
)

__all__ = [
    "AGENT_HINT_OPTION_CODE",
    "AgentHint",
    "AgentHintEcho",
    "CachedAnswer",
    "EdnsAwareResolver",
    "EdnsSignalingAdvertisement",
    "HintSelector",
    "decode_agent_hint",
    "decode_agent_hint_echo",
]
