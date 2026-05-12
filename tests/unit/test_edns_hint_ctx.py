# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for dns_aid.core._edns_hint_ctx — env-flag gating + contextvar plumbing.

The contextvar/env-flag layer is the most security-relevant runtime gate in the
experimental EDNS feature: it determines whether the agent-hint option is ever
emitted on the wire. The cache tests already verify EdnsAwareResolver wires the
option through use_edns when invoked directly; these tests cover the
``_edns_hint_ctx`` helper that the core discoverer path uses instead.
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from dns_aid.core._edns_hint_ctx import (
    apply_agent_hint_to_resolver,
    reset_agent_hint,
    set_agent_hint,
)
from dns_aid.experimental.edns_hint import AGENT_HINT_OPTION_CODE, AgentHint

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _patched_env(value: str | None) -> dict:
    """Build a patch.dict payload that sets or clears the EDNS flag."""
    if value is None:
        # Clearing via patch.dict requires pop after-entry; caller handles.
        return {}
    return {"DNS_AID_EXPERIMENTAL_EDNS_HINTS": value}


# ---------------------------------------------------------------------------
# Env-flag gate — no emission without the flag
# ---------------------------------------------------------------------------


def test_no_emission_when_flag_unset_even_with_active_hint():
    """The most important regression: no wire emission without the env flag."""
    resolver = MagicMock()
    token = set_agent_hint(AgentHint(realm="prod"))
    try:
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DNS_AID_EXPERIMENTAL_EDNS_HINTS", None)
            apply_agent_hint_to_resolver(resolver)
        resolver.use_edns.assert_not_called()
    finally:
        reset_agent_hint(token)


def test_no_emission_when_flag_set_but_no_hint():
    """Flag on but no contextvar hint set → still nothing on the wire."""
    resolver = MagicMock()
    with patch.dict(os.environ, _patched_env("1")):
        apply_agent_hint_to_resolver(resolver)
    resolver.use_edns.assert_not_called()


# ---------------------------------------------------------------------------
# Env-flag truthy-value matrix
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("flag_value", ["1", "true", "TRUE", "yes", "Yes", "True"])
def test_truthy_env_flag_values_enable_emission(flag_value):
    """1, true, yes (case-insensitive) all enable the wire emission."""
    resolver = MagicMock()
    token = set_agent_hint(AgentHint(realm="prod"))
    try:
        with patch.dict(os.environ, _patched_env(flag_value)):
            apply_agent_hint_to_resolver(resolver)
        resolver.use_edns.assert_called_once()
    finally:
        reset_agent_hint(token)


@pytest.mark.parametrize("flag_value", ["0", "no", "false", "maybe", "", " ", "off"])
def test_non_truthy_env_flag_values_keep_dormant(flag_value):
    """Anything not in {1, true, yes} keeps the helper dormant."""
    resolver = MagicMock()
    token = set_agent_hint(AgentHint(realm="prod"))
    try:
        with patch.dict(os.environ, _patched_env(flag_value)):
            apply_agent_hint_to_resolver(resolver)
        resolver.use_edns.assert_not_called()
    finally:
        reset_agent_hint(token)


# ---------------------------------------------------------------------------
# Happy path — flag + hint produces the right EDNS option
# ---------------------------------------------------------------------------


def test_emission_attaches_correct_option_code_and_payload():
    resolver = MagicMock()
    hint = AgentHint(realm="prod", transport="mcp")
    token = set_agent_hint(hint)
    try:
        with patch.dict(os.environ, _patched_env("1")):
            apply_agent_hint_to_resolver(resolver)
        resolver.use_edns.assert_called_once()
        call = resolver.use_edns.call_args
        # Helper passes (edns, ednsflags, payload_size, options=...).
        # We don't pin the positional shape; just check options[].
        options = call.kwargs.get("options")
        assert options is not None and len(options) == 1
        opt = options[0]
        assert int(opt.otype) == AGENT_HINT_OPTION_CODE
        assert opt.data == hint.encode()
    finally:
        reset_agent_hint(token)


# ---------------------------------------------------------------------------
# Exception safety — experimental code must NEVER break core discovery
# ---------------------------------------------------------------------------


def test_helper_swallows_encode_exception():
    """If hint.encode() raises, the helper must not propagate the exception.

    Core discovery in discoverer.py calls this helper unconditionally inside the
    DNS query path; an experimental-code crash here would take out a stable
    feature. The helper's try/except is the seam that protects against that.
    """
    resolver = MagicMock()

    bad_hint = MagicMock(spec=AgentHint)
    bad_hint.encode.side_effect = ValueError("forced encode failure")
    bad_hint.signature.return_value = "broken"

    token = set_agent_hint(bad_hint)
    try:
        with patch.dict(os.environ, _patched_env("1")):
            # Must not raise.
            apply_agent_hint_to_resolver(resolver)
        # use_edns never called because option construction failed.
        resolver.use_edns.assert_not_called()
    finally:
        reset_agent_hint(token)


# ---------------------------------------------------------------------------
# Contextvar scoping
# ---------------------------------------------------------------------------


def test_reset_restores_previous_hint():
    """set/reset must return the contextvar to its prior state."""
    resolver = MagicMock()
    outer_hint = AgentHint(realm="outer")
    inner_hint = AgentHint(realm="inner")

    outer_token = set_agent_hint(outer_hint)
    try:
        inner_token = set_agent_hint(inner_hint)
        with patch.dict(os.environ, _patched_env("1")):
            apply_agent_hint_to_resolver(resolver)
        # The inner hint was active.
        assert resolver.use_edns.call_args.kwargs["options"][0].data == inner_hint.encode()
        reset_agent_hint(inner_token)

        # After reset, the outer hint is active again.
        resolver.use_edns.reset_mock()
        with patch.dict(os.environ, _patched_env("1")):
            apply_agent_hint_to_resolver(resolver)
        assert resolver.use_edns.call_args.kwargs["options"][0].data == outer_hint.encode()
    finally:
        reset_agent_hint(outer_token)
