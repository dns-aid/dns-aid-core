# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""The emission gate must equal the computation gate.

``dnssec_validated`` is a plain bool defaulting to False, so the CLI and the MCP
server omit it unless a check actually ran -- otherwise "not checked" reads as
"failed validation". That made the same boolean appear in three files, and it
drifted: adding ``verify_signatures`` to the computation gate in discoverer.py
without touching the other two meant discovery produced a real verdict that both
machine-readable surfaces then dropped. SDK said False, CLI and MCP said absent,
for one record on one query.

These tests pin the shape (one predicate, no open-coded copies) and the behavior.
"""

import inspect

import pytest

from dns_aid.core.discoverer import _dnssec_check_runs

ALL_FLAGS = ("require_dnssec", "min_dnssec", "verify_dane", "verify_signatures")


class TestNoOpenCodedCopies:
    @pytest.mark.parametrize("module", ["dns_aid.cli.main", "dns_aid.mcp.server"])
    def test_surface_uses_the_shared_predicate(self, module):
        """Structural, not line-shaped: the gate spans comments and clauses."""
        import importlib

        src = inspect.getsource(importlib.import_module(module))
        at = src.find('{"dnssec_validated"')

        assert at != -1, f"{module} no longer emits dnssec_validated"
        # Everything from the key up to the closing of its conditional.
        window = src[at : at + 1200]

        assert "_dnssec_check_runs" in window, (
            f"{module} open-codes the gate instead of calling _dnssec_check_runs; "
            "it will drift the next time the computation gate changes"
        )
        # Calling the predicate is not enough. Passing a subset of the flags
        # reintroduces exactly the drift this module exists to prevent, and the
        # name check alone cannot see it.
        for flag in ALL_FLAGS:
            assert f"{flag}={flag}" in window, (
                f"{module} calls _dnssec_check_runs without forwarding {flag}"
            )

    def test_discoverer_uses_it_too(self):
        from dns_aid.core import discoverer

        src = inspect.getsource(discoverer._apply_post_discovery)

        assert "_dnssec_check_runs(" in src


class TestPredicate:
    def test_no_flag_means_no_check(self):
        assert _dnssec_check_runs() is False

    @pytest.mark.parametrize("flag", ALL_FLAGS)
    def test_every_consumer_triggers_the_check(self, flag):
        assert _dnssec_check_runs(**{flag: True}) is True, (
            f"{flag} consumes the DNSSEC verdict, so it must cause it to be computed"
        )

    def test_verify_signatures_is_a_consumer(self):
        """The JWS branch skips on a DNSSEC-validated record.

        Without the check every agent reads as unvalidated, so a signed zone
        takes the JWS branch and reports VERIFIED instead of SKIPPED_DNSSEC.
        """
        assert _dnssec_check_runs(verify_signatures=True) is True
