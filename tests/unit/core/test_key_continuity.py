# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Key continuity: an unpreventable substitution made loud.

Trust cannot be bootstrapped from inside a zone an attacker controls. Any pin in
the record is forged alongside the record, and the JWKS is fetched over WebPKI
for a name in that same zone, so an adversary with zone-level DNS control can
obtain a DV certificate and serve their own document. That is a property of the
layer, not a defect to patch.

What is achievable is detectability. Swapping the key set means swapping the
key, and a key change is observable.

The mechanism is advisory by construction: it never refuses a signature. A
publisher rotating keys legitimately must not have discovery break.
"""

import pytest

from dns_aid.core.jwks import (
    _seen_key_sets,
    export_jwks,
    generate_keypair,
    jwks_fingerprint,
    observe_key_set,
)


@pytest.fixture(autouse=True)
def _clean():
    _seen_key_sets.clear()
    yield
    _seen_key_sets.clear()


class TestFingerprintTracksKeysNotPresentation:
    def test_the_same_key_under_a_new_kid_is_not_a_change(self):
        """kid is a hint. Rotating it is not a key rotation."""
        _, pub = generate_keypair()

        assert jwks_fingerprint(export_jwks(pub, kid="k1")) == jwks_fingerprint(
            export_jwks(pub, kid="rotated-2026-08")
        )

    def test_key_order_does_not_change_it(self):
        _, a = generate_keypair()
        _, b = generate_keypair()
        one = {"keys": export_jwks(a)["keys"] + export_jwks(b)["keys"]}
        other = {"keys": export_jwks(b)["keys"] + export_jwks(a)["keys"]}

        assert jwks_fingerprint(one) == jwks_fingerprint(other)

    def test_a_different_key_changes_it(self):
        _, a = generate_keypair()
        _, b = generate_keypair()

        assert jwks_fingerprint(export_jwks(a)) != jwks_fingerprint(export_jwks(b))

    def test_a_malformed_entry_does_not_raise(self):
        assert jwks_fingerprint({"keys": ["not-a-dict", None]})
        assert jwks_fingerprint({})


class TestChangeIsReported:
    def test_first_sight_is_not_a_change(self):
        _, pub = generate_keypair()

        assert observe_key_set("zone.example", export_jwks(pub)) is None

    def test_an_unchanged_key_set_is_silent(self):
        _, pub = generate_keypair()
        doc = export_jwks(pub)
        observe_key_set("zone.example", doc)

        assert observe_key_set("zone.example", doc) is None

    def test_a_substituted_key_set_is_reported(self):
        _, real = generate_keypair()
        _, attacker = generate_keypair()
        observe_key_set("zone.example", export_jwks(real))

        previous = observe_key_set("zone.example", export_jwks(attacker))

        assert previous is not None
        assert previous == jwks_fingerprint(export_jwks(real))

    def test_zones_are_tracked_independently(self):
        _, a = generate_keypair()
        _, b = generate_keypair()
        observe_key_set("one.example", export_jwks(a))

        assert observe_key_set("two.example", export_jwks(b)) is None

    def test_the_zone_key_is_normalised(self):
        """Same zone, different spelling, must not read as a substitution."""
        _, pub = generate_keypair()
        doc = export_jwks(pub)
        observe_key_set("zone.example", doc)

        assert observe_key_set("Zone.Example.", doc) is None

    def test_it_never_refuses_only_reports(self):
        """A legitimate rotation must not break discovery."""
        _, a = generate_keypair()
        _, b = generate_keypair()
        observe_key_set("zone.example", export_jwks(a))

        # Returns the previous fingerprint; raises nothing, refuses nothing.
        assert observe_key_set("zone.example", export_jwks(b)) is not None
        assert observe_key_set("zone.example", export_jwks(b)) is None  # now the new normal

    def test_tracking_is_bounded(self):
        from dns_aid.core.jwks import _KEY_CONTINUITY_MAX

        _, pub = generate_keypair()
        doc = export_jwks(pub)
        for i in range(_KEY_CONTINUITY_MAX + 50):
            observe_key_set(f"z{i}.example", doc)

        assert len(_seen_key_sets) <= _KEY_CONTINUITY_MAX
