# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for packaging metadata in pyproject.toml."""

import re
import tomllib
from pathlib import Path

import pytest

PYPROJECT = Path(__file__).resolve().parents[2] / "pyproject.toml"


def _requirement_name(requirement: str) -> str:
    """Return the normalised distribution name from a PEP 508 requirement."""
    return re.split(r"[<>=!~\[; ]", requirement.strip())[0].lower().replace("_", "-")


@pytest.fixture(scope="module")
def extras() -> dict[str, list[str]]:
    """The [project.optional-dependencies] table."""
    with PYPROJECT.open("rb") as handle:
        return tomllib.load(handle)["project"]["optional-dependencies"]


class TestAllExtra:
    """The `all` extra must stay a superset of every other extra.

    `all` was previously written out by hand, restating each requirement, and
    drifted: it was silently missing requests, the two CEL packages and
    pqcrypto, so `pip install dns-aid[all]` shipped without the CEL policy
    engine or PQC/ML-DSA signing. It is now defined by self-reference; these
    tests keep it that way.
    """

    def test_all_extra_covers_every_other_extra(self, extras):
        """Every extra is named in `all`, including ones that are still empty.

        Empty extras are covered deliberately: an extra that gains a dependency
        later must be inherited by `all` without anyone remembering to edit it.
        """
        referenced: set[str] = set()
        for requirement in extras["all"]:
            match = re.search(r"\[(?P<names>[^\]]+)\]", requirement)
            if match:
                referenced |= {name.strip() for name in match["names"].split(",")}

        missing = set(extras) - {"all"} - referenced
        assert not missing, f"extras missing from `all`: {sorted(missing)}"

    def test_all_extra_does_not_restate_requirements(self, extras):
        """No bare requirement sneaks back into `all`.

        A direct requirement here would reintroduce a second place to declare a
        version floor, which is how the floors diverged before.
        """
        restated = [
            requirement
            for requirement in extras["all"]
            if _requirement_name(requirement) != "dns-aid"
        ]
        assert not restated, (
            f"`all` must not restate requirements directly: {restated}. "
            "Add the dependency to the extra it belongs to instead."
        )
