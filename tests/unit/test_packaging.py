# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for packaging metadata in pyproject.toml."""

import re
import tomllib
from pathlib import Path

import pytest

PYPROJECT = Path(__file__).resolve().parents[2] / "pyproject.toml"

# `all` aggregates the user-facing extras only. See the rationale above the
# `all` extra in pyproject.toml.
EXCLUDED_FROM_ALL = {"dev"}


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
        """`all` names exactly the runtime extras — no more, no fewer.

        Empty extras are covered deliberately: an extra that gains a dependency
        later must be inherited by `all` without anyone remembering to edit it.

        The assertion is equality rather than "nothing missing" because an
        extraneous name is silently dropped by uv (no error, no warning), so
        only an exact comparison catches a typo that adds a name rather than
        misspelling an existing one.
        """
        referenced: set[str] = set()
        for requirement in extras["all"]:
            match = re.search(r"\[(?P<names>[^\]]+)\]", requirement)
            if match:
                referenced |= {name.strip() for name in match["names"].split(",")}

        expected = set(extras) - {"all"} - EXCLUDED_FROM_ALL
        assert referenced == expected, (
            f"missing from `all`: {sorted(expected - referenced)}; "
            f"not a real extra: {sorted(referenced - expected)}"
        )

    def test_all_extra_excludes_dev(self, extras):
        """`all` is user-facing and must not drag in the dev toolchain.

        Folding `dev` in adds cyclonedx-bom and its SBOM/schema/URI-validation
        tree — around twenty packages with no runtime relevance — to every
        `pip install dns-aid[all]`.
        """
        referenced: set[str] = set()
        for requirement in extras["all"]:
            match = re.search(r"\[(?P<names>[^\]]+)\]", requirement)
            if match:
                referenced |= {name.strip() for name in match["names"].split(",")}

        assert "dev" not in referenced

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


class TestFloorConsistency:
    """A package declared in more than one place must carry the same specifier.

    The self-referential `all` removed the all-vs-extra duplication but several
    packages are still declared by two extras (or by an extra and the core
    dependency list). Nothing previously stopped those copies from drifting
    apart, which is the same class of bug as the original `all` drift: a floor
    raised for a CVE in one place and missed in another means
    `pip install dns-aid[a]` and `pip install dns-aid[b]` disagree on whether
    the fix is present.
    """

    def test_duplicate_requirements_agree(self, extras):
        with PYPROJECT.open("rb") as handle:
            project = tomllib.load(handle)["project"]

        # name -> {specifier -> [locations]}
        seen: dict[str, dict[str, list[str]]] = {}

        def record(requirement: str, where: str) -> None:
            name = _requirement_name(requirement)
            if name == "dns-aid":  # the self-reference is not a version floor
                return
            seen.setdefault(name, {}).setdefault(requirement.strip(), []).append(where)

        for requirement in project.get("dependencies", []):
            record(requirement, "dependencies")
        for extra, requirements in extras.items():
            if extra == "all":
                continue
            for requirement in requirements:
                record(requirement, extra)

        divergent = {name: specs for name, specs in seen.items() if len(specs) > 1}
        assert not divergent, "\n".join(
            f"{name} is declared inconsistently: "
            + "; ".join(f"{spec!r} in {locs}" for spec, locs in specs.items())
            for name, specs in sorted(divergent.items())
        )
