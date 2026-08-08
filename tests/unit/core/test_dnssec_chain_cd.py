# SPDX-License-Identifier: Apache-2.0
"""The chain walk must query with CD set, and must not lose RD doing it.

Both halves are load-bearing and both were wrong at some point:

CD absent -- a validating upstream refuses to serve a bogus zone at all, so the
walk sees a SERVFAIL, cannot tell a forged signature from an unreachable server,
and returns INDETERMINATE. That is the one verdict a local validator exists to
avoid. Without CD, `dnssec-failed.org` is unprovable rather than provably bogus.

RD absent -- `Resolver.flags` defaults to None, which is what makes dnspython
supply RD on its own. Assigning any value replaces that default wholesale, so
setting CD without re-adding RD stops a recursive resolver recursing and every
lookup fails. The first cut of the CD fix did exactly this and turned a working
`secure` verdict into "All nameservers failed".

These assert on the flags actually handed to the resolver, so deleting either
half of the fix fails here rather than silently degrading a verdict in the field.
"""

from __future__ import annotations

import dns.flags
import dns.name
import dns.resolver
import pytest

from dns_aid.core.dnssec_chain import validate_chain


class _FlagCapturingResolver(dns.resolver.Resolver):
    """A resolver that records the flags it was configured with, then stops."""

    def __init__(self) -> None:
        super().__init__(configure=False)
        self.nameservers = ["192.0.2.1"]  # TEST-NET-1, never answers
        self.captured: int | None = None

    async def resolve(self, *args: object, **kwargs: object) -> object:
        self.captured = self.flags
        raise dns.resolver.NoNameservers("stopped after capturing flags")


@pytest.mark.asyncio
async def test_the_walk_sets_cd_so_bogus_data_reaches_us() -> None:
    res = _FlagCapturingResolver()

    await validate_chain("example.com", "A", resolver=res)

    assert res.captured is not None, "resolver was never queried"
    assert res.captured & dns.flags.CD, (
        "chain walk queried without CD; a validating upstream will withhold "
        "bogus records and the walk can only say INDETERMINATE"
    )


@pytest.mark.asyncio
async def test_setting_cd_does_not_drop_rd() -> None:
    res = _FlagCapturingResolver()

    await validate_chain("example.com", "A", resolver=res)

    assert res.captured is not None, "resolver was never queried"
    assert res.captured & dns.flags.RD, (
        "chain walk dropped RD while setting CD; a recursive resolver will not "
        "recurse and every lookup fails"
    )
