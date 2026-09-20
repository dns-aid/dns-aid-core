# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for dns_aid.core.lister.list_dns_aid_records (flat-FQDN listing)."""

from __future__ import annotations

from typing import Any

import pytest

from dns_aid.core.lister import list_dns_aid_records


class _FakeBackend:
    """Minimal backend exposing the ``list_records`` async-iterator contract."""

    def __init__(self, records: list[dict[str, Any]]):
        self._records = records

    async def list_records(self, zone, name_pattern=None, record_type=None):
        for r in self._records:
            if record_type and r.get("type") != record_type:
                continue
            if name_pattern and name_pattern not in (r.get("name") or ""):
                continue
            yield r


def _rec(name: str, fqdn: str, rtype: str) -> dict[str, Any]:
    return {"name": name, "fqdn": fqdn, "type": rtype, "ttl": 3600, "values": ["x"], "id": fqdn}


@pytest.fixture
def zone_records() -> list[dict[str, Any]]:
    return [
        _rec("@", "example.com", "SOA"),
        _rec("@", "example.com", "NS"),
        _rec("www", "www.example.com", "A"),
        # Flat draft-02 agent owner — the records the old `_agents` filter missed.
        _rec("chat", "chat.example.com", "SVCB"),
        _rec("chat", "chat.example.com", "TXT"),
        # Organization index + a walkable alias (the `_agents` bookkeeping).
        _rec("_index._agents", "_index._agents.example.com", "TXT"),
        _rec("chat._agents", "chat._agents.example.com", "SVCB"),
        # A non-DNS-AID TXT that must NOT be listed.
        _rec("_dmarc", "_dmarc.example.com", "TXT"),
    ]


async def test_lists_flat_owners_and_bookkeeping(zone_records):
    result = await list_dns_aid_records(_FakeBackend(zone_records), "example.com")
    got = {(r["fqdn"], r["type"]) for r in result}

    # The regression: flat agent owner SVCB + companion TXT are surfaced.
    assert ("chat.example.com", "SVCB") in got
    assert ("chat.example.com", "TXT") in got
    # Bookkeeping records are included.
    assert ("_index._agents.example.com", "TXT") in got
    assert ("chat._agents.example.com", "SVCB") in got
    # System + unrelated records are excluded.
    assert ("example.com", "SOA") not in got
    assert ("example.com", "NS") not in got
    assert ("www.example.com", "A") not in got
    assert ("_dmarc.example.com", "TXT") not in got


async def test_empty_zone_returns_empty():
    result = await list_dns_aid_records(
        _FakeBackend([_rec("@", "example.com", "SOA")]), "example.com"
    )
    assert result == []


async def test_dedup_when_backend_double_yields():
    dup = _rec("chat", "chat.example.com", "SVCB")
    backend = _FakeBackend([dup, dict(dup)])  # same (fqdn, type) twice
    result = await list_dns_aid_records(backend, "example.com")
    assert len([r for r in result if r["type"] == "SVCB"]) == 1
