# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for the DNSBackend ABC — default get_record and publish_agent logic."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from dns_aid.backends.base import _STANDARD_SVCB_KEYS, DNSBackend
from dns_aid.core.models import AgentRecord, Protocol

# ---------------------------------------------------------------------------
# Minimal concrete backend that records every call
# ---------------------------------------------------------------------------


class RecordingBackend(DNSBackend):
    """Concrete DNSBackend that records calls, with configurable failures."""

    def __init__(
        self,
        *,
        support: bool | None = False,
        fail_first_svcb: bool = False,
        fail_alias: bool = False,
        records: list[dict] | None = None,
    ) -> None:
        self._support = support
        self._fail_first_svcb = fail_first_svcb
        self._fail_alias = fail_alias
        self._records = records or []
        self._svcb_attempts = 0
        self.svcb_calls: list[dict] = []
        self.txt_calls: list[dict] = []

    @property
    def name(self) -> str:
        return "recording"

    @property
    def supports_private_svcb_keys(self) -> bool | None:
        return self._support

    async def create_svcb_record(self, zone, name, priority, target, params, ttl=3600) -> str:
        self._svcb_attempts += 1
        if self._fail_first_svcb and self._svcb_attempts == 1:
            raise RuntimeError("server rejected private-use SVCB keys")
        if self._fail_alias and priority == 0:
            raise RuntimeError("alias write failed")
        self.svcb_calls.append(
            {
                "zone": zone,
                "name": name,
                "priority": priority,
                "target": target,
                "params": params,
                "ttl": ttl,
            }
        )
        return f"{name}.{zone}"

    async def create_txt_record(self, zone, name, values, ttl=3600) -> str:
        self.txt_calls.append({"zone": zone, "name": name, "values": values, "ttl": ttl})
        return f"{name}.{zone}"

    async def delete_record(self, zone, name, record_type) -> bool:
        return True

    async def list_records(self, zone, name_pattern=None, record_type=None):
        for record in self._records:
            yield record

    async def zone_exists(self, zone) -> bool:
        return True


def _agent(**overrides) -> AgentRecord:
    defaults: dict = {
        "name": "helper",
        "domain": "example.com",
        "protocol": Protocol.MCP,
        "target_host": "mcp.example.com",
        "port": 443,
        "capabilities": ["chat"],
        "version": "1.0.0",
    }
    defaults.update(overrides)
    return AgentRecord(**defaults)


def _custom_keys(params: dict[str, str]) -> set[str]:
    return set(params) - _STANDARD_SVCB_KEYS


# ---------------------------------------------------------------------------
# Abstract method bodies (ellipsis statements)
# ---------------------------------------------------------------------------


class TestAbstractBodies:
    @pytest.mark.asyncio
    async def test_abstract_bodies_are_noops(self):
        backend = RecordingBackend()
        assert DNSBackend.name.fget(backend) is None
        assert await DNSBackend.create_svcb_record(backend, "z", "n", 1, "t.", {}) is None
        assert await DNSBackend.create_txt_record(backend, "z", "n", ["v"]) is None
        assert await DNSBackend.delete_record(backend, "z", "n", "TXT") is None
        assert DNSBackend.list_records(backend, "z") is None
        assert await DNSBackend.zone_exists(backend, "z") is None

    def test_default_private_key_support_is_false(self):
        class Minimal(RecordingBackend):
            @property
            def supports_private_svcb_keys(self) -> bool | None:
                return DNSBackend.supports_private_svcb_keys.fget(self)

        assert Minimal().supports_private_svcb_keys is False


# ---------------------------------------------------------------------------
# Default get_record implementation
# ---------------------------------------------------------------------------


class TestDefaultGetRecord:
    @pytest.mark.asyncio
    async def test_match_by_name(self):
        backend = RecordingBackend(
            records=[
                {"name": "other", "type": "SVCB"},
                {"name": "helper", "type": "SVCB"},
            ]
        )
        record = await backend.get_record("example.com", "helper", "SVCB")
        assert record == {"name": "helper", "type": "SVCB"}

    @pytest.mark.asyncio
    async def test_match_by_fqdn(self):
        backend = RecordingBackend(records=[{"fqdn": "helper.example.com", "type": "TXT"}])
        record = await backend.get_record("example.com", "helper", "TXT")
        assert record == {"fqdn": "helper.example.com", "type": "TXT"}

    @pytest.mark.asyncio
    async def test_no_match_returns_none(self):
        backend = RecordingBackend(records=[{"name": "nope", "fqdn": "nope.example.com"}])
        assert await backend.get_record("example.com", "helper", "SVCB") is None

    @pytest.mark.asyncio
    async def test_empty_zone_returns_none(self):
        backend = RecordingBackend()
        assert await backend.get_record("example.com", "helper", "SVCB") is None


# ---------------------------------------------------------------------------
# publish_agent — param demotion / native support matrix
# ---------------------------------------------------------------------------


class TestPublishAgentSupportMatrix:
    @pytest.mark.asyncio
    async def test_native_support_passes_all_params(self):
        """support=True → private-use keys stay on the SVCB record."""
        agent = _agent(cap_uri="https://example.com/caps.json")
        backend = RecordingBackend(support=True)

        records = await backend.publish_agent(agent)

        assert any(r.startswith("SVCB ") for r in records)
        svcb_params = backend.svcb_calls[0]["params"]
        assert _custom_keys(svcb_params), "expected private-use keys on SVCB"
        # Nothing demoted to TXT
        assert not any(v.startswith("dnsaid_") for v in backend.txt_calls[0]["values"])

    @pytest.mark.asyncio
    async def test_no_support_demotes_custom_params_to_txt(self):
        """support=False → custom params demoted as dnsaid_KEY=value."""
        agent = _agent(cap_uri="https://example.com/caps.json")
        backend = RecordingBackend(support=False)

        records = await backend.publish_agent(agent)

        svcb_params = backend.svcb_calls[0]["params"]
        assert not _custom_keys(svcb_params)
        demoted = [v for v in backend.txt_calls[0]["values"] if v.startswith("dnsaid_")]
        assert demoted, "expected demoted dnsaid_* TXT values"
        assert len(records) == 2

    @pytest.mark.asyncio
    async def test_no_support_without_custom_params_no_demotion(self):
        """support=False and only standard params → nothing demoted, no warning."""
        agent = _agent()
        backend = RecordingBackend(support=False)

        await backend.publish_agent(agent)

        assert not _custom_keys(backend.svcb_calls[0]["params"])
        assert not any(v.startswith("dnsaid_") for v in backend.txt_calls[0]["values"])

    @pytest.mark.asyncio
    async def test_auto_detect_native_success(self):
        """support=None → first write with all params succeeds; no second SVCB."""
        agent = _agent(cap_uri="https://example.com/caps.json")
        backend = RecordingBackend(support=None)

        records = await backend.publish_agent(agent)

        # Single SVCB write carrying the custom keys
        assert len(backend.svcb_calls) == 1
        assert _custom_keys(backend.svcb_calls[0]["params"])
        assert records[0].startswith("SVCB ")
        assert not any(v.startswith("dnsaid_") for v in backend.txt_calls[0]["values"])

    @pytest.mark.asyncio
    async def test_auto_detect_fallback_on_rejection(self):
        """support=None → server rejects, retry with standard params + demotion."""
        agent = _agent(cap_uri="https://example.com/caps.json")
        backend = RecordingBackend(support=None, fail_first_svcb=True)

        records = await backend.publish_agent(agent)

        # First attempt raised, second (recorded) attempt has only standard keys
        assert backend._svcb_attempts == 2
        assert len(backend.svcb_calls) == 1
        assert not _custom_keys(backend.svcb_calls[0]["params"])
        demoted = [v for v in backend.txt_calls[0]["values"] if v.startswith("dnsaid_")]
        assert demoted
        assert any(r.startswith("SVCB ") for r in records)

    @pytest.mark.asyncio
    async def test_auto_detect_without_custom_params_uses_standard_path(self):
        """support=None but no custom params → plain demotion branch (no-op)."""
        agent = _agent()
        backend = RecordingBackend(support=None)

        await backend.publish_agent(agent)

        assert len(backend.svcb_calls) == 1
        assert not _custom_keys(backend.svcb_calls[0]["params"])


# ---------------------------------------------------------------------------
# publish_agent — walkable alias + TXT edge cases
# ---------------------------------------------------------------------------


class TestPublishAgentWalkableAndTxt:
    @pytest.mark.asyncio
    async def test_walkable_alias_written_when_opted_in(self):
        agent = _agent(publish_walkable_alias=True)
        backend = RecordingBackend()

        records = await backend.publish_agent(agent)

        alias_calls = [c for c in backend.svcb_calls if c["priority"] == 0]
        assert len(alias_calls) == 1
        assert alias_calls[0]["name"] == "helper._agents"
        assert alias_calls[0]["target"] == f"{agent.fqdn}."
        assert any(r.startswith("SVCB(AliasMode)") for r in records)

    @pytest.mark.asyncio
    async def test_walkable_alias_failure_is_non_fatal(self):
        agent = _agent(publish_walkable_alias=True)
        backend = RecordingBackend(fail_alias=True)

        records = await backend.publish_agent(agent)

        assert any(r.startswith("SVCB ") for r in records)
        assert any(r.startswith("TXT ") for r in records)
        assert not any("AliasMode" in r for r in records)

    @pytest.mark.asyncio
    async def test_no_txt_record_when_no_values(self):
        agent = _agent()
        backend = RecordingBackend()

        with patch.object(AgentRecord, "to_txt_values", return_value=[]):
            records = await backend.publish_agent(agent)

        assert backend.txt_calls == []
        assert records == ["SVCB helper.example.com"]
