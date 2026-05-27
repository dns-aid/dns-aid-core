# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Publisher tests for the flag-gated TXT-fallback write path.

The gate has two preconditions, both required:

1. The backend declares ``supports_svcb=False`` (it wraps a DNS system
   that can't write SVCB).
2. The operator sets ``DNS_AID_EXPERIMENTAL_TXT_FALLBACK=1`` in the
   environment.

When both are true the publisher emits a single TXT RR with a ``v=1``
endpoint body alongside the companion metadata TXT. When either is false
the publisher behaves exactly as it does today (SVCB + companion TXT).
"""

from __future__ import annotations

import pytest

from dns_aid.backends.mock import MockBackend
from dns_aid.core.models import AgentRecord, Protocol


def _make_agent() -> AgentRecord:
    return AgentRecord(
        name="chat",
        domain="example.com",
        protocol=Protocol.MCP,
        target_host="mcp.example.com",
        port=443,
        capabilities=["chat", "code-review"],
        version="1.0.0",
        cap_uri="https://example.com/cap/chat-v1.json",
        cap_sha256="DEADBEEF",
    )


class _SvcbLessBackend(MockBackend):
    """Test double: a backend whose underlying DNS system can't write SVCB."""

    @property
    def supports_svcb(self) -> bool:
        return False


# ---------------------------------------------------------------------------
# Default path (SVCB-capable backend) — no TXT fallback regardless of env flag
# ---------------------------------------------------------------------------


async def test_svcb_capable_backend_writes_svcb_not_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Even with env flag on, a backend reporting supports_svcb=True writes SVCB."""
    monkeypatch.setenv("DNS_AID_EXPERIMENTAL_TXT_FALLBACK", "1")
    backend = MockBackend()  # supports_svcb defaults to True
    agent = _make_agent()

    records = await backend.publish_agent(agent)

    # Expect a normal SVCB + metadata TXT publication
    assert any("SVCB" in r for r in records)
    assert any("TXT" in r for r in records)
    assert not any("fallback v=1" in r for r in records)

    # The TXT record should NOT contain a v=1 body — backend wrote SVCB
    zone = backend.records.get("example.com", {})
    txt_rrs = zone.get("_chat._mcp._agents", {}).get("TXT", [])
    txt_bodies = " ".join(
        v for rec in txt_rrs for v in (rec.get("values", []) if isinstance(rec, dict) else [])
    )
    assert "v=1 target=" not in txt_bodies


# ---------------------------------------------------------------------------
# Backend signals SVCB-less, env flag OFF → no fallback (today's behavior)
# ---------------------------------------------------------------------------


async def test_svcb_less_backend_no_env_flag_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Backend says no-SVCB but operator hasn't opted in — base path runs as today.

    For a real legacy-DNS backend without env opt-in the SVCB write would
    typically fail downstream; we don't change that behaviour here. The
    important property is that the TXT-fallback path is NOT silently taken
    without explicit operator consent.
    """
    monkeypatch.delenv("DNS_AID_EXPERIMENTAL_TXT_FALLBACK", raising=False)
    backend = _SvcbLessBackend()
    agent = _make_agent()

    records = await backend.publish_agent(agent)

    # No fallback marker — the gate did NOT fire
    assert not any("fallback v=1" in r for r in records)


# ---------------------------------------------------------------------------
# Backend signals SVCB-less, env flag ON → TXT fallback path
# ---------------------------------------------------------------------------


async def test_fallback_path_when_both_preconditions_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DNS_AID_EXPERIMENTAL_TXT_FALLBACK", "1")
    backend = _SvcbLessBackend()
    agent = _make_agent()

    records = await backend.publish_agent(agent)

    # Only TXT records; no SVCB attempted
    assert all("SVCB" not in r for r in records)
    assert any("fallback v=1" in r for r in records)

    # The single TXT RR should carry: (1) the v=1 endpoint body, AND
    # (2) the companion metadata values (capabilities=, version=, etc.)
    zone = backend.records["example.com"]
    txt_rrs = zone["_chat._mcp._agents"]["TXT"]
    assert len(txt_rrs) >= 1
    first = txt_rrs[0]
    values = first["values"] if isinstance(first, dict) else first.values  # type: ignore[attr-defined]
    joined = " | ".join(values)
    # Endpoint body
    assert "v=1" in joined
    assert "target=mcp.example.com" in joined
    assert "alpn=mcp" in joined
    assert "cap=https://example.com/cap/chat-v1.json" in joined
    assert "cap-sha256=DEADBEEF" in joined
    # Companion metadata (must coexist on the same FQDN)
    assert any("capabilities=" in v for v in values)
    assert any("version=" in v for v in values)


# ---------------------------------------------------------------------------
# Env flag accepts the same truthy values as the rest of the codebase
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("flag_value", ["1", "true", "yes", "TRUE", "Yes"])
async def test_env_flag_truthy_variants(monkeypatch: pytest.MonkeyPatch, flag_value: str) -> None:
    monkeypatch.setenv("DNS_AID_EXPERIMENTAL_TXT_FALLBACK", flag_value)
    backend = _SvcbLessBackend()
    agent = _make_agent()
    records = await backend.publish_agent(agent)
    assert any("fallback v=1" in r for r in records)


@pytest.mark.parametrize("flag_value", ["0", "false", "no", "off", ""])
async def test_env_flag_falsy_variants_keep_default_path(
    monkeypatch: pytest.MonkeyPatch, flag_value: str
) -> None:
    monkeypatch.setenv("DNS_AID_EXPERIMENTAL_TXT_FALLBACK", flag_value)
    backend = _SvcbLessBackend()
    agent = _make_agent()
    records = await backend.publish_agent(agent)
    assert not any("fallback v=1" in r for r in records)
