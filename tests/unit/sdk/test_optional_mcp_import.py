# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Regression: the package (and CLI) must import without the optional ``mcp`` extra.

``mcp`` is declared in the ``mcp`` extra, not the core dependencies. A stray
module-level ``from mcp...`` in the SDK import chain made ``import dns_aid``
(and therefore ``dns-aid[cli]`` with no ``mcp`` extra) fail with
``ModuleNotFoundError: No module named 'mcp'``. The MCP telemetry seam only
references ``mcp`` as a type annotation, so the import belongs under
``TYPE_CHECKING``. These tests pin that contract.
"""

from __future__ import annotations

import builtins
import importlib
import sys


def _block_mcp(monkeypatch) -> None:
    """Make any ``import mcp`` / ``from mcp...`` raise, simulating the absent extra."""
    for mod in list(sys.modules):
        if mod == "mcp" or mod.startswith("mcp."):
            monkeypatch.delitem(sys.modules, mod, raising=False)

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "mcp" or name.startswith("mcp."):
            raise ModuleNotFoundError("No module named 'mcp' (simulated: extra not installed)")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)


def test_mcp_telemetry_module_imports_without_mcp(monkeypatch):
    """The telemetry module references ``mcp`` only for typing — import must not need it."""
    _block_mcp(monkeypatch)
    monkeypatch.delitem(sys.modules, "dns_aid.sdk.protocols._mcp_telemetry", raising=False)

    mod = importlib.import_module("dns_aid.sdk.protocols._mcp_telemetry")

    assert hasattr(mod, "_make_telemetry_factory")
    # The factory builds a plain httpx client factory and never touches ``mcp``.
    assert "mcp" not in sys.modules


async def test_factory_builds_without_mcp(monkeypatch):
    """The telemetry factory is callable and returns an httpx client without ``mcp``."""
    import httpx

    _block_mcp(monkeypatch)
    monkeypatch.delitem(sys.modules, "dns_aid.sdk.protocols._mcp_telemetry", raising=False)
    mod = importlib.import_module("dns_aid.sdk.protocols._mcp_telemetry")

    capture = mod._TelemetryCapture()
    factory = mod._make_telemetry_factory(capture)
    client = factory()
    try:
        assert isinstance(client, httpx.AsyncClient)
    finally:
        await client.aclose()
