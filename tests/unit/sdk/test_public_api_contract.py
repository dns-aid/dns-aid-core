# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Public API surface contract test.

Asserts that the public function signatures and return-type field sets
that this feature COMMITS to preserve (per
``specs/001-mcp-streamable-http/contracts/mcp-protocol-handler.md``)
have not drifted. If anyone changes one of these signatures the test
fails loudly so the contract document and any downstream callers can
be updated together.

Run this test directly to see the recorded contract:
    pytest tests/unit/sdk/test_public_api_contract.py -v
"""

from __future__ import annotations

import dataclasses
import inspect
from typing import Any


def _signature_param_names(fn: Any) -> list[str]:
    return list(inspect.signature(fn).parameters.keys())


def _signature_param_kinds(fn: Any) -> list[tuple[str, str]]:
    """Return [(name, kind)] tuples — kind is e.g. POSITIONAL_OR_KEYWORD, KEYWORD_ONLY."""
    return [(name, p.kind.name) for name, p in inspect.signature(fn).parameters.items()]


# ── 1. MCPProtocolHandler.invoke ──────────────────────────────────────────


def test_mcp_protocol_handler_invoke_signature_unchanged() -> None:
    from dns_aid.sdk.protocols.mcp import MCPProtocolHandler

    expected = ["self", "client", "endpoint", "method", "arguments", "timeout", "auth_handler"]
    assert _signature_param_names(MCPProtocolHandler.invoke) == expected


def test_mcp_protocol_handler_protocol_name_returns_mcp() -> None:
    from dns_aid.sdk.protocols.mcp import MCPProtocolHandler

    handler = MCPProtocolHandler()
    assert handler.protocol_name == "mcp"


# ── 2. RawResponse field set ──────────────────────────────────────────────


def test_raw_response_field_set_unchanged() -> None:
    from dns_aid.sdk.protocols.base import RawResponse

    expected_fields = {
        "success",
        "status",
        "data",
        "http_status_code",
        "error_type",
        "error_message",
        "invocation_latency_ms",
        "ttfb_ms",
        "response_size_bytes",
        "cost_units",
        "cost_currency",
        "tls_version",
        "headers",
    }
    actual_fields = {f.name for f in dataclasses.fields(RawResponse)}
    assert actual_fields == expected_fields, (
        f"RawResponse fields changed.\nAdded: {actual_fields - expected_fields}\n"
        f"Removed: {expected_fields - actual_fields}"
    )


# ── 3. call_mcp_tool ──────────────────────────────────────────────────────


def test_call_mcp_tool_signature_unchanged() -> None:
    from dns_aid.core.invoke import call_mcp_tool

    expected = [
        "endpoint",
        "tool_name",
        "arguments",
        "timeout",
        "caller_id",
        "credentials",
        "agent_record",
        "auth_type",
        "auth_config",
        "policy_uri",
    ]
    assert _signature_param_names(call_mcp_tool) == expected


def test_call_mcp_tool_keyword_only_params_preserved() -> None:
    from dns_aid.core.invoke import call_mcp_tool

    kinds = dict(_signature_param_kinds(call_mcp_tool))
    # Per the contract, all non-positional fields are keyword-only
    for kw_only in (
        "timeout",
        "caller_id",
        "credentials",
        "agent_record",
        "auth_type",
        "auth_config",
        "policy_uri",
    ):
        assert kinds[kw_only] == "KEYWORD_ONLY", (
            f"{kw_only} must remain keyword-only (was {kinds[kw_only]})"
        )


# ── 4. list_mcp_tools ─────────────────────────────────────────────────────


def test_list_mcp_tools_signature_unchanged() -> None:
    from dns_aid.core.invoke import list_mcp_tools

    expected = [
        "endpoint",
        "timeout",
        "caller_id",
        "credentials",
        "agent_record",
        "auth_type",
        "auth_config",
        "policy_uri",
    ]
    assert _signature_param_names(list_mcp_tools) == expected


# ── 5. AgentClient.invoke ─────────────────────────────────────────────────


def test_agent_client_invoke_signature_unchanged() -> None:
    """Locks the public surface of ``AgentClient.invoke``.

    Guards against accidental signature changes. When a feature deliberately
    adds a new keyword-only parameter (a backward-compatible additive change),
    update the ``expected`` list to include the new name. Removing or renaming
    an existing parameter requires a major version bump.

    History:
        Feature 003 (credential_provider callback) added ``credential_provider``
        between ``credentials`` and ``auth_handler``. The parameter is
        keyword-only with default ``None``, so every existing call site
        continues to function unchanged (FR-009 backward-compatibility lock).
    """
    from dns_aid.sdk.client import AgentClient

    expected = [
        "self",
        "agent",
        "method",
        "arguments",
        "timeout",
        "credentials",
        "credential_provider",
        "auth_handler",
    ]
    assert _signature_param_names(AgentClient.invoke) == expected


# ── 6. AuthHandler interface ──────────────────────────────────────────────


def test_auth_handler_protocol_unchanged() -> None:
    from dns_aid.sdk.auth.base import AuthHandler

    # AuthHandler is an ABC with `apply` and `auth_type`
    assert hasattr(AuthHandler, "apply")
    assert hasattr(AuthHandler, "auth_type")

    apply_sig = _signature_param_names(AuthHandler.apply)
    assert apply_sig == ["self", "request"]


# ── 7. InvocationStatus enum values preserved ────────────────────────────


def test_invocation_status_values_preserved() -> None:
    from dns_aid.sdk.models import InvocationStatus

    expected_values = {"SUCCESS", "TIMEOUT", "REFUSED", "ERROR"}
    actual_values = {member.name for member in InvocationStatus}
    # New values may be added (not breaking) but existing ones must remain
    assert expected_values.issubset(actual_values), (
        f"Expected InvocationStatus members removed: {expected_values - actual_values}"
    )


# ── 8. InvokeResult shape ─────────────────────────────────────────────────


def test_invoke_result_field_set_unchanged() -> None:
    from dns_aid.core.invoke import InvokeResult

    expected_fields = {"success", "data", "error", "telemetry"}
    actual_fields = {f.name for f in dataclasses.fields(InvokeResult)}
    assert actual_fields == expected_fields, (
        f"InvokeResult fields changed.\nAdded: {actual_fields - expected_fields}\n"
        f"Removed: {expected_fields - actual_fields}"
    )
