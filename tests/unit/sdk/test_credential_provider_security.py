# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Sentinel-based security regression tests for the credential_provider path.

These tests verify FR-005, FR-015, FR-016, and SC-004 from the feature spec:
no credential value supplied to or returned by a ``credential_provider`` MUST
appear in any log capture, exception serialization (str/repr/args), or
SDK-internal state across ALL six authentication handlers.

Test layout: one parameterized test case per auth handler. Each case uses a
unique sentinel value embedded in the credential dict and asserts the sentinel
does not appear anywhere observable. The sentinel is generated per-case so a
leak in one handler cannot mask a leak in another.

TDD state at file creation (T004 in tasks.md):
    The ``credential_provider`` keyword-only parameter on ``AgentClient.invoke``
    does not yet exist. Every test in this file will fail with
    ``TypeError: invoke() got an unexpected keyword argument 'credential_provider'``.
    That is the expected RED state. T012/T013 in the task list add the parameter
    and the resolution logic; the tests must transition to GREEN at T014 without
    any modification to this file.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx
import pytest

from dns_aid.core.models import AgentRecord, Protocol
from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.client import AgentClient

# ---------------------------------------------------------------------------
# Per-handler sentinel credential dicts.
#
# Each sentinel string is unique to its handler so that, if a leak occurs, the
# failing assertion identifies which handler is at fault. Sentinels follow the
# pattern ``SENTINEL_<HANDLER>_<RANDOM>`` — random enough to be unique under
# grep, descriptive enough to be obvious in a failing test output.
# ---------------------------------------------------------------------------

_SENTINEL_NONE = "SENTINEL_NONE_a1b2c3d4_should_never_appear"  # noqa: S105 — test sentinel, not a secret
_SENTINEL_API_KEY = "SENTINEL_APIKEY_e5f6g7h8_should_never_appear"  # noqa: S105
_SENTINEL_BEARER = "SENTINEL_BEARER_i9j0k1l2_should_never_appear"  # noqa: S105
_SENTINEL_OAUTH2_ID = "SENTINEL_OAUTH2ID_m3n4o5p6_should_never_appear"  # noqa: S105
_SENTINEL_OAUTH2_SECRET = "SENTINEL_OAUTH2SECRET_q7r8s9t0_should_never_appear"  # noqa: S105
_SENTINEL_HTTP_MSG_SIG_KEY = "SENTINEL_HMSIG_u1v2w3x4_should_never_appear"  # noqa: S105 — not a real PEM
_SENTINEL_HTTP_MSG_SIG_KID = "SENTINEL_HMSIGKID_y5z6a7b8_should_never_appear"  # noqa: S105
_SENTINEL_SIGV4_AK = "SENTINEL_SIGV4AK_c9d0e1f2_should_never_appear"  # noqa: S105
_SENTINEL_SIGV4_SK = "SENTINEL_SIGV4SK_g3h4i5j6_should_never_appear"  # noqa: S105
_SENTINEL_SIGV4_ST = "SENTINEL_SIGV4ST_k7l8m9n0_should_never_appear"  # noqa: S105


# All sentinels in one set for "did any of them leak" cross-checks.
_ALL_SENTINELS = frozenset(
    {
        _SENTINEL_NONE,
        _SENTINEL_API_KEY,
        _SENTINEL_BEARER,
        _SENTINEL_OAUTH2_ID,
        _SENTINEL_OAUTH2_SECRET,
        _SENTINEL_HTTP_MSG_SIG_KEY,
        _SENTINEL_HTTP_MSG_SIG_KID,
        _SENTINEL_SIGV4_AK,
        _SENTINEL_SIGV4_SK,
        _SENTINEL_SIGV4_ST,
    }
)


# ---------------------------------------------------------------------------
# Parameter cases: (auth_type, auth_config, sentinel_credentials_dict, sentinels_to_check)
# ---------------------------------------------------------------------------

_HANDLER_CASES: list[tuple[str | None, dict[str, Any] | None, dict[str, Any], frozenset[str]]] = [
    # The 'none' handler should never receive credentials at all — the SDK
    # short-circuits before the provider is called (FR-008). We still pass a
    # sentinel-containing dict to verify that even if the SDK somehow logged
    # the provider's existence, no sentinel leaks.
    (
        "none",
        None,
        {"token": _SENTINEL_NONE},
        frozenset({_SENTINEL_NONE}),
    ),
    (
        "api_key",
        {"header_name": "X-API-Key"},
        {"api_key": _SENTINEL_API_KEY},
        frozenset({_SENTINEL_API_KEY}),
    ),
    (
        "bearer",
        {"header_name": "Authorization"},
        {"token": _SENTINEL_BEARER},
        frozenset({_SENTINEL_BEARER}),
    ),
    (
        "oauth2",
        {"token_endpoint": "https://idp.example.com/oauth2/token"},
        {
            "client_id": _SENTINEL_OAUTH2_ID,
            "client_secret": _SENTINEL_OAUTH2_SECRET,
        },
        frozenset({_SENTINEL_OAUTH2_ID, _SENTINEL_OAUTH2_SECRET}),
    ),
    (
        "http_msg_sig",
        {},
        {
            "private_key_pem": _SENTINEL_HTTP_MSG_SIG_KEY,
            "key_id": _SENTINEL_HTTP_MSG_SIG_KID,
        },
        frozenset({_SENTINEL_HTTP_MSG_SIG_KEY, _SENTINEL_HTTP_MSG_SIG_KID}),
    ),
    (
        "sigv4",
        {"region": "us-east-1", "service": "vpc-lattice-svcs"},
        {
            "access_key": _SENTINEL_SIGV4_AK,
            "secret_key": _SENTINEL_SIGV4_SK,
            "session_token": _SENTINEL_SIGV4_ST,
        },
        frozenset({_SENTINEL_SIGV4_AK, _SENTINEL_SIGV4_SK, _SENTINEL_SIGV4_ST}),
    ),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _agent_for(auth_type: str | None, auth_config: dict[str, Any] | None) -> AgentRecord:
    """Build a minimal AgentRecord with the requested auth_type/auth_config.

    Note: ``AgentRecord.name`` only accepts the regex ``^[a-z0-9]([a-z0-9-]*[a-z0-9])?$``,
    so we sanitize ``auth_type`` by replacing underscores with hyphens for the name field.
    """
    name_suffix = (auth_type or "none").replace("_", "-")
    return AgentRecord(
        name=f"sec-test-{name_suffix}",
        domain="example.com",
        protocol=Protocol.MCP,
        target_host="mcp.example.com",
        port=443,
        capabilities=[],
        auth_type=auth_type,
        auth_config=auth_config,
    )


def _assert_no_sentinel_in(text: str, sentinels: frozenset[str], where: str) -> None:
    """Assert no sentinel from the set appears in the given text."""
    for sentinel in sentinels:
        assert sentinel not in text, (
            f"Credential leak detected: sentinel {sentinel!r} found in {where}. "
            f"This is a SC-004 / FR-005 regression — credentials must never appear "
            f"in {where}."
        )


def _assert_no_sentinel_in_exception(exc: BaseException, sentinels: frozenset[str]) -> None:
    """Assert no sentinel appears in any externally observable form of the exception."""
    _assert_no_sentinel_in(str(exc), sentinels, "str(exception)")
    _assert_no_sentinel_in(repr(exc), sentinels, "repr(exception)")
    for i, arg in enumerate(exc.args):
        _assert_no_sentinel_in(str(arg), sentinels, f"exception.args[{i}]")


def _assert_no_sentinel_in_logs(
    caplog: pytest.LogCaptureFixture, sentinels: frozenset[str]
) -> None:
    """Assert no sentinel appears in caplog text or any individual record."""
    _assert_no_sentinel_in(caplog.text, sentinels, "caplog.text")
    for record in caplog.records:
        _assert_no_sentinel_in(record.getMessage(), sentinels, f"log record at {record.levelname}")
        # Check structured fields in extra dict (structlog dumps these)
        for attr_name in dir(record):
            if attr_name.startswith("_"):
                continue
            try:
                value = getattr(record, attr_name)
            except AttributeError:
                continue
            if isinstance(value, str | bytes):
                text = value if isinstance(value, str) else value.decode("utf-8", errors="replace")
                _assert_no_sentinel_in(text, sentinels, f"log record attribute {attr_name!r}")


def _mock_transport(request: httpx.Request) -> httpx.Response:
    """Mock HTTP transport that succeeds without inspecting credentials.

    Used so the invoke path completes (or fails harmlessly) without making any
    real network call. The transport DOES NOT log the request headers — that
    would itself be a credential-leak vector outside the SDK's resolution path.
    """
    return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("auth_type", "auth_config", "credentials", "sentinels"),
    _HANDLER_CASES,
    ids=[case[0] or "none" for case in _HANDLER_CASES],
)
@pytest.mark.asyncio
async def test_provider_credentials_never_leak_in_logs(
    auth_type: str | None,
    auth_config: dict[str, Any] | None,
    credentials: dict[str, Any],
    sentinels: frozenset[str],
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """For every handler: a credential_provider's returned credentials never appear in logs.

    The provider is awaited fresh (per FR-006), the handler is constructed
    against the sentinel credentials, the invocation either succeeds or fails
    — and in either outcome no sentinel value appears in any log message,
    structured log attribute, or log capture.

    This is the FR-005 / FR-016 / SC-004 regression test for the handler.
    """
    caplog.set_level(logging.DEBUG)

    agent = _agent_for(auth_type, auth_config)
    config = SDKConfig(timeout_seconds=5.0, caller_id="security-test", console_signals=False)

    async def provider(_agent: AgentRecord) -> dict[str, Any]:
        return credentials

    # The invoke may succeed (mock transport) or fail (handler can't construct
    # against the sentinel material — e.g., http_msg_sig won't parse a sentinel
    # string as a PEM key). Either outcome is acceptable for this test. The
    # invariant is: the sentinel must not leak regardless of outcome.
    #
    # However: if invoke() does not yet accept the `credential_provider` kwarg
    # (TDD red state before T012), the TypeError MUST surface — silently
    # swallowing it would make the test pass when the feature is missing,
    # defeating the TDD-first discipline. We catch Exception only (not
    # BaseException) and let TypeError specifically NOT be the swallowed case.
    captured_exception: BaseException | None = None
    try:
        async with AgentClient(config=config) as client:
            # The transport is mocked so no real HTTP call leaves the process.
            monkeypatch.setattr(
                client,
                "_http_client",
                httpx.AsyncClient(transport=httpx.MockTransport(_mock_transport)),
            )
            await client.invoke(
                agent=agent,
                method="tools/list",
                credential_provider=provider,
            )
    except TypeError:
        # TypeError from missing kwarg = feature not yet implemented (TDD red).
        # Re-raise so the test fails loudly until T012 lands.
        raise
    except Exception as exc:  # noqa: BLE001 — we deliberately catch any leak surface
        captured_exception = exc

    # Invariant: regardless of success or failure, sentinels never appear in logs.
    _assert_no_sentinel_in_logs(caplog, sentinels)

    # Cross-handler invariant: NO sentinel from any handler appears (catches
    # accidental cross-contamination, e.g., a handler logging its peer's keys).
    _assert_no_sentinel_in_logs(caplog, _ALL_SENTINELS)

    # If the invocation raised, the exception must not contain any sentinel
    # value either. (CredentialProviderError sanitization is verified in detail
    # in test_credential_provider_errors.py; this assertion catches any other
    # leak path via unwrapped exceptions.)
    if captured_exception is not None:
        _assert_no_sentinel_in_exception(captured_exception, sentinels)
        _assert_no_sentinel_in_exception(captured_exception, _ALL_SENTINELS)


@pytest.mark.parametrize(
    ("auth_type", "auth_config", "credentials", "sentinels"),
    _HANDLER_CASES,
    ids=[case[0] or "none" for case in _HANDLER_CASES],
)
@pytest.mark.asyncio
async def test_provider_called_fresh_each_invoke(
    auth_type: str | None,
    auth_config: dict[str, Any] | None,
    credentials: dict[str, Any],
    sentinels: frozenset[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """For every handler: the credential_provider is awaited freshly on every invoke.

    Verifies FR-006: the SDK does not cache credentials returned by the
    provider across invocations. Each invoke that uses the provider branch
    MUST await the provider function fresh.

    The provider increments a counter on each call. After N invokes, the
    counter MUST equal N.
    """
    agent = _agent_for(auth_type, auth_config)
    config = SDKConfig(timeout_seconds=5.0, caller_id="freshness-test", console_signals=False)

    call_count = 0

    async def counting_provider(_agent: AgentRecord) -> dict[str, Any]:
        nonlocal call_count
        call_count += 1
        return credentials

    expected_calls = 3
    async with AgentClient(config=config) as client:
        monkeypatch.setattr(
            client,
            "_http_client",
            httpx.AsyncClient(transport=httpx.MockTransport(_mock_transport)),
        )
        for _ in range(expected_calls):
            try:
                await client.invoke(
                    agent=agent,
                    method="tools/list",
                    credential_provider=counting_provider,
                )
            except TypeError:
                # TypeError from missing kwarg = feature not yet implemented
                # (TDD red). Re-raise so the test fails loudly until T012 lands.
                raise
            except Exception:  # noqa: BLE001
                # Handler construction or transport may fail with sentinel
                # material once the feature exists — that's OK; we only care
                # that the provider was called.
                pass

    if auth_type is None or auth_type == "none":
        # auth_type=none short-circuits before the provider is called (FR-008).
        # The counter must remain 0 — that's the desired behavior.
        assert call_count == 0, (
            f"Provider must NOT be called when auth_type is {auth_type!r} "
            f"(FR-008 short-circuit). Got {call_count} calls."
        )
    else:
        # Every invoke must trigger a fresh provider call.
        assert call_count == expected_calls, (
            f"Provider must be awaited fresh on every invoke (FR-006). "
            f"Expected {expected_calls} calls, got {call_count}."
        )
