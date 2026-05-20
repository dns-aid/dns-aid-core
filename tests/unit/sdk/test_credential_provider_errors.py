# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for ``CredentialProviderError`` sanitization invariants.

Implements T006 from ``specs/003-credential-provider-callback/tasks.md`` and
verifies the contract documented in ``contracts/credential_provider_error_contract.md``.

The single invariant under test: when a credential_provider callable raises an
exception whose message itself contains a credential-shaped sentinel value,
the wrapping ``CredentialProviderError`` instance MUST NOT expose that
sentinel via any of its own observable surfaces — ``str(error)``, ``repr(error)``,
``error.args``, or marshalling round-trips. The sentinel is permitted (and
expected) to remain accessible via ``error.__cause__`` for deliberate inspection
during debugging.

T010 will extend this file with additional cases specific to the
credential_provider invocation path (``None`` returns, empty-dict returns, dicts
missing required keys for the declared ``auth_type``). Those cases require the
``credential_provider`` parameter on ``AgentClient.invoke`` to exist, so they
land at T010 after T012/T013 implement the parameter.
"""

from __future__ import annotations

import copy
import inspect
import logging
from typing import Any

import httpx
import pytest

from dns_aid.core.models import AgentRecord, Protocol
from dns_aid.sdk._config import SDKConfig
from dns_aid.sdk.client import AgentClient
from dns_aid.sdk.exceptions import CredentialProviderError, DirectoryError

# A sentinel value that mimics credential material a provider's underlying
# exception might inadvertently embed in its message (e.g., httpx surfacing
# the request body of a failed token-exchange call). The wrapper must never
# expose this sentinel through its own surface.
_SENTINEL = "SENTINEL_CAUSE_a7f8c9d0_should_never_appear_in_wrapper"  # noqa: S105


class TestCredentialProviderErrorBasicConstruction:
    """The constructor signature is single-positional ``agent_fqdn: str``."""

    def test_construction_with_agent_fqdn(self) -> None:
        err = CredentialProviderError(agent_fqdn="agent.example.com")
        assert err.agent_fqdn == "agent.example.com"

    def test_agent_fqdn_is_public_attribute(self) -> None:
        err = CredentialProviderError(agent_fqdn="agent.example.com")
        assert hasattr(err, "agent_fqdn")
        assert isinstance(err.agent_fqdn, str)

    def test_message_template_includes_agent_fqdn(self) -> None:
        err = CredentialProviderError(agent_fqdn="weird-name.example.com")
        # The static message template must include the agent_fqdn so log
        # correlation works, but the message body is intentionally minimal.
        # We assert the exact message template (not a bare substring) to
        # avoid CodeQL flagging this as URL substring sanitisation — the
        # check here is about exception message formatting, not URL handling.
        assert str(err) == "credential_provider failed for agent 'weird-name.example.com'"


class TestCredentialProviderErrorExtendsException:
    """The class extends Exception directly, not DirectoryError."""

    def test_isinstance_exception(self) -> None:
        err = CredentialProviderError(agent_fqdn="agent.example.com")
        assert isinstance(err, Exception)

    def test_is_not_directory_error(self) -> None:
        # Architectural decision per T003 and research.md Decision 3 base-class
        # paragraph: credential resolution is not a directory operation. The
        # wrapper must NOT inherit from DirectoryError.
        err = CredentialProviderError(agent_fqdn="agent.example.com")
        assert not isinstance(err, DirectoryError)


class TestCredentialProviderErrorSanitization:
    """Sentinel values from a wrapped exception must not leak through the wrapper."""

    @pytest.fixture
    def wrapped_error(self) -> CredentialProviderError:
        """Construct a CredentialProviderError wrapping an exception whose message
        contains a sentinel value, simulating a provider whose underlying failure
        embeds credential material in the error message."""
        try:
            raise RuntimeError(f"token-endpoint failed: {_SENTINEL}")
        except RuntimeError as inner:
            try:
                raise CredentialProviderError(agent_fqdn="target.example.com") from inner
            except CredentialProviderError as outer:
                return outer

    def test_str_does_not_contain_sentinel(self, wrapped_error: CredentialProviderError) -> None:
        assert _SENTINEL not in str(wrapped_error), (
            "CredentialProviderError.__str__ must not expose values from __cause__."
        )

    def test_repr_does_not_contain_sentinel(self, wrapped_error: CredentialProviderError) -> None:
        assert _SENTINEL not in repr(wrapped_error), (
            "CredentialProviderError.__repr__ must not expose values from __cause__."
        )

    def test_args_does_not_contain_sentinel(self, wrapped_error: CredentialProviderError) -> None:
        for i, arg in enumerate(wrapped_error.args):
            assert _SENTINEL not in str(arg), (
                f"CredentialProviderError.args[{i}] must not expose values from __cause__."
            )

    def test_cause_is_preserved_for_debugging(self, wrapped_error: CredentialProviderError) -> None:
        """The __cause__ chain remains intact so debuggers can deliberately inspect it.

        Sanitization applies to the wrapper's OWN surface — not to __cause__.
        Callers who want to inspect the underlying exception must do so explicitly.
        """
        assert wrapped_error.__cause__ is not None
        assert isinstance(wrapped_error.__cause__, RuntimeError)
        # The sentinel IS expected to be in __cause__ — that's the point of
        # preserving the cause chain. The wrapper's surface must not surface it.
        assert _SENTINEL in str(wrapped_error.__cause__)


class TestCredentialProviderErrorMarshalling:
    """Standard exception marshalling (e.g., for multiprocessing or persistence) must
    preserve agent_fqdn and must not regress the sanitization invariant.

    We exercise the same ``__reduce_ex__`` serialization machinery that Python's
    standard marshalling subsystem uses, via ``copy.deepcopy`` (which calls the
    same protocol). A secondary direct marshalling check uses a lazy import to
    confirm the wire-format path behaves identically.
    """

    def test_deepcopy_round_trip_preserves_agent_fqdn(self) -> None:
        original = CredentialProviderError(agent_fqdn="round-trip.example.com")
        restored = copy.deepcopy(original)
        assert restored.agent_fqdn == "round-trip.example.com"
        assert isinstance(restored, CredentialProviderError)

    def test_deepcopy_round_trip_does_not_leak_cause_sentinel(self) -> None:
        """If a wrapped exception is marshalled, the wrapper's serialized form does
        not expose the sentinel from __cause__'s message via its own surface."""
        try:
            raise RuntimeError(f"underlying provider failure: {_SENTINEL}")
        except RuntimeError as inner:
            try:
                raise CredentialProviderError(agent_fqdn="target.example.com") from inner
            except CredentialProviderError as outer:
                restored = copy.deepcopy(outer)
                assert _SENTINEL not in str(restored)
                assert _SENTINEL not in repr(restored)
                assert all(_SENTINEL not in str(a) for a in restored.args)
                # agent_fqdn must survive the round-trip intact.
                assert restored.agent_fqdn == "target.example.com"

    def test_standard_wire_marshalling_round_trip_sanitization(self) -> None:
        """Exercise Python's standard wire-format marshalling subsystem (the one
        used by ``multiprocessing`` and ``concurrent.futures.ProcessPoolExecutor``)
        to verify the wrapper's sanitization survives that path identically to
        the in-process ``__reduce_ex__`` path.

        The import is deliberately local because this subsystem is only required
        for this single test; the rest of the file uses ``copy.deepcopy`` which
        exercises the same ``__reduce_ex__`` protocol.
        """
        import pickle as _pickle  # noqa: S403 — required for this test only

        original = CredentialProviderError(agent_fqdn="wire-round-trip.example.com")
        blob = _pickle.dumps(original)
        restored = _pickle.loads(blob)  # noqa: S301 — self-marshalled trusted object
        assert restored.agent_fqdn == "wire-round-trip.example.com"
        assert isinstance(restored, CredentialProviderError)
        assert _SENTINEL not in str(restored)
        assert _SENTINEL not in repr(restored)


class TestCredentialProviderErrorNoUnsafeConstructorArgs:
    """The constructor accepts ONLY agent_fqdn — never the original exception or dict."""

    def test_constructor_takes_exactly_one_positional(self) -> None:
        # Verify the signature by inspecting it. If a future change adds a
        # second positional that could carry credential material, this test
        # fails as a contract regression.
        sig = inspect.signature(CredentialProviderError.__init__)
        params = [p for p in sig.parameters.values() if p.name != "self"]
        assert len(params) == 1, (
            f"CredentialProviderError.__init__ must accept exactly one parameter "
            f"besides self (agent_fqdn). Got: {[p.name for p in params]}"
        )
        assert params[0].name == "agent_fqdn"


# ---------------------------------------------------------------------------
# T010: Provider-path edge cases — exercise the SDK's resolution branch with
# unusual provider return values. TDD red until T012/T013 land the parameter.
# ---------------------------------------------------------------------------


def _bearer_agent() -> AgentRecord:
    """Build a bearer-auth AgentRecord for provider-path edge-case tests."""
    return AgentRecord(
        name="provider-edge",
        domain="example.com",
        protocol=Protocol.MCP,
        target_host="mcp.example.com",
        port=443,
        capabilities=[],
        auth_type="bearer",
        auth_config={"header_name": "Authorization"},
    )


def _mock_transport(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {"tools": []}})


@pytest.fixture
def sdk_config_provider_edge() -> SDKConfig:
    return SDKConfig(timeout_seconds=5.0, caller_id="provider-edge-test", console_signals=False)


class TestProviderReturnsNoneOrEmpty:
    """Per FR-003: provider returning None or an empty dict is treated identically
    to 'no credentials provided' — debug log emitted, invocation proceeds without
    auth handler resolution, no exception raised."""

    @pytest.mark.asyncio
    async def test_provider_returning_none_treated_as_no_credentials(
        self,
        sdk_config_provider_edge: SDKConfig,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A provider that returns None must not raise from the resolution path —
        the SDK proceeds without authentication and emits a debug log.

        TDD red until T012 lands the ``credential_provider`` kwarg: this test
        currently fails with TypeError. Once T012/T013 land, the resolution
        path completes without raising. Downstream transport errors are
        unrelated to this assertion and are allowed.
        """
        caplog.set_level(logging.DEBUG)
        agent = _bearer_agent()
        provider_was_awaited = False

        async def none_provider(_agent: AgentRecord) -> dict[str, Any] | None:
            nonlocal provider_was_awaited
            provider_was_awaited = True
            return None  # type: ignore[return-value]

        async with AgentClient(config=sdk_config_provider_edge) as client:
            monkeypatch.setattr(
                client,
                "_http_client",
                httpx.AsyncClient(transport=httpx.MockTransport(_mock_transport)),
            )
            # If the resolution path raises (CredentialProviderError or a typed
            # subclass thereof), this test FAILS — that would mean the SDK
            # treated None as a provider error rather than as "no credentials
            # provided," contradicting FR-003.
            try:
                await client.invoke(
                    agent=agent,
                    method="tools/list",
                    credential_provider=none_provider,  # type: ignore[arg-type]
                )
            except TypeError:
                # TDD red until T012: missing kwarg surfaces TypeError; re-raise
                # so this test fails loudly until the feature is implemented.
                raise
            except CredentialProviderError:
                # If the resolution path itself raised CredentialProviderError,
                # that's a violation of FR-003 — fail explicitly.
                raise AssertionError(
                    "FR-003 violation: provider returning None must NOT raise "
                    "CredentialProviderError; it must be treated as 'no credentials'."
                ) from None
            except Exception:  # noqa: BLE001
                # Downstream transport errors (mock not matching MCP semantics)
                # are not what this test asserts on. Tolerate them.
                pass

        assert provider_was_awaited, (
            "Provider was never awaited — the SDK short-circuited before the "
            "resolution path, indicating a precedence-order bug."
        )

    @pytest.mark.asyncio
    async def test_provider_returning_empty_dict_treated_as_no_credentials(
        self,
        sdk_config_provider_edge: SDKConfig,
        caplog: pytest.LogCaptureFixture,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A provider that returns ``{}`` must not raise from the resolution path —
        identical handling to None per FR-003."""
        caplog.set_level(logging.DEBUG)
        agent = _bearer_agent()
        provider_was_awaited = False

        async def empty_provider(_agent: AgentRecord) -> dict[str, Any]:
            nonlocal provider_was_awaited
            provider_was_awaited = True
            return {}

        async with AgentClient(config=sdk_config_provider_edge) as client:
            monkeypatch.setattr(
                client,
                "_http_client",
                httpx.AsyncClient(transport=httpx.MockTransport(_mock_transport)),
            )
            try:
                await client.invoke(
                    agent=agent,
                    method="tools/list",
                    credential_provider=empty_provider,
                )
            except TypeError:
                raise
            except CredentialProviderError:
                raise AssertionError(
                    "FR-003 violation: provider returning {} must NOT raise "
                    "CredentialProviderError; it must be treated as 'no credentials'."
                ) from None
            except Exception:  # noqa: BLE001
                pass

        assert provider_was_awaited, (
            "Provider was never awaited — the SDK short-circuited before the "
            "resolution path, indicating a precedence-order bug."
        )


class TestProviderReturnsDictMissingRequiredKeys:
    """When a provider returns a dict that lacks the keys the declared ``auth_type``
    requires (e.g., ``auth_type=bearer`` but provider returns ``{}`` or
    ``{"wrong_key": "..."}`` AND non-empty enough to bypass the empty-dict
    short-circuit), the handler factory's existing ValueError propagates with
    auth_type and missing-key context. The provider's actual return value must
    NOT appear in the error message."""

    @pytest.mark.asyncio
    async def test_bearer_missing_token_key_raises_with_context(
        self,
        sdk_config_provider_edge: SDKConfig,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A bearer-typed target with a provider returning a non-empty dict that
        lacks the ``token`` key surfaces a clear ValueError naming ``auth_type``
        and the missing key. The sentinel value present in the wrong-key entry
        must NOT appear in the error message."""
        agent = _bearer_agent()
        sentinel = "SENTINEL_WRONG_KEY_VALUE_should_not_leak"  # noqa: S105

        async def wrong_shape_provider(_agent: AgentRecord) -> dict[str, Any]:
            # Non-empty dict (so the empty-dict short-circuit doesn't apply),
            # but missing the bearer handler's required "token" key.
            return {"unexpected_key": sentinel}

        async with AgentClient(config=sdk_config_provider_edge) as client:
            monkeypatch.setattr(
                client,
                "_http_client",
                httpx.AsyncClient(transport=httpx.MockTransport(_mock_transport)),
            )

            # The resolution must raise a clear error. The exact exception type
            # is implementation-defined (existing registry surfaces ValueError;
            # the SDK may wrap it). The invariants are: an exception IS raised,
            # and the sentinel from the provider's return does NOT appear in
            # the raised exception's message.
            captured: BaseException | None = None
            try:
                await client.invoke(
                    agent=agent,
                    method="tools/list",
                    credential_provider=wrong_shape_provider,
                )
            except TypeError:
                # TDD red until T012 lands the kwarg.
                raise
            except Exception as exc:  # noqa: BLE001
                captured = exc

            assert captured is not None, (
                "A provider returning a dict missing the required key for the "
                "agent's auth_type must surface a clear resolution error."
            )
            # Sanitization invariant: the provider's value for the unexpected
            # key must not appear in the propagating error.
            assert sentinel not in str(captured), (
                f"Sentinel from provider's wrong-shape dict leaked into the "
                f"propagating exception: {captured!r}"
            )
            assert sentinel not in repr(captured), (
                f"Sentinel from provider's wrong-shape dict leaked into the "
                f"exception repr: {captured!r}"
            )
