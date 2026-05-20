# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for ``SigV4AuthHandler`` explicit-credentials extension (T018).

Implements T018 from ``specs/003-credential-provider-callback/tasks.md`` and
verifies the contract documented in
``contracts/sigv4_explicit_credentials_contract.md``.

The contract: ``SigV4AuthHandler.__init__`` accepts three optional keyword
arguments — ``access_key``, ``secret_key``, ``session_token`` — that allow
callers to supply AWS credentials explicitly instead of relying on the
boto3 default credential chain. The behavior selection table:

    access_key | secret_key | session_token | Behavior
    -----------|------------|---------------|---------------------------------
    None       | None       | None          | boto3 default chain (existing)
    supplied   | supplied   | None          | Static IAM-user signing, no STS
    supplied   | supplied   | supplied      | STS signing with x-amz-security-token
    supplied   | None       | (any)         | ValueError at construction
    None       | supplied   | (any)         | ValueError at construction
    None       | None       | supplied      | ValueError at construction

TDD state at file creation: ``SigV4AuthHandler.__init__`` does NOT yet
accept ``access_key``/``secret_key``/``session_token`` kwargs. Tests fail
with ``TypeError`` until T021 extends the constructor.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from dns_aid.sdk.auth.sigv4 import SigV4AuthHandler

# ---------------------------------------------------------------------------
# Test sentinels — visible enough to identify in failure messages, clearly
# fake enough to never be confused with real credentials.
# ---------------------------------------------------------------------------

EXPLICIT_AK = "AKIAIOSFODNN7EXAMPLE"  # AWS-style fake access key  # noqa: S105
EXPLICIT_SK = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # AWS-style fake secret  # noqa: S105
EXPLICIT_ST = "AQoDYXdzEJr...session-token-fake..."  # AWS-style fake session token  # noqa: S105


# ---------------------------------------------------------------------------
# Construction behavior — the six rows of the behavior selection table.
# ---------------------------------------------------------------------------


class TestSigV4ExplicitCredentialsConstruction:
    """Verify the constructor's behavior selection table."""

    def test_no_explicit_credentials_uses_boto3_chain(self) -> None:
        """When none of access_key/secret_key/session_token are supplied,
        the handler falls back to the existing boto3 default credential
        chain. Backward-compatibility lock for FR-009."""
        with patch("dns_aid.sdk.auth.sigv4._create_signer") as mock_create_signer:
            mock_create_signer.return_value = (MagicMock(), MagicMock())
            SigV4AuthHandler(region="us-east-1")
            mock_create_signer.assert_called_once_with("us-east-1", "vpc-lattice-svcs", None)

    def test_access_key_and_secret_key_no_session_uses_static_creds(self) -> None:
        """Static IAM-user credentials path: access + secret with no session
        token. Handler builds a signer from the explicit values, does NOT
        invoke the boto3 default chain."""
        with patch("dns_aid.sdk.auth.sigv4._create_signer") as mock_chain:
            handler = SigV4AuthHandler(
                region="us-east-1",
                access_key=EXPLICIT_AK,
                secret_key=EXPLICIT_SK,
            )
            mock_chain.assert_not_called()
            assert handler.auth_type == "sigv4"

    def test_all_three_explicit_credentials_uses_sts_creds(self) -> None:
        """STS-issued credentials path: access + secret + session_token.
        Handler builds a signer from all three; the session token is what
        will produce the x-amz-security-token header during signing."""
        with patch("dns_aid.sdk.auth.sigv4._create_signer") as mock_chain:
            handler = SigV4AuthHandler(
                region="us-east-1",
                access_key=EXPLICIT_AK,
                secret_key=EXPLICIT_SK,
                session_token=EXPLICIT_ST,
            )
            mock_chain.assert_not_called()
            assert handler.auth_type == "sigv4"


class TestSigV4ExplicitCredentialsValidation:
    """Construction-time validation of partial credential supply."""

    def test_access_key_without_secret_key_raises(self) -> None:
        """access_key supplied alone (no secret_key) is meaningless for
        SigV4 signing — fail fast at construction with a clear error."""
        with pytest.raises(ValueError, match="access_key.*secret_key"):
            SigV4AuthHandler(region="us-east-1", access_key=EXPLICIT_AK)

    def test_secret_key_without_access_key_raises(self) -> None:
        """secret_key supplied alone is meaningless — same fail-fast."""
        with pytest.raises(ValueError, match="access_key.*secret_key"):
            SigV4AuthHandler(region="us-east-1", secret_key=EXPLICIT_SK)

    def test_session_token_alone_raises(self) -> None:
        """session_token alone — without access_key + secret_key — is
        meaningless. Static error rather than silently routing to the
        boto3 chain (which would surprise the caller who supplied a session
        token expecting it to be used)."""
        with pytest.raises(ValueError, match="session_token requires.*access_key.*secret_key"):
            SigV4AuthHandler(region="us-east-1", session_token=EXPLICIT_ST)

    def test_session_token_with_only_access_key_raises(self) -> None:
        """session_token + access_key without secret_key is also rejected —
        same partial-credential principle."""
        with pytest.raises(ValueError):
            SigV4AuthHandler(
                region="us-east-1",
                access_key=EXPLICIT_AK,
                session_token=EXPLICIT_ST,
            )

    def test_session_token_with_only_secret_key_raises(self) -> None:
        """session_token + secret_key without access_key — same."""
        with pytest.raises(ValueError):
            SigV4AuthHandler(
                region="us-east-1",
                secret_key=EXPLICIT_SK,
                session_token=EXPLICIT_ST,
            )

    def test_empty_access_key_raises(self) -> None:
        """Hardening: empty-string access_key is rejected at construction
        instead of producing a confusing botocore canonical-request error
        downstream."""
        with pytest.raises(ValueError, match="access_key cannot be empty"):
            SigV4AuthHandler(region="us-east-1", access_key="", secret_key=EXPLICIT_SK)

    def test_whitespace_access_key_raises(self) -> None:
        """Whitespace-only access_key is equivalently invalid."""
        with pytest.raises(ValueError, match="access_key cannot be empty"):
            SigV4AuthHandler(region="us-east-1", access_key="   ", secret_key=EXPLICIT_SK)

    def test_empty_secret_key_raises(self) -> None:
        """Empty secret_key — fail fast at construction."""
        with pytest.raises(ValueError, match="secret_key cannot be empty"):
            SigV4AuthHandler(region="us-east-1", access_key=EXPLICIT_AK, secret_key="")

    def test_whitespace_secret_key_raises(self) -> None:
        """Whitespace-only secret_key — equivalently rejected."""
        with pytest.raises(ValueError, match="secret_key cannot be empty"):
            SigV4AuthHandler(region="us-east-1", access_key=EXPLICIT_AK, secret_key="\t\n")

    def test_empty_session_token_raises(self) -> None:
        """Empty-string session_token is rejected — callers must pass
        ``None`` to sign without a session token, not ``""``."""
        with pytest.raises(ValueError, match="session_token cannot be empty"):
            SigV4AuthHandler(
                region="us-east-1",
                access_key=EXPLICIT_AK,
                secret_key=EXPLICIT_SK,
                session_token="",
            )

    def test_validation_error_messages_credential_clean(self) -> None:
        """The ValueError message text NEVER contains the supplied credential
        value — even when the value is the thing being rejected (e.g. empty
        string). Static field-name-only messages keep partial supplies from
        leaking into logs at the validation stage."""
        sentinel = "AKIASENTINEL12345"  # would appear in message if leaking
        try:
            SigV4AuthHandler(region="us-east-1", access_key=sentinel)
        except ValueError as e:
            assert sentinel not in str(e), (
                "ValueError message must not include the supplied credential value"
            )
            assert sentinel not in repr(e), (
                "ValueError repr must not include the supplied credential value"
            )
        else:
            pytest.fail("expected ValueError for partial credential supply")


# ---------------------------------------------------------------------------
# Signing behavior — verify the signer applies the right headers based on
# whether session_token was supplied.
# ---------------------------------------------------------------------------


class TestSigV4ExplicitCredentialsSigning:
    """The right headers appear on the signed request depending on whether
    a session_token was supplied."""

    @pytest.mark.asyncio
    async def test_apply_with_session_token_adds_security_token_header(self) -> None:
        """When session_token is supplied (STS path), the signed request
        carries the ``x-amz-security-token`` header carrying that session
        token. This is the observable signal a downstream service uses to
        recognise STS-issued credentials."""
        handler = SigV4AuthHandler(
            region="us-east-1",
            service="execute-api",
            access_key=EXPLICIT_AK,
            secret_key=EXPLICIT_SK,
            session_token=EXPLICIT_ST,
        )
        request = httpx.Request("GET", "https://example.amazonaws.com/test")
        signed = await handler.apply(request)
        # The signature itself is opaque; what we assert is that the
        # session-token header was emitted with our supplied value.
        assert signed.headers.get("x-amz-security-token") == EXPLICIT_ST
        # The Authorization header MUST be present and SigV4-formatted.
        assert signed.headers.get("authorization", "").startswith("AWS4-HMAC-SHA256")

    @pytest.mark.asyncio
    async def test_apply_without_session_token_omits_security_token_header(self) -> None:
        """Static IAM-user path (no session token): the request is signed
        but the ``x-amz-security-token`` header is NOT emitted (no token
        to forward)."""
        handler = SigV4AuthHandler(
            region="us-east-1",
            service="execute-api",
            access_key=EXPLICIT_AK,
            secret_key=EXPLICIT_SK,
        )
        request = httpx.Request("GET", "https://example.amazonaws.com/test")
        signed = await handler.apply(request)
        assert "x-amz-security-token" not in signed.headers
        # SigV4 still applied via the access/secret pair.
        assert signed.headers.get("authorization", "").startswith("AWS4-HMAC-SHA256")


# ---------------------------------------------------------------------------
# Hardening regressions: defensive invariants that protect future changes
# ---------------------------------------------------------------------------


class TestSigV4HandlerReprDoesNotLeakCredentials:
    """``repr(handler)`` must not expose credential values via the handler's
    own surface. The underlying botocore signer holds the credentials
    internally; the handler's repr provides only safe metadata."""

    def test_handler_repr_omits_access_key(self) -> None:
        handler = SigV4AuthHandler(
            region="us-east-1",
            access_key=EXPLICIT_AK,
            secret_key=EXPLICIT_SK,
            session_token=EXPLICIT_ST,
        )
        text = repr(handler)
        assert EXPLICIT_AK not in text, f"repr(handler) leaked access_key: {text!r}"
        assert EXPLICIT_SK not in text, f"repr(handler) leaked secret_key: {text!r}"
        assert EXPLICIT_ST not in text, f"repr(handler) leaked session_token: {text!r}"

    def test_handler_str_omits_credential_values(self) -> None:
        handler = SigV4AuthHandler(
            region="us-east-1",
            access_key=EXPLICIT_AK,
            secret_key=EXPLICIT_SK,
            session_token=EXPLICIT_ST,
        )
        text = str(handler)
        assert EXPLICIT_AK not in text
        assert EXPLICIT_SK not in text
        assert EXPLICIT_ST not in text


class TestSigV4ValidationMessagesDoNotLeakCredentials:
    """Construction-time validation errors must not include credential values
    in their messages. A future refactor that interpolates values into a
    ValueError message would silently regress this. Sentinel-based tests
    catch such regressions immediately."""

    def test_partial_access_key_validation_error_omits_credentials(self) -> None:
        with pytest.raises(ValueError) as exc_info:
            SigV4AuthHandler(region="us-east-1", access_key=EXPLICIT_AK)
        msg = str(exc_info.value)
        assert EXPLICIT_AK not in msg, (
            f"ValueError from partial access_key leaked the value: {msg!r}"
        )

    def test_partial_secret_key_validation_error_omits_credentials(self) -> None:
        with pytest.raises(ValueError) as exc_info:
            SigV4AuthHandler(region="us-east-1", secret_key=EXPLICIT_SK)
        msg = str(exc_info.value)
        assert EXPLICIT_SK not in msg

    def test_session_token_alone_validation_error_omits_credentials(self) -> None:
        with pytest.raises(ValueError) as exc_info:
            SigV4AuthHandler(region="us-east-1", session_token=EXPLICIT_ST)
        msg = str(exc_info.value)
        assert EXPLICIT_ST not in msg


class TestBotocoreAuthLogSuppressionConcurrency:
    """The reference-counted log suppression must survive concurrent entries.

    Pre-fix this test would catch the race: Task A enters/exits while Task B
    is mid-context, and Task B's exit incorrectly restores the wrong state.
    With reference counting, the original state is only restored when the
    last context exits.
    """

    def test_nested_suppression_preserves_original_state(self) -> None:
        """Nested entries don't toggle the logger off and on prematurely."""
        from dns_aid.sdk.auth.sigv4 import _suppress_botocore_auth_logs

        botocore_auth_logger = logging.getLogger("botocore.auth")
        original = botocore_auth_logger.disabled

        with _suppress_botocore_auth_logs():
            assert botocore_auth_logger.disabled is True
            with _suppress_botocore_auth_logs():
                assert botocore_auth_logger.disabled is True
            # Inner exited but outer still active — must STAY disabled.
            assert botocore_auth_logger.disabled is True
        # Both exited — must restore original state.
        assert botocore_auth_logger.disabled == original

    def test_concurrent_suppression_via_threads(self) -> None:
        """Two threads entering and exiting the suppression simultaneously
        do not corrupt the logger state. After both threads complete, the
        logger is back to its original ``disabled`` value."""
        import threading
        import time

        from dns_aid.sdk.auth.sigv4 import _suppress_botocore_auth_logs

        botocore_auth_logger = logging.getLogger("botocore.auth")
        original = botocore_auth_logger.disabled

        # Synchronization: both threads enter the context before either exits,
        # creating the concurrent-suppression scenario that would have
        # exposed the pre-fix race.
        both_entered = threading.Barrier(2)

        def worker() -> None:
            with _suppress_botocore_auth_logs():
                both_entered.wait(timeout=5.0)
                # Hold the suppression briefly to ensure the threads overlap.
                time.sleep(0.05)

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10.0)
            assert not t.is_alive(), "Worker thread did not complete"

        # After both threads exit, the logger MUST be back to its original
        # state. Pre-fix, the second-exiting thread would have restored to
        # ``True`` even though the original was ``False``.
        assert botocore_auth_logger.disabled == original, (
            f"Concurrent suppression corrupted logger.disabled: "
            f"original={original} after={botocore_auth_logger.disabled}"
        )


# Imported lazily inside the concurrency-test class above; logging at
# module level here keeps the import close to its first user.
import logging  # noqa: E402
