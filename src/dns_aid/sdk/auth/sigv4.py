# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""AWS SigV4 auth handler for VPC Lattice and API Gateway IAM auth."""

from __future__ import annotations

import contextlib
import logging
import threading
from collections.abc import Iterator
from io import BytesIO
from typing import Any
from urllib.parse import urlparse

import httpx
import structlog

from dns_aid.sdk.auth.base import AuthHandler

logger = structlog.get_logger(__name__)

# Headers that SigV4 produces and we copy back to the httpx request.
_SIGV4_HEADERS = ("authorization", "x-amz-date", "x-amz-security-token", "x-amz-content-sha256")


# Reference-counted suppression of botocore.auth DEBUG logs.
#
# A simple ``logger.disabled = True/False`` toggle has a race condition under
# concurrent signing: Task A saves disabled=False and sets True; Task B then
# saves disabled=True and sets True; Task A exits and restores False; Task B
# exits and restores True — leaving the logger disabled when it should not be.
# The reference-counted variant tracks how many suppression contexts are
# currently active and only restores the original state when the last one
# exits.
_botocore_auth_suppression_lock = threading.Lock()
_botocore_auth_suppression_depth = 0
_botocore_auth_suppression_original_disabled: bool | None = None


@contextlib.contextmanager
def _suppress_botocore_auth_logs() -> Iterator[None]:
    """Suppress botocore.auth's DEBUG logging during signing.

    Hardening: botocore.auth logs the canonical request at DEBUG level
    during ``SigV4Auth.add_auth()``. The canonical request includes ALL
    signed headers — among them ``x-amz-security-token`` (the STS session
    token). Any application running with botocore at DEBUG level
    therefore leaks session tokens into its log stream every time SigV4
    signs a request.

    This is a known botocore behavior and not something we can fix at the
    botocore layer without modifying the library. The defensive fix is to
    disable the ``botocore.auth`` logger for the duration of the
    ``add_auth()`` call.

    Implementation: reference-counted suppression. Concurrent SigV4 signings
    (e.g., parallel ``AgentClient.invoke()`` calls from the same process)
    share the suppression; the logger is only re-enabled when the LAST
    context exits. This avoids the toggling race where one task's "restore"
    runs before another task's "exit" and leaves the logger disabled.

    Verified by ``tests/unit/sdk/test_credential_provider_security.py``'s
    sigv4-case sentinel assertion: with this suppression, the sentinel
    session-token value does NOT appear in any captured log.
    """
    global _botocore_auth_suppression_depth, _botocore_auth_suppression_original_disabled
    botocore_auth_logger = logging.getLogger("botocore.auth")
    with _botocore_auth_suppression_lock:
        if _botocore_auth_suppression_depth == 0:
            _botocore_auth_suppression_original_disabled = botocore_auth_logger.disabled
            botocore_auth_logger.disabled = True
        _botocore_auth_suppression_depth += 1
    try:
        yield
    finally:
        with _botocore_auth_suppression_lock:
            _botocore_auth_suppression_depth -= 1
            if _botocore_auth_suppression_depth == 0:
                # Restore the original state recorded by the first context.
                # ``_original_disabled`` is guaranteed to be non-None here
                # because depth was incremented from 0 to 1 by the first
                # entering caller and stays >=1 until this last exit.
                assert _botocore_auth_suppression_original_disabled is not None
                botocore_auth_logger.disabled = _botocore_auth_suppression_original_disabled
                # Reset to None so the NEXT entering caller (a future call
                # site) re-captures the original disabled state cleanly.
                # CodeQL flags this as "unused" because its analysis is
                # single-call-scoped; the read happens on a later call.
                _botocore_auth_suppression_original_disabled = (
                    None  # lgtm[py/unused-global-variable]
                )


class SigV4AuthHandler(AuthHandler):
    """Sign requests with AWS Signature Version 4.

    Used for agents behind **VPC Lattice** (``connect-class=lattice``)
    or **API Gateway with IAM auth**.

    Credential resolution: two paths, selected at construction.

    1. **Explicit credentials** (``access_key`` + ``secret_key``, optional
       ``session_token``): the handler signs requests using the supplied
       credentials directly. Suited for short-lived STS credentials minted
       per-invoke by a ``credential_provider`` callback (e.g., the result
       of ``sts.assume_role()``).
    2. **boto3 default credential chain** (no explicit credentials
       supplied): the handler defers to boto3 (env vars → config files →
       IAM role / instance profile). Backward-compatible existing behavior
       — every prior call site continues to function unchanged.

    See ``specs/003-credential-provider-callback/contracts/
    sigv4_explicit_credentials_contract.md`` for the full behavior table.

    Args:
        region: AWS region (e.g., ``"us-east-1"``).
        service: AWS service name for signing scope. Defaults to
            ``"vpc-lattice-svcs"`` for VPC Lattice. Use
            ``"execute-api"`` for API Gateway.
        profile_name: Optional AWS profile name for credential resolution.
            Only consulted in the boto3-chain path (ignored when explicit
            credentials are supplied).
        access_key: Optional explicit AWS Access Key ID. When supplied,
            ``secret_key`` is also required. Bypasses the boto3 chain.
        secret_key: Optional explicit AWS Secret Access Key. When supplied,
            ``access_key`` is also required.
        session_token: Optional explicit STS session token. Only valid
            when ``access_key`` and ``secret_key`` are also supplied.
            When present, the signed request will include the
            ``x-amz-security-token`` header.

    Raises:
        ValueError: When credential supply is incomplete — i.e., one of
            access_key/secret_key without the other, or session_token
            alone without access_key+secret_key.
    """

    def __init__(
        self,
        region: str,
        *,
        service: str = "vpc-lattice-svcs",
        profile_name: str | None = None,
        access_key: str | None = None,
        secret_key: str | None = None,
        session_token: str | None = None,
    ) -> None:
        # Validation: explicit credentials must be supplied as a complete
        # pair (access + secret), with session_token only valid when the
        # pair is present.
        if (access_key is None) != (secret_key is None):
            raise ValueError(
                "SigV4AuthHandler requires both access_key and secret_key "
                "when either is supplied (partial credentials are meaningless "
                "for SigV4 signing)."
            )
        if session_token is not None and access_key is None:
            raise ValueError(
                "SigV4AuthHandler session_token requires access_key and "
                "secret_key (a session token alone cannot sign requests)."
            )
        # Hardening: reject empty / whitespace-only credentials up front so
        # the failure surfaces at construction with a clear message instead
        # of as a confusing botocore canonical-request error at signing time.
        # The error message names the field that failed but NEVER includes
        # the supplied value (credential-clean per FR-005).
        if access_key is not None and not access_key.strip():
            raise ValueError("SigV4AuthHandler access_key cannot be empty or whitespace-only.")
        if secret_key is not None and not secret_key.strip():
            raise ValueError("SigV4AuthHandler secret_key cannot be empty or whitespace-only.")
        if session_token is not None and not session_token.strip():
            raise ValueError(
                "SigV4AuthHandler session_token cannot be empty or whitespace-only "
                "(supply None instead to sign without a session token)."
            )

        self._region = region
        self._service = service

        if access_key is not None:
            # Explicit-credentials path: build the signer directly from the
            # supplied triplet. No boto3 chain involvement.
            assert secret_key is not None  # validated above
            self._signer = _create_signer_from_explicit(
                access_key, secret_key, session_token, region, service
            )
            self._uses_explicit_credentials = True
            self._credentials: Any = None  # not used in explicit path
        else:
            # boto3 default credential chain path (existing behavior).
            self._signer, self._credentials = _create_signer(region, service, profile_name)
            self._uses_explicit_credentials = False

    @property
    def auth_type(self) -> str:
        return "sigv4"

    def __repr__(self) -> str:
        return f"SigV4AuthHandler(region={self._region!r}, service={self._service!r})"

    async def apply(self, request: httpx.Request) -> httpx.Request:
        if self._uses_explicit_credentials:
            # Explicit credentials are static — no refresh path. The signer
            # built at construction time signs every request from the
            # supplied frozen credentials.
            signer = self._signer
        else:
            # Refresh credentials if they're from an assumed role /
            # instance profile (boto3 chain may rotate them).
            frozen = self._credentials.get_frozen_credentials()
            signer, _ = _create_signer_from_frozen(frozen, self._region, self._service)
            self._signer = signer

        aws_request = _httpx_to_aws_request(request)
        # Suppress botocore.auth DEBUG logs during signing to prevent the
        # session token from leaking through the canonical-request log.
        with _suppress_botocore_auth_logs():
            signer.add_auth(aws_request)

        # Copy SigV4 headers back to httpx request
        for header in _SIGV4_HEADERS:
            value = aws_request.headers.get(header)
            if value:
                request.headers[header] = value

        logger.debug(
            "sigv4.signed",
            service=self._service,
            region=self._region,
            method=request.method,
            explicit_credentials=self._uses_explicit_credentials,
        )
        return request


def _create_signer(region: str, service: str, profile_name: str | None) -> tuple[Any, Any]:
    """Create a SigV4Auth signer from boto3 session credentials."""
    try:
        import boto3
        from botocore.auth import SigV4Auth
    except ImportError:
        raise ImportError(
            "SigV4 signing requires 'boto3'. Install with: pip install dns-aid[route53]"
        ) from None

    session = boto3.Session(profile_name=profile_name)
    credentials = session.get_credentials()
    if not credentials:
        raise ValueError(
            "No AWS credentials found. Configure via environment variables, "
            "AWS config files, or IAM role."
        )
    frozen = credentials.get_frozen_credentials()
    signer = SigV4Auth(frozen, service, region)
    return signer, credentials


def _create_signer_from_frozen(frozen: Any, region: str, service: str) -> tuple[Any, Any]:
    """Create a SigV4Auth signer from already-frozen credentials."""
    from botocore.auth import SigV4Auth

    return SigV4Auth(frozen, service, region), frozen


def _create_signer_from_explicit(
    access_key: str,
    secret_key: str,
    session_token: str | None,
    region: str,
    service: str,
) -> Any:
    """Create a SigV4Auth signer from explicit AWS credentials.

    Used by the explicit-credentials path in ``SigV4AuthHandler``. Builds
    a ``ReadOnlyCredentials`` namedtuple directly — no boto3 session or
    credential-chain involvement. The resulting signer signs requests
    statically; the supplied credentials never change for the lifetime
    of the handler instance.

    Caller is responsible for validation that ``access_key`` and
    ``secret_key`` are both non-empty (``SigV4AuthHandler.__init__``
    handles this).
    """
    try:
        from botocore.auth import SigV4Auth
        from botocore.credentials import ReadOnlyCredentials
    except ImportError:
        raise ImportError(
            "SigV4 signing requires 'boto3'. Install with: pip install dns-aid[route53]"
        ) from None

    frozen = ReadOnlyCredentials(access_key, secret_key, session_token)
    return SigV4Auth(frozen, service, region)


def _httpx_to_aws_request(request: httpx.Request) -> Any:
    """Convert an httpx Request to a botocore AWSRequest for signing."""
    from botocore.awsrequest import AWSRequest

    parsed = urlparse(str(request.url))
    url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    if parsed.query:
        url = f"{url}?{parsed.query}"

    # Only include content-related headers for signing.
    # httpx adds transport headers (accept-encoding, connection, user-agent)
    # that must NOT be signed — API Gateway rejects mismatched signatures
    # when proxies strip or modify these headers in transit.
    sign_headers = {"host", "content-type", "content-length", "x-amz-target"}
    headers = {"Host": parsed.netloc}
    for k, v in request.headers.items():
        if k.lower() in sign_headers and k.lower() != "host":
            headers[k] = v

    return AWSRequest(
        method=request.method,
        url=url,
        headers=headers,
        data=BytesIO(request.content) if request.content else None,
    )
