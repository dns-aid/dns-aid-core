# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
SDK exception hierarchy for directory-backed operations.

The class hierarchy distinguishes configuration errors (the directory was never set up) from
transient errors (the directory is temporarily unavailable) so callers can dispatch on type
and shells can map distinct exit codes:

* :class:`DirectoryError` — base; never raised directly.
* :class:`DirectoryConfigError` — caller invoked a directory-tied method without configuring
  ``directory_api_url``. Caller MUST treat as configuration; should not retry.
* :class:`DirectoryUnavailableError` — directory is reachable in principle but unavailable now
  (5xx response, connect refused, timeout, body validation failure). Caller SHOULD retry.
* :class:`DirectoryRateLimitedError` — directory rate-limited the call (HTTP 429). Caller
  SHOULD honor ``Retry-After`` before retrying.
* :class:`DirectoryAuthError` — directory rejected the call's credentials (HTTP 401/403).
  Caller MUST review auth handler config; should not retry blindly.

Each subclass carries a typed ``details`` mapping with structured context for log analyzers
(``directory_url``, ``status_code``, ``underlying``, ``retry_after_seconds`` as applicable),
keeping diagnostic data out of free-form message strings.
"""

from __future__ import annotations

from typing import Any


class DirectoryError(Exception):
    """
    Base class for failures of directory-backed SDK operations.

    Subclasses carry a ``details`` mapping with structured context. Never raised directly;
    callers should ``except`` the specific subclass or this base for catch-all dispatch.
    """

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details: dict[str, Any] = dict(details) if details else {}

    def __repr__(self) -> str:
        return f"{type(self).__name__}({self.message!r}, details={self.details!r})"


class DirectoryConfigError(DirectoryError):
    """
    Directory-tied SDK method invoked without a configured ``directory_api_url``.

    ``details`` keys:

    * ``missing_field`` — the configuration field name (always ``"directory_api_url"``).
    * ``env_var`` — the environment variable that would have populated it
      (always ``"DNS_AID_SDK_DIRECTORY_API_URL"``).
    """


class DirectoryUnavailableError(DirectoryError):
    """
    Directory backend is currently unavailable (transient failure).

    Raised on connect refused, DNS failure, TLS error, network timeout, HTTP 5xx, HTTP 4xx
    other than 401/403/429, and unexpected response shapes. Callers SHOULD retry with backoff.

    ``details`` keys:

    * ``directory_url`` — the resolved base URL that was contacted.
    * ``status_code`` — HTTP status code if applicable, else ``None``.
    * ``underlying`` — class name of the underlying exception (e.g., ``"ConnectError"``,
      ``"ValidationError"``) when one wrapped this failure.
    """


class DirectoryRateLimitedError(DirectoryUnavailableError):
    """
    Directory rate-limited the call (HTTP 429).

    Inherits from :class:`DirectoryUnavailableError` so a generic ``except DirectoryUnavailableError``
    catches both rate-limit and other transient failures. Callers SHOULD honor ``Retry-After``.

    ``details`` keys (in addition to those of :class:`DirectoryUnavailableError`):

    * ``retry_after_seconds`` — value of the ``Retry-After`` header in seconds, or ``None``
      if the directory did not provide one.
    """


class DirectoryAuthError(DirectoryError):
    """
    Directory rejected the call's authentication credentials (HTTP 401 or 403).

    Distinct from :class:`DirectoryUnavailableError` because retrying without changing auth
    configuration will not succeed. Callers MUST review the auth handler.

    ``details`` keys:

    * ``directory_url`` — the resolved base URL that was contacted.
    * ``status_code`` — ``401`` or ``403``.
    * ``auth_handler_class`` — class name of the resolved AuthHandler subclass, or ``None``
      if no auth handler was configured.
    """


class CredentialProviderError(Exception):
    """
    Raised when a ``credential_provider`` callable supplied to ``AgentClient.invoke()``
    fails during credential resolution.

    The original provider exception is preserved as ``__cause__`` for debugging via Python's
    standard exception-chaining mechanism (set automatically when the SDK raises this with
    ``raise CredentialProviderError(...) from provider_exc``). Credential values from the
    provider's return dict NEVER appear in this exception's ``args``, ``str()``, ``repr()``,
    or any serialized form. Callers wishing to inspect the underlying failure must do so
    deliberately through ``__cause__``.

    This class extends :class:`Exception` directly rather than the directory-scoped
    :class:`DirectoryError` because credential resolution is conceptually distinct from
    directory operations. See ``specs/003-credential-provider-callback/contracts/
    credential_provider_error_contract.md`` for the full contract, including the per-handler
    sanitization invariants verified by automated regression tests.

    Sanitization invariants (verified by ``tests/unit/sdk/test_credential_provider_errors.py``):

    * ``str(error)`` contains only the static message template and ``agent_fqdn``.
    * ``repr(error)`` contains only the class name plus the safe ``args`` tuple.
    * ``error.args`` is a tuple of safe values only — never the credential dict, never the
      provider callable, never any partial return material.
    * Standard exception marshalling round-trips without leaking credentials.
    * ``error.__cause__`` is the original provider exception, available for deliberate
      inspection but never logged or formatted by the SDK.

    Args:
        agent_fqdn: The target agent's FQDN at the time the provider was invoked. Used for
            log correlation and incident triage. Never contains credential values.
    """

    def __init__(self, agent_fqdn: str) -> None:
        message = f"credential_provider failed for agent {agent_fqdn!r}"
        super().__init__(message)
        self.agent_fqdn: str = agent_fqdn

    def __repr__(self) -> str:
        return f"{type(self).__name__}(agent_fqdn={self.agent_fqdn!r})"
