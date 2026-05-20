# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Auth handler registry and factory function."""

from __future__ import annotations

from collections.abc import Callable

import structlog

from dns_aid.sdk.auth.base import AuthHandler
from dns_aid.sdk.auth.simple import ApiKeyAuthHandler, BearerAuthHandler, NoopAuthHandler

logger = structlog.get_logger(__name__)


def resolve_auth_handler(
    auth_type: str,
    auth_config: dict | None = None,
    credentials: dict | None = None,
) -> AuthHandler:
    """Resolve an AuthHandler from discovery metadata and caller credentials.

    Args:
        auth_type: The ``auth_type`` from discovery (e.g., ``"bearer"``,
            ``"oauth2"``).  Also accepts ZTAIP canonical forms
            (``"bearer_token"``, ``"oauth2_client_credentials"``).
        auth_config: Authentication configuration from the agent's
            ``.well-known/agent.json`` ``AuthSpec`` (header_name,
            oauth_discovery, etc.).
        credentials: Caller-supplied secrets (tokens, client_id/secret,
            private keys).  Never stored in discovery metadata.

    Returns:
        An AuthHandler ready to ``apply()`` to outgoing requests.

    Raises:
        ValueError: If *auth_type* is unknown or required credentials
            are missing.
    """
    auth_config = auth_config or {}
    credentials = credentials or {}

    # Normalize ZTAIP canonical names
    normalized = _ZTAIP_ALIASES.get(auth_type, auth_type)

    factory = _REGISTRY.get(normalized)
    if factory is None:
        raise ValueError(
            f"Unknown auth_type: {auth_type!r}. Supported: {', '.join(sorted(_REGISTRY.keys()))}"
        )

    return factory(auth_config, credentials)


def _build_noop(config: dict, credentials: dict) -> AuthHandler:
    return NoopAuthHandler()


def _build_api_key(config: dict, credentials: dict) -> AuthHandler:
    api_key = credentials.get("api_key")
    if not api_key:
        raise ValueError("ApiKeyAuthHandler requires 'api_key' in credentials")
    return ApiKeyAuthHandler(
        api_key=api_key,
        header_name=config.get("header_name", "X-API-Key"),
        location=config.get("location", "header"),
        query_param=config.get("query_param", "api_key"),
    )


def _build_bearer(config: dict, credentials: dict) -> AuthHandler:
    token = credentials.get("token")
    if not token:
        raise ValueError("BearerAuthHandler requires 'token' in credentials")
    return BearerAuthHandler(
        token=token,
        header_name=config.get("header_name", "Authorization"),
    )


def _build_oauth2(config: dict, credentials: dict) -> AuthHandler:
    from dns_aid.sdk.auth.oauth2 import OAuth2AuthHandler

    client_id = credentials.get("client_id")
    client_secret = credentials.get("client_secret")
    if not client_id or not client_secret:
        raise ValueError(
            "OAuth2AuthHandler requires 'client_id' and 'client_secret' in credentials"
        )
    return OAuth2AuthHandler(
        client_id=client_id,
        client_secret=client_secret,
        token_url=config.get("token_url") or credentials.get("token_url"),
        discovery_url=config.get("oauth_discovery"),
        scopes=config.get("scopes") or credentials.get("scopes"),
    )


def _build_http_msg_sig(config: dict, credentials: dict) -> AuthHandler:
    from dns_aid.sdk.auth.http_msg_sig import HttpMsgSigAuthHandler

    private_key_pem = credentials.get("private_key_pem")
    key_id = credentials.get("key_id")
    if not private_key_pem or not key_id:
        raise ValueError(
            "HttpMsgSigAuthHandler requires 'private_key_pem' and 'key_id' in credentials"
        )
    return HttpMsgSigAuthHandler(
        private_key_pem=private_key_pem,
        key_id=key_id,
        algorithm=credentials.get("algorithm", "ed25519"),
    )


def _build_sigv4(config: dict, credentials: dict) -> AuthHandler:
    """Build a SigV4AuthHandler from auth_config + credentials.

    The credentials dict may contain three additional SigV4-specific keys
    that enable the explicit-credentials path (see feature 003 — the
    ``credential_provider`` callback returns these from ``sts.assume_role()``):

    * ``access_key`` — AWS Access Key ID
    * ``secret_key`` — AWS Secret Access Key
    * ``session_token`` — Optional STS session token

    When the credentials dict omits these keys, the handler falls back to
    the boto3 default credential chain (env vars → ``~/.aws/credentials`` →
    IAM role). This is the existing backward-compatible behavior.
    """
    from dns_aid.sdk.auth.sigv4 import SigV4AuthHandler

    region = config.get("region") or credentials.get("region")
    if not region:
        raise ValueError("SigV4AuthHandler requires 'region' in auth_config or credentials")
    return SigV4AuthHandler(
        region=region,
        service=config.get("service", "vpc-lattice-svcs"),
        profile_name=credentials.get("profile_name"),
        access_key=credentials.get("access_key"),
        secret_key=credentials.get("secret_key"),
        session_token=credentials.get("session_token"),
    )


# Auth type → factory function
_REGISTRY: dict[str, Callable[[dict, dict], AuthHandler]] = {
    "none": _build_noop,
    "api_key": _build_api_key,
    "bearer": _build_bearer,
    "oauth2": _build_oauth2,
    "http_msg_sig": _build_http_msg_sig,
    "sigv4": _build_sigv4,
}

# ZTAIP canonical names → our enum values
_ZTAIP_ALIASES: dict[str, str] = {
    "bearer_token": "bearer",  # nosec B105 — protocol identifier, not a password
    "oauth2_client_credentials": "oauth2",
}
