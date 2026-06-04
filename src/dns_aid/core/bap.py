# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Single source of truth for the draft-02 ``bap`` (Bulk Agent Protocol)
SvcParamKey value shape.

draft-02 §5.1 (experimental, §FutureWork) defines a single versioned
agent-protocol identifier per SVCB record. Two value forms are
accepted, matching the draft's own examples:

- **Bare** — ``mcp`` / ``a2a`` (unversioned)
- **Versioned** — ``mcp=1.0`` / ``a2a=1.1`` (protocol name, ``=``,
  dotted version)

Multi-protocol agents publish multiple SVCB records at the same flat
owner, each with its own ``alpn`` and (optionally) ``bap``. ``bap``
is NOT a comma-separated list of protocols.

This module centralizes:

- :data:`BAP_VALUE_PATTERN` — the wire-format character constraint
- :func:`validate_bap` — model field-validator
- :func:`normalize_bap` — coerce legacy / forgiving inputs into the
  canonical scalar shape
- :func:`split_bap_token` — extract the protocol token before any
  ``=`` so consumers can reconcile against ``Protocol`` enums
"""

from __future__ import annotations

import re
from typing import Final

import structlog

logger = structlog.get_logger(__name__)

# Wire-format constraint. Protocol name lowercase alnum starting with
# a letter; optional ``=`` followed by a version token. The version
# token allows the dotted shape (e.g. ``1.0``, ``1.1.0``,
# ``2026-01-15``) but excludes quotes, spaces, commas, and any other
# character that would let a forged value break out of the SVCB
# SvcParam quoting and inject sibling keys.
#
# Without this validator the value is emitted verbatim into
# ``key="<value>"`` by the backend formatters, so a forged value with a
# quote could break out of the SvcParam quoting and inject sibling keys
# — a server-side parameter-injection on the publish path.
_PROTOCOL_PATTERN = r"[a-z][a-z0-9]*"
_VERSION_PATTERN = r"[A-Za-z0-9][A-Za-z0-9._\-]{0,63}"
BAP_VALUE_PATTERN: Final = re.compile(rf"^{_PROTOCOL_PATTERN}(={_VERSION_PATTERN})?$")

_BAP_MAX_LEN = 128


def validate_bap(value: str) -> str:
    """Validate a single ``bap`` SvcParamKey value.

    Used as a Pydantic field validator on both ``SvcbRecord.bap`` and
    ``AgentRecord.bap``. Enforces the canonical scalar shape so:

    - Injection via SVCB quoting (e.g. ``mcp" key65500="x``) is
      rejected at the type boundary.
    - Comma-separated legacy values are rejected (caller should run
      ``normalize_bap`` first if accepting legacy input).
    - Whitespace, control characters, and other URL/quote special
      characters are rejected.

    Args:
        value: The bap value to validate. Empty / None should be
            handled by the caller before reaching this function.

    Returns:
        The validated value unchanged.

    Raises:
        ValueError: When the value violates the wire-format rule.
    """
    if not isinstance(value, str):
        raise ValueError(f"bap must be a string, got {type(value).__name__}")
    if not value:
        raise ValueError("bap must be a non-empty string (or None)")
    if len(value) > _BAP_MAX_LEN:
        raise ValueError(f"bap value exceeds {_BAP_MAX_LEN} characters")
    if not BAP_VALUE_PATTERN.match(value):
        raise ValueError(
            f"bap value {value!r} does not match the canonical form. "
            "Allowed: a lowercase protocol token (e.g. 'mcp', 'a2a') "
            "optionally followed by '=<version>' (e.g. 'mcp=1.0'). "
            "Reject quotes, spaces, commas, control chars, and any "
            "other character that could break SVCB SvcParam quoting."
        )
    return value


def normalize_bap(value: str | list[str] | None) -> str | None:
    """Coerce forgiving input into the canonical scalar shape.

    Accepts:

    - ``None`` → ``None``
    - ``""`` / whitespace-only string → ``None``
    - ``"mcp"`` / ``"mcp=1.0"`` → unchanged after strip
    - ``"mcp,a2a"`` (legacy comma-list) → first non-empty token,
      warning logged because later tokens are dropped
    - ``["mcp", "a2a"]`` (legacy list) → first non-empty token,
      warning logged
    - ``[]`` / list of empties → ``None``

    Does NOT enforce :func:`validate_bap` — callers should run it
    after normalization (or rely on the model's field validator).

    Args:
        value: A string, list of strings, or None. Other types are
            silently treated as None to keep the public API forgiving.

    Returns:
        The normalized scalar (or None when no usable value exists).
    """
    if value is None:
        return None

    # Coerce a list into a scalar by taking the first non-empty entry.
    # Empty list / list of empties → None.
    if isinstance(value, list):
        tokens = [str(v).strip() for v in value if v is not None]
        non_empty = [t for t in tokens if t]
        if not non_empty:
            return None
        if len(non_empty) > 1:
            logger.warning(
                "bap list input collapsed to first token — multi-protocol "
                "agents should publish multiple SVCB records, not a list "
                "on one record",
                input=value,
                kept=non_empty[0],
                dropped=non_empty[1:],
                warning_class="dns_aid.bap_list_collapsed",
            )
        return non_empty[0]

    # Scalar string. Strip whitespace, drop empties.
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if not stripped:
        return None

    # Legacy comma-list ("mcp,a2a") → first non-empty token.
    if "," in stripped:
        tokens = [t.strip() for t in stripped.split(",")]
        non_empty = [t for t in tokens if t]
        if not non_empty:
            return None
        if len(non_empty) > 1:
            logger.warning(
                "bap comma-list input collapsed to first token — "
                "multi-protocol agents should publish multiple SVCB "
                "records, not a comma-separated list on one record",
                input=value,
                kept=non_empty[0],
                dropped=non_empty[1:],
                warning_class="dns_aid.bap_comma_list_collapsed",
            )
        return non_empty[0]

    return stripped


def split_bap_token(value: str | None) -> tuple[str | None, str | None]:
    """Split a bap value into ``(protocol_token, version)``.

    ``mcp`` → ``("mcp", None)``
    ``mcp=1.0`` → ``("mcp", "1.0")``
    ``None`` / unparseable → ``(None, None)``

    Used by the discoverer's protocol reconciliation: the ``Protocol``
    enum holds bare tokens (``mcp``, ``a2a``), so consumers need to
    extract just the token before checking membership.
    """
    if not value:
        return None, None
    stripped = value.strip()
    if not stripped:
        return None, None
    if "=" not in stripped:
        return stripped, None
    proto, _, ver = stripped.partition("=")
    proto = proto.strip()
    ver = ver.strip()
    return (proto or None), (ver or None)
