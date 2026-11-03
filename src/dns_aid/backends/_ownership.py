# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Which existing RRs a DNS-AID write is allowed to replace.

A flat agent owner (``{name}.{domain}``) is shared:

- draft-02 §3.1.1 puts one SVCB record per agent protocol in the RRset at
  the same owner, so publishing ``mcp`` must not remove the ``a2a`` record.
- Other DNS-based discovery publishers (for example the common-params
  SVCB ``alpn="h2" key65420="a2a"``) may use the same owner.

Backends that used to replace the whole SVCB RRset on every write use
these predicates to delete only the RRs DNS-AID owns for the record being
written, and keep everything else. The functions are pure and work on the
presentation forms every backend already has (a params dict for the record
being written, the rdata text for the existing RRs) so each backend can apply them to its own API shape.
"""

from __future__ import annotations

import shlex
from collections.abc import Mapping

from dns_aid.core.bap import split_bap_token
from dns_aid.core.models import DNS_AID_KEY_MAP

_BAP_KEYS = ("bap", DNS_AID_KEY_MAP["bap"])


def _first_alpn(alpn: str | None) -> str | None:
    if not alpn:
        return None
    for token in alpn.strip().strip('"').split(","):
        token = token.strip().lower()
        if token:
            return token
    return None


def svcb_identity(params: Mapping[str, str]) -> str | None:
    """The agent protocol a ServiceMode SVCB record is published for.

    Same order as the discoverer's ``_reconcile_protocol``: the ``bap``
    token (``key65402``) when present, else the first ``alpn`` id. ``None``
    when the record carries neither.
    """
    for key in _BAP_KEYS:
        raw = params.get(key)
        if raw:
            token = split_bap_token(str(raw).strip().strip('"').split(",")[0])[0]
            if token:
                return token.strip().lower()
    return _first_alpn(params.get("alpn"))


def parse_svcb_text(rdata_text: str) -> tuple[int, dict[str, str]] | None:
    """Parse SVCB presentation text (``1 target. alpn="a2a" port=443``).

    Returns ``(priority, params)`` with lowercased keys and unquoted values,
    or ``None`` when the text cannot be parsed.
    """
    try:
        parts = shlex.split(rdata_text)
    except ValueError:
        return None
    if not parts:
        return None
    try:
        priority = int(parts[0])
    except ValueError:
        return None
    params: dict[str, str] = {}
    for part in parts[2:]:
        key, sep, value = part.partition("=")
        params[key.strip().lower()] = value if sep else ""
    return priority, params


def svcb_rr_is_replaced(
    existing_priority: int,
    existing_params: Mapping[str, str],
    new_priority: int,
    new_params: Mapping[str, str],
) -> bool:
    """Whether a DNS-AID SVCB write should replace an existing SVCB RR.

    - Writing AliasMode (priority 0): AliasMode must be alone in its RRset
      (RFC 9460 §2.4.2), so every existing RR is replaced.
    - Writing ServiceMode for a protocol: replace an existing AliasMode RR
      (it would mask the new record) and the existing ServiceMode RR for
      the same protocol (same ``bap`` token, else same first ``alpn``).
      RRs for other protocols, including foreign records such as
      ``alpn="h2" key65420="a2a"``, are kept.
    - Writing ServiceMode with no protocol identity: replace everything,
      the previous behaviour.
    """
    if new_priority == 0 or existing_priority == 0:
        return True
    new_id = svcb_identity(new_params)
    if new_id is None:
        return True
    return svcb_identity(existing_params) == new_id


def svcb_text_is_replaced(
    rdata_text: str, new_priority: int, new_params: Mapping[str, str]
) -> bool:
    """:func:`svcb_rr_is_replaced` for an existing RR in presentation text.

    Text that cannot be parsed is kept: never delete what we cannot read.
    """
    parsed = parse_svcb_text(rdata_text)
    if parsed is None:
        return False
    priority, params = parsed
    return svcb_rr_is_replaced(priority, params, new_priority, new_params)
