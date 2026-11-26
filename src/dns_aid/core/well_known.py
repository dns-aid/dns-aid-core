# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Decoding of the ``well-known`` SvcParam (key65409).

Two wire formats are in use:

- **Plain string** — the whole value is one UTF-8 suffix, e.g.
  ``agent-card.json``. Every existing DNS-AID deployment publishes this at
  the private-use key, and dns-aid itself still writes it.
- **draft-mk-dnsop-svcb-well-known-01 §2.1** — a list of entries, each a
  2-octet length in network byte order followed by that many octets of
  suffix, read until the value is exhausted. One value can carry several
  suffixes (presentation form ``well-known="agent-card.json,api-catalog"``).

A value is read as wk-01 only when the length prefixes walk it *exactly*:
every entry non-empty and the last one ending on the final octet. A plain
string can't satisfy that in practice: its first two ASCII octets read as a
length of at least 0x2020 (8224), far beyond any value the suffix validator
accepts. Anything that doesn't walk is treated as a plain string.

wk-01 §2.1 makes an undecodable value a malformed RR (RFC 9460 §2.2).
:class:`WellKnownDecodeError` reports that, so callers can log it instead
of silently using a default.
"""

from __future__ import annotations

WELL_KNOWN_KEY = 65409


class WellKnownDecodeError(ValueError):
    """The ``well-known`` value is present but cannot be decoded."""


def _walk_wk01(value: bytes) -> list[bytes] | None:
    """Split a wk-01 value into entries, or None if the prefixes don't walk it exactly."""
    entries: list[bytes] = []
    pos = 0
    while pos < len(value):
        if pos + 2 > len(value):
            return None
        length = int.from_bytes(value[pos : pos + 2], "big")
        pos += 2
        if length == 0 or pos + length > len(value):
            return None
        entries.append(value[pos : pos + length])
        pos += length
    return entries or None


def decode_well_known(value: bytes) -> list[str]:
    """Decode a raw ``well-known`` value into its suffixes.

    Raises:
        WellKnownDecodeError: The value is empty or not valid UTF-8.
    """
    if not value:
        raise WellKnownDecodeError("empty well-known value")
    entries = _walk_wk01(value) or [value]
    try:
        return [entry.decode("utf-8", "strict") for entry in entries]
    except UnicodeDecodeError as exc:
        raise WellKnownDecodeError(f"well-known value is not UTF-8: {exc}") from exc


def read_well_known(rdata: object) -> list[str] | None:
    """The ``well-known`` suffixes of an SVCB rdata, or None when the param is absent.

    Raises:
        WellKnownDecodeError: The param is present but cannot be decoded.
    """
    params = getattr(rdata, "params", None) or {}
    try:
        param = params.get(WELL_KNOWN_KEY)
    except (AttributeError, TypeError):
        return None
    if param is None:
        return None
    value = getattr(param, "value", param)
    if isinstance(value, str):
        value = value.encode("utf-8")
    if not isinstance(value, (bytes, bytearray)):
        return None
    return decode_well_known(bytes(value))
