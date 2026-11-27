# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Which recursive resolver DNS-AID lookups use.

By default every lookup goes to the system resolver (``/etc/resolv.conf``),
so the AD bit that discovery and ``verify`` report is whatever that
resolver says. A consumer that relies on the AD bit needs a trusted path
to a validating resolver (draft-02 §6.4, RFC 4035 §4.9.3), which is not
always the system one (a laptop on venue or hotel Wi-Fi, a container
behind an embedded DNS proxy).

:func:`use_nameservers` scopes an override to one ``discover()`` /
``verify()`` call. It is a context variable, so it follows the call into
the tasks it gathers and does not leak to concurrent callers.

Accepted nameserver forms:

- an IP address: ``10.53.0.3``, ``2001:db8::53``
- an IP address with a port: ``10.53.0.3#5353``, ``[2001:db8::53]:5353``
  or ``10.53.0.3:5353``
- a DNS-over-HTTPS URL: ``https://dns.example/dns-query``
"""

from __future__ import annotations

import functools
import ipaddress
from collections.abc import Awaitable, Callable, Iterator, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from typing import ParamSpec, TypeVar

import dns.asyncresolver
import dns.nameserver

_P = ParamSpec("_P")
_R = TypeVar("_R")

_NAMESERVERS: ContextVar[tuple[dns.nameserver.Nameserver, ...] | None] = ContextVar(
    "dns_aid_nameservers", default=None
)


def _port(value: str, text: str) -> int:
    try:
        return int(text)
    except ValueError:
        raise ValueError(f"invalid nameserver {value!r}: bad port {text!r}") from None


def _split_port(value: str) -> tuple[str, int]:
    if value.startswith("["):
        host, sep, rest = value[1:].partition("]")
        if not sep:
            raise ValueError(f"invalid nameserver {value!r}: missing ']'")
        if rest.startswith(":") or rest.startswith("#"):
            return host, _port(value, rest[1:])
        if rest:
            raise ValueError(f"invalid nameserver {value!r}")
        return host, 53
    if "#" in value:
        host, _, port = value.partition("#")
        return host, _port(value, port)
    if value.count(":") == 1:
        host, _, port = value.partition(":")
        return host, _port(value, port)
    return value, 53


def parse_nameserver(value: str) -> dns.nameserver.Nameserver:
    """Parse one nameserver string. Raises ``ValueError`` on bad input."""
    text = value.strip()
    if not text:
        raise ValueError("empty nameserver")
    if text.lower().startswith("https://"):
        return dns.nameserver.DoHNameserver(text)
    host, port = _split_port(text)
    try:
        address = str(ipaddress.ip_address(host))
    except ValueError as exc:
        raise ValueError(
            f"invalid nameserver {value!r}: expected an IP address, IP#port or https:// URL"
        ) from exc
    if not 0 < port < 65536:
        raise ValueError(f"invalid nameserver {value!r}: port out of range")
    return dns.nameserver.Do53Nameserver(address, port)


def parse_nameservers(values: str | Sequence[str] | None) -> list[dns.nameserver.Nameserver]:
    """Parse a nameserver string, a comma-separated list, or a sequence."""
    if values is None:
        return []
    items = [values] if isinstance(values, str) else list(values)
    parsed: list[dns.nameserver.Nameserver] = []
    for item in items:
        for part in item.split(","):
            if part.strip():
                parsed.append(parse_nameserver(part))
    return parsed


@contextmanager
def use_nameservers(values: str | Sequence[str] | None) -> Iterator[None]:
    """Route DNS-AID lookups made inside the block to ``values``.

    ``None`` or an empty list keeps the current setting (the system
    resolver unless an outer block set one).
    """
    parsed = parse_nameservers(values)
    if not parsed:
        yield
        return
    token = _NAMESERVERS.set(tuple(parsed))
    try:
        yield
    finally:
        _NAMESERVERS.reset(token)


def current_nameservers() -> list[str]:
    """The override in effect, as text (``[]`` means the system resolver)."""
    override = _NAMESERVERS.get()
    return [_display(ns) for ns in override] if override else []


def _display(ns: dns.nameserver.Nameserver) -> str:
    if isinstance(ns, dns.nameserver.Do53Nameserver):
        address = ns.answer_nameserver()
        port = ns.answer_port()
        return address if port == 53 else f"{address}#{port}"
    return str(ns)


def make_resolver() -> dns.asyncresolver.Resolver:
    """An async resolver honouring the :func:`use_nameservers` override."""
    override = _NAMESERVERS.get()
    if not override:
        return dns.asyncresolver.Resolver()
    # configure=False: do not read /etc/resolv.conf (it may be absent or
    # point at the resolver the caller is trying to avoid).
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = list(override)
    return resolver


def scoped_nameservers(
    fn: Callable[_P, Awaitable[_R]],
) -> Callable[_P, Awaitable[_R]]:
    """Decorate an async entry point that takes a ``nameservers=`` keyword.

    The call runs inside :func:`use_nameservers` for that keyword, so every
    lookup it makes (including in tasks it gathers) uses those resolvers.
    """

    @functools.wraps(fn)
    async def wrapper(*args: _P.args, **kwargs: _P.kwargs) -> _R:
        with use_nameservers(kwargs.get("nameservers")):  # type: ignore[arg-type]
            return await fn(*args, **kwargs)

    return wrapper
