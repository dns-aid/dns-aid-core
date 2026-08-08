# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Multi-address fallback for SSRF-pinned dials.

Pinning the connection to the address the guard vetted closed a real TOCTOU
window (validate the name, then let httpx resolve it a second time). But
recording only the FIRST resolved address silently removed the multi-address
fallback the HTTP stack used to provide.

``getaddrinfo(AF_UNSPEC)`` does not apply ``AI_ADDRCONFIG``, so a dual-stack
name returns its AAAA first even on a client with no IPv6 route. Pinning that
one literal turned a routine deployment into a hard failure: fetching a JWKS
from an IPv4-only container failed on the v6 address instead of falling through
to the A record, and every agent in the zone came back
``signature_status='no_key'``.

Every address still passes the same range check, so trying them in turn is
exactly as safe as trying the first -- one bad address in the set still fails
the whole URL.
"""

import socket
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from dns_aid.utils import url_safety
from dns_aid.utils.url_safety import (
    UnsafeURLError,
    validate_fetch_url,
    vetted_ip_for,
    vetted_ips_for,
)

V6 = "2606:4700::6810:85e5"
V4 = "104.16.133.229"
URL = "https://dns-aid.example.com/.well-known/dns-aid-jwks.json"


def _addrinfo(*addresses):
    """getaddrinfo output, AAAA first -- the ordering that caused the failure."""
    out = []
    for addr in addresses:
        family = socket.AF_INET6 if ":" in addr else socket.AF_INET
        sockaddr = (addr, 0, 0, 0) if family == socket.AF_INET6 else (addr, 0)
        out.append((family, socket.SOCK_STREAM, 6, "", sockaddr))
    return out


@pytest.fixture(autouse=True)
def _clear_pins():
    url_safety._last_vetted_ip.clear()
    yield
    url_safety._last_vetted_ip.clear()


class TestEveryVettedAddressIsRecorded:
    def test_all_addresses_are_kept_in_resolution_order(self):
        with patch("socket.getaddrinfo", return_value=_addrinfo(V6, V4)):
            validate_fetch_url(URL)

        assert vetted_ips_for(URL) == [V6, V4]

    def test_the_first_is_still_what_the_single_address_reader_returns(self):
        """Existing callers keep the behaviour they had."""
        with patch("socket.getaddrinfo", return_value=_addrinfo(V6, V4)):
            validate_fetch_url(URL)

        assert vetted_ip_for(URL) == V6

    def test_duplicates_are_collapsed(self):
        with patch("socket.getaddrinfo", return_value=_addrinfo(V4, V4, V6)):
            validate_fetch_url(URL)

        assert vetted_ips_for(URL) == [V4, V6]

    def test_one_bad_address_still_fails_the_whole_url(self):
        """The fallback must not become a way to reach an internal address.

        A hostile authoritative server answering with one public and one
        loopback address must not have the public one 'win'.
        """
        with patch("socket.getaddrinfo", return_value=_addrinfo(V4, "127.0.0.1")):
            with pytest.raises(UnsafeURLError):
                validate_fetch_url(URL)

    def test_an_unresolvable_url_records_nothing(self):
        assert vetted_ips_for("https://never-validated.example/") == []


class TestSafeFetchFallsThroughToTheNextAddress:
    @pytest.mark.asyncio
    async def test_an_unroutable_first_address_falls_through(self):
        """The reported failure: AAAA first, no IPv6 route, A record healthy."""
        with patch("socket.getaddrinfo", return_value=_addrinfo(V6, V4)):
            validate_fetch_url(URL)

        attempted: list[str] = []

        def _client(**kwargs):
            client = MagicMock()

            def _stream(method, request_url, **kw):
                attempted.append(request_url)
                if V6 in request_url:
                    raise httpx.ConnectError("Network is unreachable")
                response = MagicMock()
                response.status_code = 200
                response.headers = {}

                async def _iter(chunk_size=8192):
                    yield b'{"keys":[]}'

                response.aiter_bytes = _iter
                ctx = MagicMock()
                ctx.__aenter__ = AsyncMock(return_value=response)
                ctx.__aexit__ = AsyncMock(return_value=False)
                return ctx

            client.stream = _stream
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            return client

        with patch("httpx.AsyncClient", side_effect=_client):
            body = await url_safety.safe_fetch_bytes(URL, max_bytes=65536)

        assert body == b'{"keys":[]}'
        assert len(attempted) == 2, "the second vetted address was never tried"
        assert V6 in attempted[0] and V4 in attempted[1]

    @pytest.mark.asyncio
    async def test_a_non_transport_answer_is_not_retried(self):
        """A 404 is the server's real answer; retrying a sibling address just
        repeats it more slowly."""
        with patch("socket.getaddrinfo", return_value=_addrinfo(V6, V4)):
            validate_fetch_url(URL)

        attempted: list[str] = []

        def _client(**kwargs):
            client = MagicMock()

            def _stream(method, request_url, **kw):
                attempted.append(request_url)
                response = MagicMock()
                response.status_code = 404
                response.headers = {}
                ctx = MagicMock()
                ctx.__aenter__ = AsyncMock(return_value=response)
                ctx.__aexit__ = AsyncMock(return_value=False)
                return ctx

            client.stream = _stream
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            return client

        with patch("httpx.AsyncClient", side_effect=_client):
            body = await url_safety.safe_fetch_bytes(URL, max_bytes=65536)

        assert body is None
        assert len(attempted) == 1

    @pytest.mark.asyncio
    async def test_the_last_address_raises_rather_than_reporting_success(self):
        with patch("socket.getaddrinfo", return_value=_addrinfo(V6, V4)):
            validate_fetch_url(URL)

        def _client(**kwargs):
            client = MagicMock()

            def _stream(method, request_url, **kw):
                raise httpx.ConnectError("Network is unreachable")

            client.stream = _stream
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            return client

        with patch("httpx.AsyncClient", side_effect=_client):
            with pytest.raises(httpx.ConnectError):
                await url_safety.safe_fetch_bytes(URL, max_bytes=65536)


class TestDaneDialFallsThrough:
    @pytest.mark.asyncio
    async def test_peer_cert_retries_the_next_vetted_address(self):
        from dns_aid.core.validator import _fetch_peer_cert

        attempted: list[str] = []

        async def _open(host, port, **kwargs):
            attempted.append(host)
            if host == V6:
                raise OSError("Network is unreachable")
            ssl_object = MagicMock()
            ssl_object.getpeercert.return_value = b"DER"
            writer = MagicMock()
            writer.get_extra_info.return_value = ssl_object
            writer.wait_closed = AsyncMock()
            return MagicMock(), writer

        with (
            patch(
                "dns_aid.core.validator._guarded_dial_hosts",
                new=AsyncMock(return_value=[V6, V4]),
            ),
            patch("dns_aid.core.validator.asyncio.open_connection", new=_open),
        ):
            der = await _fetch_peer_cert("mcp.example.com", 443, pkix=False)

        assert der == b"DER"
        assert attempted == [V6, V4]

    @pytest.mark.asyncio
    async def test_the_last_address_still_raises(self):
        from dns_aid.core.validator import _fetch_peer_cert

        async def _open(host, port, **kwargs):
            raise OSError("Network is unreachable")

        with (
            patch(
                "dns_aid.core.validator._guarded_dial_hosts",
                new=AsyncMock(return_value=[V6, V4]),
            ),
            patch("dns_aid.core.validator.asyncio.open_connection", new=_open),
        ):
            with pytest.raises(OSError):
                await _fetch_peer_cert("mcp.example.com", 443, pkix=False)
