# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for ARD catalog DNS pointer publish + resolve (spec 007 dual-A)."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import dns.resolver
import pytest

from dns_aid.core.catalog_pointer import (
    CATALOG_POINTER_LABELS,
    DEFAULT_CATALOG_FILENAME,
    publish_catalog_pointer,
    resolve_catalog_pointer,
)


def _svcb_rdata(target: str, priority: int = 1, wellknown: bytes | None = None):
    """A mock SVCB rdata with a target and optional well-known (key65409) param."""
    rdata = MagicMock()
    rdata.priority = priority
    rdata.target = MagicMock()
    rdata.target.__str__ = lambda self: target  # type: ignore[assignment]
    if wellknown is not None:
        param = MagicMock()
        param.value = wellknown
        rdata.params = {65409: param}
    else:
        rdata.params = {}
    return rdata


def _resolver_returning(mapping: dict):
    """Build a mock async resolver: fqdn -> list[rdata] | NXDOMAIN/NoAnswer."""

    async def _resolve(fqdn, rdtype):
        answer = mapping.get(fqdn)
        if answer is None:
            raise dns.resolver.NXDOMAIN()
        if answer == "noanswer":
            raise dns.resolver.NoAnswer()
        return answer

    resolver = MagicMock()
    resolver.resolve = AsyncMock(side_effect=_resolve)
    return resolver


class TestResolveCatalogPointer:
    @pytest.fixture(autouse=True)
    def _bypass_ssrf(self):
        # These tests exercise resolution logic with unresolvable mock hosts;
        # bypass the SSRF/DNS guard here (its own behavior is tested below).
        with patch("dns_aid.core.catalog_pointer.validate_fetch_url", side_effect=lambda u: u):
            yield

    @pytest.mark.asyncio
    async def test_resolves_catalog_label(self):
        mapping = {"_catalog._agents.acme.com": [_svcb_rdata("ard.acme.com.")]}
        with patch(
            "dns_aid.core.catalog_pointer.dns.asyncresolver.Resolver",
            return_value=_resolver_returning(mapping),
        ):
            url = await resolve_catalog_pointer("acme.com")
        assert url == "https://ard.acme.com/.well-known/ai-catalog.json"

    @pytest.mark.asyncio
    async def test_catalog_label_precedes_index(self):
        # Both labels published to different hosts — _catalog wins.
        mapping = {
            "_catalog._agents.acme.com": [_svcb_rdata("cat.acme.com.")],
            "_index._agents.acme.com": [_svcb_rdata("idx.acme.com.")],
        }
        with patch(
            "dns_aid.core.catalog_pointer.dns.asyncresolver.Resolver",
            return_value=_resolver_returning(mapping),
        ):
            url = await resolve_catalog_pointer("acme.com")
        assert "cat.acme.com" in url

    @pytest.mark.asyncio
    async def test_falls_back_to_index_label(self):
        mapping = {"_index._agents.acme.com": [_svcb_rdata("idx.acme.com.")]}
        with patch(
            "dns_aid.core.catalog_pointer.dns.asyncresolver.Resolver",
            return_value=_resolver_returning(mapping),
        ):
            url = await resolve_catalog_pointer("acme.com")
        assert url == "https://idx.acme.com/.well-known/ai-catalog.json"

    @pytest.mark.asyncio
    async def test_no_pointer_returns_none(self):
        with patch(
            "dns_aid.core.catalog_pointer.dns.asyncresolver.Resolver",
            return_value=_resolver_returning({}),
        ):
            assert await resolve_catalog_pointer("acme.com") is None

    @pytest.mark.asyncio
    async def test_wellknown_override(self):
        mapping = {
            "_catalog._agents.acme.com": [_svcb_rdata("ard.acme.com.", wellknown=b"catalog2.json")]
        }
        with patch(
            "dns_aid.core.catalog_pointer.dns.asyncresolver.Resolver",
            return_value=_resolver_returning(mapping),
        ):
            url = await resolve_catalog_pointer("acme.com")
        assert url == "https://ard.acme.com/.well-known/catalog2.json"

    @pytest.mark.asyncio
    async def test_malicious_wellknown_path_ignored(self):
        # Path traversal / separators in the override are rejected → default used.
        for evil in (b"../../etc/passwd", b"a/b.json", b""):
            mapping = {"_catalog._agents.acme.com": [_svcb_rdata("ard.acme.com.", wellknown=evil)]}
            with patch(
                "dns_aid.core.catalog_pointer.dns.asyncresolver.Resolver",
                return_value=_resolver_returning(mapping),
            ):
                url = await resolve_catalog_pointer("acme.com")
            assert url == f"https://ard.acme.com/.well-known/{DEFAULT_CATALOG_FILENAME}"

    @pytest.mark.asyncio
    async def test_aliasmode_skipped(self):
        mapping = {"_catalog._agents.acme.com": [_svcb_rdata("alias.acme.com.", priority=0)]}
        with patch(
            "dns_aid.core.catalog_pointer.dns.asyncresolver.Resolver",
            return_value=_resolver_returning(mapping),
        ):
            assert await resolve_catalog_pointer("acme.com") is None

    @pytest.mark.asyncio
    async def test_resolution_error_never_raises(self):
        resolver = MagicMock()
        resolver.resolve = AsyncMock(side_effect=RuntimeError("dns exploded"))
        with patch(
            "dns_aid.core.catalog_pointer.dns.asyncresolver.Resolver", return_value=resolver
        ):
            assert await resolve_catalog_pointer("acme.com") is None


class TestResolveSsrf:
    """A pointer to a private/internal host must be rejected (SSRF guard)."""

    @pytest.mark.asyncio
    async def test_private_ip_target_rejected(self):
        from dns_aid.utils.url_safety import UnsafeURLError

        mapping = {"_catalog._agents.evil.com": [_svcb_rdata("internal.evil.com.")]}
        with (
            patch(
                "dns_aid.core.catalog_pointer.dns.asyncresolver.Resolver",
                return_value=_resolver_returning(mapping),
            ),
            patch(
                "dns_aid.core.catalog_pointer.validate_fetch_url",
                side_effect=UnsafeURLError("resolves to non-public IP 169.254.169.254"),
            ),
        ):
            # Unsafe pointer skipped → falls through (no _index either) → None
            assert await resolve_catalog_pointer("evil.com") is None

    @pytest.mark.asyncio
    async def test_record_flood_capped(self):
        # adv-3: a large SVCB RRset must not fan out into unbounded validation.
        from dns_aid.core.catalog_pointer import _MAX_POINTER_RECORDS

        flood = [_svcb_rdata(f"h{i}.evil.com.") for i in range(_MAX_POINTER_RECORDS + 20)]
        mapping = {"_catalog._agents.evil.com": flood}
        calls = {"n": 0}

        def _count(url):
            calls["n"] += 1
            raise __import__(
                "dns_aid.utils.url_safety", fromlist=["UnsafeURLError"]
            ).UnsafeURLError("blocked")

        with (
            patch(
                "dns_aid.core.catalog_pointer.dns.asyncresolver.Resolver",
                return_value=_resolver_returning(mapping),
            ),
            patch("dns_aid.core.catalog_pointer.validate_fetch_url", side_effect=_count),
        ):
            assert await resolve_catalog_pointer("evil.com") is None
        assert calls["n"] <= _MAX_POINTER_RECORDS

    @pytest.mark.asyncio
    async def test_unsafe_catalog_falls_through_to_safe_index(self):
        from dns_aid.utils.url_safety import UnsafeURLError

        mapping = {
            "_catalog._agents.acme.com": [_svcb_rdata("169.254.169.254.")],  # unsafe
            "_index._agents.acme.com": [_svcb_rdata("idx.acme.com.")],  # safe
        }

        def _guard(url):
            if "169.254" in url:
                raise UnsafeURLError("non-public IP")
            return url

        with (
            patch(
                "dns_aid.core.catalog_pointer.dns.asyncresolver.Resolver",
                return_value=_resolver_returning(mapping),
            ),
            patch("dns_aid.core.catalog_pointer.validate_fetch_url", side_effect=_guard),
        ):
            url = await resolve_catalog_pointer("acme.com")
        assert url == "https://idx.acme.com/.well-known/ai-catalog.json"


class TestPublishCatalogPointer:
    def _mock_backend(self):
        backend = MagicMock()
        backend.zone_exists = AsyncMock(return_value=True)
        backend.create_svcb_record = AsyncMock(
            side_effect=lambda **kw: f"{kw['name']}.{kw['zone']}"
        )
        backend.get_record = AsyncMock(return_value=None)  # no existing _index by default
        return backend

    @pytest.mark.asyncio
    async def test_dual_label_publish(self):
        backend = self._mock_backend()
        written = await publish_catalog_pointer("acme.com", "ard.acme.com", backend=backend)
        assert written == ["_catalog._agents.acme.com", "_index._agents.acme.com"]
        assert backend.create_svcb_record.await_count == 2
        # Correct owner names, ServiceMode, trailing-dot target
        calls = {c.kwargs["name"]: c.kwargs for c in backend.create_svcb_record.await_args_list}
        assert set(calls) == set(CATALOG_POINTER_LABELS)
        for kw in calls.values():
            assert kw["priority"] == 1
            assert kw["target"] == "ard.acme.com."
            assert kw["params"]["alpn"] == "h2"
            assert kw["params"]["port"] == "443"
            assert "key65409" not in kw["params"]  # default filename → no override param

    @pytest.mark.asyncio
    async def test_catalog_only_label(self):
        backend = self._mock_backend()
        written = await publish_catalog_pointer(
            "acme.com", "ard.acme.com", labels=("_catalog._agents",), backend=backend
        )
        assert written == ["_catalog._agents.acme.com"]
        assert backend.create_svcb_record.await_count == 1

    @pytest.mark.asyncio
    async def test_custom_filename_carried_in_param(self):
        backend = self._mock_backend()
        await publish_catalog_pointer(
            "acme.com", "ard.acme.com", filename="catalog2.json", backend=backend
        )
        kw = backend.create_svcb_record.await_args_list[0].kwargs
        assert kw["params"]["key65409"] == "catalog2.json"

    @pytest.mark.asyncio
    async def test_address_hints_added(self):
        backend = self._mock_backend()
        await publish_catalog_pointer(
            "acme.com",
            "catalogue.acme.com",
            ipv4_hint="1.2.3.4",
            ipv6_hint="2001:db8::1",
            labels=("_catalog._agents",),
            backend=backend,
        )
        params = backend.create_svcb_record.await_args_list[0].kwargs["params"]
        assert params["ipv4hint"] == "1.2.3.4"
        assert params["ipv6hint"] == "2001:db8::1"

    @pytest.mark.asyncio
    async def test_malformed_address_hint_rejected(self):
        backend = self._mock_backend()
        with pytest.raises(ValueError):
            await publish_catalog_pointer(
                "acme.com", "catalogue.acme.com", ipv4_hint="not-an-ip", backend=backend
            )
        # a v6 address in the v4 slot is also rejected
        with pytest.raises(ValueError, match="not an IPv4"):
            await publish_catalog_pointer(
                "acme.com", "catalogue.acme.com", ipv4_hint="2001:db8::1", backend=backend
            )
        backend.create_svcb_record.assert_not_called()

    @pytest.mark.asyncio
    async def test_alpn_quote_breakout_rejected(self):
        # adv-4: an alpn value that could break SVCB param quoting is rejected.
        backend = self._mock_backend()
        with pytest.raises(Exception):  # noqa: B017 — ValidationError from validate_svcparam_value
            await publish_catalog_pointer(
                "acme.com", "ard.acme.com", alpn='h2" ipv4hint="1.2.3.4', backend=backend
            )
        backend.create_svcb_record.assert_not_called()

    @pytest.mark.asyncio
    async def test_index_clobber_prevented(self):
        # adv-5: existing _index._agents SVCB with a DIFFERENT target is preserved.
        backend = self._mock_backend()
        backend.get_record = AsyncMock(
            return_value={"values": ['1 other-index.acme.com. alpn="h2" port="443"']}
        )
        written = await publish_catalog_pointer("acme.com", "ard.acme.com", backend=backend)
        # _catalog written, _index skipped (would clobber)
        assert written == ["_catalog._agents.acme.com"]
        names = [c.kwargs["name"] for c in backend.create_svcb_record.await_args_list]
        assert names == ["_catalog._agents"]

    @pytest.mark.asyncio
    async def test_index_same_target_not_skipped(self):
        # If the existing _index points at the SAME host, dual publish proceeds.
        backend = self._mock_backend()
        backend.get_record = AsyncMock(
            return_value={"values": ['1 ard.acme.com. alpn="h2" port="443"']}
        )
        written = await publish_catalog_pointer("acme.com", "ard.acme.com", backend=backend)
        assert written == ["_catalog._agents.acme.com", "_index._agents.acme.com"]

    @pytest.mark.asyncio
    async def test_force_index_overrides_clobber_guard(self):
        backend = self._mock_backend()
        backend.get_record = AsyncMock(
            return_value={"values": ['1 other-index.acme.com. alpn="h2" port="443"']}
        )
        written = await publish_catalog_pointer(
            "acme.com", "ard.acme.com", backend=backend, force_index=True
        )
        assert written == ["_catalog._agents.acme.com", "_index._agents.acme.com"]

    @pytest.mark.asyncio
    async def test_underscore_host_rejected(self):
        backend = self._mock_backend()
        with pytest.raises(Exception):  # noqa: B017 — validation error type is backend-internal
            await publish_catalog_pointer("acme.com", "_bad._host.acme.com", backend=backend)
        backend.create_svcb_record.assert_not_called()

    @pytest.mark.asyncio
    async def test_missing_zone_raises(self):
        backend = self._mock_backend()
        backend.zone_exists = AsyncMock(return_value=False)
        with pytest.raises(ValueError, match="does not exist"):
            await publish_catalog_pointer("acme.com", "ard.acme.com", backend=backend)


class TestPointerDrivenDiscovery:
    """Discoverer resolves the pointer and fetches the catalog there first."""

    def _stream_response(self, payload, status=200):
        body = json.dumps(payload).encode()

        async def _aiter_bytes():
            yield body

        resp = MagicMock()
        resp.status_code = status
        resp.is_redirect = 300 <= status < 400
        resp.aiter_bytes = _aiter_bytes
        cm = MagicMock()
        cm.__aenter__ = AsyncMock(return_value=resp)
        cm.__aexit__ = AsyncMock(return_value=None)
        return cm

    @pytest.mark.asyncio
    async def test_fetch_uses_catalog_url_first(self):
        from dns_aid.core.http_index import fetch_http_index

        catalog = {
            "specVersion": "1.0",
            "entries": [
                {
                    "identifier": "urn:air:acme.com:server:weather",
                    "displayName": "Weather",
                    "type": "application/mcp-server-card+json",
                    "url": "https://api.acme.com/weather.json",
                }
            ],
        }
        client = MagicMock()
        # Only the catalog_url is fetched — patterns are never reached.
        client.stream = MagicMock(return_value=self._stream_response(catalog))
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)
        with patch("dns_aid.core.http_index.httpx.AsyncClient", return_value=client):
            agents = await fetch_http_index(
                "acme.com", catalog_url="https://cat.acme.com/.well-known/ai-catalog.json"
            )
        assert [a.name for a in agents] == ["weather"]
        assert client.stream.call_count == 1
        assert client.stream.call_args[0][1] == "https://cat.acme.com/.well-known/ai-catalog.json"

    @pytest.mark.asyncio
    async def test_catalog_url_redirect_refused(self):
        # adv-1: a 302 from the pointer host is refused (no redirect follow),
        # so fetch fails over to the well-known patterns instead.
        from dns_aid.core.http_index import HttpIndexError, fetch_http_index

        client = MagicMock()
        # catalog_url → 302; all 5 well-known patterns → 404
        client.stream = MagicMock(
            side_effect=[self._stream_response({}, status=302)]
            + [self._stream_response({}, status=404) for _ in range(5)]
        )
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)
        with patch("dns_aid.core.http_index.httpx.AsyncClient", return_value=client):
            with pytest.raises(HttpIndexError):
                await fetch_http_index(
                    "acme.com", catalog_url="https://evil.acme.com/.well-known/ai-catalog.json"
                )
        # First call was the catalog_url with follow_redirects disabled
        first = client.stream.call_args_list[0]
        assert first.kwargs.get("follow_redirects") is False

    @pytest.mark.asyncio
    async def test_discover_resolves_pointer_then_fetches(self):
        from dns_aid.core import discoverer as disc

        catalog = {
            "specVersion": "1.0",
            "entries": [
                {
                    "identifier": "urn:air:acme.com:server:weather",
                    "displayName": "Weather",
                    "type": "application/mcp-server-card+json",
                    "url": "https://api.acme.com/weather.json",
                }
            ],
        }
        client = MagicMock()
        client.stream = MagicMock(return_value=self._stream_response(catalog))
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=None)
        with (
            patch.object(
                disc,
                "resolve_catalog_pointer",
                AsyncMock(return_value="https://cat.acme.com/.well-known/ai-catalog.json"),
            ),
            patch("dns_aid.core.http_index.httpx.AsyncClient", return_value=client),
            patch.object(disc, "_query_single_agent", AsyncMock(return_value=None)),
        ):
            records = await disc._discover_via_http_index("acme.com")
        assert [r.name for r in records] == ["weather"]
        assert records[0].capability_source == "ard_catalog"
        # The pointer URL was fetched, not a well-known pattern
        assert client.stream.call_args[0][1] == "https://cat.acme.com/.well-known/ai-catalog.json"
