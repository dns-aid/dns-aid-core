# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""``nameservers=`` / ``--resolver`` route lookups away from /etc/resolv.conf (F9)."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import dns.nameserver
import dns.resolver
import pytest
from typer.testing import CliRunner

from dns_aid.core.models import VerifyResult
from dns_aid.core.resolver import (
    current_nameservers,
    make_resolver,
    parse_nameserver,
    parse_nameservers,
    use_nameservers,
)


class TestParse:
    @pytest.mark.parametrize(
        ("text", "address", "port"),
        [
            ("10.53.0.3", "10.53.0.3", 53),
            (" 10.53.0.3 ", "10.53.0.3", 53),
            ("10.53.0.3#5353", "10.53.0.3", 5353),
            ("10.53.0.3:5300", "10.53.0.3", 5300),
            ("2001:db8::53", "2001:db8::53", 53),
            ("[2001:db8::53]:5353", "2001:db8::53", 5353),
            ("[2001:db8::53]", "2001:db8::53", 53),
        ],
    )
    def test_do53(self, text, address, port):
        ns = parse_nameserver(text)
        assert isinstance(ns, dns.nameserver.Do53Nameserver)
        assert ns.answer_nameserver() == address
        assert ns.answer_port() == port

    def test_doh(self):
        ns = parse_nameserver("https://dns.example/dns-query")
        assert isinstance(ns, dns.nameserver.DoHNameserver)

    @pytest.mark.parametrize(
        "text", ["", "resolver.example", "10.0.0.1#0", "10.0.0.1#x", "[::1", "http://x/"]
    )
    def test_invalid(self, text):
        with pytest.raises(ValueError):
            parse_nameserver(text)

    def test_list_and_comma_forms(self):
        assert len(parse_nameservers("10.0.0.1,10.0.0.2")) == 2
        assert len(parse_nameservers(["10.0.0.1", "10.0.0.2,10.0.0.3"])) == 3
        assert parse_nameservers(None) == []


class TestScope:
    def test_default_is_system_resolver(self):
        assert current_nameservers() == []
        with patch("dns.asyncresolver.Resolver") as cls:
            make_resolver()
        cls.assert_called_once_with()

    def test_override_skips_resolv_conf(self):
        with use_nameservers(["10.53.0.3", "10.53.0.4#5353"]):
            assert current_nameservers() == ["10.53.0.3", "10.53.0.4#5353"]
            resolver = make_resolver()
            assert [str(ns.answer_nameserver()) for ns in resolver.nameservers] == [
                "10.53.0.3",
                "10.53.0.4",
            ]
        assert current_nameservers() == []

    def test_empty_override_keeps_outer(self):
        with use_nameservers("10.0.0.1"), use_nameservers(None):
            assert current_nameservers() == ["10.0.0.1"]

    @pytest.mark.asyncio
    async def test_override_follows_gathered_tasks_and_does_not_leak(self):
        seen: dict[str, list[str]] = {}

        async def probe(tag: str) -> None:
            await asyncio.sleep(0)
            seen[tag] = current_nameservers()

        async def scoped() -> None:
            with use_nameservers("10.53.0.3"):
                await asyncio.gather(probe("a"), probe("b"))

        await asyncio.gather(scoped(), probe("outside"))
        assert seen == {"a": ["10.53.0.3"], "b": ["10.53.0.3"], "outside": []}


class TestDiscoverAndVerifyUseOverride:
    @pytest.mark.asyncio
    async def test_discover_queries_given_resolver(self):
        from dns_aid.core.discoverer import discover

        used: list[list[str]] = []

        def make(*args, **kwargs):
            resolver = MagicMock()

            async def resolve(*a, **k):
                used.append(
                    [ns.answer_nameserver() for ns in resolver.nameservers]
                    if isinstance(resolver.nameservers, list)
                    else []
                )
                raise dns.resolver.NXDOMAIN()

            resolver.resolve = AsyncMock(side_effect=resolve)
            return resolver

        with patch("dns.asyncresolver.Resolver", side_effect=make):
            await discover(
                "example.com",
                protocol="mcp",
                name="chat",
                enrich_endpoints=False,
                nameservers="10.53.0.3",
            )
        assert used and all(u == ["10.53.0.3"] for u in used)

    @pytest.mark.asyncio
    async def test_discover_rejects_bad_resolver(self):
        from dns_aid.core.discoverer import discover

        with pytest.raises(ValueError, match="invalid nameserver"):
            await discover("example.com", nameservers="not-an-ip")

    @pytest.mark.asyncio
    async def test_verify_notes_resolver(self):
        from dns_aid.core import validator

        with (
            patch.object(validator, "_check_svcb_record", AsyncMock(return_value=None)),
            patch.object(
                validator,
                "_check_dnssec_detail",
                AsyncMock(return_value=validator.DNSSECDetail(validated=True)),
            ),
        ):
            result = await validator.verify("chat.example.com", nameservers=["10.53.0.3"])
        assert "resolver: 10.53.0.3" in result.dnssec_note
        assert current_nameservers() == []


class TestCli:
    def test_verify_passes_resolver(self):
        from dns_aid.cli.main import app

        captured: dict = {}

        async def fake_verify(fqdn, **kwargs):
            captured.update(kwargs, fqdn=fqdn)
            return VerifyResult(fqdn=fqdn)

        with patch("dns_aid.core.validator.verify", fake_verify):
            result = CliRunner().invoke(
                app, ["verify", "chat.example.com", "--resolver", "10.53.0.3"]
            )
        assert result.exit_code == 0, result.output
        assert captured["nameservers"] == ["10.53.0.3"]
        assert "Resolver: 10.53.0.3" in result.output

    def test_discover_passes_resolver_and_reports_it(self):
        from dns_aid.cli.main import app
        from dns_aid.core.models import DiscoveryResult

        captured: dict = {}

        async def fake_discover(**kwargs):
            captured.update(kwargs)
            return DiscoveryResult(query="q", domain=kwargs["domain"])

        with patch("dns_aid.core.discoverer.discover", fake_discover):
            result = CliRunner().invoke(
                app,
                ["discover", "example.com", "--json", "--nameserver", "10.53.0.3#5353"],
            )
        assert result.exit_code == 0, result.output
        assert captured["nameservers"] == ["10.53.0.3#5353"]
        assert '"resolver"' in result.output

    def test_bad_resolver_exit_64(self):
        from dns_aid.cli.main import app

        result = CliRunner().invoke(app, ["verify", "chat.example.com", "--resolver", "nope"])
        assert result.exit_code == 64


class TestMcp:
    def test_mcp_rejects_doh_and_custom_port(self):
        from dns_aid.mcp.server import _validate_resolver_arg

        assert _validate_resolver_arg(None) is None
        assert _validate_resolver_arg(["10.53.0.3"]) is None
        for bad in (["https://dns.example/dns-query"], ["10.53.0.3#5353"], ["x"]):
            err = _validate_resolver_arg(bad)
            assert err is not None and err["success"] is False
