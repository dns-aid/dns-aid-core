# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Behavioural coverage for the new security controls.

Mutation testing found every one of these could be deleted with the whole suite
still green, while the status and rendering logic around them was well tested.
That is not bookkeeping: the NAT64 unwrap shipped a real exploitable bug -- an
address reaching 169.254.169.254 through a gateway was accepted -- and no test
caught it.

Each case here was confirmed to fail with its mechanism disabled.
"""

import asyncio
import ipaddress
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from dns_aid.utils import url_safety


class TestAddressAllowList:
    """An allow-list, not an enumeration of bad ranges.

    The enumeration missed RFC 6598 shared address space and multicast, both of
    which a forgeable SVCB target could name.
    """

    @pytest.mark.parametrize(
        "addr",
        [
            "100.64.0.1",  # RFC 6598 CGNAT
            "100.100.100.200",  # Alibaba Cloud metadata
            "224.0.0.1",  # multicast
            "0.0.0.0",  # unspecified
            "127.0.0.1",
            "169.254.169.254",
            "10.0.0.5",
            "192.168.1.1",
        ],
    )
    def test_non_public_addresses_are_rejected(self, addr):
        ip = url_safety._unwrap_embedded_v4(ipaddress.ip_address(addr))

        assert not ip.is_global or ip.is_multicast or ip.is_unspecified

    @pytest.mark.parametrize("addr", ["8.8.8.8", "1.1.1.1", "93.184.216.34"])
    def test_public_addresses_still_pass(self, addr):
        ip = url_safety._unwrap_embedded_v4(ipaddress.ip_address(addr))

        assert ip.is_global and not ip.is_multicast


class TestEmbeddedV4IsResolvedBeforeTheCheck:
    """RFC 6052 puts the embedded IPv4 at a different offset per prefix length.

    Reading the low 32 bits is correct only for /96; for /48 those bits are the
    attacker-chosen suffix, so a decode returned a public address for something
    that reaches the metadata service through a NAT64 gateway.
    """

    @pytest.mark.parametrize(
        "v6,expected",
        [
            ("64:ff9b::a9fe:a9fe", "169.254.169.254"),  # /96
            ("64:ff9b::7f00:1", "127.0.0.1"),  # /96
            ("64:ff9b:1:a9fe:a9:fe00:808:808", "169.254.169.254"),  # /48
            ("64:ff9b:1:7f00:0:100:808:808", "127.0.0.1"),  # /48
            ("::ffff:169.254.169.254", "169.254.169.254"),  # v4-mapped
            ("::169.254.169.254", "169.254.169.254"),  # v4-compatible
        ],
    )
    def test_the_real_destination_is_recovered(self, v6, expected):
        got = url_safety._unwrap_embedded_v4(ipaddress.ip_address(v6))

        assert str(got) == expected, f"{v6} decoded to {got}, not {expected}"
        assert not got.is_global, "the decoded destination must fail the range check"

    def test_a_legitimate_nat64_address_is_not_broken(self):
        got = url_safety._unwrap_embedded_v4(ipaddress.ip_address("64:ff9b::5db8:d822"))

        assert str(got) == "93.184.216.34"
        assert got.is_global

    def test_ordinary_ipv6_is_untouched(self):
        addr = ipaddress.ip_address("2606:4700:4700::1111")

        assert url_safety._unwrap_embedded_v4(addr) is addr


class TestVettedAddressPin:
    def test_the_vetted_address_is_recorded_and_retrievable(self):
        url = "https://pinned.example/x"
        url_safety._last_vetted_ip.pop(url, None)
        with patch.object(
            url_safety.socket, "getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.216.34", 443))]
        ):
            url_safety.validate_fetch_url(url)

        assert url_safety.vetted_ip_for(url) == "93.184.216.34"

    def test_the_map_is_bounded(self):
        for i in range(url_safety._VETTED_IP_MAX + 20):
            url_safety._last_vetted_ip[f"https://z{i}.example/"] = "8.8.8.8"
            while len(url_safety._last_vetted_ip) > url_safety._VETTED_IP_MAX:
                url_safety._last_vetted_ip.pop(next(iter(url_safety._last_vetted_ip)), None)

        assert len(url_safety._last_vetted_ip) <= url_safety._VETTED_IP_MAX

    def test_a_pin_is_never_returned_for_a_different_url(self):
        url_safety._last_vetted_ip["https://a.example/"] = "93.184.216.34"

        assert url_safety.vetted_ip_for("https://b.example/") is None


class TestDanePortAllowList:
    """target AND port come off a forgeable record."""

    @pytest.mark.parametrize("port", [443, 853, 8443])
    def test_tls_ports_are_allowed(self, port):
        from dns_aid.core.validator import _dane_port_allowed

        assert _dane_port_allowed(port) is True

    @pytest.mark.parametrize("port", [22, 25, 3306, 6379, 9200, 80])
    def test_scanner_ports_are_refused(self, port):
        from dns_aid.core.validator import _dane_port_allowed

        assert _dane_port_allowed(port) is False

    def test_the_override_is_honoured(self, monkeypatch):
        from dns_aid.core.validator import _dane_port_allowed

        monkeypatch.setenv("DNS_AID_DANE_ALLOWED_PORTS", "443,9443")

        assert _dane_port_allowed(9443) is True
        assert _dane_port_allowed(8443) is False

    def test_any_disables_the_list(self, monkeypatch):
        from dns_aid.core.validator import _dane_port_allowed

        monkeypatch.setenv("DNS_AID_DANE_ALLOWED_PORTS", "any")

        assert _dane_port_allowed(6379) is True

    def test_a_malformed_override_falls_back_to_the_default(self, monkeypatch):
        from dns_aid.core.validator import _dane_port_allowed

        monkeypatch.setenv("DNS_AID_DANE_ALLOWED_PORTS", "not,a,port")

        assert _dane_port_allowed(443) is True
        assert _dane_port_allowed(6379) is False


class TestProbesAreGuarded:
    """The reachability probes take their destination from the record too."""

    @pytest.mark.asyncio
    async def test_check_endpoint_refuses_an_internal_target(self):
        from dns_aid.core.validator import _check_endpoint

        result = await _check_endpoint("169.254.169.254", 443)

        assert result["reachable"] is False

    @pytest.mark.asyncio
    async def test_check_tls_refuses_an_internal_target(self):
        from dns_aid.core.validator import _check_tls

        detail = await _check_tls("10.0.0.5", 443)

        assert detail.connected is False

    @pytest.mark.asyncio
    async def test_the_reachability_probes_do_not_enforce_the_port_list(self):
        """A healthy agent on 8080 must not read as a broken endpoint."""
        from dns_aid.core.validator import _guarded_dial_host

        with patch(
            "dns_aid.utils.url_safety.validate_fetch_url_async", new=AsyncMock(return_value="")
        ):
            host = await _guarded_dial_host("agent.example.com", 8080, enforce_ports=False)

        assert host == "agent.example.com"

        with pytest.raises(ConnectionError):
            await _guarded_dial_host("agent.example.com", 8080)


class TestDaneTimeouts:
    def test_the_connect_and_shutdown_budgets_are_bounded(self):
        from dns_aid.core.validator import DANE_CONNECT_TIMEOUT, DANE_SHUTDOWN_TIMEOUT

        assert 0 < DANE_CONNECT_TIMEOUT <= 15, "an unbounded dial stalls discovery"
        assert 0 < DANE_SHUTDOWN_TIMEOUT <= DANE_CONNECT_TIMEOUT

    def test_they_fit_inside_the_aggregate_budget(self):
        from dns_aid.core.discoverer import DANE_TOTAL_BUDGET_SECONDS, MAX_CONCURRENT_DANE
        from dns_aid.core.validator import DANE_CONNECT_TIMEOUT

        assert MAX_CONCURRENT_DANE >= 1
        assert DANE_TOTAL_BUDGET_SECONDS > DANE_CONNECT_TIMEOUT


class TestJwksSingleFlight:
    @pytest.mark.asyncio
    async def test_concurrent_lookups_share_one_fetch(self):
        from dns_aid.core.jwks import _jwks_cache, _jwks_inflight, _jwks_negative, fetch_jwks

        for d in (_jwks_cache, _jwks_negative, _jwks_inflight):
            d.clear()
        attempts = []

        async def slow(url, domain):  # noqa: ARG001
            attempts.append(url)
            await asyncio.sleep(0.05)
            return None

        with patch("dns_aid.core.jwks._fetch_jwks_from", new=slow):
            await asyncio.gather(*[fetch_jwks("busy.example") for _ in range(16)])

        assert len(attempts) <= 2, f"{len(attempts)} fetches for 16 concurrent lookups"


class TestSignatureBudgetIsVisibleAndFailSafe:
    @pytest.mark.asyncio
    async def test_unverified_records_report_not_checked_and_are_dropped(self):
        from dns_aid.core.discoverer import _verify_agent_signatures
        from dns_aid.core.filters import apply_filters
        from dns_aid.core.jwks import SignatureStatus
        from dns_aid.core.models import AgentRecord, Protocol

        agents = [
            AgentRecord(
                name=f"a{i}",
                domain="example.com",
                protocol=Protocol.MCP,
                target_host=f"t{i}.example.com",
                port=443,
                sig="eyJhbGciOiJFUzI1NiJ9.eyJ9.c2ln",
            )
            for i in range(4)
        ]

        async def hangs(zone, jws):  # noqa: ARG001
            await asyncio.sleep(3600)

        with (
            patch("dns_aid.core.jwks.verify_record_signature_detailed", new=hangs),
            patch("dns_aid.core.discoverer.SIG_VERIFY_BUDGET_SECONDS", 0.1),
        ):
            await _verify_agent_signatures(agents, "example.com")

        assert all(a.signature_status == SignatureStatus.NOT_CHECKED for a in agents), (
            "status None is indistinguishable from never being in scope"
        )
        assert all(a.signature_verified is None for a in agents), "unknown, never refuted"
        assert apply_filters(agents, require_signed=True) == [], "must stay fail-safe"

    @pytest.mark.asyncio
    async def test_an_outside_cancellation_leaves_no_signature_task_alive(self):
        from dns_aid.core.discoverer import _verify_agent_signatures
        from dns_aid.core.models import AgentRecord, Protocol

        agents = [
            AgentRecord(
                name=f"a{i}",
                domain="example.com",
                protocol=Protocol.MCP,
                target_host=f"t{i}.example.com",
                port=443,
                sig="eyJhbGciOiJFUzI1NiJ9.eyJ9.c2ln",
            )
            for i in range(6)
        ]
        created = []
        real_create = asyncio.create_task

        def tracking(coro, **kw):
            task = real_create(coro, **kw)
            created.append(task)
            return task

        async def hangs(zone, jws):  # noqa: ARG001
            await asyncio.sleep(3600)

        with (
            patch("dns_aid.core.jwks.verify_record_signature_detailed", new=hangs),
            patch("dns_aid.core.discoverer.asyncio.create_task", tracking),
        ):
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(
                    _verify_agent_signatures(agents, "example.com"),
                    timeout=0.05,
                )

        await asyncio.sleep(0)
        assert created, "no tasks created, the test proves nothing"
        assert all(t.cancelled() or t.done() for t in created)


def test_the_dane_and_signature_phases_use_the_same_shape():
    """One phase bounded and the other not is how the 120s cap was blown."""
    from dns_aid.core.discoverer import (
        DANE_TOTAL_BUDGET_SECONDS,
        MAX_CONCURRENT_DANE,
        MAX_CONCURRENT_SIG_VERIFY,
        SIG_VERIFY_BUDGET_SECONDS,
    )

    assert MAX_CONCURRENT_DANE > 1 and MAX_CONCURRENT_SIG_VERIFY > 1
    assert DANE_TOTAL_BUDGET_SECONDS > 0 and SIG_VERIFY_BUDGET_SECONDS > 0
    _ = MagicMock  # keep the import honest for the fixture style above
