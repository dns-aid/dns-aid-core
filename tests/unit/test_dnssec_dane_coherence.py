# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Spec 009 — DNSSEC/DANE coherence + real DANE.

Covers the four coherence fixes and the new opt-in DANE surface across the SDK,
the pure filter primitives, and BOTH the CLI and MCP interfaces:

1. ``min_dnssec`` no longer silently drops HTTP-catalog / ARD agents (they are
   exempt — their trust is ``catalog_trust``), and it now actually *triggers* the
   DNSSEC check instead of dropping everyone because the flag was never stamped.
2. ``require_dnssec`` no longer raises for a working ARD-only catalog; enforcement
   is scoped to non-catalog (DNS-plane / direct) agents.
3. ``_match_dane_cert`` honors the TLSA ``usage`` field — DANE-EE/DANE-TA
   (self-signed / privately issued) certificates are matched against a *real*
   in-process TLS server, not a patched-out stub.
4. ``cryptography`` is importable from a base install (moved to core deps).

Plus the ``verify_dane`` opt-in that stamps ``AgentRecord.dane_verified`` (demoted
to ``None`` without DNSSEC), surfaced ARD-style in CLI ``--json`` / MCP discover
output, and ``dnssec_note`` / ``dnssec_detail`` / ``dane_note`` in verify output.
"""

from __future__ import annotations

import asyncio
import datetime
import hashlib
import os
import ssl
import tempfile
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from typer.testing import CliRunner

from dns_aid.cli.main import app
from dns_aid.core.discoverer import _apply_post_discovery, _verify_agents_dane
from dns_aid.core.filters import apply_filters
from dns_aid.core.models import (
    AgentRecord,
    DiscoveryResult,
    DNSSECDetail,
    DNSSECError,
    Protocol,
    VerifyResult,
)
from dns_aid.mcp.server import discover_agents_via_dns, verify_agent_dns

runner = CliRunner()


# --------------------------------------------------------------------------- #
# Builders
# --------------------------------------------------------------------------- #
def _dns_agent(name: str, *, validated: bool, source: str = "dns_svcb") -> AgentRecord:
    return AgentRecord(
        name=name,
        domain="example.com",
        protocol=Protocol.MCP,
        target_host=f"{name}.example.com",
        port=443,
        endpoint_source=source,
        dnssec_validated=validated,
    )


def _ard_agent(name: str, *, source: str = "ard_card") -> AgentRecord:
    return AgentRecord(
        name=name,
        domain="example.com",
        protocol=Protocol.A2A,
        target_host=f"{name}.acme.com",
        port=443,
        endpoint_source=source,
        dnssec_validated=False,
        catalog_trust="tls_domain",
    )


def _result(agents: list[AgentRecord]) -> DiscoveryResult:
    return DiscoveryResult(
        query="_index._agents.example.com",
        domain="example.com",
        agents=agents,
        dnssec_validated=False,
        cached=False,
        query_time_ms=1.0,
    )


_CATALOG_SOURCES = ("ard_card", "ard_inline", "http_index", "http_index_fallback")


# --------------------------------------------------------------------------- #
# Fix 1 (filter side): min_dnssec exempts catalog/ARD agents, filters the rest
# --------------------------------------------------------------------------- #
class TestMinDnssecCatalogExemption:
    def test_dns_validated_kept(self) -> None:
        a = _dns_agent("v", validated=True)
        assert apply_filters([a], min_dnssec=True) == [a]

    def test_dns_unvalidated_dropped(self) -> None:
        a = _dns_agent("u", validated=False)
        assert apply_filters([a], min_dnssec=True) == []

    @pytest.mark.parametrize("source", _CATALOG_SOURCES)
    def test_every_catalog_source_is_exempt(self, source: str) -> None:
        a = _ard_agent("a", source=source)
        # dnssec_validated is False, but a catalog agent must NOT be dropped.
        assert apply_filters([a], min_dnssec=True) == [a]

    def test_all_ard_catalog_not_silently_emptied(self) -> None:
        # The exact reported bug: min_dnssec against an all-ARD catalog returned [].
        agents = [_ard_agent(f"a{i}") for i in range(2)]
        assert apply_filters(agents, min_dnssec=True) == agents

    def test_mixed_keeps_validated_dns_and_all_ard(self) -> None:
        dns_ok = _dns_agent("dnsok", validated=True)
        dns_bad = _dns_agent("dnsbad", validated=False)
        ard = _ard_agent("ard")
        out = apply_filters([dns_ok, dns_bad, ard], min_dnssec=True)
        assert out == [dns_ok, ard]

    def test_unknown_provenance_still_filtered_failsafe(self) -> None:
        # endpoint_source=None is NOT a catalog source → must prove DNSSEC.
        a = AgentRecord(
            name="x",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="x.example.com",
            dnssec_validated=False,
        )
        assert apply_filters([a], min_dnssec=True) == []

    def test_min_dnssec_false_is_noop(self) -> None:
        agents = [_dns_agent("u", validated=False), _ard_agent("a")]
        assert apply_filters(agents, min_dnssec=False) is agents


# --------------------------------------------------------------------------- #
# Fixes 1 + 2 (post-discovery side): DNSSEC scope excludes catalog agents
# --------------------------------------------------------------------------- #
class TestApplyPostDiscoveryScope:
    async def _run(self, agents: list[AgentRecord], **kw: Any) -> bool:
        return await _apply_post_discovery(
            agents,
            kw.get("require_dnssec", False),
            False,  # enrich_endpoints
            False,  # verify_signatures
            "example.com",
            min_dnssec=kw.get("min_dnssec", False),
            verify_dane=kw.get("verify_dane", False),
        )

    async def test_ard_only_require_dnssec_does_not_raise_or_call_check(self) -> None:
        ard = _ard_agent("chat")
        with patch("dns_aid.core.validator._check_dnssec", new_callable=AsyncMock) as mock_check:
            result = await self._run([ard], require_dnssec=True)
        assert result is False
        assert ard.dnssec_validated is False
        mock_check.assert_not_called()  # no DNS-plane agents → check never runs

    async def test_dns_all_validated_returns_true_and_stamps(self) -> None:
        a, b = _dns_agent("chat", validated=False), _dns_agent("search", validated=False)
        with patch(
            "dns_aid.core.validator._check_dnssec",
            new_callable=AsyncMock,
            return_value=True,
        ):
            result = await self._run([a, b], require_dnssec=True)
        assert result is True
        assert a.dnssec_validated is True and b.dnssec_validated is True

    async def test_dns_unvalidated_raises(self) -> None:
        a = _dns_agent("chat", validated=False)
        with patch(
            "dns_aid.core.validator._check_dnssec",
            new_callable=AsyncMock,
            return_value=False,
        ):
            with pytest.raises(DNSSECError):
                await self._run([a], require_dnssec=True)

    async def test_mixed_raises_only_naming_dns_agent(self) -> None:
        dns_bad = _dns_agent("dnsbad", validated=False)
        ard = _ard_agent("ardagent")

        async def selective(fqdn: str) -> bool:
            return False  # the only in-scope agent (dns) fails

        with patch("dns_aid.core.validator._check_dnssec", new=selective):
            with pytest.raises(DNSSECError) as exc:
                await self._run([dns_bad, ard], require_dnssec=True)
        msg = str(exc.value)
        # The failed DNS-plane agent is named in the error; the exempt ARD agent is not.
        # Assert on the bare label rather than the dotted FQDN so a URL-substring lint
        # is not tripped on what is only an error-message assertion.
        assert "dnsbad" in msg
        assert "ardagent" not in msg  # catalog agent is not part of enforcement

    async def test_min_dnssec_triggers_check_without_raising(self) -> None:
        # min_dnssec must STAMP (so the filter has real data) but never raise.
        a = _dns_agent("chat", validated=False)
        with patch(
            "dns_aid.core.validator._check_dnssec",
            new_callable=AsyncMock,
            return_value=False,
        ) as mock_check:
            result = await self._run([a], min_dnssec=True)  # require_dnssec=False
        assert result is False
        assert a.dnssec_validated is False
        mock_check.assert_awaited_once()

    async def test_min_dnssec_stamps_true_when_validated(self) -> None:
        a = _dns_agent("chat", validated=False)
        with patch(
            "dns_aid.core.validator._check_dnssec",
            new_callable=AsyncMock,
            return_value=True,
        ):
            await self._run([a], min_dnssec=True)
        assert a.dnssec_validated is True

    async def test_verify_dane_triggers_dnssec_stamp_and_dane(self) -> None:
        a = _dns_agent("chat", validated=False)
        with (
            patch(
                "dns_aid.core.validator._check_dnssec",
                new_callable=AsyncMock,
                return_value=True,
            ) as mock_dnssec,
            patch(
                "dns_aid.core.discoverer._verify_agents_dane", new_callable=AsyncMock
            ) as mock_dane,
        ):
            await self._run([a], verify_dane=True)
        mock_dnssec.assert_awaited_once()  # DANE needs a DNSSEC anchor
        mock_dane.assert_awaited_once()

    async def test_verify_dane_off_does_not_call_dane(self) -> None:
        a = _dns_agent("chat", validated=True)
        with patch(
            "dns_aid.core.discoverer._verify_agents_dane", new_callable=AsyncMock
        ) as mock_dane:
            await self._run([a], require_dnssec=False, verify_dane=False)
        mock_dane.assert_not_called()


# --------------------------------------------------------------------------- #
# Fix 3: real DANE cert matching against a live self-signed TLS server
# --------------------------------------------------------------------------- #
def _make_self_signed() -> tuple[Any, Any]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


@pytest_asyncio.fixture
async def dane_server():
    """A real asyncio TLS server presenting a self-signed cert on 127.0.0.1."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    key, cert = _make_self_signed()
    cert_der = cert.public_bytes(Encoding.DER)
    spki_der = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    with tempfile.TemporaryDirectory() as d:
        certfile = os.path.join(d, "cert.pem")
        keyfile = os.path.join(d, "key.pem")
        with open(certfile, "wb") as f:
            f.write(cert.public_bytes(Encoding.PEM))
        with open(keyfile, "wb") as f:
            f.write(
                key.private_bytes(
                    Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
            )

        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(certfile, keyfile)

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                await reader.read(1)
            except Exception:
                # Test TLS server: the DANE client closes right after the handshake
                # (it only needs the presented cert), so a read error here is expected.
                pass
            finally:
                writer.close()

        server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=server_ctx)
        port = server.sockets[0].getsockname()[1]
        async with server:
            yield {
                "host": "127.0.0.1",
                "port": port,
                "spki_sha256": hashlib.sha256(spki_der).digest(),
                "cert_sha256": hashlib.sha256(cert_der).digest(),
                "cert_sha512": hashlib.sha512(cert_der).digest(),
            }


class TestMatchDaneCertUsage:
    async def test_dane_ee_spki_sha256_matches(self, dane_server: dict) -> None:
        from dns_aid.core.validator import _match_dane_cert

        ok = await _match_dane_cert(
            dane_server["host"],
            dane_server["port"],
            usage=3,
            selector=1,
            mtype=1,
            tlsa_data=dane_server["spki_sha256"],
        )
        assert ok is True

    async def test_dane_ee_spki_sha256_mismatch(self, dane_server: dict) -> None:
        from dns_aid.core.validator import _match_dane_cert

        ok = await _match_dane_cert(
            dane_server["host"],
            dane_server["port"],
            usage=3,
            selector=1,
            mtype=1,
            tlsa_data=b"\x00" * 32,
        )
        assert ok is False

    async def test_dane_ee_full_cert_sha256_matches(self, dane_server: dict) -> None:
        from dns_aid.core.validator import _match_dane_cert

        ok = await _match_dane_cert(
            dane_server["host"],
            dane_server["port"],
            usage=3,
            selector=0,
            mtype=1,
            tlsa_data=dane_server["cert_sha256"],
        )
        assert ok is True

    async def test_dane_ee_full_cert_sha512_matches(self, dane_server: dict) -> None:
        from dns_aid.core.validator import _match_dane_cert

        ok = await _match_dane_cert(
            dane_server["host"],
            dane_server["port"],
            usage=3,
            selector=0,
            mtype=2,
            tlsa_data=dane_server["cert_sha512"],
        )
        assert ok is True

    async def test_pkix_ee_rejects_self_signed(self, dane_server: dict) -> None:
        # usage 1 (PKIX-EE) keeps PKIX + hostname enforcement, so a self-signed
        # cert on 127.0.0.1 fails the TLS handshake before any digest compare.
        from dns_aid.core.validator import _match_dane_cert

        with pytest.raises(ssl.SSLError):
            await _match_dane_cert(
                dane_server["host"],
                dane_server["port"],
                usage=1,
                selector=1,
                mtype=1,
                tlsa_data=dane_server["spki_sha256"],
            )


# --------------------------------------------------------------------------- #
# Fix 3 wiring: _verify_agents_dane demotes without a DNSSEC anchor
# --------------------------------------------------------------------------- #
class TestVerifyAgentsDane:
    async def test_dane_true_with_dnssec_stamps_true(self) -> None:
        agent = _dns_agent("chat", validated=True)
        with patch(
            "dns_aid.core.validator._check_dane",
            new_callable=AsyncMock,
            return_value=True,
        ):
            await _verify_agents_dane([agent])
        assert agent.dane_verified is True

    async def test_dane_true_without_dnssec_demoted_to_none(self) -> None:
        agent = _dns_agent("chat", validated=False)
        with patch(
            "dns_aid.core.validator._check_dane",
            new_callable=AsyncMock,
            return_value=True,
        ):
            await _verify_agents_dane([agent])
        assert agent.dane_verified is None  # DANE without DNSSEC carries no guarantee

    async def test_dane_false_with_dnssec_stays_false(self) -> None:
        agent = _dns_agent("chat", validated=True)
        with patch(
            "dns_aid.core.validator._check_dane",
            new_callable=AsyncMock,
            return_value=False,
        ):
            await _verify_agents_dane([agent])
        assert agent.dane_verified is False

    async def test_no_tlsa_record_is_none(self) -> None:
        agent = _dns_agent("chat", validated=True)
        with patch(
            "dns_aid.core.validator._check_dane",
            new_callable=AsyncMock,
            return_value=None,
        ):
            await _verify_agents_dane([agent])
        assert agent.dane_verified is None

    async def test_exception_is_swallowed_as_none(self) -> None:
        agent = _dns_agent("chat", validated=True)
        with patch(
            "dns_aid.core.validator._check_dane",
            new_callable=AsyncMock,
            side_effect=OSError("connection refused"),
        ):
            await _verify_agents_dane([agent])
        assert agent.dane_verified is None


# --------------------------------------------------------------------------- #
# SDK end-to-end: discover() threads verify_dane through to dane_verified
# --------------------------------------------------------------------------- #
class TestDiscoverVerifyDaneEndToEnd:
    async def test_discover_stamps_dane_verified(self) -> None:
        """Full chain: discover(verify_dane=True) → _apply_post_discovery →
        DNSSEC stamp → _verify_agents_dane → _check_dane → AgentRecord."""
        from dns_aid.core.discoverer import discover

        agent = _dns_agent("chat", validated=False)
        with (
            patch(
                "dns_aid.core.discoverer._execute_discovery",
                new=AsyncMock(return_value=[agent]),
            ),
            patch(
                "dns_aid.core.discoverer._enrich_agents_with_endpoint_paths",
                new=AsyncMock(),
            ),
            patch(
                "dns_aid.core.validator._check_dnssec",
                new_callable=AsyncMock,
                return_value=True,
            ),
            patch(
                "dns_aid.core.validator._check_dane",
                new_callable=AsyncMock,
                return_value=True,
            ) as mock_dane,
        ):
            result = await discover("example.com", verify_dane=True)

        assert result.agents[0].dnssec_validated is True
        assert result.agents[0].dane_verified is True
        mock_dane.assert_awaited()

    async def test_discover_without_verify_dane_leaves_none(self) -> None:
        from dns_aid.core.discoverer import discover

        agent = _dns_agent("chat", validated=True)
        with (
            patch(
                "dns_aid.core.discoverer._execute_discovery",
                new=AsyncMock(return_value=[agent]),
            ),
            patch(
                "dns_aid.core.discoverer._enrich_agents_with_endpoint_paths",
                new=AsyncMock(),
            ),
            patch(
                "dns_aid.core.validator._check_dane",
                new_callable=AsyncMock,
                return_value=True,
            ) as mock_dane,
        ):
            result = await discover("example.com")

        assert result.agents[0].dane_verified is None
        mock_dane.assert_not_called()


# --------------------------------------------------------------------------- #
# Interface: CLI discover (--verify-dane, dane_verified in --json)
# --------------------------------------------------------------------------- #
class TestCliDiscoverVerifyDane:
    def test_verify_dane_flag_reaches_discover(self) -> None:
        captured: dict[str, Any] = {}

        async def fake_discover(*_a: Any, **kw: Any) -> DiscoveryResult:
            captured.update(kw)
            return _result([])

        with patch("dns_aid.core.discoverer.discover", new=fake_discover):
            result = runner.invoke(app, ["discover", "example.com", "--verify-dane", "--json"])
        assert result.exit_code == 0, result.output
        assert captured["verify_dane"] is True

    def test_default_verify_dane_is_false(self) -> None:
        captured: dict[str, Any] = {}

        async def fake_discover(*_a: Any, **kw: Any) -> DiscoveryResult:
            captured.update(kw)
            return _result([])

        with patch("dns_aid.core.discoverer.discover", new=fake_discover):
            result = runner.invoke(app, ["discover", "example.com", "--json"])
        assert result.exit_code == 0, result.output
        assert captured["verify_dane"] is False

    def test_dane_verified_emitted_when_set(self) -> None:
        agent = _dns_agent("chat", validated=True)
        agent.dane_verified = True

        async def fake_discover(*_a: Any, **_kw: Any) -> DiscoveryResult:
            return _result([agent])

        with patch("dns_aid.core.discoverer.discover", new=fake_discover):
            result = runner.invoke(app, ["discover", "example.com", "--json"])
        assert result.exit_code == 0, result.output
        assert "dane_verified" in result.output

    def test_dane_verified_omitted_when_none_bytes_identical(self) -> None:
        # Pure-DNS agent, dane_verified left at None → key MUST NOT appear.
        agent = _dns_agent("chat", validated=True)

        async def fake_discover(*_a: Any, **_kw: Any) -> DiscoveryResult:
            return _result([agent])

        with patch("dns_aid.core.discoverer.discover", new=fake_discover):
            result = runner.invoke(app, ["discover", "example.com", "--json"])
        assert result.exit_code == 0, result.output
        assert "dane_verified" not in result.output


# --------------------------------------------------------------------------- #
# Interface: MCP discover_agents_via_dns (verify_dane, dane_verified)
# --------------------------------------------------------------------------- #
class TestMcpDiscoverVerifyDane:
    def test_verify_dane_propagates(self) -> None:
        captured: dict[str, Any] = {}

        async def fake_discover(*_a: Any, **kw: Any) -> DiscoveryResult:
            captured.update(kw)
            return _result([])

        with patch("dns_aid.core.discoverer.discover", new=fake_discover):
            out = discover_agents_via_dns(domain="example.com", verify_dane=True)
        assert out["domain"] == "example.com"
        assert captured["verify_dane"] is True

    def test_default_verify_dane_false(self) -> None:
        captured: dict[str, Any] = {}

        async def fake_discover(*_a: Any, **kw: Any) -> DiscoveryResult:
            captured.update(kw)
            return _result([])

        with patch("dns_aid.core.discoverer.discover", new=fake_discover):
            discover_agents_via_dns(domain="example.com")
        assert captured["verify_dane"] is False

    def test_dane_verified_in_output_when_set(self) -> None:
        agent = _dns_agent("chat", validated=True)
        agent.dane_verified = True

        async def fake_discover(*_a: Any, **_kw: Any) -> DiscoveryResult:
            return _result([agent])

        with patch("dns_aid.core.discoverer.discover", new=fake_discover):
            out = discover_agents_via_dns(domain="example.com", verify_dane=True)
        assert out["agents"][0]["dane_verified"] is True

    def test_dane_verified_omitted_when_none(self) -> None:
        agent = _dns_agent("chat", validated=True)  # dane_verified defaults to None

        async def fake_discover(*_a: Any, **_kw: Any) -> DiscoveryResult:
            return _result([agent])

        with patch("dns_aid.core.discoverer.discover", new=fake_discover):
            out = discover_agents_via_dns(domain="example.com")
        assert "dane_verified" not in out["agents"][0]


# --------------------------------------------------------------------------- #
# Interface parity: require_dnssec on CLI (--require-dnssec) + MCP (require_dnssec)
# --------------------------------------------------------------------------- #
class TestRequireDnssecInterfaceParity:
    """require_dnssec must be reachable from all three interfaces, not just the SDK."""

    def test_cli_require_dnssec_flag_reaches_discover(self) -> None:
        captured: dict[str, Any] = {}

        async def fake_discover(*_a: Any, **kw: Any) -> DiscoveryResult:
            captured.update(kw)
            return _result([])

        with patch("dns_aid.core.discoverer.discover", new=fake_discover):
            result = runner.invoke(app, ["discover", "example.com", "--require-dnssec", "--json"])
        assert result.exit_code == 0, result.output
        assert captured["require_dnssec"] is True

    def test_cli_default_require_dnssec_is_false(self) -> None:
        captured: dict[str, Any] = {}

        async def fake_discover(*_a: Any, **kw: Any) -> DiscoveryResult:
            captured.update(kw)
            return _result([])

        with patch("dns_aid.core.discoverer.discover", new=fake_discover):
            result = runner.invoke(app, ["discover", "example.com", "--json"])
        assert result.exit_code == 0, result.output
        assert captured["require_dnssec"] is False

    def test_mcp_require_dnssec_propagates(self) -> None:
        captured: dict[str, Any] = {}

        async def fake_discover(*_a: Any, **kw: Any) -> DiscoveryResult:
            captured.update(kw)
            return _result([])

        with patch("dns_aid.core.discoverer.discover", new=fake_discover):
            discover_agents_via_dns(domain="example.com", require_dnssec=True)
        assert captured["require_dnssec"] is True

    def test_mcp_default_require_dnssec_false(self) -> None:
        captured: dict[str, Any] = {}

        async def fake_discover(*_a: Any, **kw: Any) -> DiscoveryResult:
            captured.update(kw)
            return _result([])

        with patch("dns_aid.core.discoverer.discover", new=fake_discover):
            discover_agents_via_dns(domain="example.com")
        assert captured["require_dnssec"] is False


# --------------------------------------------------------------------------- #
# Interface: verify surfaces dnssec_note / dnssec_detail / dane_note
# --------------------------------------------------------------------------- #
def _verify_result() -> VerifyResult:
    return VerifyResult(
        fqdn="chat.example.com",
        record_exists=True,
        svcb_valid=True,
        dnssec_valid=True,
        dnssec_detail=DNSSECDetail(
            validated=True,
            algorithm="ECDSAP256SHA256",
            algorithm_strength="strong",
            chain_depth=2,
            ad_flag=True,
        ),
        dane_valid=None,
        endpoint_reachable=True,
    )


class TestVerifyOutputSurfaces:
    def test_cli_verify_shows_dnssec_note_and_algorithm(self) -> None:
        async def fake_verify(_fqdn: str) -> VerifyResult:
            return _verify_result()

        with patch("dns_aid.core.validator.verify", new=fake_verify):
            result = runner.invoke(app, ["verify", "chat.example.com"])
        assert result.exit_code == 0, result.output
        # The honest AD-flag caveat and the algorithm detail must both surface.
        assert "no independent DNSSEC chain validation" in result.output
        assert "ECDSAP256SHA256" in result.output

    def test_mcp_verify_returns_notes_and_detail(self) -> None:
        async def fake_verify(_fqdn: str) -> VerifyResult:
            return _verify_result()

        with patch("dns_aid.core.validator.verify", new=fake_verify):
            out = verify_agent_dns(fqdn="chat.example.com")
        assert out["dnssec_note"] == (
            "Checks AD flag from resolver; no independent DNSSEC chain validation"
        )
        assert out["dnssec_detail"]["algorithm"] == "ECDSAP256SHA256"
        assert out["dnssec_detail"]["ad_flag"] is True
        assert "dane_note" in out


# --------------------------------------------------------------------------- #
# Live stubs — skipped in the unit gate; run against real infra with -m live
# --------------------------------------------------------------------------- #
@pytest.mark.live
class TestDaneLive:
    async def test_dane_ee_against_real_host(self) -> None:
        """Placeholder: point at a real DANE-EE endpoint with a published TLSA
        record and assert ``verify_dane`` stamps ``dane_verified=True`` when the
        DNS response is DNSSEC-validated. Requires live infra + a signed zone."""
        pytest.skip("live DANE-EE endpoint required (set up TLSA + DNSSEC zone)")

    async def test_require_dnssec_with_ard_catalog_live(self) -> None:
        """Placeholder: discover a live all-ARD catalog with require_dnssec=True and
        assert it returns the ARD agents without raising DNSSECError."""
        pytest.skip("live ARD catalog required")
