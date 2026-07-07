# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""ARD catalog-pointer trust (spec 008).

Covers the layered pointer trust decision (on-domain / DNSSEC / JWS / fallback),
the foreign-publisher anchor fix (② — anchored on the served host, not the query
domain), and the surfaced ``catalog_trust`` basis.
"""

from unittest.mock import AsyncMock, patch

import pytest
import structlog

from dns_aid.core.catalog_pointer import PointerResolution
from dns_aid.core.discoverer import (
    _discover_via_http_index,
    _drop_unverified_off_domain,
    _http_agent_to_record,
    _validated_trust_manifest,
)
from dns_aid.core.http_index import (
    HttpIndexAgent,
    HttpIndexResult,
    is_on_domain,
    parse_http_index,
)
from dns_aid.core.models import AgentRecord, Protocol

DOMAIN = "acme.com"
ON_DOMAIN = PointerResolution(
    url="https://ard.acme.com/.well-known/ai-catalog.json",
    target_host="ard.acme.com",
    pointer_fqdn="_catalog._agents.acme.com",
)
# An off-domain pointer target (a different registrable domain) — the shape an
# injected/spoofed pointer takes, and also a legitimate third-party CDN host.
OFF_DOMAIN = PointerResolution(
    url="https://catalog.partner.com/.well-known/ai-catalog.json",
    target_host="catalog.partner.com",
    pointer_fqdn="_catalog._agents.acme.com",
)


def _ard_agent(name: str = "chat") -> HttpIndexAgent:
    return HttpIndexAgent(
        name=name,
        fqdn=f"{name}.acme.com",
        source_format="ard",
        protocols=["a2a"],
        identifier=f"urn:air:acme.com:agents:{name}",
        card_url="https://acme.com/agents/chat.json",
    )


async def _run_decision(
    pointer,
    *,
    verify_signatures: bool = False,
    dnssec_validated: bool = False,
    trust_dnssec_pointers: bool = False,
):
    """Drive _discover_via_http_index with the pointer resolution mocked.

    Returns (captured_catalog_url, records). ``fake_fetch`` reports the
    off-domain host as the server only when the pointer URL was actually
    followed, mirroring the real fetch-vs-fallback behaviour.
    """
    captured: dict = {}

    async def fake_fetch(domain, *, catalog_url=None):
        captured["catalog_url"] = catalog_url
        served = pointer.target_host if (catalog_url and pointer) else domain
        return HttpIndexResult(agents=[_ard_agent()], served_host=served)

    async def fake_process(ha, domain, protocol, name):
        return AgentRecord(
            name=ha.name,
            domain=domain,
            protocol=Protocol.A2A,
            target_host="chat.acme.com",
            port=443,
        )

    with (
        patch(
            "dns_aid.core.discoverer.resolve_catalog_pointer_detail",
            AsyncMock(return_value=pointer),
        ),
        patch(
            "dns_aid.core.discoverer._pointer_dnssec_validated",
            AsyncMock(return_value=dnssec_validated),
        ),
        patch(
            "dns_aid.core.discoverer.fetch_http_index_result_or_empty",
            side_effect=fake_fetch,
        ),
        patch("dns_aid.core.discoverer._process_http_agent", side_effect=fake_process),
    ):
        records = await _discover_via_http_index(
            DOMAIN,
            verify_signatures=verify_signatures,
            trust_dnssec_pointers=trust_dnssec_pointers,
        )
    return captured.get("catalog_url"), records


class TestOnDomainCheck:
    @pytest.mark.parametrize(
        ("host", "domain", "expected"),
        [
            ("acme.com", "acme.com", True),
            ("ard.acme.com", "acme.com", True),
            ("a.b.acme.com", "acme.com", True),
            ("ARD.ACME.COM", "acme.com", True),  # case-insensitive
            ("ard.acme.com.", "acme.com", True),  # trailing dot
            ("catalog.evil.com", "acme.com", False),
            ("evil-acme.com", "acme.com", False),  # label-boundary, not substring
            ("acme.com.evil.com", "acme.com", False),  # suffix spoof
        ],
    )
    def test_is_on_domain(self, host, domain, expected):
        assert is_on_domain(host, domain) is expected


class TestPointerTrustDecision:
    """US1/US3 — which pointer targets are followed vs. fall back to well-known."""

    @pytest.mark.asyncio
    async def test_no_pointer_uses_wellknown(self):
        catalog_url, records = await _run_decision(None)
        assert catalog_url is None  # well-known cascade on the queried domain
        assert records[0].catalog_trust == "tls_domain"

    @pytest.mark.asyncio
    async def test_on_domain_pointer_followed(self):
        catalog_url, records = await _run_decision(ON_DOMAIN)
        assert catalog_url == ON_DOMAIN.url  # subdomain of the queried domain — TLS-bound
        assert records[0].catalog_trust == "tls_domain"

    @pytest.mark.asyncio
    async def test_off_domain_unauthenticated_falls_back(self):
        # THE security property: a spoofed/injected off-domain pointer is NOT
        # followed — discovery falls back to the on-domain well-known catalog.
        catalog_url, records = await _run_decision(OFF_DOMAIN)
        assert catalog_url is None
        assert records[0].catalog_trust == "tls_domain"

    @pytest.mark.asyncio
    async def test_off_domain_dnssec_followed_when_opted_in(self):
        # Opt-in trust_dnssec_pointers=True + DNSSEC-validated pointer → followed.
        catalog_url, records = await _run_decision(
            OFF_DOMAIN, dnssec_validated=True, trust_dnssec_pointers=True
        )
        assert catalog_url == OFF_DOMAIN.url
        assert records[0].catalog_trust == "dnssec"

    @pytest.mark.asyncio
    async def test_off_domain_dnssec_ignored_without_optin(self):
        # DNSSEC-validated pointer but the caller did NOT opt in → NOT followed;
        # falls back to the on-domain well-known catalog (JWS is the default anchor).
        catalog_url, records = await _run_decision(OFF_DOMAIN, dnssec_validated=True)
        assert catalog_url is None
        assert records[0].catalog_trust == "tls_domain"

    @pytest.mark.asyncio
    async def test_off_domain_jws_followed_under_verify_signatures(self):
        catalog_url, records = await _run_decision(OFF_DOMAIN, verify_signatures=True)
        assert catalog_url == OFF_DOMAIN.url
        assert records[0].catalog_trust == "jws"

    @pytest.mark.asyncio
    async def test_off_domain_without_verify_signatures_still_falls_back(self):
        catalog_url, _ = await _run_decision(OFF_DOMAIN, verify_signatures=False)
        assert catalog_url is None


class TestForeignPublisherAnchor:
    """② — the foreign-publisher warning anchors on the served host, not the query domain."""

    def _agent(self) -> HttpIndexAgent:
        return HttpIndexAgent(
            name="chat",
            fqdn="chat.acme.com",
            source_format="ard",
            identifier="urn:air:acme.com:agents:chat",
            trust_manifest={
                "identity": "spiffe://acme.com/agents/chat",
                "identityType": "spiffe",
                "attestations": [{"type": "SOC2-Type2", "uri": "https://acme.com/soc2.pdf"}],
            },
        )

    def test_off_domain_served_host_trips_warning(self):
        with structlog.testing.capture_logs() as logs:
            manifest = _validated_trust_manifest(self._agent(), "catalog.evil.com")
        events = {e.get("event") for e in logs}
        assert "http_index.ard_trust_foreign_publisher" in events
        # The manifest is still returned (advisory-only), now with the true anchor.
        assert manifest is not None

    def test_on_domain_served_host_does_not_trip_warning(self):
        with structlog.testing.capture_logs() as logs:
            _validated_trust_manifest(self._agent(), "acme.com")
        events = {e.get("event") for e in logs}
        assert "http_index.ard_trust_foreign_publisher" not in events

    def test_query_domain_would_have_masked_it(self):
        # Regression guard: passing the *query* domain (the old behaviour) hides
        # the foreign publisher; the served host must be used instead.
        with structlog.testing.capture_logs() as logs:
            _validated_trust_manifest(self._agent(), "acme.com")  # query domain
        assert not any(e.get("event") == "http_index.ard_trust_foreign_publisher" for e in logs)


class TestOffDomainSignatureEnforcement:
    """③ safe-by-default — off-domain (jws) records that did not verify are dropped."""

    def _rec(self, catalog_trust, sig_verified):
        r = AgentRecord(
            name="x",
            domain="acme.com",
            protocol=Protocol.MCP,
            target_host="x.acme.com",
            port=443,
        )
        r.catalog_trust = catalog_trust
        r.signature_verified = sig_verified
        return r

    def test_drops_unverified_off_domain_records(self):
        agents = [
            self._rec("jws", True),  # verified off-domain — keep
            self._rec("jws", False),  # failed verification — drop
            self._rec("jws", None),  # not verified (e.g. no sig) — drop
            self._rec("tls_domain", None),  # on-domain — keep
            self._rec("dnssec", None),  # DNSSEC-authenticated off-domain — keep
            self._rec(None, None),  # pure-DNS — keep
        ]
        kept = _drop_unverified_off_domain(agents, "acme.com")
        assert [(a.catalog_trust, a.signature_verified) for a in kept] == [
            ("jws", True),
            ("tls_domain", None),
            ("dnssec", None),
            (None, None),
        ]

    def test_empty_input_ok(self):
        assert _drop_unverified_off_domain([], "acme.com") == []


class TestArdSigWiring:
    """Adversarial-review fix — the per-entry `sig` is actually read + carried,
    so the JWS off-domain arm is not dead code (it was previously never parsed)."""

    def test_ard_entry_sig_is_extracted_from_wire(self):
        catalog = {
            "specVersion": "1.0",
            "entries": [
                {
                    "identifier": "urn:air:acme.com:agents:billing",
                    "displayName": "Billing",
                    "type": "application/mcp-server-card+json",
                    "url": "https://cards.acme.com/billing.json",
                    "sig": "eyJhbGciOiJFUzI1NiJ9.payload.signature",
                }
            ],
        }
        agents = parse_http_index(catalog)
        assert len(agents) == 1
        assert agents[0].sig == "eyJhbGciOiJFUzI1NiJ9.payload.signature"

    def test_ard_sig_flows_into_record(self):
        ha = HttpIndexAgent(
            name="billing",
            fqdn="billing.acme.com",
            source_format="ard",
            protocols=["mcp"],
            identifier="urn:air:acme.com:agents:billing",
            card_url="https://cards.acme.com/billing.json",
            sig="eyJ.a.b",
        )
        rec = _http_agent_to_record(ha, "acme.com", "billing", Protocol.MCP)
        assert rec is not None
        assert rec.sig == "eyJ.a.b"
