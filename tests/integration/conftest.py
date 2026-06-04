# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""
Fixtures for mock integration tests.

Provides MockDNSBridge — the bridge between MockBackend's in-memory
store (publisher write path) and the dns.asyncresolver.Resolver /
httpx.AsyncClient mocks (discoverer/validator read path).
"""

from __future__ import annotations

import json
from contextlib import ExitStack, asynccontextmanager, contextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import urlparse

import dns.flags
import dns.name
import dns.resolver
import httpx
import pytest

from dns_aid.backends.mock import MockBackend


class MockDNSBridge:
    """Bridge between MockBackend (publisher) and DNS/HTTP mocks (discoverer/validator).

    Reads what MockBackend stored and produces properly-shaped dnspython mock
    objects so that discover() and verify() work against the same in-memory data
    that publish() wrote to.
    """

    def __init__(self, backend: MockBackend) -> None:
        self.backend = backend
        self._dnssec_domains: set[str] = set()
        self._tlsa_records: dict[str, dict[str, int]] = {}  # "host:port" -> TLSA data
        self._endpoint_responses: dict[str, dict[str, Any]] = {}  # "host:port" -> response
        self._cap_documents: dict[str, tuple[dict, bytes]] = {}  # uri -> (json, raw_bytes)
        self._http_index_data: dict[str, dict] = {}  # domain -> index data
        self._agent_cards: dict[str, dict] = {}  # host -> card data

    # ── Configuration methods ──────────────────────────────────────────

    def enable_dnssec(self, domain: str) -> None:
        """Set AD flag on DNS responses for this domain."""
        self._dnssec_domains.add(domain)

    def add_tlsa_record(
        self, target: str, port: int, usage: int = 3, selector: int = 1, mtype: int = 1
    ) -> None:
        """Register a mock DANE/TLSA record."""
        self._tlsa_records[f"{target}:{port}"] = {
            "usage": usage,
            "selector": selector,
            "mtype": mtype,
        }

    def set_endpoint_reachable(self, host: str, port: int = 443) -> None:
        """Register an endpoint as reachable (returns HTTP 200)."""
        self._endpoint_responses[f"{host}:{port}"] = {"status_code": 200}

    def set_cap_document(self, uri: str, data: dict) -> None:
        """Register a capability document at the given URI."""
        raw_bytes = json.dumps(data, separators=(",", ":"), sort_keys=True).encode()
        self._cap_documents[uri] = (data, raw_bytes)

    def set_http_index(self, domain: str, data: dict) -> None:
        """Register HTTP index data for a domain."""
        self._http_index_data[domain] = data

    def set_agent_card(self, host: str, data: dict) -> None:
        """Register an A2A agent card at /.well-known/agent.json on the host."""
        self._agent_cards[host] = data

    # ── DNS mock builders ──────────────────────────────────────────────

    def _parse_fqdn(self, fqdn: str) -> tuple[str, str] | None:
        """Split FQDN into (zone, record_name) by matching against stored zones."""
        fqdn = fqdn.rstrip(".")
        # Check zones that actually have records (not just defaultdict ghosts)
        for zone in list(self.backend.records.keys()):
            if fqdn.endswith(f".{zone}"):
                record_name = fqdn[: -(len(zone) + 1)]
                return zone, record_name
        return None

    def _build_svcb_answer(self, zone: str, record_name: str) -> MagicMock | None:
        """Build mock SVCB rdata from MockBackend's stored records."""
        records = self.backend.records.get(zone, {}).get(record_name, {}).get("SVCB", [])
        if not records:
            return None

        mock_rdatas = []
        for rec in records:
            rdata = MagicMock()
            target = rec["target"]
            # svcb_target already includes trailing dot ("mcp.example.com.")
            rdata.target = dns.name.from_text(target if target.endswith(".") else f"{target}.")
            rdata.priority = rec["priority"]

            port = int(rec.get("params", {}).get("port", "443"))
            rdata.port = port

            # Validator reads port from rdata.params[3].port (SVCB port param key)
            port_param = MagicMock()
            port_param.port = port
            rdata.params = {3: port_param}

            # __str__() produces the presentation format that
            # _parse_svcb_custom_params() splits on spaces.
            params = rec.get("params", {})
            parts = [f'{k}="{v}"' for k, v in params.items()]
            str_repr = f"{rec['priority']} {target}. {' '.join(parts)}"
            # Use default argument capture to avoid late-binding closure bug
            rdata.__str__ = lambda _self, _s=str_repr: _s

            mock_rdatas.append(rdata)

        mock_answer = MagicMock()
        mock_answer.__iter__ = lambda _self, _r=mock_rdatas: iter(_r)
        mock_answer.response = MagicMock()
        mock_answer.response.flags = dns.flags.AD if zone in self._dnssec_domains else 0
        return mock_answer

    def _build_txt_answer(self, zone: str, record_name: str) -> MagicMock | None:
        """Build mock TXT rdata from MockBackend's stored records."""
        records = self.backend.records.get(zone, {}).get(record_name, {}).get("TXT", [])
        if not records:
            return None

        mock_rdatas = []
        for rec in records:
            rdata = MagicMock()
            rdata.strings = [
                v.encode("utf-8") if isinstance(v, str) else v for v in rec.get("values", [])
            ]
            mock_rdatas.append(rdata)

        mock_answer = MagicMock()
        mock_answer.__iter__ = lambda _self, _r=mock_rdatas: iter(_r)
        mock_answer.response = MagicMock()
        mock_answer.response.flags = dns.flags.AD if zone in self._dnssec_domains else 0
        return mock_answer

    def _build_tlsa_answer(self, fqdn: str) -> MagicMock | None:
        """Build mock TLSA rdata for DANE checks.

        TLSA FQDN format: _{port}._tcp.{target}
        """
        parts = fqdn.rstrip(".").split(".")
        if len(parts) < 3:
            return None
        port_str = parts[0].lstrip("_")
        target = ".".join(parts[2:])

        key = f"{target}:{port_str}"
        if key not in self._tlsa_records:
            return None

        tlsa_data = self._tlsa_records[key]
        rdata = MagicMock()
        rdata.usage = tlsa_data["usage"]
        rdata.selector = tlsa_data["selector"]
        rdata.mtype = tlsa_data["mtype"]

        mock_answer = MagicMock()
        mock_answer.__iter__ = lambda _self, _r=[rdata]: iter(_r)
        return mock_answer

    def build_resolver_mock(self) -> MagicMock:
        """Build a mock dns.asyncresolver.Resolver."""
        bridge = self

        async def resolve(fqdn: str, rdtype: str, **kwargs: Any) -> MagicMock:
            fqdn_str = str(fqdn).rstrip(".")
            rdtype_str = str(rdtype)

            # TLSA queries (DANE)
            if rdtype_str == "TLSA":
                answer = bridge._build_tlsa_answer(fqdn_str)
                if answer:
                    return answer
                raise dns.resolver.NXDOMAIN()

            # Parse FQDN to zone + record_name
            parsed = bridge._parse_fqdn(fqdn_str)
            if parsed is None:
                raise dns.resolver.NXDOMAIN()

            zone, record_name = parsed

            if rdtype_str in ("SVCB", "HTTPS"):
                answer = bridge._build_svcb_answer(zone, record_name)
                if answer is None:
                    raise dns.resolver.NXDOMAIN()
                return answer

            if rdtype_str == "TXT":
                answer = bridge._build_txt_answer(zone, record_name)
                if answer is None:
                    raise dns.resolver.NoAnswer()
                return answer

            raise dns.resolver.NXDOMAIN()

        mock_resolver = MagicMock()
        mock_resolver.resolve = AsyncMock(side_effect=resolve)
        mock_resolver.use_edns = MagicMock()  # DNSSEC check calls this; no-op
        return mock_resolver

    # ── HTTP mock builder ──────────────────────────────────────────────

    def build_http_client_mock(self) -> AsyncMock:
        """Build a mock httpx.AsyncClient that routes requests by URL."""
        bridge = self

        async def mock_get(url: str, **kwargs: Any) -> MagicMock:
            parsed = urlparse(url)
            host = parsed.hostname or ""
            port = parsed.port or 443
            path = parsed.path

            # 1. Cap document — exact URI match (most specific)
            if url in bridge._cap_documents:
                data, raw_bytes = bridge._cap_documents[url]
                resp = MagicMock()
                resp.status_code = 200
                resp.json.return_value = data
                resp.content = raw_bytes
                resp.raise_for_status = MagicMock()
                return resp

            # 2. Agent card — /.well-known/agent.json on known host
            if path == "/.well-known/agent.json" and host in bridge._agent_cards:
                resp = MagicMock()
                resp.status_code = 200
                resp.json.return_value = bridge._agent_cards[host]
                resp.content = json.dumps(bridge._agent_cards[host]).encode()
                resp.raise_for_status = MagicMock()
                return resp

            # 3. HTTP index — specific well-known paths
            index_paths = {
                "/index-wellknown",
                "/.well-known/agents-index.json",
                "/.well-known/agents.json",
            }
            if path in index_paths:
                for domain, data in bridge._http_index_data.items():
                    if domain in host:
                        resp = MagicMock()
                        resp.status_code = 200
                        resp.json.return_value = data
                        resp.content = json.dumps(data).encode()
                        resp.raise_for_status = MagicMock()
                        return resp

            # 4. Endpoint reachability — host:port match
            key = f"{host}:{port}"
            if key in bridge._endpoint_responses:
                resp_data = bridge._endpoint_responses[key]
                resp = MagicMock()
                resp.status_code = resp_data.get("status_code", 200)
                resp.json.return_value = {}
                resp.content = b""
                resp.raise_for_status = MagicMock()
                return resp

            # 5. Default: connection error
            raise httpx.ConnectError(f"Mock: no route for {url}")

        def mock_stream(method: str, url: str, **kwargs: Any):
            # http_index now streams the body with a size cap instead of
            # calling response.json(). Reuse the same URL routing and adapt
            # the resolved response to the streaming interface.
            @asynccontextmanager
            async def _cm():
                resp = await mock_get(url)  # raises ConnectError on no route
                body = getattr(resp, "content", b"") or b""

                async def _aiter_bytes():
                    yield body

                stream_resp = MagicMock()
                stream_resp.status_code = resp.status_code
                stream_resp.headers = {}
                stream_resp.aiter_bytes = _aiter_bytes
                yield stream_resp

            return _cm()

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=mock_get)
        mock_client.stream = MagicMock(side_effect=mock_stream)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        return mock_client

    # ── Patch context manager ──────────────────────────────────────────

    @contextmanager
    def patch_all(self):
        """Patch all DNS and HTTP I/O so discover/verify use MockBackend data.

        Patches:
        - dns.asyncresolver.Resolver (shared by discoverer + validator)
        - httpx.AsyncClient in cap_fetcher, a2a_card, validator, http_index
        - validate_fetch_url (SSRF bypass for test hostnames)
        """
        resolver_mock = self.build_resolver_mock()
        http_mock = self.build_http_client_mock()

        # Build a safe_fetch_bytes mock that reuses the HTTP routing logic.
        # safe_fetch_bytes returns raw bytes (not a Response object), so we
        # adapt the existing mock_get → bytes conversion.
        async def mock_safe_fetch(url: str, **kwargs: Any) -> bytes | None:
            try:
                resp = await http_mock.get(url)
                if resp.status_code != 200:
                    return None
                return resp.content
            except httpx.ConnectError:
                return None

        with ExitStack() as stack:
            # DNS resolver — one patch covers all modules since they share
            # the same dns.asyncresolver module object
            stack.enter_context(patch("dns.asyncresolver.Resolver", return_value=resolver_mock))
            # HTTP clients — validator and http_index still use httpx directly
            for mod in (
                "dns_aid.core.validator",
                "dns_aid.core.http_index",
            ):
                stack.enter_context(patch(f"{mod}.httpx.AsyncClient", return_value=http_mock))
            # cap_fetcher, a2a_card, and discoverer now use safe_fetch_bytes
            stack.enter_context(
                patch(
                    "dns_aid.utils.url_safety.safe_fetch_bytes",
                    side_effect=mock_safe_fetch,
                )
            )
            # SSRF bypass — validate_fetch_url is lazy-imported inside
            # cap_fetcher and a2a_card, so patching at the module level works
            stack.enter_context(
                patch(
                    "dns_aid.utils.url_safety.validate_fetch_url",
                    side_effect=lambda u: u,
                )
            )
            yield


# ── Fixtures ───────────────────────────────────────────────────────────


@pytest.fixture
def dns_bridge(mock_backend: MockBackend) -> MockDNSBridge:
    """MockDNSBridge wired to the test's MockBackend."""
    return MockDNSBridge(mock_backend)
