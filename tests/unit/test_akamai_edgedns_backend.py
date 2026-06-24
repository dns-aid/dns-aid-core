# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for dns_aid.backends.akamai_edgedns module."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from dns_aid.backends.akamai_edgedns import AkamaiEdgeDNSBackend

# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------


class TestAkamaiEdgeDNSBackendInit:
    """Tests for AkamaiEdgeDNSBackend initialization."""

    def test_init_with_explicit_credentials(self):
        """Explicit credential kwargs are stored on the instance."""
        backend = AkamaiEdgeDNSBackend(
            host="akab-test.luna.akamaiapis.net",
            client_token="ct-xxx",
            client_secret="cs-xxx",
            access_token="at-xxx",
        )
        assert backend._host == "akab-test.luna.akamaiapis.net"
        assert backend._client_token == "ct-xxx"
        assert backend._client_secret == "cs-xxx"
        assert backend._access_token == "at-xxx"

    def test_init_from_env_vars(self):
        """Backend reads credentials from AKAMAI_* env vars when kwargs omitted."""
        env = {
            "AKAMAI_HOST": "akab-env.luna.akamaiapis.net",
            "AKAMAI_CLIENT_TOKEN": "ct-env",
            "AKAMAI_CLIENT_SECRET": "cs-env",
            "AKAMAI_ACCESS_TOKEN": "at-env",
        }
        with patch.dict("os.environ", env):
            backend = AkamaiEdgeDNSBackend()
            assert backend._host == "akab-env.luna.akamaiapis.net"
            assert backend._client_token == "ct-env"

    def test_init_defaults(self):
        """Lazy state (client, auth, zone cache) starts uninitialised; edgerc defaults apply."""
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )
        assert backend._client is None
        assert backend._zone_cache == {}
        assert backend._auth is None
        assert backend._edgerc_path == "~/.edgerc"
        assert backend._edgerc_section == "default"

    def test_init_custom_edgerc(self):
        """Custom edgerc_path and edgerc_section kwargs override defaults."""
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
            edgerc_path="/custom/.edgerc",
            edgerc_section="dns",
        )
        assert backend._edgerc_path == "/custom/.edgerc"
        assert backend._edgerc_section == "dns"


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------


class TestAkamaiEdgeDNSBackendProperties:
    """Tests for backend properties."""

    def test_name_property(self):
        """`name` returns the backend's registry identifier."""
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )
        assert backend.name == "akamai-edgedns"

    def test_supports_private_svcb_keys(self):
        """Akamai Edge DNS accepts private-use SVCB keys natively."""
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )
        assert backend.supports_private_svcb_keys is True


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


class TestAkamaiEdgeDNSBackendAuth:
    """Tests for EdgeGrid authentication initialization."""

    def test_ensure_auth_with_env_credentials(self):
        """Real _ensure_auth() initialises EdgeGridAuth from explicit credentials."""
        backend = AkamaiEdgeDNSBackend(
            host="akab-test.luna.akamaiapis.net",
            client_token="ct-xxx",
            client_secret="cs-xxx",
            access_token="at-xxx",
        )
        mock_ega_instance = MagicMock()
        with patch(
            "akamai.edgegrid.EdgeGridAuth", return_value=mock_ega_instance
        ) as mock_ega:
            backend._ensure_auth()

        assert backend._auth is mock_ega_instance
        mock_ega.assert_called_once_with(
            client_token="ct-xxx",
            client_secret="cs-xxx",
            access_token="at-xxx",
        )

    def test_ensure_auth_is_idempotent(self):
        """Second call to _ensure_auth() short-circuits when _auth is already set."""
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )
        existing_auth = MagicMock()
        backend._auth = existing_auth
        backend._ensure_auth()
        assert backend._auth is existing_auth

    def test_ensure_auth_falls_back_to_edgerc(self):
        """When env creds are absent, _ensure_auth() reads credentials from .edgerc."""
        with patch.dict(
            "os.environ",
            {
                "AKAMAI_HOST": "",
                "AKAMAI_CLIENT_TOKEN": "",
                "AKAMAI_CLIENT_SECRET": "",
                "AKAMAI_ACCESS_TOKEN": "",
            },
        ):
            backend = AkamaiEdgeDNSBackend()

        mock_edgerc = MagicMock()
        mock_edgerc.get.return_value = "akab-from-edgerc.luna.akamaiapis.net"
        mock_auth_instance = MagicMock()

        with (
            patch("akamai.edgegrid.EdgeRc", return_value=mock_edgerc),
            patch("akamai.edgegrid.EdgeGridAuth") as mock_ega_cls,
        ):
            mock_ega_cls.from_edgerc.return_value = mock_auth_instance
            backend._ensure_auth()

        assert backend._auth is mock_auth_instance
        mock_ega_cls.from_edgerc.assert_called_once_with(mock_edgerc, "default")

    def test_ensure_auth_raises_without_credentials(self):
        """Missing creds and missing .edgerc raises ValueError with setup hint."""
        backend = AkamaiEdgeDNSBackend()
        backend._edgerc_path = "/nonexistent/.edgerc"
        with pytest.raises(ValueError, match="credentials not configured"):
            backend._ensure_auth()


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class TestAkamaiEdgeDNSBackendClient:
    """Tests for httpx client creation."""

    @pytest.mark.asyncio
    async def test_get_client_creates_client(self):
        """First call to _get_client() returns a real httpx.AsyncClient."""
        backend = AkamaiEdgeDNSBackend(
            host="akab-test.luna.akamaiapis.net",
            client_token="ct-xxx",
            client_secret="cs-xxx",
            access_token="at-xxx",
        )
        mock_auth = MagicMock()
        with patch.object(
            backend, "_ensure_auth", side_effect=lambda: setattr(backend, "_auth", mock_auth)
        ):
            client = await backend._get_client()
            assert isinstance(client, httpx.AsyncClient)
            await backend.close()

    @pytest.mark.asyncio
    async def test_get_client_recreates_on_loop_change(self):
        """Client is replaced when the running event loop changes."""
        backend = AkamaiEdgeDNSBackend(
            host="akab-test.luna.akamaiapis.net",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        # Plant a stale client bound to a different (fake) loop ID
        old_client = AsyncMock(spec=httpx.AsyncClient)
        backend._client = old_client
        backend._client_loop_id = -1  # guaranteed to differ from the real loop id

        mock_auth = MagicMock()
        with patch.object(
            backend, "_ensure_auth", side_effect=lambda: setattr(backend, "_auth", mock_auth)
        ):
            new_client = await backend._get_client()

        assert new_client is not old_client
        old_client.aclose.assert_called_once()
        await backend.close()

    @pytest.mark.asyncio
    async def test_get_client_caches_client(self):
        """Subsequent calls to _get_client() return the same cached instance."""
        backend = AkamaiEdgeDNSBackend(
            host="akab-test.luna.akamaiapis.net",
            client_token="ct-xxx",
            client_secret="cs-xxx",
            access_token="at-xxx",
        )
        mock_auth = MagicMock()
        with patch.object(
            backend, "_ensure_auth", side_effect=lambda: setattr(backend, "_auth", mock_auth)
        ):
            client1 = await backend._get_client()
            client2 = await backend._get_client()
            assert client1 is client2
            await backend.close()


# ---------------------------------------------------------------------------
# Internal _request() helper
# ---------------------------------------------------------------------------


def _make_response(status_code: int, json_body=None, text: str = "") -> MagicMock:
    """Build a mock httpx.Response with the supplied status and body."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.text = text or (str(json_body) if json_body is not None else "")
    resp.content = b"x" if json_body is not None or text else b""
    resp.json = MagicMock(return_value=json_body if json_body is not None else {})

    if status_code >= 400:
        request = httpx.Request("GET", "https://example.com")
        resp.raise_for_status = MagicMock(
            side_effect=httpx.HTTPStatusError("error", request=request, response=resp)
        )
    else:
        resp.raise_for_status = MagicMock()
    return resp


class TestAkamaiEdgeDNSBackendRequest:
    """Tests for the internal _request() helper."""

    @pytest.mark.asyncio
    async def test_request_returns_json_on_success(self):
        """A 200 response returns the parsed JSON body."""
        backend = AkamaiEdgeDNSBackend(
            host="h", client_token="ct", client_secret="cs", access_token="at"
        )
        backend._auth = MagicMock()
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(
            return_value=_make_response(200, json_body={"zone": "example.com"})
        )

        with (
            patch.object(backend, "_get_client", return_value=mock_client),
            patch.object(backend, "_sign_request", return_value={}),
        ):
            result = await backend._request("GET", "/config-dns/v2/zones/example.com")

        assert result == {"zone": "example.com"}

    @pytest.mark.asyncio
    async def test_request_returns_none_on_404(self):
        """A 404 response is converted to None (record/zone not found)."""
        backend = AkamaiEdgeDNSBackend(
            host="h", client_token="ct", client_secret="cs", access_token="at"
        )
        backend._auth = MagicMock()
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=_make_response(404))

        with (
            patch.object(backend, "_get_client", return_value=mock_client),
            patch.object(backend, "_sign_request", return_value={}),
        ):
            result = await backend._request("GET", "/config-dns/v2/zones/missing.com")

        assert result is None

    @pytest.mark.asyncio
    async def test_request_raises_value_error_on_transport_error(self):
        """httpx.HTTPError raised by the client is converted to ValueError."""
        backend = AkamaiEdgeDNSBackend(
            host="h", client_token="ct", client_secret="cs", access_token="at"
        )
        backend._auth = MagicMock()
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(side_effect=httpx.ConnectError("refused"))

        with (
            patch.object(backend, "_get_client", return_value=mock_client),
            patch.object(backend, "_sign_request", return_value={}),
        ):
            with pytest.raises(ValueError, match="transport error"):
                await backend._request("GET", "/config-dns/v2/zones/example.com")

    @pytest.mark.asyncio
    async def test_request_raises_value_error_on_api_error_status(self):
        """A non-404 HTTP error status is converted to ValueError."""
        backend = AkamaiEdgeDNSBackend(
            host="h", client_token="ct", client_secret="cs", access_token="at"
        )
        backend._auth = MagicMock()
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(
            return_value=_make_response(403, text="Forbidden")
        )

        with (
            patch.object(backend, "_get_client", return_value=mock_client),
            patch.object(backend, "_sign_request", return_value={}),
        ):
            with pytest.raises(ValueError, match="status=403"):
                await backend._request("GET", "/config-dns/v2/zones/example.com")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TestAkamaiEdgeDNSBackendHelpers:
    """Tests for helper methods."""

    def test_to_fqdn(self):
        """`_to_fqdn` joins a relative name to its zone."""
        assert (
            AkamaiEdgeDNSBackend._to_fqdn("_chat._a2a._agents", "example.com")
            == "_chat._a2a._agents.example.com"
        )

    def test_to_fqdn_already_qualified(self):
        """Names already ending with the zone are returned unchanged."""
        assert (
            AkamaiEdgeDNSBackend._to_fqdn("_chat._agents.example.com", "example.com")
            == "_chat._agents.example.com"
        )

    def test_to_fqdn_strips_trailing_dot(self):
        """Trailing dots on the zone are stripped from the resulting FQDN."""
        assert AkamaiEdgeDNSBackend._to_fqdn("_chat", "example.com.") == "_chat.example.com"

    def test_extract_name_from_fqdn(self):
        """`_extract_name_from_fqdn` strips the zone suffix to recover the record name."""
        assert (
            AkamaiEdgeDNSBackend._extract_name_from_fqdn("_chat._agents.example.com", "example.com")
            == "_chat._agents"
        )

    def test_extract_name_from_fqdn_no_match(self):
        """FQDN that does not end with the zone is returned unchanged."""
        assert (
            AkamaiEdgeDNSBackend._extract_name_from_fqdn("other.net", "example.com") == "other.net"
        )

    def test_to_numeric_key_custom(self):
        """DNS-AID custom param names map to private-use key65400-key65408."""
        assert AkamaiEdgeDNSBackend._to_numeric_key("cap") == "key65400"
        assert AkamaiEdgeDNSBackend._to_numeric_key("bap") == "key65402"
        assert AkamaiEdgeDNSBackend._to_numeric_key("realm") == "key65404"

    def test_to_numeric_key_standard(self):
        """Standard SVCB param names (alpn, port) pass through unchanged."""
        assert AkamaiEdgeDNSBackend._to_numeric_key("alpn") == "alpn"
        assert AkamaiEdgeDNSBackend._to_numeric_key("port") == "port"

    def test_to_numeric_key_already_numeric(self):
        """Already numeric keyNNNNN strings pass through unchanged."""
        assert AkamaiEdgeDNSBackend._to_numeric_key("key65500") == "key65500"

    def test_from_numeric_key(self):
        """Numeric key65400-key65408 map back to DNS-AID names."""
        assert AkamaiEdgeDNSBackend._from_numeric_key("key65400") == "cap"
        assert AkamaiEdgeDNSBackend._from_numeric_key("key65402") == "bap"

    def test_from_numeric_key_unknown(self):
        """Unknown standard keys (alpn) pass through unchanged."""
        assert AkamaiEdgeDNSBackend._from_numeric_key("alpn") == "alpn"

    def test_build_url(self):
        """`_build_url` prefixes the host with https:// when scheme is missing."""
        backend = AkamaiEdgeDNSBackend(
            host="akab-test.luna.akamaiapis.net",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )
        assert (
            backend._build_url("/config-dns/v2/zones")
            == "https://akab-test.luna.akamaiapis.net/config-dns/v2/zones"
        )

    def test_build_url_with_https_prefix(self):
        """An explicit https:// prefix on the host is preserved (no double-scheme)."""
        backend = AkamaiEdgeDNSBackend(
            host="https://akab-test.luna.akamaiapis.net",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )
        assert (
            backend._build_url("/config-dns/v2/zones")
            == "https://akab-test.luna.akamaiapis.net/config-dns/v2/zones"
        )


# ---------------------------------------------------------------------------
# SVCB rdata formatting
# ---------------------------------------------------------------------------


class TestAkamaiEdgeDNSBackendSvcbFormat:
    """Tests for SVCB rdata formatting."""

    def test_format_svcb_rdata_basic(self):
        """Standard alpn/port params are emitted in presentation format."""
        rdata = AkamaiEdgeDNSBackend._format_svcb_rdata(
            priority=1,
            target="chat.example.com",
            params={"alpn": "a2a", "port": "443"},
        )
        assert rdata.startswith("1 chat.example.com.")
        assert 'alpn="a2a"' in rdata
        assert 'port="443"' in rdata

    def test_format_svcb_rdata_trailing_dot_preserved(self):
        """Targets already ending in '.' are not double-dotted."""
        rdata = AkamaiEdgeDNSBackend._format_svcb_rdata(
            priority=1,
            target="chat.example.com.",
            params={},
        )
        assert rdata == "1 chat.example.com."

    def test_format_svcb_rdata_custom_params_mapped(self):
        """DNS-AID custom params are rewritten to their numeric key alias."""
        rdata = AkamaiEdgeDNSBackend._format_svcb_rdata(
            priority=1,
            target="chat.example.com",
            params={"alpn": "mcp", "cap": "https://cap.example.com"},
        )
        assert 'key65400="https://cap.example.com"' in rdata
        assert 'alpn="mcp"' in rdata

    def test_format_svcb_rdata_no_params(self):
        """Priority 0 with no params produces a bare AliasMode record."""
        rdata = AkamaiEdgeDNSBackend._format_svcb_rdata(
            priority=0,
            target="alias.example.com.",
            params={},
        )
        assert rdata == "0 alias.example.com."

    def test_format_svcb_rdata_all_custom_params(self):
        """cap/bap/realm all map to their assigned private-use keys."""
        rdata = AkamaiEdgeDNSBackend._format_svcb_rdata(
            priority=1,
            target="t.example.com",
            params={
                "cap": "https://cap.example.com",
                "bap": "mcp=1.0",
                "realm": "prod",
            },
        )
        assert 'key65400="https://cap.example.com"' in rdata
        assert 'key65402="mcp=1.0"' in rdata
        assert 'key65404="prod"' in rdata


# ---------------------------------------------------------------------------
# Create SVCB record
# ---------------------------------------------------------------------------


class TestAkamaiEdgeDNSBackendCreateSvcb:
    """Tests for SVCB record creation."""

    @pytest.mark.asyncio
    async def test_create_svcb_record_new(self):
        """No existing record → POST is issued and the FQDN is returned."""
        backend = AkamaiEdgeDNSBackend(
            host="akab-test.luna.akamaiapis.net",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        call_log: list[tuple[str, str]] = []

        async def mock_request(method, path, **kwargs):
            call_log.append((method, path))
            if method == "GET":
                return None  # record doesn't exist
            return {}

        with patch.object(backend, "_request", side_effect=mock_request):
            result = await backend.create_svcb_record(
                zone="example.com",
                name="_chat._a2a._agents",
                priority=1,
                target="chat.example.com",
                params={"alpn": "a2a", "port": "443"},
                ttl=3600,
            )

        assert result == "_chat._a2a._agents.example.com"
        assert call_log[0] == (
            "GET",
            "/config-dns/v2/zones/example.com/names/_chat._a2a._agents.example.com/types/SVCB",
        )
        assert call_log[1][0] == "POST"

    @pytest.mark.asyncio
    async def test_create_svcb_record_update_existing(self):
        """Existing record → PUT (upsert) is issued instead of POST."""
        backend = AkamaiEdgeDNSBackend(
            host="akab-test.luna.akamaiapis.net",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        call_log: list[tuple[str, str]] = []

        async def mock_request(method, path, **kwargs):
            call_log.append((method, path))
            if method == "GET":
                return {"name": "fqdn", "type": "SVCB", "ttl": 3600, "rdata": ["1 old."]}
            return {}

        with patch.object(backend, "_request", side_effect=mock_request):
            result = await backend.create_svcb_record(
                zone="example.com",
                name="_chat._a2a._agents",
                priority=1,
                target="chat.example.com",
                params={"alpn": "a2a"},
                ttl=3600,
            )

        assert result == "_chat._a2a._agents.example.com"
        assert call_log[1][0] == "PUT"

    @pytest.mark.asyncio
    async def test_create_svcb_passes_custom_params_natively(self):
        """DNS-AID custom params reach the SVCB rdata mapped to private-use keys."""
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        captured_payload: list[dict] = []

        async def mock_request(method, path, *, json_data=None, **kwargs):
            if method == "GET":
                return None
            if json_data:
                captured_payload.append(json_data)
            return {}

        with patch.object(backend, "_request", side_effect=mock_request):
            await backend.create_svcb_record(
                zone="example.com",
                name="agent",
                priority=1,
                target="agent.example.com",
                params={"alpn": "mcp", "port": "443", "cap": "https://c.example.com"},
            )

        rdata = captured_payload[0]["rdata"][0]
        assert 'key65400="https://c.example.com"' in rdata
        assert 'alpn="mcp"' in rdata


# ---------------------------------------------------------------------------
# Create TXT record
# ---------------------------------------------------------------------------


class TestAkamaiEdgeDNSBackendCreateTxt:
    """Tests for TXT record creation."""

    @pytest.mark.asyncio
    async def test_create_txt_record_new(self):
        """No existing record → POST is issued with joined rdata."""
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        captured_payload: list[dict] = []

        async def mock_request(method, path, *, json_data=None, **kwargs):
            if method == "GET":
                return None
            if json_data:
                captured_payload.append(json_data)
            return {}

        with patch.object(backend, "_request", side_effect=mock_request):
            result = await backend.create_txt_record(
                zone="example.com",
                name="_chat._agents",
                values=["capabilities=chat,code", "version=1.0.0"],
                ttl=3600,
            )

        assert result == "_chat._agents.example.com"
        assert captured_payload[0]["type"] == "TXT"
        assert "capabilities=chat,code version=1.0.0" in captured_payload[0]["rdata"][0]

    @pytest.mark.asyncio
    async def test_create_txt_record_update_existing(self):
        """Existing TXT record → PUT (upsert) is issued instead of POST."""
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        call_log: list[tuple[str, str]] = []

        async def mock_request(method, path, **kwargs):
            call_log.append((method, path))
            if method == "GET":
                return {
                    "name": "_chat._agents.example.com",
                    "type": "TXT",
                    "ttl": 3600,
                    "rdata": ["capabilities=old"],
                }
            return {}

        with patch.object(backend, "_request", side_effect=mock_request):
            result = await backend.create_txt_record(
                zone="example.com",
                name="_chat._agents",
                values=["capabilities=new"],
                ttl=3600,
            )

        assert result == "_chat._agents.example.com"
        assert call_log[1][0] == "PUT"


# ---------------------------------------------------------------------------
# Delete record
# ---------------------------------------------------------------------------


class TestAkamaiEdgeDNSBackendDeleteRecord:
    """Tests for record deletion."""

    @pytest.mark.asyncio
    async def test_delete_record_success(self):
        """A successful DELETE returns True."""
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        async def mock_request(method, path, **kwargs):
            return {}

        with patch.object(backend, "_request", side_effect=mock_request):
            result = await backend.delete_record(
                zone="example.com",
                name="_chat._agents",
                record_type="SVCB",
            )

        assert result is True

    @pytest.mark.asyncio
    async def test_delete_record_not_found(self):
        """A 404 (via _request returning None) returns False, not an exception."""
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        async def mock_request(method, path, **kwargs):
            return None

        with patch.object(backend, "_request", side_effect=mock_request):
            result = await backend.delete_record(
                zone="example.com",
                name="_nonexistent._agents",
                record_type="SVCB",
            )

        assert result is False

    @pytest.mark.asyncio
    async def test_delete_record_returns_false_on_api_error(self):
        """An API error (e.g. 500) is swallowed and delete_record returns False."""
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        async def mock_request(method, path, **kwargs):
            raise ValueError("API error 500")

        with patch.object(backend, "_request", side_effect=mock_request):
            result = await backend.delete_record(
                zone="example.com",
                name="_chat._agents",
                record_type="SVCB",
            )

        assert result is False


# ---------------------------------------------------------------------------
# List records
# ---------------------------------------------------------------------------


class TestAkamaiEdgeDNSBackendListRecords:
    """Tests for record listing."""

    @pytest.mark.asyncio
    async def test_list_records_all(self):
        """list_records yields both SVCB and TXT recordsets returned by the API."""
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        async def mock_request(method, path, *, params=None, **kwargs):
            return {
                "recordsets": [
                    {
                        "name": "_chat._agents.example.com",
                        "type": "SVCB",
                        "ttl": 3600,
                        "rdata": ['1 chat.example.com. alpn="mcp"'],
                    },
                    {
                        "name": "_chat._agents.example.com",
                        "type": "TXT",
                        "ttl": 3600,
                        "rdata": ["capabilities=chat"],
                    },
                ],
                "metadata": {"totalElements": 2, "pageSize": 100},
            }

        with patch.object(backend, "_request", side_effect=mock_request):
            records = []
            async for record in backend.list_records(zone="example.com"):
                records.append(record)

        assert len(records) == 2
        assert records[0]["type"] == "SVCB"
        assert records[1]["type"] == "TXT"

    @pytest.mark.asyncio
    async def test_list_records_filter_by_name(self):
        """A name_pattern substring filter drops non-matching records."""
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        async def mock_request(method, path, *, params=None, **kwargs):
            return {
                "recordsets": [
                    {"name": "_chat._agents.example.com", "type": "SVCB", "ttl": 3600, "rdata": []},
                    {"name": "www.example.com", "type": "A", "ttl": 300, "rdata": []},
                ],
                "metadata": {"totalElements": 2, "pageSize": 100},
            }

        with patch.object(backend, "_request", side_effect=mock_request):
            records = []
            async for record in backend.list_records(zone="example.com", name_pattern="_agents"):
                records.append(record)

        assert len(records) == 1
        assert "_agents" in records[0]["fqdn"]

    @pytest.mark.asyncio
    async def test_list_records_record_type_as_types_param(self):
        """record_type is forwarded as the types= query parameter to the API."""
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        captured_params: list[dict] = []

        async def mock_request(method, path, *, params=None, **kwargs):
            if params:
                captured_params.append(dict(params))
            return {"recordsets": [], "metadata": {"totalElements": 0, "pageSize": 100}}

        with patch.object(backend, "_request", side_effect=mock_request):
            async for _ in backend.list_records(zone="example.com", record_type="SVCB"):
                pass

        assert captured_params[0]["types"] == "SVCB"

    @pytest.mark.asyncio
    async def test_list_records_pagination(self):
        """Pagination metadata drives multiple GET pages until total is reached."""
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        call_count = 0

        async def mock_request(method, path, *, params=None, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {
                    "recordsets": [
                        {"name": "a.example.com", "type": "TXT", "ttl": 300, "rdata": ["v1"]},
                    ],
                    "metadata": {"totalElements": 2, "pageSize": 1},
                }
            return {
                "recordsets": [
                    {"name": "b.example.com", "type": "TXT", "ttl": 300, "rdata": ["v2"]},
                ],
                "metadata": {"totalElements": 2, "pageSize": 1},
            }

        with patch.object(backend, "_request", side_effect=mock_request):
            records = []
            async for record in backend.list_records(zone="example.com"):
                records.append(record)

        assert len(records) == 2


# ---------------------------------------------------------------------------
# Zone exists
# ---------------------------------------------------------------------------


class TestAkamaiEdgeDNSBackendZoneExists:
    """Tests for zone existence check."""

    @pytest.mark.asyncio
    async def test_zone_exists_true(self):
        """A 200 zone GET returns True and caches the positive answer."""
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        async def mock_request(method, path, **kwargs):
            return {"zone": "example.com", "type": "primary"}

        with patch.object(backend, "_request", side_effect=mock_request):
            result = await backend.zone_exists("example.com")

        assert result is True
        assert backend._zone_cache["example.com"] is True

    @pytest.mark.asyncio
    async def test_zone_exists_false(self):
        """A 404 zone GET returns False and caches the negative answer."""
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        async def mock_request(method, path, **kwargs):
            return None

        with patch.object(backend, "_request", side_effect=mock_request):
            result = await backend.zone_exists("notfound.com")

        assert result is False
        assert backend._zone_cache["notfound.com"] is False

    @pytest.mark.asyncio
    async def test_zone_exists_cached(self):
        """A cached entry short-circuits the API call entirely."""
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )
        backend._zone_cache["cached.com"] = True

        result = await backend.zone_exists("cached.com")
        assert result is True

    @pytest.mark.asyncio
    async def test_zone_exists_error_returns_false(self):
        """zone_exists swallows API errors and returns False (never raises)."""
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        async def mock_request(method, path, **kwargs):
            raise ValueError("API error")

        with patch.object(backend, "_request", side_effect=mock_request):
            result = await backend.zone_exists("error.com")

        assert result is False


# ---------------------------------------------------------------------------
# List zones
# ---------------------------------------------------------------------------


class TestAkamaiEdgeDNSBackendListZones:
    """Tests for listing zones."""

    @pytest.mark.asyncio
    async def test_list_zones(self):
        """list_zones returns the full shape (id, name, type, contract_id)."""
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        async def mock_request(method, path, *, params=None, **kwargs):
            return {
                "zones": [
                    {"zone": "example.com", "type": "primary", "contractId": "ctr-123"},
                    {"zone": "other.com", "type": "secondary", "contractId": "ctr-456"},
                ],
                "metadata": {"totalElements": 2, "pageSize": 100},
            }

        with patch.object(backend, "_request", side_effect=mock_request):
            zones = await backend.list_zones()

        assert len(zones) == 2
        assert zones[0]["id"] == "example.com"
        assert zones[0]["name"] == "example.com"
        assert zones[0]["type"] == "primary"
        assert zones[0]["contract_id"] == "ctr-123"
        assert zones[1]["name"] == "other.com"
        assert zones[1]["contract_id"] == "ctr-456"


# ---------------------------------------------------------------------------
# Close
# ---------------------------------------------------------------------------


class TestAkamaiEdgeDNSBackendClose:
    """Tests for client cleanup."""

    @pytest.mark.asyncio
    async def test_close(self):
        """close() releases the cached httpx client."""
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        mock_auth = MagicMock()
        with patch.object(
            backend, "_ensure_auth", side_effect=lambda: setattr(backend, "_auth", mock_auth)
        ):
            await backend._get_client()
            assert backend._client is not None

            await backend.close()
            assert backend._client is None

    @pytest.mark.asyncio
    async def test_close_is_no_op_when_already_closed(self):
        """Second close() call does not raise and leaves _client as None."""
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        mock_auth = MagicMock()
        with patch.object(
            backend, "_ensure_auth", side_effect=lambda: setattr(backend, "_auth", mock_auth)
        ):
            await backend._get_client()

        await backend.close()
        assert backend._client is None

        # Second call — must not raise
        await backend.close()
        assert backend._client is None


# ---------------------------------------------------------------------------
# Get record
# ---------------------------------------------------------------------------


class TestAkamaiEdgeDNSBackendGetRecord:
    """Tests for get_record method."""

    @pytest.mark.asyncio
    async def test_get_record_found(self):
        """A 200 record GET returns a normalised record dict."""
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        async def mock_request(method, path, **kwargs):
            return {
                "name": "_chat._agents.example.com",
                "type": "SVCB",
                "ttl": 3600,
                "rdata": ['1 chat.example.com. alpn="a2a"'],
            }

        with patch.object(backend, "_request", side_effect=mock_request):
            record = await backend.get_record("example.com", "_chat._agents", "SVCB")

        assert record is not None
        assert record["type"] == "SVCB"
        assert record["fqdn"] == "_chat._agents.example.com"
        assert '1 chat.example.com. alpn="a2a"' in record["values"]

    @pytest.mark.asyncio
    async def test_get_record_not_found(self):
        """A 404 record GET returns None (no record at that name+type)."""
        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        async def mock_request(method, path, **kwargs):
            return None

        with patch.object(backend, "_request", side_effect=mock_request):
            record = await backend.get_record("example.com", "_missing._agents", "SVCB")

        assert record is None


# ---------------------------------------------------------------------------
# Param demotion (should NOT demote — supports_private_svcb_keys = True)
# ---------------------------------------------------------------------------


class TestAkamaiEdgeDNSBackendPublishAgentNoDemotion:
    """Akamai Edge DNS passes ALL SVCB params natively — no demotion to TXT."""

    @pytest.mark.asyncio
    async def test_publish_passes_all_params_to_svcb(self):
        """Custom DNS-AID params land in the SVCB record, not as TXT fallbacks."""
        from dns_aid.core.models import AgentRecord, Protocol

        agent = AgentRecord(
            name="lf-test",
            domain="example.com",
            protocol=Protocol.MCP,
            target_host="lf-test.example.com",
            port=443,
            capabilities=["testing"],
            realm="demo",
            publish_walkable_alias=True,
        )

        backend = AkamaiEdgeDNSBackend(
            host="h",
            client_token="ct",
            client_secret="cs",
            access_token="at",
        )

        svcb_calls: list[dict] = []
        txt_calls: list[dict] = []

        async def _mock_create_svcb(**kwargs):
            svcb_calls.append(kwargs)
            return f"SVCB {kwargs.get('name', '')}.{kwargs.get('zone', '')}"

        async def _mock_create_txt(**kwargs):
            txt_calls.append(kwargs)
            return f"TXT {kwargs.get('name', '')}.{kwargs.get('zone', '')}"

        with (
            patch.object(backend, "create_svcb_record", side_effect=_mock_create_svcb),
            patch.object(backend, "create_txt_record", side_effect=_mock_create_txt),
        ):
            records = await backend.publish_agent(agent)

        # SVCB primary + TXT + walkable AliasMode
        assert any(r.startswith("SVCB") for r in records)

        # SVCB params SHOULD contain custom keys (no demotion)
        svcb_params = svcb_calls[0]["params"]
        custom_keys = [
            k
            for k in svcb_params
            if k
            not in {
                "mandatory",
                "alpn",
                "no-default-alpn",
                "port",
                "ipv4hint",
                "ipv6hint",
                "ech",
            }
        ]
        assert len(custom_keys) > 0, "Custom params should be in SVCB, not demoted"

        # TXT should NOT contain dnsaid_ demoted params
        if txt_calls:
            txt_values = txt_calls[0]["values"]
            dnsaid_txt = [v for v in txt_values if v.startswith("dnsaid_")]
            assert len(dnsaid_txt) == 0, "No dnsaid_ params should appear in TXT"


# ---------------------------------------------------------------------------
# Factory wiring & CLI registry contract
# ---------------------------------------------------------------------------


class TestAkamaiEdgeDNSBackendFactoryWiring:
    """create_backend("akamai-edgedns") wiring and env registry contract."""

    def test_factory_creates_akamai_backend(self):
        """create_backend("akamai-edgedns") returns AkamaiEdgeDNSBackend."""
        from dns_aid.backends import create_backend

        backend = create_backend("akamai-edgedns")
        assert isinstance(backend, AkamaiEdgeDNSBackend)

    def test_akamai_host_in_optional_env_registry(self):
        """AKAMAI_HOST is advertised in the CLI backend registry."""
        from dns_aid.cli.backends import BACKEND_REGISTRY

        assert "AKAMAI_HOST" in BACKEND_REGISTRY["akamai-edgedns"].optional_env

    def test_akamai_client_token_in_optional_env_registry(self):
        """AKAMAI_CLIENT_TOKEN is advertised in the CLI backend registry."""
        from dns_aid.cli.backends import BACKEND_REGISTRY

        assert "AKAMAI_CLIENT_TOKEN" in BACKEND_REGISTRY["akamai-edgedns"].optional_env

    def test_akamai_client_secret_in_optional_env_registry(self):
        """AKAMAI_CLIENT_SECRET is advertised in the CLI backend registry."""
        from dns_aid.cli.backends import BACKEND_REGISTRY

        assert "AKAMAI_CLIENT_SECRET" in BACKEND_REGISTRY["akamai-edgedns"].optional_env

    def test_akamai_access_token_in_optional_env_registry(self):
        """AKAMAI_ACCESS_TOKEN is advertised in the CLI backend registry."""
        from dns_aid.cli.backends import BACKEND_REGISTRY

        assert "AKAMAI_ACCESS_TOKEN" in BACKEND_REGISTRY["akamai-edgedns"].optional_env

    def test_akamai_edgerc_in_optional_env_registry(self):
        """AKAMAI_EDGERC and AKAMAI_EDGERC_SECTION are advertised in the CLI registry."""
        from dns_aid.cli.backends import BACKEND_REGISTRY

        assert "AKAMAI_EDGERC" in BACKEND_REGISTRY["akamai-edgedns"].optional_env
        assert "AKAMAI_EDGERC_SECTION" in BACKEND_REGISTRY["akamai-edgedns"].optional_env

    def test_akamai_required_env_is_empty(self):
        """No env vars are *required* — creds resolve via env OR ~/.edgerc."""
        from dns_aid.cli.backends import BACKEND_REGISTRY

        assert BACKEND_REGISTRY["akamai-edgedns"].required_env == {}
