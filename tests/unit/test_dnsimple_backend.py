# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for dns_aid.backends.dnsimple module."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from dns_aid.backends.dnsimple import DEFAULT_BASE_URL, DNSimpleBackend

DNSIMPLE_ENV_VARS = ("DNSIMPLE_TOKEN", "DNSIMPLE_ACCOUNT_ID", "DNSIMPLE_BASE_URL")


@pytest.fixture(autouse=True)
def _clear_dnsimple_env(monkeypatch):
    """Remove DNSimple environment variables so that tests are isolated."""
    for var in DNSIMPLE_ENV_VARS:
        monkeypatch.delenv(var, raising=False)


def _json_response(data: dict) -> MagicMock:
    """Make a mock 200 response with a DNSimple ``data`` envelope."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"data": data}
    mock_response.raise_for_status = MagicMock()
    return mock_response


def _whoami_response(account: dict | None, user: dict | None = None) -> MagicMock:
    """Make a mock response for GET /v2/whoami."""
    return _json_response({"user": user, "account": account})


class TestDNSimpleBackendInit:
    """Tests for DNSimpleBackend initialization."""

    def test_init_with_token(self):
        """Test initialization with token."""
        backend = DNSimpleBackend(token="test-token-123")
        assert backend._token == "test-token-123"

    def test_init_with_account_id(self):
        """Test initialization with account ID."""
        backend = DNSimpleBackend(token="token", account_id="149004")
        assert backend._account_id == "149004"

    def test_init_with_base_url(self):
        """Test initialization with custom base URL."""
        backend = DNSimpleBackend(token="token", base_url="https://api.sandbox.dnsimple.com")
        assert backend._base_url == "https://api.sandbox.dnsimple.com"

    def test_init_strips_trailing_slash_from_base_url(self):
        """Test that trailing slash is stripped from base URL."""
        backend = DNSimpleBackend(token="token", base_url="https://api.sandbox.dnsimple.com/")
        assert backend._base_url == "https://api.sandbox.dnsimple.com"

    def test_init_from_env_token(self):
        """Test token from environment variable."""
        with patch.dict("os.environ", {"DNSIMPLE_TOKEN": "env-token"}):
            backend = DNSimpleBackend()
            assert backend._token == "env-token"

    def test_init_from_env_account_id(self):
        """Test account ID from environment variable."""
        with patch.dict(
            "os.environ",
            {"DNSIMPLE_TOKEN": "token", "DNSIMPLE_ACCOUNT_ID": "12345"},
        ):
            backend = DNSimpleBackend()
            assert backend._account_id == "12345"

    def test_init_from_env_base_url(self):
        """Test base URL from environment variable."""
        with patch.dict(
            "os.environ",
            {
                "DNSIMPLE_TOKEN": "token",
                "DNSIMPLE_BASE_URL": "https://api.sandbox.dnsimple.com/",
            },
        ):
            backend = DNSimpleBackend()
            assert backend._base_url == "https://api.sandbox.dnsimple.com"

    def test_init_explicit_args_override_env(self):
        """Test that explicit arguments take precedence over env vars."""
        with patch.dict(
            "os.environ",
            {
                "DNSIMPLE_TOKEN": "env-token",
                "DNSIMPLE_ACCOUNT_ID": "111",
                "DNSIMPLE_BASE_URL": "https://env.example.com",
            },
        ):
            backend = DNSimpleBackend(
                token="arg-token",
                account_id="222",
                base_url="https://arg.example.com",
            )
            assert backend._token == "arg-token"
            assert backend._account_id == "222"
            assert backend._base_url == "https://arg.example.com"

    def test_init_defaults(self):
        """Test default values."""
        backend = DNSimpleBackend(token="token")
        assert backend._client is None
        assert backend._zone_cache == {}
        assert backend._account_id is None
        assert backend._base_url == "https://api.dnsimple.com"
        assert DEFAULT_BASE_URL == "https://api.dnsimple.com"

    def test_init_without_credentials_does_not_raise(self):
        """Test that constructor does not validate credentials."""
        backend = DNSimpleBackend()
        assert backend._token is None
        assert backend._account_id is None
        assert backend._client is None


class TestDNSimpleBackendProperties:
    """Tests for DNSimpleBackend properties."""

    def test_name_property(self):
        """Test name property returns 'dnsimple'."""
        backend = DNSimpleBackend(token="token")
        assert backend.name == "dnsimple"

    def test_supports_private_svcb_keys(self):
        """Test that DNSimple supports private-use SVCB keys."""
        backend = DNSimpleBackend(token="token")
        assert backend.supports_private_svcb_keys is True


class TestDNSimpleBackendClient:
    """Tests for httpx client creation."""

    @pytest.mark.asyncio
    async def test_get_client_creates_client(self):
        """Test that _get_client creates httpx client with auth headers."""
        backend = DNSimpleBackend(token="test-token")

        client = await backend._get_client()

        assert isinstance(client, httpx.AsyncClient)
        assert client.headers["Authorization"] == "Bearer test-token"
        assert client.headers["Accept"] == "application/json"
        assert client.headers["Content-Type"] == "application/json"
        assert "dns-aid" in client.headers["User-Agent"]

        await backend.close()

    @pytest.mark.asyncio
    async def test_get_client_uses_base_url(self):
        """Test that client uses the configured base URL."""
        backend = DNSimpleBackend(token="test-token", base_url="https://api.sandbox.dnsimple.com/")

        client = await backend._get_client()

        assert str(client.base_url).rstrip("/") == "https://api.sandbox.dnsimple.com"

        await backend.close()

    @pytest.mark.asyncio
    async def test_get_client_uses_default_base_url(self):
        """Test that client uses the default base URL."""
        backend = DNSimpleBackend(token="test-token")

        client = await backend._get_client()

        assert str(client.base_url).rstrip("/") == "https://api.dnsimple.com"

        await backend.close()

    @pytest.mark.asyncio
    async def test_get_client_caches_client(self):
        """Test that client is cached."""
        backend = DNSimpleBackend(token="test-token")

        client1 = await backend._get_client()
        client2 = await backend._get_client()

        assert client1 is client2

        await backend.close()

    @pytest.mark.asyncio
    async def test_get_client_raises_without_token(self):
        """Test that missing token raises ValueError."""
        backend = DNSimpleBackend()
        backend._token = None

        with pytest.raises(ValueError, match="token not configured"):
            await backend._get_client()


class TestDNSimpleBackendAccountId:
    """Tests for account ID resolution."""

    @pytest.mark.asyncio
    async def test_get_account_id_configured(self):
        """Test that configured account ID is returned without HTTP calls."""
        backend = DNSimpleBackend(token="token", account_id="149004")

        mock_client = AsyncMock()
        mock_client.get = AsyncMock()

        with patch.object(backend, "_get_client", return_value=mock_client):
            account_id = await backend._get_account_id()
            assert account_id == "149004"
            mock_client.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_account_id_from_whoami(self):
        """Test account ID lookup from whoami endpoint."""
        backend = DNSimpleBackend(token="token")

        mock_response = _whoami_response({"id": 149004, "email": "ops@example.com"})

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch.object(backend, "_get_client", return_value=mock_client):
            account_id = await backend._get_account_id()
            assert account_id == "149004"
            assert isinstance(account_id, str)
            mock_client.get.assert_called_once()
            assert mock_client.get.call_args[0][0] == "/v2/whoami"

    @pytest.mark.asyncio
    async def test_get_account_id_caches_result(self):
        """Test that account ID from whoami is cached."""
        backend = DNSimpleBackend(token="token")

        mock_response = _whoami_response({"id": 149004, "email": "ops@example.com"})

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch.object(backend, "_get_client", return_value=mock_client):
            first = await backend._get_account_id()
            second = await backend._get_account_id()
            assert first == second == "149004"
            assert backend._account_id == "149004"
            mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_account_id_user_token_raises(self):
        """Test that a user token (no account in whoami) raises ValueError."""
        backend = DNSimpleBackend(token="token")

        mock_response = _whoami_response(None, user={"id": 1, "email": "user@example.com"})

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with (
            patch.object(backend, "_get_client", return_value=mock_client),
            pytest.raises(ValueError, match="DNSIMPLE_ACCOUNT_ID"),
        ):
            await backend._get_account_id()


class TestDNSimpleBackendZone:
    """Tests for zone resolution."""

    @pytest.mark.asyncio
    async def test_get_zone_from_cache(self):
        """Test that cached zone is returned."""
        backend = DNSimpleBackend(token="token", account_id="149004")
        backend._zone_cache["example.com"] = {"id": 1, "name": "example.com"}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock()

        with patch.object(backend, "_get_client", return_value=mock_client):
            zone = await backend._get_zone("example.com")
            assert zone == {"id": 1, "name": "example.com"}
            mock_client.get.assert_not_called()

    @pytest.mark.asyncio
    async def test_get_zone_from_api(self):
        """Test zone lookup from API."""
        backend = DNSimpleBackend(token="token", account_id="149004")

        mock_response = _json_response({"id": 1, "account_id": 149004, "name": "example.com"})

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch.object(backend, "_get_client", return_value=mock_client):
            zone = await backend._get_zone("example.com")
            assert zone == {"id": 1, "account_id": 149004, "name": "example.com"}
            assert backend._zone_cache["example.com"] == zone
            assert mock_client.get.call_args[0][0] == "/v2/149004/zones/example.com"

    @pytest.mark.asyncio
    async def test_get_zone_normalizes_name(self):
        """Test that zone name is lowercased and trailing dot is stripped."""
        backend = DNSimpleBackend(token="token", account_id="149004")

        mock_response = _json_response({"id": 1, "name": "example.com"})

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch.object(backend, "_get_client", return_value=mock_client):
            await backend._get_zone("Example.COM.")
            assert mock_client.get.call_args[0][0] == "/v2/149004/zones/example.com"
            assert "example.com" in backend._zone_cache

    @pytest.mark.asyncio
    async def test_get_zone_strips_trailing_dot(self):
        """Test that trailing dots are stripped for cache lookup."""
        backend = DNSimpleBackend(token="token", account_id="149004")
        backend._zone_cache["example.com"] = {"id": 1, "name": "example.com"}

        zone = await backend._get_zone("example.com.")
        assert zone == {"id": 1, "name": "example.com"}

    @pytest.mark.asyncio
    async def test_get_zone_uses_cache_on_second_call(self):
        """Test that second lookup does not call the API."""
        backend = DNSimpleBackend(token="token", account_id="149004")

        mock_response = _json_response({"id": 1, "name": "example.com"})

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with patch.object(backend, "_get_client", return_value=mock_client):
            await backend._get_zone("example.com")
            await backend._get_zone("example.com")
            mock_client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_zone_not_found(self):
        """Test zone lookup when zone does not exist."""
        backend = DNSimpleBackend(token="token", account_id="149004")

        mock_response = MagicMock()
        mock_response.status_code = 404

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_response)

        with (
            patch.object(backend, "_get_client", return_value=mock_client),
            pytest.raises(ValueError, match="No zone found"),
        ):
            await backend._get_zone("notfound.com")

    @pytest.mark.asyncio
    async def test_get_zone_propagates_server_errors(self):
        """Test that non-404 errors propagate from raise_for_status."""
        backend = DNSimpleBackend(token="token", account_id="149004")

        mock_500 = MagicMock()
        mock_500.status_code = 500
        mock_500.raise_for_status = MagicMock(
            side_effect=httpx.HTTPStatusError(
                "Server Error", request=MagicMock(), response=mock_500
            )
        )

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_500)

        with (
            patch.object(backend, "_get_client", return_value=mock_client),
            pytest.raises(httpx.HTTPStatusError),
        ):
            await backend._get_zone("example.com")
        assert "example.com" not in backend._zone_cache


class TestDNSimpleBackendZoneExists:
    """Tests for zone_exists."""

    @pytest.mark.asyncio
    async def test_zone_exists_true(self):
        """Test zone_exists returns True when zone is found."""
        backend = DNSimpleBackend(token="token", account_id="149004")

        with patch.object(
            backend, "_get_zone", AsyncMock(return_value={"id": 1, "name": "example.com"})
        ):
            assert await backend.zone_exists("example.com") is True

    @pytest.mark.asyncio
    async def test_zone_exists_false_on_value_error(self):
        """Test zone_exists returns False when zone is not found."""
        backend = DNSimpleBackend(token="token", account_id="149004")

        with patch.object(backend, "_get_zone", AsyncMock(side_effect=ValueError("No zone found"))):
            assert await backend.zone_exists("notfound.com") is False

    @pytest.mark.asyncio
    async def test_zone_exists_false_on_http_error(self):
        """Test zone_exists returns False on HTTP status errors."""
        backend = DNSimpleBackend(token="token", account_id="149004")

        error = httpx.HTTPStatusError("Unauthorized", request=MagicMock(), response=MagicMock())
        with patch.object(backend, "_get_zone", AsyncMock(side_effect=error)):
            assert await backend.zone_exists("example.com") is False

    @pytest.mark.asyncio
    async def test_zone_exists_false_on_other_error(self):
        """Test zone_exists returns False on unexpected errors."""
        backend = DNSimpleBackend(token="token", account_id="149004")

        with patch.object(backend, "_get_zone", AsyncMock(side_effect=httpx.ConnectError("boom"))):
            assert await backend.zone_exists("example.com") is False


class TestDNSimpleBackendClose:
    """Tests for close."""

    @pytest.mark.asyncio
    async def test_close_closes_client(self):
        """Test that close closes the client and clears it."""
        backend = DNSimpleBackend(token="token")

        mock_client = AsyncMock()
        backend._client = mock_client

        await backend.close()

        mock_client.aclose.assert_awaited_once()
        assert backend._client is None

    @pytest.mark.asyncio
    async def test_close_after_get_client(self):
        """Test close after a real client is created."""
        backend = DNSimpleBackend(token="token")
        await backend._get_client()

        await backend.close()

        assert backend._client is None

    @pytest.mark.asyncio
    async def test_close_without_client(self):
        """Test that close is safe when no client exists."""
        backend = DNSimpleBackend(token="token")

        await backend.close()

        assert backend._client is None


RECORDS_PATH = "/v2/149004/zones/example.com/records"


def _records_page(records: list[dict], current_page: int = 1, total_pages: int = 1) -> MagicMock:
    """Make a mock 200 response for GET .../records with pagination."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": records,
        "pagination": {
            "current_page": current_page,
            "per_page": 100,
            "total_entries": len(records),
            "total_pages": total_pages,
        },
    }
    mock_response.raise_for_status = MagicMock()
    return mock_response


def _record(record_id: int, name: str = "chat", rtype: str = "SVCB", content: str = "") -> dict:
    """Make a DNSimple record dict."""
    return {
        "id": record_id,
        "zone_id": "example.com",
        "name": name,
        "type": rtype,
        "content": content,
        "ttl": 3600,
    }


def _status_response(status_code: int, data: dict | None = None) -> MagicMock:
    """Make a mock response with a status code. Error codes raise in raise_for_status."""
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.json.return_value = {"data": data} if data is not None else {}
    if status_code >= 400:
        mock_response.raise_for_status = MagicMock(
            side_effect=httpx.HTTPStatusError(
                f"HTTP {status_code}", request=MagicMock(), response=mock_response
            )
        )
    else:
        mock_response.raise_for_status = MagicMock()
    return mock_response


def _make_backend() -> DNSimpleBackend:
    """Make a backend with a configured account and a cached zone."""
    backend = DNSimpleBackend(token="token", account_id="149004")
    backend._zone_cache["example.com"] = {"id": 1, "name": "example.com"}
    return backend


def _make_client(
    pages: list[MagicMock] | None = None,
    delete_responses: list[MagicMock] | None = None,
    post_response: MagicMock | None = None,
) -> tuple[AsyncMock, list[tuple]]:
    """Make a mock client. Return the client and an ordered list of HTTP events."""
    events: list[tuple] = []
    pages = list(pages) if pages is not None else [_records_page([])]
    delete_responses = list(delete_responses) if delete_responses is not None else []

    async def _get(path, *args, **kwargs):
        events.append(("GET", path, kwargs.get("params")))
        return pages.pop(0)

    async def _delete(path, *args, **kwargs):
        events.append(("DELETE", path))
        if delete_responses:
            return delete_responses.pop(0)
        return _status_response(204)

    async def _post(path, *args, **kwargs):
        events.append(("POST", path, kwargs.get("json")))
        if post_response is not None:
            return post_response
        return _status_response(201, {"id": 999, **(kwargs.get("json") or {})})

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(side_effect=_get)
    mock_client.delete = AsyncMock(side_effect=_delete)
    mock_client.post = AsyncMock(side_effect=_post)
    return mock_client, events


def _posts(events: list[tuple]) -> list[tuple]:
    return [e for e in events if e[0] == "POST"]


def _deletes(events: list[tuple]) -> list[tuple]:
    return [e for e in events if e[0] == "DELETE"]


def _gets(events: list[tuple]) -> list[tuple]:
    return [e for e in events if e[0] == "GET"]


def _assert_posts_after_deletes(events: list[tuple]) -> None:
    """Assert that the first POST comes after the last DELETE."""
    methods = [e[0] for e in events]
    first_post = methods.index("POST")
    last_delete = max(i for i, m in enumerate(methods) if m == "DELETE")
    assert first_post > last_delete


class TestDNSimpleBackendCreateSVCB:
    """Tests for create_svcb_record."""

    @pytest.mark.asyncio
    async def test_create_svcb_replaces_existing_and_posts(self):
        """Test that existing SVCB records are deleted before the new record is created."""
        backend = _make_backend()
        mock_client, events = _make_client(
            pages=[_records_page([_record(11), _record(12)])],
        )

        with patch.object(backend, "_get_client", return_value=mock_client):
            fqdn = await backend.create_svcb_record(
                zone="example.com",
                name="chat",
                priority=1,
                target="chat.example.com.",
                params={"alpn": "mcp", "port": "443", "key65400": "https://x/cap.json"},
                ttl=300,
            )

        assert fqdn == "chat.example.com"

        gets = _gets(events)
        assert len(gets) >= 1
        assert gets[0][1] == RECORDS_PATH
        assert gets[0][2]["name"] == "chat"
        assert gets[0][2]["type"] == "SVCB"

        assert _deletes(events) == [
            ("DELETE", f"{RECORDS_PATH}/11"),
            ("DELETE", f"{RECORDS_PATH}/12"),
        ]
        assert _posts(events) == [
            (
                "POST",
                RECORDS_PATH,
                {
                    "name": "chat",
                    "type": "SVCB",
                    "content": '1 chat.example.com alpn="mcp" port="443" '
                    'key65400="https://x/cap.json"',
                    "ttl": 300,
                },
            )
        ]
        _assert_posts_after_deletes(events)

    @pytest.mark.asyncio
    async def test_create_svcb_alias_mode_empty_params(self):
        """Test AliasMode content with no params has no trailing space."""
        backend = _make_backend()
        mock_client, events = _make_client()

        with patch.object(backend, "_get_client", return_value=mock_client):
            await backend.create_svcb_record(
                zone="example.com",
                name="chat",
                priority=0,
                target="chat.example.com.",
                params={},
                ttl=300,
            )

        assert _posts(events)[0][2]["content"] == "0 chat.example.com"

    @pytest.mark.asyncio
    async def test_create_svcb_root_target_unchanged(self):
        """Test that root target '.' is sent as-is."""
        backend = _make_backend()
        mock_client, events = _make_client()

        with patch.object(backend, "_get_client", return_value=mock_client):
            await backend.create_svcb_record(
                zone="example.com",
                name="chat",
                priority=1,
                target=".",
                params={"alpn": "mcp"},
                ttl=300,
            )

        assert _posts(events)[0][2]["content"] == '1 . alpn="mcp"'

    @pytest.mark.asyncio
    async def test_create_svcb_target_without_trailing_dot_unchanged(self):
        """Test that a target without a trailing dot is sent unchanged."""
        backend = _make_backend()
        mock_client, events = _make_client()

        with patch.object(backend, "_get_client", return_value=mock_client):
            await backend.create_svcb_record(
                zone="example.com",
                name="chat",
                priority=1,
                target="svc.example.net",
                params={"alpn": "mcp"},
                ttl=300,
            )

        assert _posts(events)[0][2]["content"] == '1 svc.example.net alpn="mcp"'

    @pytest.mark.asyncio
    async def test_create_svcb_with_sub_labels(self):
        """Test that a name with sub-labels is sent as a relative name."""
        backend = _make_backend()
        mock_client, events = _make_client()

        with patch.object(backend, "_get_client", return_value=mock_client):
            fqdn = await backend.create_svcb_record(
                zone="example.com",
                name="chat._agents",
                priority=1,
                target="chat.example.com.",
                params={"alpn": "mcp"},
                ttl=300,
            )

        assert fqdn == "chat._agents.example.com"
        assert _gets(events)[0][2]["name"] == "chat._agents"
        assert _posts(events)[0][2]["name"] == "chat._agents"

    @pytest.mark.asyncio
    async def test_create_svcb_normalizes_zone(self):
        """Test that zone name is lowercased and trailing dot is stripped in paths."""
        backend = _make_backend()
        mock_client, events = _make_client(pages=[_records_page([_record(5)])])

        with patch.object(backend, "_get_client", return_value=mock_client):
            fqdn = await backend.create_svcb_record(
                zone="Example.COM.",
                name="chat",
                priority=1,
                target="chat.example.com.",
                params={"alpn": "mcp"},
                ttl=300,
            )

        assert fqdn == "chat.example.com"
        assert _gets(events)[0][1] == RECORDS_PATH
        assert _deletes(events) == [("DELETE", f"{RECORDS_PATH}/5")]
        assert _posts(events)[0][1] == RECORDS_PATH

    @pytest.mark.asyncio
    async def test_create_svcb_no_existing_records_no_delete(self):
        """Test that no DELETE is made when no records exist."""
        backend = _make_backend()
        mock_client, events = _make_client(pages=[_records_page([])])

        with patch.object(backend, "_get_client", return_value=mock_client):
            await backend.create_svcb_record(
                zone="example.com",
                name="chat",
                priority=1,
                target="chat.example.com.",
                params={"alpn": "mcp"},
                ttl=300,
            )

        mock_client.delete.assert_not_called()
        assert len(_posts(events)) == 1

    @pytest.mark.asyncio
    async def test_create_svcb_follows_pagination(self):
        """Test that records on all pages are deleted."""
        backend = _make_backend()
        mock_client, events = _make_client(
            pages=[
                _records_page([_record(21), _record(22)], current_page=1, total_pages=2),
                _records_page([_record(23)], current_page=2, total_pages=2),
            ],
        )

        with patch.object(backend, "_get_client", return_value=mock_client):
            await backend.create_svcb_record(
                zone="example.com",
                name="chat",
                priority=1,
                target="chat.example.com.",
                params={"alpn": "mcp"},
                ttl=300,
            )

        gets = _gets(events)
        assert len(gets) == 2
        assert all(g[1] == RECORDS_PATH for g in gets)
        assert gets[1][2]["page"] == 2
        assert sorted(d[1] for d in _deletes(events)) == [
            f"{RECORDS_PATH}/21",
            f"{RECORDS_PATH}/22",
            f"{RECORDS_PATH}/23",
        ]
        assert len(_posts(events)) == 1

    @pytest.mark.asyncio
    async def test_create_svcb_post_error_propagates(self):
        """Test that a failed POST raises HTTPStatusError."""
        backend = _make_backend()
        mock_client, _events = _make_client(post_response=_status_response(400))

        with (
            patch.object(backend, "_get_client", return_value=mock_client),
            pytest.raises(httpx.HTTPStatusError),
        ):
            await backend.create_svcb_record(
                zone="example.com",
                name="chat",
                priority=1,
                target="chat.example.com.",
                params={"alpn": "mcp"},
                ttl=300,
            )


class TestDNSimpleBackendCreateTXT:
    """Tests for create_txt_record."""

    @pytest.mark.asyncio
    async def test_create_txt_replaces_existing_and_posts_each_value(self):
        """Test that existing TXT records are deleted and one record is posted per value."""
        backend = _make_backend()
        mock_client, events = _make_client(
            pages=[_records_page([_record(31, rtype="TXT"), _record(32, rtype="TXT")])],
        )

        with patch.object(backend, "_get_client", return_value=mock_client):
            fqdn = await backend.create_txt_record(
                zone="example.com",
                name="chat",
                values=["version=1.0.0", 'description=Say "hi"'],
                ttl=300,
            )

        assert fqdn == "chat.example.com"

        gets = _gets(events)
        assert gets[0][1] == RECORDS_PATH
        assert gets[0][2]["name"] == "chat"
        assert gets[0][2]["type"] == "TXT"

        assert _deletes(events) == [
            ("DELETE", f"{RECORDS_PATH}/31"),
            ("DELETE", f"{RECORDS_PATH}/32"),
        ]
        assert _posts(events) == [
            (
                "POST",
                RECORDS_PATH,
                {"name": "chat", "type": "TXT", "content": "version=1.0.0", "ttl": 300},
            ),
            (
                "POST",
                RECORDS_PATH,
                {"name": "chat", "type": "TXT", "content": 'description=Say "hi"', "ttl": 300},
            ),
        ]
        _assert_posts_after_deletes(events)


class TestDNSimpleBackendDeleteRecord:
    """Tests for delete_record."""

    @pytest.mark.asyncio
    async def test_delete_record_deletes_all_matches(self):
        """Test that all records at name and type are deleted."""
        backend = _make_backend()
        mock_client, events = _make_client(
            pages=[_records_page([_record(41, rtype="TXT"), _record(42, rtype="TXT")])],
        )

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend.delete_record(zone="example.com", name="chat", record_type="TXT")

        assert result is True
        gets = _gets(events)
        assert gets[0][1] == RECORDS_PATH
        assert gets[0][2]["name"] == "chat"
        assert gets[0][2]["type"] == "TXT"
        assert _deletes(events) == [
            ("DELETE", f"{RECORDS_PATH}/41"),
            ("DELETE", f"{RECORDS_PATH}/42"),
        ]
        mock_client.post.assert_not_called()

    @pytest.mark.asyncio
    async def test_delete_record_not_found_returns_false(self):
        """Test that False is returned and no DELETE is made when no records exist."""
        backend = _make_backend()
        mock_client, _events = _make_client(pages=[_records_page([])])

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend.delete_record(zone="example.com", name="chat", record_type="TXT")

        assert result is False
        mock_client.delete.assert_not_called()

    @pytest.mark.asyncio
    async def test_delete_record_tolerates_404(self):
        """Test that a 404 on a DELETE (record already gone) is not raised."""
        backend = _make_backend()
        mock_client, events = _make_client(
            pages=[_records_page([_record(51, rtype="TXT"), _record(52, rtype="TXT")])],
            delete_responses=[_status_response(404), _status_response(204)],
        )

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend.delete_record(zone="example.com", name="chat", record_type="TXT")

        assert result is True
        assert len(_deletes(events)) == 2

    @pytest.mark.asyncio
    async def test_delete_record_other_errors_propagate(self):
        """Test that non-404 DELETE errors raise HTTPStatusError."""
        backend = _make_backend()
        mock_client, _events = _make_client(
            pages=[_records_page([_record(61, rtype="TXT")])],
            delete_responses=[_status_response(500)],
        )

        with (
            patch.object(backend, "_get_client", return_value=mock_client),
            pytest.raises(httpx.HTTPStatusError),
        ):
            await backend.delete_record(zone="example.com", name="chat", record_type="TXT")


async def _collect(backend: DNSimpleBackend, zone: str = "example.com", **kwargs) -> list[dict]:
    """Collect all records that list_records yields."""
    return [record async for record in backend.list_records(zone=zone, **kwargs)]


class TestDNSimpleBackendListRecords:
    """Tests for list_records."""

    @pytest.mark.asyncio
    async def test_list_records_requests_records_path_with_per_page(self):
        """Test that list_records gets the records path with per_page=100 and no type filter."""
        backend = _make_backend()
        mock_client, events = _make_client(pages=[_records_page([])])

        with patch.object(backend, "_get_client", return_value=mock_client):
            records = await _collect(backend)

        assert records == []
        gets = _gets(events)
        assert len(gets) == 1
        assert gets[0][1] == RECORDS_PATH
        params = gets[0][2]
        assert params["per_page"] == 100
        assert params.get("page", 1) == 1
        assert "type" not in params

    @pytest.mark.asyncio
    async def test_list_records_passes_type_filter(self):
        """Test that list_records sends the type param when record_type is given."""
        backend = _make_backend()
        mock_client, events = _make_client(pages=[_records_page([])])

        with patch.object(backend, "_get_client", return_value=mock_client):
            await _collect(backend, record_type="SVCB")

        gets = _gets(events)
        assert len(gets) == 1
        assert gets[0][2]["type"] == "SVCB"
        assert gets[0][2]["per_page"] == 100

    @pytest.mark.asyncio
    async def test_list_records_follows_all_pages(self):
        """Test that list_records follows pages 1..total_pages."""
        backend = _make_backend()
        mock_client, events = _make_client(
            pages=[
                _records_page(
                    [_record(1, name="_a._mcp._agents", content="1 a.example.com")],
                    current_page=1,
                    total_pages=3,
                ),
                _records_page(
                    [_record(2, name="_b._mcp._agents", content="1 b.example.com")],
                    current_page=2,
                    total_pages=3,
                ),
                _records_page(
                    [_record(3, name="_c._mcp._agents", content="1 c.example.com")],
                    current_page=3,
                    total_pages=3,
                ),
            ]
        )

        with patch.object(backend, "_get_client", return_value=mock_client):
            records = await _collect(backend)

        gets = _gets(events)
        assert [g[2]["page"] for g in gets] == [1, 2, 3]
        assert all(g[1] == RECORDS_PATH for g in gets)
        assert [r["name"] for r in records] == [
            "_a._mcp._agents",
            "_b._mcp._agents",
            "_c._mcp._agents",
        ]

    @pytest.mark.asyncio
    async def test_list_records_groups_by_name_and_type(self):
        """Test that records are grouped by (name, type) in first-seen order."""
        backend = _make_backend()
        first_txt = _record(11, name="_chat._mcp._agents", rtype="TXT", content='"version=1.0.0"')
        first_txt["ttl"] = 300
        mock_client, _events = _make_client(
            pages=[
                _records_page(
                    [
                        first_txt,
                        _record(
                            12,
                            name="_chat._mcp._agents",
                            rtype="SVCB",
                            content='1 mcp.example.com alpn="mcp" port="443"',
                        ),
                        _record(
                            13, name="_chat._mcp._agents", rtype="TXT", content='"protocol=mcp"'
                        ),
                    ]
                )
            ]
        )

        with patch.object(backend, "_get_client", return_value=mock_client):
            records = await _collect(backend)

        assert records == [
            {
                "name": "_chat._mcp._agents",
                "fqdn": "_chat._mcp._agents.example.com",
                "type": "TXT",
                "ttl": 300,
                "values": ["version=1.0.0", "protocol=mcp"],
            },
            {
                "name": "_chat._mcp._agents",
                "fqdn": "_chat._mcp._agents.example.com",
                "type": "SVCB",
                "ttl": 3600,
                "values": ['1 mcp.example.com alpn="mcp" port="443"'],
            },
        ]

    @pytest.mark.asyncio
    async def test_list_records_groups_across_pages(self):
        """Test that records with the same name and type on different pages are one group."""
        backend = _make_backend()
        mock_client, _events = _make_client(
            pages=[
                _records_page(
                    [_record(1, name="_chat._mcp._agents", rtype="TXT", content='"a=1"')],
                    current_page=1,
                    total_pages=2,
                ),
                _records_page(
                    [_record(2, name="_chat._mcp._agents", rtype="TXT", content='"b=2"')],
                    current_page=2,
                    total_pages=2,
                ),
            ]
        )

        with patch.object(backend, "_get_client", return_value=mock_client):
            records = await _collect(backend)

        assert len(records) == 1
        assert records[0]["values"] == ["a=1", "b=2"]

    @pytest.mark.asyncio
    async def test_list_records_apex_name(self):
        """Test that an apex record has name "@" and the zone as fqdn."""
        backend = _make_backend()
        mock_client, _events = _make_client(
            pages=[_records_page([_record(1, name="", rtype="TXT", content='"v=spf1 -all"')])]
        )

        with patch.object(backend, "_get_client", return_value=mock_client):
            records = await _collect(backend)

        assert len(records) == 1
        assert records[0]["name"] == "@"
        assert records[0]["fqdn"] == "example.com"
        assert records[0]["values"] == ["v=spf1 -all"]

    @pytest.mark.asyncio
    async def test_list_records_decodes_txt_escapes(self):
        """Test that TXT values are decoded from presentation format."""
        backend = _make_backend()
        mock_client, _events = _make_client(
            pages=[
                _records_page(
                    [
                        _record(
                            1,
                            name="_chat._mcp._agents",
                            rtype="TXT",
                            content='"description=Say \\"hi\\" to the agent"',
                        ),
                        _record(
                            2,
                            name="_chat._mcp._agents",
                            rtype="TXT",
                            content='"path=C:\\\\agents"',
                        ),
                    ]
                )
            ]
        )

        with patch.object(backend, "_get_client", return_value=mock_client):
            records = await _collect(backend)

        assert records[0]["values"] == [
            'description=Say "hi" to the agent',
            "path=C:\\agents",
        ]

    @pytest.mark.asyncio
    async def test_list_records_joins_txt_character_strings(self):
        """Test that several character-strings in one TXT record become one value."""
        backend = _make_backend()
        mock_client, _events = _make_client(
            pages=[
                _records_page(
                    [_record(1, name="_chat._mcp._agents", rtype="TXT", content='"aaa" "bbb"')]
                )
            ]
        )

        with patch.object(backend, "_get_client", return_value=mock_client):
            records = await _collect(backend)

        assert records[0]["values"] == ["aaabbb"]

    @pytest.mark.asyncio
    async def test_list_records_bare_txt_unchanged(self):
        """Test that unquoted TXT content is returned unchanged."""
        backend = _make_backend()
        mock_client, _events = _make_client(
            pages=[
                _records_page(
                    [_record(1, name="_chat._mcp._agents", rtype="TXT", content="version=1.0.0")]
                )
            ]
        )

        with patch.object(backend, "_get_client", return_value=mock_client):
            records = await _collect(backend)

        assert records[0]["values"] == ["version=1.0.0"]

    @pytest.mark.asyncio
    async def test_list_records_svcb_content_unchanged(self):
        """Test that SVCB content is returned as the API gives it."""
        backend = _make_backend()
        content = (
            '1 mcp.example.com mandatory="alpn,port" alpn="mcp" port="443" '
            'key65400="https://x/cap.json"'
        )
        mock_client, _events = _make_client(
            pages=[_records_page([_record(1, name="_chat._mcp._agents", content=content)])]
        )

        with patch.object(backend, "_get_client", return_value=mock_client):
            records = await _collect(backend)

        assert records[0]["values"] == [content]

    @pytest.mark.asyncio
    async def test_list_records_name_pattern_filters_by_fqdn_substring(self):
        """Test that name_pattern yields only groups whose fqdn contains the pattern."""
        backend = _make_backend()
        mock_client, _events = _make_client(
            pages=[
                _records_page(
                    [
                        _record(1, name="_index._agents", rtype="TXT", content='"agents=chat:mcp"'),
                        _record(2, name="_chat._mcp._agents", content="1 mcp.example.com"),
                        _record(3, name="www", rtype="CNAME", content="example.com"),
                    ]
                )
            ]
        )

        with patch.object(backend, "_get_client", return_value=mock_client):
            records = await _collect(backend, name_pattern="_index._agents")

        assert len(records) == 1
        assert records[0]["name"] == "_index._agents"
        assert records[0]["fqdn"] == "_index._agents.example.com"
        assert records[0]["values"] == ["agents=chat:mcp"]

    @pytest.mark.asyncio
    async def test_list_records_normalizes_zone(self):
        """Test that the zone name is lowercased and the trailing dot is removed."""
        backend = _make_backend()
        mock_client, events = _make_client(
            pages=[
                _records_page([_record(1, name="_chat._mcp._agents", content="1 a.example.com")])
            ]
        )

        with patch.object(backend, "_get_client", return_value=mock_client):
            records = await _collect(backend, zone="Example.COM.")

        assert _gets(events)[0][1] == RECORDS_PATH
        assert records[0]["fqdn"] == "_chat._mcp._agents.example.com"

    @pytest.mark.asyncio
    async def test_list_records_zone_not_found_yields_nothing(self):
        """Test that a 404 for the zone yields no records and raises no exception."""
        backend = _make_backend()
        mock_client, _events = _make_client(pages=[_status_response(404)])

        with patch.object(backend, "_get_client", return_value=mock_client):
            records = await _collect(backend)

        assert records == []


class TestDNSimpleBackendGetRecord:
    """Tests for get_record."""

    @pytest.mark.asyncio
    async def test_get_record_uses_one_filtered_lookup(self):
        """Test that get_record makes one GET filtered by name and type."""
        backend = _make_backend()
        mock_client, events = _make_client(
            pages=[
                _records_page(
                    [
                        _record(
                            1,
                            name="_chat._mcp._agents",
                            content='1 mcp.example.com alpn="mcp" port="443"',
                        )
                    ]
                )
            ]
        )

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend.get_record(
                zone="example.com", name="_chat._mcp._agents", record_type="SVCB"
            )

        gets = _gets(events)
        assert len(gets) == 1
        assert gets[0][1] == RECORDS_PATH
        assert gets[0][2]["name"] == "_chat._mcp._agents"
        assert gets[0][2]["type"] == "SVCB"
        assert gets[0][2]["page"] == 1
        assert gets[0][2]["per_page"] == 100
        assert result == {
            "name": "_chat._mcp._agents",
            "fqdn": "_chat._mcp._agents.example.com",
            "type": "SVCB",
            "ttl": 3600,
            "values": ['1 mcp.example.com alpn="mcp" port="443"'],
        }

    @pytest.mark.asyncio
    async def test_get_record_decodes_txt_values(self):
        """Test that get_record returns one decoded value for each TXT record."""
        backend = _make_backend()
        first = _record(1, name="_chat._mcp._agents", rtype="TXT", content='"version=1.0.0"')
        first["ttl"] = 600
        mock_client, _events = _make_client(
            pages=[
                _records_page(
                    [
                        first,
                        _record(
                            2,
                            name="_chat._mcp._agents",
                            rtype="TXT",
                            content='"description=Say \\"hi\\" to the agent"',
                        ),
                        _record(3, name="_chat._mcp._agents", rtype="TXT", content='"aaa" "bbb"'),
                    ]
                )
            ]
        )

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend.get_record(
                zone="example.com", name="_chat._mcp._agents", record_type="TXT"
            )

        assert result is not None
        assert result["fqdn"] == "_chat._mcp._agents.example.com"
        assert result["type"] == "TXT"
        assert result["ttl"] == 600
        assert result["values"] == [
            "version=1.0.0",
            'description=Say "hi" to the agent',
            "aaabbb",
        ]

    @pytest.mark.asyncio
    async def test_get_record_follows_pages(self):
        """Test that get_record follows all pages of the filtered lookup."""
        backend = _make_backend()
        mock_client, events = _make_client(
            pages=[
                _records_page(
                    [_record(1, name="_chat._mcp._agents", rtype="TXT", content='"a=1"')],
                    current_page=1,
                    total_pages=2,
                ),
                _records_page(
                    [_record(2, name="_chat._mcp._agents", rtype="TXT", content='"b=2"')],
                    current_page=2,
                    total_pages=2,
                ),
            ]
        )

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend.get_record(
                zone="example.com", name="_chat._mcp._agents", record_type="TXT"
            )

        gets = _gets(events)
        assert [g[2]["page"] for g in gets] == [1, 2]
        assert all(g[2]["name"] == "_chat._mcp._agents" for g in gets)
        assert all(g[2]["type"] == "TXT" for g in gets)
        assert result is not None
        assert result["values"] == ["a=1", "b=2"]

    @pytest.mark.asyncio
    async def test_get_record_not_found_returns_none(self):
        """Test that get_record returns None when no records match."""
        backend = _make_backend()
        mock_client, events = _make_client(pages=[_records_page([])])

        with patch.object(backend, "_get_client", return_value=mock_client):
            result = await backend.get_record(
                zone="example.com", name="_chat._mcp._agents", record_type="SVCB"
            )

        assert result is None
        gets = _gets(events)
        assert len(gets) == 1
        assert gets[0][2]["name"] == "_chat._mcp._agents"
        assert gets[0][2]["type"] == "SVCB"

    @pytest.mark.asyncio
    async def test_get_record_other_errors_propagate(self):
        """Test that a 500 on the lookup raises HTTPStatusError and does not return None."""
        backend = _make_backend()
        mock_client, _events = _make_client(pages=[_status_response(500)])

        with (
            patch.object(backend, "_get_client", return_value=mock_client),
            pytest.raises(httpx.HTTPStatusError),
        ):
            await backend.get_record(
                zone="example.com", name="_chat._mcp._agents", record_type="SVCB"
            )


class TestDNSimpleBackendFactoryWiring:
    """create_backend("dnsimple") wiring and env registry contract."""

    def test_create_backend_returns_dnsimple_backend(self, monkeypatch):
        """create_backend("dnsimple") returns DNSimpleBackend."""
        from dns_aid.backends import create_backend

        monkeypatch.setenv("DNSIMPLE_TOKEN", "test-token")
        backend = create_backend("dnsimple")
        assert isinstance(backend, DNSimpleBackend)

    def test_registry_entry_exists(self):
        """The CLI backend registry has a "dnsimple" entry."""
        from dns_aid.cli.backends import BACKEND_REGISTRY

        info = BACKEND_REGISTRY["dnsimple"]
        assert info.name == "dnsimple"
        assert info.display_name == "DNSimple"

    def test_dnsimple_token_in_required_env_registry(self):
        """DNSIMPLE_TOKEN is a required env var in the CLI registry."""
        from dns_aid.cli.backends import BACKEND_REGISTRY

        assert "DNSIMPLE_TOKEN" in BACKEND_REGISTRY["dnsimple"].required_env

    def test_optional_env_in_registry(self):
        """DNSIMPLE_ACCOUNT_ID and DNSIMPLE_BASE_URL are optional env vars."""
        from dns_aid.cli.backends import BACKEND_REGISTRY

        optional_env = BACKEND_REGISTRY["dnsimple"].optional_env
        assert "DNSIMPLE_ACCOUNT_ID" in optional_env
        assert "DNSIMPLE_BASE_URL" in optional_env

    def test_optional_dep_in_registry(self):
        """The pip extra for the DNSimple backend is "dnsimple"."""
        from dns_aid.cli.backends import BACKEND_REGISTRY

        assert BACKEND_REGISTRY["dnsimple"].optional_dep == "dnsimple"
