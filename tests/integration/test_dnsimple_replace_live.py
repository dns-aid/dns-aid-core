# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Live tests for record replacement in the DNSimple backend.

These tests make sure that a rejected replacement does not remove the
existing records. They use the real DNSimple API. The API refuses the
replacement with a validation error (HTTP 400), which is the same failure
path as a 429 or a 5xx response.

The API has no input that makes a DELETE fail. Thus, the test for the last
step (delete) makes the DELETE requests of the backend fail with a network
error. All other requests go to the real API.

Each test uses a new record name and removes its records at the end.

Gated behind DNS_AID_LIVE_TESTS=1 so CI stays hermetic:

    DNS_AID_LIVE_TESTS=1 \\
    DNSIMPLE_TOKEN=... DNSIMPLE_ACCOUNT_ID=... DNSIMPLE_TEST_ZONE=example.com \\
    uv run pytest tests/integration/test_dnsimple_replace_live.py -v
"""

from __future__ import annotations

import os
import uuid

import httpx
import pytest

from dns_aid.backends.dnsimple import DEFAULT_BASE_URL, DNSimpleBackend

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("DNS_AID_LIVE_TESTS") != "1"
        or not os.environ.get("DNSIMPLE_TOKEN")
        or not os.environ.get("DNSIMPLE_TEST_ZONE"),
        reason="Set DNS_AID_LIVE_TESTS=1, DNSIMPLE_TOKEN and DNSIMPLE_TEST_ZONE",
    ),
]

ZONE = os.environ.get("DNSIMPLE_TEST_ZONE", "")
TTL = 300

# The DNSimple API refuses these values with HTTP 400 and creates nothing.
INVALID_SVCB_TARGET = "bad..invalid"  # "Target can't have empty labels"
INVALID_TXT_VALUE = "x" * 1001  # "is too long (maximum is 1000 characters)"


@pytest.fixture
async def backend():
    """DNSimple backend for the live API."""
    b = DNSimpleBackend()
    yield b
    await b.close()


@pytest.fixture
async def api(backend):
    """Plain API client, separate from the backend under test.

    The test uses it to set up records, to read the zone, and to clean up.
    """
    account_id = await backend._get_account_id()
    base_url = os.environ.get("DNSIMPLE_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
    path = f"/v2/{account_id}/zones/{ZONE}/records"
    async with httpx.AsyncClient(
        base_url=base_url,
        headers={
            "Authorization": f"Bearer {os.environ['DNSIMPLE_TOKEN']}",
            "Accept": "application/json",
        },
        timeout=30.0,
    ) as client:
        yield _Api(client, path)


class _Api:
    def __init__(self, client: httpx.AsyncClient, path: str) -> None:
        self.client = client
        self.path = path

    async def create(self, name: str, rtype: str, content: str) -> dict:
        r = await self.client.post(
            self.path, json={"name": name, "type": rtype, "content": content, "ttl": TTL}
        )
        r.raise_for_status()
        return r.json()["data"]

    async def find(self, name: str, rtype: str) -> list[dict]:
        r = await self.client.get(self.path, params={"name": name, "type": rtype})
        r.raise_for_status()
        return r.json()["data"]

    async def remove_all(self, name: str) -> None:
        r = await self.client.get(self.path, params={"name": name})
        r.raise_for_status()
        for record in r.json()["data"]:
            d = await self.client.delete(f"{self.path}/{record['id']}")
            if d.status_code != 404:
                d.raise_for_status()


@pytest.fixture
async def name(api):
    """New record name for each test. Remove its records at the end."""
    n = f"replace-{uuid.uuid4().hex[:8]}.dnsaid-test"
    yield n
    await api.remove_all(n)


async def test_rejected_svcb_replacement_keeps_existing_record(backend, api, name):
    """A rejected SVCB replacement must not remove the existing SVCB record."""
    old = await api.create(name, "SVCB", f'1 old.{ZONE} alpn="mcp" port="443"')

    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        await backend.create_svcb_record(
            zone=ZONE,
            name=name,
            priority=1,
            target=INVALID_SVCB_TARGET,
            params={"alpn": "mcp", "port": "443"},
            ttl=TTL,
        )
    assert exc_info.value.response.status_code == 400

    after = await api.find(name, "SVCB")
    assert [r["content"] for r in after] == [old["content"]], (
        f"Existing SVCB record {old['id']} ({old['content']!r}) was removed "
        f"by a rejected replacement. Records now: {after!r}"
    )


async def test_rejected_txt_replacement_keeps_existing_records(backend, api, name):
    """A TXT replacement that fails on a later value must not leave a partial set."""
    old_values = ["capabilities=search", "version=1.0.0"]
    for value in old_values:
        await api.create(name, "TXT", value)

    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        await backend.create_txt_record(
            zone=ZONE,
            name=name,
            values=["capabilities=chat", INVALID_TXT_VALUE],
            ttl=TTL,
        )
    assert exc_info.value.response.status_code == 400

    after = sorted(backend._record_value(r) for r in await api.find(name, "TXT"))
    assert after == sorted(old_values), (
        f"Rejected TXT replacement changed the record set. "
        f"Before: {sorted(old_values)!r}. After: {after!r}"
    )


async def test_failed_final_delete_keeps_existing_records(backend, api, name):
    """A TXT replacement that fails in the last step (delete) must not leave a mixed set.

    The replacement updates one old record in place and then deletes the
    other old records. If a DELETE fails, the record set must be the old set.
    It must not be the new value plus the old values that were not deleted.
    """
    old_values = ["capabilities=search", "version=1.0.0", "realm=prod"]
    for value in old_values:
        await api.create(name, "TXT", value)

    async def fail_delete(request: httpx.Request) -> None:
        if request.method == "DELETE":
            raise httpx.ConnectError("DELETE failed for the test", request=request)

    client = await backend._get_client()
    client.event_hooks = {"request": [fail_delete], "response": []}

    with pytest.raises(httpx.ConnectError):
        await backend.create_txt_record(
            zone=ZONE,
            name=name,
            values=["capabilities=chat"],
            ttl=TTL,
        )

    after = sorted(backend._record_value(r) for r in await api.find(name, "TXT"))
    assert after == sorted(old_values), (
        f"A failed final delete changed the record set. "
        f"Before: {sorted(old_values)!r}. After: {after!r}"
    )
