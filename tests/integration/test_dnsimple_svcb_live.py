# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Live tests for SVCB parameter values in the DNSimple backend.

The DNSimple API cannot keep an SVCB parameter value that has a double quote
or a backslash. It refuses a backslash ("must not contain backslashes"), and
a double quote stops the quoted value, also when it is escaped.

These tests make sure that:

- the API still has this limit. If a test of this type fails, the API
  changed, and the backend can escape these characters again.
- the backend refuses such a value before it sends a request, so that the
  existing SVCB record does not change.

Each test uses a new record name and removes its records at the end.

Gated behind DNS_AID_LIVE_TESTS=1 so CI stays hermetic:

    DNS_AID_LIVE_TESTS=1 \\
    DNSIMPLE_TOKEN=... DNSIMPLE_ACCOUNT_ID=... DNSIMPLE_TEST_ZONE=example.com \\
    uv run pytest tests/integration/test_dnsimple_svcb_live.py -v
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
KEY = "key65400"

SPECIAL_VALUES = [
    pytest.param('say "hi" now', id="double-quote"),
    pytest.param("path\\to\\policy", id="backslash"),
]


@pytest.fixture
async def backend():
    """DNSimple backend for the live API."""
    b = DNSimpleBackend()
    yield b
    await b.close()


@pytest.fixture
async def api(backend):
    """Plain API client, separate from the backend under test."""
    account_id = await backend._get_account_id()
    base_url = os.environ.get("DNSIMPLE_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
    async with httpx.AsyncClient(
        base_url=base_url,
        headers={
            "Authorization": f"Bearer {os.environ['DNSIMPLE_TOKEN']}",
            "Accept": "application/json",
        },
        timeout=30.0,
    ) as client:
        yield client, f"/v2/{account_id}/zones/{ZONE}/records"


@pytest.fixture
async def name(api):
    """New record name for each test. Remove its records at the end."""
    client, path = api
    n = f"svcb-{uuid.uuid4().hex[:8]}.dnsaid-test"
    yield n
    r = await client.get(path, params={"name": n})
    r.raise_for_status()
    for record in r.json()["data"]:
        await client.delete(f"{path}/{record['id']}")


@pytest.mark.parametrize("value", SPECIAL_VALUES)
async def test_api_refuses_escaped_quote_or_backslash_in_svcb_value(api, name, value):
    """The API refuses an SVCB param value with an escaped double quote or backslash."""
    client, path = api
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    content = f'1 agent.{ZONE} alpn="mcp" {KEY}="{escaped}"'

    r = await client.post(path, json={"name": name, "type": "SVCB", "content": content, "ttl": TTL})

    assert r.status_code == 400, (
        f"The API accepted {content!r} (HTTP {r.status_code}). The API limit "
        f"changed: the backend can escape these characters. Response: {r.text}"
    )


@pytest.mark.parametrize("value", SPECIAL_VALUES)
async def test_backend_refuses_quote_or_backslash_and_keeps_record(backend, api, name, value):
    """The backend refuses the value before a request, and the existing record stays."""
    client, path = api
    r = await client.post(
        path,
        json={
            "name": name,
            "type": "SVCB",
            "content": f'1 agent.{ZONE} alpn="mcp" port="443"',
            "ttl": TTL,
        },
    )
    r.raise_for_status()
    old = r.json()["data"]

    with pytest.raises(ValueError, match=KEY):
        await backend.create_svcb_record(
            zone=ZONE,
            name=name,
            priority=1,
            target=f"agent.{ZONE}.",
            params={"alpn": "mcp", "port": "443", KEY: value},
            ttl=TTL,
        )

    r = await client.get(path, params={"name": name, "type": "SVCB"})
    r.raise_for_status()
    after = r.json()["data"]
    assert [(rec["id"], rec["content"]) for rec in after] == [(old["id"], old["content"])], (
        f"The refused SVCB value changed the record set. Before: {old!r}. After: {after!r}"
    )
