# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Backends replace only the SVCB / TXT RRs they own at a shared owner.

Issue #246 (SVCB siblings) and the lab finding F3 (foreign TXT).

draft-02 §3.1.1 keeps one SVCB record per agent protocol at the flat owner,
and other DNS-based discovery publishers may write SVCB records at the same
owner. A publish for one protocol must not remove the others.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import dns.message
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import pytest

from dns_aid.backends._ownership import (
    parse_svcb_text,
    svcb_identity,
    svcb_rr_is_replaced,
    svcb_text_is_replaced,
    txt_key,
    txt_rr_is_replaced,
    txt_strings,
)
from dns_aid.backends.cloudflare import CloudflareBackend
from dns_aid.backends.ddns import DDNSBackend
from dns_aid.backends.mock import MockBackend
from dns_aid.backends.route53 import Route53Backend
from dns_aid.core.models import AgentRecord, Protocol

A2A_RR = '1 agent.example.com. mandatory=alpn,port alpn="a2a" port=443'
MCP_RR = '1 agent.example.com. mandatory=alpn,port alpn="mcp" port=443'
COMMON_RR = '1 site.example.com. alpn="h2" port=443 key65420="a2a"'
WEBMCP_RR = '1 site.example.com. alpn="https" port=443 key65402="webmcp"'


class TestSvcbIdentity:
    def test_alpn_only(self):
        assert svcb_identity({"alpn": "a2a", "port": "443"}) == "a2a"

    def test_bap_wins_over_alpn(self):
        assert svcb_identity({"alpn": "https", "key65402": "webmcp"}) == "webmcp"
        assert svcb_identity({"alpn": "h2", "bap": "mcp=1.0"}) == "mcp"

    def test_first_alpn_of_list(self):
        assert svcb_identity({"alpn": '"h2,h3"'}) == "h2"

    def test_no_identity(self):
        assert svcb_identity({"port": "443"}) is None
        assert svcb_identity({}) is None

    def test_parse_svcb_text(self):
        parsed = parse_svcb_text(COMMON_RR)
        assert parsed == (1, {"alpn": "h2", "port": "443", "key65420": "a2a"})
        assert parse_svcb_text("not svcb") is None
        assert parse_svcb_text('1 x. alpn="unterminated') is None


class TestSvcbReplacePredicate:
    def test_same_protocol_replaced(self):
        assert svcb_text_is_replaced(A2A_RR, 1, {"alpn": "a2a", "port": "8443"})

    def test_other_protocol_kept(self):
        assert not svcb_text_is_replaced(A2A_RR, 1, {"alpn": "mcp", "port": "443"})

    def test_foreign_common_params_record_kept(self):
        # alpn="h2" + key65420: not a DNS-AID protocol record.
        assert not svcb_text_is_replaced(COMMON_RR, 1, {"alpn": "a2a", "port": "443"})

    def test_bap_records_distinguished_by_bap(self):
        assert not svcb_text_is_replaced(WEBMCP_RR, 1, {"alpn": "mcp", "port": "443"})
        assert svcb_text_is_replaced(WEBMCP_RR, 1, {"alpn": "https", "key65402": "webmcp"})

    def test_alias_mode_write_replaces_everything(self):
        assert svcb_text_is_replaced(A2A_RR, 0, {})
        assert svcb_text_is_replaced(COMMON_RR, 0, {})

    def test_existing_alias_mode_replaced_by_service_mode(self):
        assert svcb_rr_is_replaced(0, {}, 1, {"alpn": "a2a"})

    def test_write_without_identity_replaces_everything(self):
        assert svcb_text_is_replaced(COMMON_RR, 1, {"port": "443"})

    def test_unparseable_existing_kept(self):
        assert not svcb_text_is_replaced("garbage", 1, {"alpn": "a2a"})


def _svcb_response(fqdn: str, *rdatas: str) -> dns.message.Message:
    query = dns.message.make_query(fqdn, "SVCB")
    response = dns.message.make_response(query)
    if rdatas:
        response.answer.append(dns.rrset.from_text(f"{fqdn}.", 300, "IN", "SVCB", *rdatas))
    return response


def _noerror() -> MagicMock:
    ok = MagicMock()
    ok.rcode.return_value = dns.rcode.NOERROR
    return ok


def _update_sections(update: dns.message.Message) -> tuple[list[str], list[str]]:
    """(deleted rdata texts, added rdata texts) of a DNS UPDATE message."""
    deleted: list[str] = []
    added: list[str] = []
    for rrset in update.update:  # type: ignore[attr-defined]
        if rrset.deleting == dns.rdataclass.NONE:
            deleted.extend(r.to_text(origin=update.origin, relativize=False) for r in rrset)
        elif rrset.deleting == dns.rdataclass.ANY:
            deleted.append(f"ANY {dns.rdatatype.to_text(rrset.rdtype)}")
        else:
            added.extend(r.to_text(origin=update.origin, relativize=False) for r in rrset)
    return deleted, added


class TestDDNSSvcbSiblings:
    @pytest.fixture
    def backend(self) -> DDNSBackend:
        return DDNSBackend(server="192.0.2.53", key_name="k", key_secret="c2VjcmV0")

    @pytest.mark.asyncio
    async def test_second_protocol_keeps_first_and_foreign(self, backend):
        existing = _svcb_response("agent.example.com", A2A_RR, COMMON_RR)
        sent: list[dns.message.Message] = []

        def fake_tcp(msg, *args, **kwargs):
            sent.append(msg)
            return existing if len(sent) == 1 else _noerror()

        with patch("dns.query.tcp", side_effect=fake_tcp):
            await backend.create_svcb_record(
                zone="example.com",
                name="agent",
                priority=1,
                target="agent.example.com",
                params={"mandatory": "alpn,port", "alpn": "mcp", "port": "443"},
            )

        assert len(sent) == 2
        deleted, added = _update_sections(sent[1])
        assert deleted == []
        assert len(added) == 1 and 'alpn="mcp"' in added[0]

    @pytest.mark.asyncio
    async def test_republish_same_protocol_replaces_only_that_rr(self, backend):
        existing = _svcb_response("agent.example.com", A2A_RR, MCP_RR, COMMON_RR)
        sent: list[dns.message.Message] = []

        def fake_tcp(msg, *args, **kwargs):
            sent.append(msg)
            return existing if len(sent) == 1 else _noerror()

        with patch("dns.query.tcp", side_effect=fake_tcp):
            await backend.create_svcb_record(
                zone="example.com",
                name="agent",
                priority=1,
                target="agent2.example.com",
                params={"alpn": "a2a", "port": "443"},
            )

        deleted, added = _update_sections(sent[1])
        assert len(deleted) == 1 and 'alpn="a2a"' in deleted[0]
        assert "ANY SVCB" not in deleted
        assert len(added) == 1 and "agent2.example.com." in added[0]

    @pytest.mark.asyncio
    async def test_alias_mode_write_replaces_rrset_members(self, backend):
        existing = _svcb_response("agent._agents.example.com", "0 old.example.com.")
        sent: list[dns.message.Message] = []

        def fake_tcp(msg, *args, **kwargs):
            sent.append(msg)
            return existing if len(sent) == 1 else _noerror()

        with patch("dns.query.tcp", side_effect=fake_tcp):
            await backend.create_svcb_record(
                zone="example.com",
                name="agent._agents",
                priority=0,
                target="agent.example.com.",
                params={},
            )

        deleted, added = _update_sections(sent[1])
        assert deleted == ["0 old.example.com."]
        assert added == ["0 agent.example.com."]

    @pytest.mark.asyncio
    async def test_nxdomain_owner_just_adds(self, backend):
        query = dns.message.make_query("new.example.com", "SVCB")
        nx = dns.message.make_response(query)
        nx.set_rcode(dns.rcode.NXDOMAIN)
        sent: list[dns.message.Message] = []

        def fake_tcp(msg, *args, **kwargs):
            sent.append(msg)
            return nx if len(sent) == 1 else _noerror()

        with patch("dns.query.tcp", side_effect=fake_tcp):
            await backend.create_svcb_record(
                zone="example.com",
                name="new",
                priority=1,
                target="new.example.com",
                params={"alpn": "a2a"},
            )
        deleted, added = _update_sections(sent[1])
        assert deleted == [] and len(added) == 1

    @pytest.mark.asyncio
    async def test_unreadable_rrset_fails_instead_of_clobbering(self, backend):
        refused = MagicMock()
        refused.rcode.return_value = dns.rcode.REFUSED
        with (
            patch("dns.query.tcp", return_value=refused) as tcp,
            pytest.raises(RuntimeError, match="could not read the existing records"),
        ):
            await backend.create_svcb_record(
                zone="example.com",
                name="agent",
                priority=1,
                target="agent.example.com",
                params={"alpn": "a2a"},
            )
        assert tcp.call_count == 1  # no UPDATE sent


class TestRoute53SvcbSiblings:
    @pytest.mark.asyncio
    async def test_upsert_carries_other_protocols(self):
        backend = Route53Backend(zone_id="Z123")
        client = MagicMock()
        client.list_resource_record_sets.return_value = {
            "ResourceRecordSets": [
                {
                    "Name": "agent.example.com.",
                    "Type": "SVCB",
                    "TTL": 300,
                    "ResourceRecords": [{"Value": A2A_RR}, {"Value": COMMON_RR}],
                }
            ]
        }
        client.change_resource_record_sets.return_value = {"ChangeInfo": {"Id": "/change/C1"}}

        with patch.object(backend, "_get_client", return_value=client):
            await backend.create_svcb_record(
                zone="example.com",
                name="agent",
                priority=1,
                target="agent.example.com",
                params={"alpn": "mcp", "port": "443"},
            )

        batch = client.change_resource_record_sets.call_args.kwargs["ChangeBatch"]
        values = [rr["Value"] for rr in batch["Changes"][0]["ResourceRecordSet"]["ResourceRecords"]]
        assert values[:2] == [A2A_RR, COMMON_RR]
        assert len(values) == 3 and 'alpn="mcp"' in values[2]

    @pytest.mark.asyncio
    async def test_upsert_replaces_same_protocol(self):
        backend = Route53Backend(zone_id="Z123")
        client = MagicMock()
        client.list_resource_record_sets.return_value = {
            "ResourceRecordSets": [
                {
                    "Name": "agent.example.com.",
                    "Type": "SVCB",
                    "TTL": 300,
                    "ResourceRecords": [{"Value": A2A_RR}, {"Value": MCP_RR}],
                }
            ]
        }
        client.change_resource_record_sets.return_value = {"ChangeInfo": {"Id": "/change/C1"}}

        with patch.object(backend, "_get_client", return_value=client):
            await backend.create_svcb_record(
                zone="example.com",
                name="agent",
                priority=1,
                target="other.example.com",
                params={"alpn": "mcp", "port": "443"},
            )

        batch = client.change_resource_record_sets.call_args.kwargs["ChangeBatch"]
        values = [rr["Value"] for rr in batch["Changes"][0]["ResourceRecordSet"]["ResourceRecords"]]
        assert values[0] == A2A_RR
        assert len(values) == 2 and "other.example.com." in values[1]

    @pytest.mark.asyncio
    async def test_absent_rrset_next_name_ignored(self):
        backend = Route53Backend(zone_id="Z123")
        client = MagicMock()
        client.list_resource_record_sets.return_value = {
            "ResourceRecordSets": [
                {
                    "Name": "zzz.example.com.",
                    "Type": "SVCB",
                    "ResourceRecords": [{"Value": A2A_RR}],
                }
            ]
        }
        client.change_resource_record_sets.return_value = {"ChangeInfo": {"Id": "/change/C1"}}
        with patch.object(backend, "_get_client", return_value=client):
            await backend.create_svcb_record(
                zone="example.com",
                name="agent",
                priority=1,
                target="agent.example.com",
                params={"alpn": "mcp"},
            )
        batch = client.change_resource_record_sets.call_args.kwargs["ChangeBatch"]
        assert len(batch["Changes"][0]["ResourceRecordSet"]["ResourceRecords"]) == 1


class TestCloudflareSvcbSiblings:
    def _client(self, existing: list[dict]) -> AsyncMock:
        client = AsyncMock()
        client.get = AsyncMock(
            return_value=MagicMock(
                json=MagicMock(return_value={"success": True, "result": existing}),
                raise_for_status=MagicMock(),
            )
        )
        ok = MagicMock(status_code=200)
        ok.json.return_value = {"success": True, "result": {"id": "new"}}
        client.post = AsyncMock(return_value=ok)
        client.put = AsyncMock(return_value=ok)
        return client

    @pytest.mark.asyncio
    async def test_other_protocol_first_in_list_is_not_overwritten(self):
        backend = CloudflareBackend(api_token="t", zone_id="Z1")
        client = self._client(
            [
                {
                    "id": "a2a-rec",
                    "data": {"priority": 1, "target": "agent.example.com.", "value": 'alpn="a2a"'},
                }
            ]
        )
        with patch.object(backend, "_get_client", return_value=client):
            await backend.create_svcb_record(
                zone="example.com",
                name="agent",
                priority=1,
                target="agent.example.com",
                params={"alpn": "mcp", "port": "443"},
            )
        client.put.assert_not_called()
        client.post.assert_called_once()

    @pytest.mark.asyncio
    async def test_same_protocol_record_is_updated(self):
        backend = CloudflareBackend(api_token="t", zone_id="Z1")
        client = self._client(
            [
                {
                    "id": "a2a-rec",
                    "data": {"priority": 1, "target": "agent.example.com.", "value": 'alpn="a2a"'},
                },
                {
                    "id": "mcp-rec",
                    "data": {"priority": 1, "target": "agent.example.com.", "value": 'alpn="mcp"'},
                },
            ]
        )
        with patch.object(backend, "_get_client", return_value=client):
            await backend.create_svcb_record(
                zone="example.com",
                name="agent",
                priority=1,
                target="agent.example.com",
                params={"alpn": "mcp", "port": "443"},
            )
        client.post.assert_not_called()
        assert client.put.call_args.args[0].endswith("/dns_records/mcp-rec")


class TestMockSvcbSiblings:
    @pytest.mark.asyncio
    async def test_two_protocols_coexist(self):
        backend = MockBackend()
        for proto in (Protocol.A2A, Protocol.MCP):
            await backend.publish_agent(
                AgentRecord(
                    name="agent",
                    domain="example.com",
                    protocol=proto,
                    target_host="agent.example.com",
                )
            )
        svcb = backend.records["example.com"]["agent"]["SVCB"]
        assert sorted(r["params"]["alpn"] for r in svcb) == ["a2a", "mcp"]
        record = await backend.get_record("example.com", "agent", "SVCB")
        assert record is not None and len(record["values"]) == 2

        # Republishing one protocol replaces only that RR.
        await backend.publish_agent(
            AgentRecord(
                name="agent",
                domain="example.com",
                protocol=Protocol.A2A,
                target_host="agent2.example.com",
                port=8443,
            )
        )
        svcb = backend.records["example.com"]["agent"]["SVCB"]
        assert len(svcb) == 2
        a2a = next(r for r in svcb if r["params"]["alpn"] == "a2a")
        assert a2a["params"]["port"] == "8443"


# ---------------------------------------------------------------------------
# TXT: replace only DNS-AID's own TXT RRs (findings F3, issue #247 context)
# ---------------------------------------------------------------------------

DNSAID_TXT = ["capabilities=chat", "version=1.0.0"]
COMMON_TXT = '"txtvers=1" "proto=a2a" "path=/a2a"'


class TestTxtReplacePredicate:
    def test_txt_key(self):
        assert txt_key("Capabilities=chat") == "capabilities"
        assert txt_key("bare") == "bare"

    @pytest.mark.parametrize(
        "first",
        [
            "capabilities=a,b",
            "version=1.0.0",
            "description=x",
            "use_cases=a",
            "category=c",
            "dnsaid_key65402=webmcp",
        ],
    )
    def test_dnsaid_keys_replaced(self, first):
        assert txt_rr_is_replaced([first], DNSAID_TXT)

    def test_foreign_txt_kept(self):
        assert not txt_rr_is_replaced(["txtvers=1", "proto=a2a"], DNSAID_TXT)
        assert not txt_rr_is_replaced(["v=spf1 -all"], DNSAID_TXT)

    def test_only_first_string_decides(self):
        # A foreign RR that happens to carry version= later is still foreign.
        assert not txt_rr_is_replaced(["txtvers=1", "version=2"], DNSAID_TXT)

    def test_key_written_by_this_call_replaced(self):
        # The index TXT writes agents=...; its previous value must go.
        assert txt_rr_is_replaced(["agents=a:mcp"], ["agents=a:mcp,b:a2a"])
        assert not txt_rr_is_replaced(["agents=a:mcp"], DNSAID_TXT)

    def test_empty_rr_kept(self):
        assert not txt_rr_is_replaced([], DNSAID_TXT)

    def test_txt_strings(self):
        assert txt_strings(COMMON_TXT) == ["txtvers=1", "proto=a2a", "path=/a2a"]
        assert txt_strings('"capabilities=chat"') == ["capabilities=chat"]


def _txt_response(fqdn: str, *rdatas: str) -> dns.message.Message:
    query = dns.message.make_query(fqdn, "TXT")
    response = dns.message.make_response(query)
    if rdatas:
        response.answer.append(dns.rrset.from_text(f"{fqdn}.", 300, "IN", "TXT", *rdatas))
    return response


class TestDDNSTxtOwnership:
    @pytest.mark.asyncio
    async def test_publish_keeps_common_params_txt(self):
        backend = DDNSBackend(server="192.0.2.53", key_name="k", key_secret="c2VjcmV0")
        existing = _txt_response(
            "agent.example.com",
            COMMON_TXT,
            '"capabilities=old"',
            '"version=0.9"',
            '"description=gone"',
        )
        sent: list[dns.message.Message] = []

        def fake_tcp(msg, *args, **kwargs):
            sent.append(msg)
            return existing if len(sent) == 1 else _noerror()

        with patch("dns.query.tcp", side_effect=fake_tcp):
            await backend.create_txt_record(
                zone="example.com", name="agent", values=["capabilities=new", "version=1.0.0"]
            )

        deleted, added = _update_sections(sent[1])
        assert sorted(deleted) == ['"capabilities=old"', '"description=gone"', '"version=0.9"']
        assert "ANY TXT" not in deleted
        assert sorted(added) == ['"capabilities=new"', '"version=1.0.0"']


class TestRoute53TxtOwnership:
    @pytest.mark.asyncio
    async def test_upsert_carries_foreign_txt(self):
        backend = Route53Backend(zone_id="Z123")
        client = MagicMock()
        client.list_resource_record_sets.return_value = {
            "ResourceRecordSets": [
                {
                    "Name": "agent.example.com.",
                    "Type": "TXT",
                    "TTL": 300,
                    "ResourceRecords": [
                        {"Value": COMMON_TXT},
                        {"Value": '"capabilities=old"'},
                        {"Value": '"version=1.0.0"'},
                    ],
                }
            ]
        }
        client.change_resource_record_sets.return_value = {"ChangeInfo": {"Id": "/change/C1"}}
        with patch.object(backend, "_get_client", return_value=client):
            await backend.create_txt_record(
                zone="example.com", name="agent", values=["capabilities=new", "version=1.0.0"]
            )
        batch = client.change_resource_record_sets.call_args.kwargs["ChangeBatch"]
        values = [rr["Value"] for rr in batch["Changes"][0]["ResourceRecordSet"]["ResourceRecords"]]
        assert values == [COMMON_TXT, '"capabilities=new"', '"version=1.0.0"']


class TestCloudflareTxtOwnership:
    @pytest.mark.asyncio
    async def test_foreign_txt_listed_first_is_not_overwritten(self):
        backend = CloudflareBackend(api_token="t", zone_id="Z1")
        client = TestCloudflareSvcbSiblings()._client(
            [
                {"id": "common", "content": COMMON_TXT},
                {"id": "ours", "content": '"capabilities=old" "version=1.0.0"'},
            ]
        )
        with patch.object(backend, "_get_client", return_value=client):
            await backend.create_txt_record(
                zone="example.com", name="agent", values=["capabilities=new", "version=1.0.0"]
            )
        client.post.assert_not_called()
        assert client.put.call_args.args[0].endswith("/dns_records/ours")

    @pytest.mark.asyncio
    async def test_only_foreign_txt_adds_new_record(self):
        backend = CloudflareBackend(api_token="t", zone_id="Z1")
        client = TestCloudflareSvcbSiblings()._client([{"id": "common", "content": COMMON_TXT}])
        with patch.object(backend, "_get_client", return_value=client):
            await backend.create_txt_record(
                zone="example.com", name="agent", values=["capabilities=new"]
            )
        client.put.assert_not_called()
        client.post.assert_called_once()


class TestMockTxtOwnership:
    @pytest.mark.asyncio
    async def test_foreign_txt_kept_across_publishes(self):
        backend = MockBackend()
        backend.records["example.com"]["agent"]["TXT"] = [
            {"values": ["txtvers=1", "proto=a2a"], "ttl": 300}
        ]
        await backend.create_txt_record("example.com", "agent", ["capabilities=a", "version=1"])
        await backend.create_txt_record("example.com", "agent", ["capabilities=b", "version=1"])
        txt = backend.records["example.com"]["agent"]["TXT"]
        assert [r["values"] for r in txt] == [
            ["capabilities=b", "version=1"],
            ["txtvers=1", "proto=a2a"],
        ]
        assert backend.get_txt_record("example.com", "agent") == ["capabilities=b", "version=1"]
