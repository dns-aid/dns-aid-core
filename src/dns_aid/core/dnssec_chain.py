# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Full DNSSEC chain validation, anchored at the IANA root KSK.

Why this module exists.

DNS-AID's premise is that DNSSEC provides cryptographic verification. Until
now the library asserted that on the strength of the AD flag: one bit, set by
whichever resolver answered, over a path this code does not control. An
on-path attacker, a hostile resolver, or a resolver reached over an untrusted
network sets that bit at will. Every trust decision built on it -- the JWS
skip, the DANE gate, ``require_dnssec``, ``min_dnssec`` -- inherited that.

Validating here means the answer is proved against a trust anchor shipped with
the code, so the resolver becomes untrusted transport rather than an authority.
That is the difference between a reference implementation and a demonstration.

The AD flag keeps its place as a cheap pre-check and as a diagnostic; it is no
longer the thing a trust decision rests on.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from enum import StrEnum

import dns.asyncresolver
import dns.dnssec
import dns.flags
import dns.name
import dns.rdatatype
import dns.rrset
import structlog

logger = structlog.get_logger(__name__)

# The supported surface of this module. The tuning constants below are
# deliberately excluded: this package has no other __all__, so anything
# non-underscored would otherwise become API on release and could not be
# renamed afterwards.
__all__ = [
    "ChainResult",
    "ChainStatus",
    "ROOT_ANCHORS",
    "validate_chain",
]

# IANA root zone trust anchors, as DS records over the root DNSKEY RRset.
# KSK-2017 (tag 20326) is the anchor in force; KSK-2024 (tag 38696) is carried
# so a rollover does not require a code change. Source: the IANA root anchors
# XML, and both are published in RFC-adjacent operational documentation.
#
# These are the ONLY trust in this module. Everything else is derived.
ROOT_ANCHORS: tuple[tuple[int, int, int, str], ...] = (
    (20326, 8, 2, "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"),
    (38696, 8, 2, "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"),
)

# A chain walk is one DNSKEY plus one DS query per label. Bounded so a long
# attacker-chosen name cannot turn one discovery into an unbounded query burst.
MAX_CHAIN_LABELS = 12
CHAIN_QUERY_TIMEOUT = 5.0


class ChainStatus(StrEnum):
    """What the walk concluded. Only SECURE may support a trust decision."""

    SECURE = "secure"
    """Every link validated from the root anchor to the answer."""

    INSECURE = "insecure"
    """A provably unsigned delegation. The zone opted out, not an attack."""

    BOGUS = "bogus"
    """Signatures present and wrong, or a broken link. Treat as hostile."""

    INDETERMINATE = "indeterminate"
    """The walk could not complete -- timeout, SERVFAIL, unsupported algorithm.
    Unknown, never a rejection."""


@dataclass(frozen=True)
class ChainResult:
    status: ChainStatus
    reason: str
    zone: str | None = None

    @property
    def secure(self) -> bool:
        """The only property a caller should gate trust on."""
        return self.status is ChainStatus.SECURE


def _anchor_ds_rrset() -> dns.rrset.RRset:
    """The embedded root anchors as a DS RRset."""
    return dns.rrset.from_text_list(
        dns.name.root,
        0,
        "IN",
        "DS",
        [f"{tag} {alg} {dtype} {digest}" for tag, alg, dtype, digest in ROOT_ANCHORS],
    )


async def _query(resolver, qname, rdtype):
    """One DNSSEC-aware query, returning the raw response."""
    answer = await asyncio.wait_for(
        resolver.resolve(qname, rdtype, raise_on_no_answer=False),
        timeout=CHAIN_QUERY_TIMEOUT,
    )
    return answer.response


def _find_rrset(response, name, rdtype, covers=dns.rdatatype.NONE):
    for rrset in response.answer:
        if rrset.name == name and rrset.rdtype == rdtype and rrset.covers == covers:
            return rrset
    return None


# A CNAME chain longer than this is a misconfiguration, and the length is
# attacker-influenced, so it is bounded rather than followed indefinitely.
MAX_CNAME_HOPS = 8


def _follow_cname(response, name, rdtype, zone, keys):
    """Resolve the queried name through any CNAME chain in the answer.

    Looking for the requested type only at the QUERIED name reported
    ``no answer`` for every CNAMEd record, which the walk then folded into
    INDETERMINATE -- so a name whose CNAME is signed and provable read the same
    as a resolver that could not answer. Most real deployments CNAME their agent
    names at a CDN, so this affected the common case.

    Each CNAME hop is validated under the zone's keys before it is followed: an
    unvalidated CNAME would let a responder redirect the lookup to a name of its
    choosing and have the answer there validate on its own merits.

    Returns ``(rrset, final_name)``, or ``(None, final_name)`` when the type is
    not present at the end of the chain.
    """
    current = name
    for _ in range(MAX_CNAME_HOPS):
        direct = _find_rrset(response, current, rdtype)
        if direct is not None:
            return direct, current

        cname = _find_rrset(response, current, dns.rdatatype.CNAME)
        if cname is None:
            return None, current

        cname_sig = _find_rrset(response, current, dns.rdatatype.RRSIG, covers=dns.rdatatype.CNAME)
        if cname_sig is None:
            raise _BogusError(f"CNAME at {current} carries no signature")
        # Only meaningful while the chain stays inside the zone we hold keys for.
        if current.is_subdomain(zone):
            dns.dnssec.validate(cname, cname_sig, {zone: keys})
        current = cname[0].target

    raise _IndeterminateError(f"CNAME chain from {name} exceeded {MAX_CNAME_HOPS} hops")


async def _validated_dnskey(resolver, zone, ds_rrset):
    """Fetch a zone's DNSKEY RRset and prove it against the parent's DS.

    Two proofs are required and both are load bearing: some key in the RRset
    must hash to a DS the parent published, and the RRset's own signature must
    verify under that RRset. The first ties the zone to its parent; the second
    proves the keys were not substituted in transit.
    """
    response = await _query(resolver, zone, dns.rdatatype.DNSKEY)
    dnskeys = _find_rrset(response, zone, dns.rdatatype.DNSKEY)
    rrsig = _find_rrset(response, zone, dns.rdatatype.RRSIG, covers=dns.rdatatype.DNSKEY)
    if dnskeys is None or rrsig is None:
        raise _IndeterminateError(
            f"no signed DNSKEY RRset for {zone}; the resolver may not serve DNSSEC "
            "records (set DNS_AID_DNSSEC_RESOLVERS to one that does)"
        )

    # Collect the keys the parent's DS actually references -- not merely whether
    # one exists.
    #
    # RFC 4035 Section 5.2 requires the DS-referenced key to be the key that
    # verifies the DNSKEY RRset. Recording a boolean "some key matched" and then
    # validating against the whole served RRset breaks the chain: a responder can
    # republish the genuine anchor's PUBLIC key beside its own, sign everything
    # below with its own key, and the RRset validates under the attacker's key
    # while the DS check is satisfied by the anchor key it merely copied. No
    # access to the anchor's private key is needed, and the walk reports SECURE.
    matched_keys = []
    for key in dnskeys:
        for ds in ds_rrset:
            try:
                if dns.dnssec.make_ds(zone, key, ds.digest_type) == ds:
                    matched_keys.append(key)
                    break
            except Exception:  # noqa: BLE001 - unsupported digest type
                continue
    if not matched_keys:
        raise _BogusError(f"no DNSKEY in {zone} matches the DS published by its parent")

    # Validate the RRset under ONLY those keys. Once its signature verifies, the
    # whole RRset is authenticated, so the full set is returned for the child's
    # DS and the final answer -- both are signed by a ZSK inside it.
    trusted = dns.rrset.from_rdata_list(zone, dnskeys.ttl, matched_keys)
    dns.dnssec.validate(dnskeys, rrsig, {zone: trusted})
    return dnskeys


async def _child_ds(resolver, child, parent_keys, parent_zone):
    """The DS the parent publishes for a child, proved under the parent's keys.

    Returns None for a provably unsigned delegation. Distinguishing "the parent
    says this child is unsigned" from "someone stripped the DS" is the whole
    point of validating the answer rather than reading it.
    """
    response = await _query(resolver, child, dns.rdatatype.DS)
    ds_rrset = _find_rrset(response, child, dns.rdatatype.DS)
    if ds_rrset is None:
        # No DS. Authenticated denial would prove the delegation is unsigned;
        # without validating NSEC/NSEC3 here we can only report it as insecure,
        # never as secure, which keeps the failure direction safe.
        return None
    rrsig = _find_rrset(response, child, dns.rdatatype.RRSIG, covers=dns.rdatatype.DS)
    if rrsig is None:
        raise _BogusError(f"DS for {child} carries no signature")
    dns.dnssec.validate(ds_rrset, rrsig, {parent_zone: parent_keys})
    return ds_rrset


class _BogusError(Exception):
    """Signatures present and wrong, or a link that does not join up."""


class _IndeterminateError(Exception):
    """The walk could not complete. Unknown, not a rejection."""


def _default_resolver() -> dns.asyncresolver.Resolver:
    """A resolver that can actually serve a chain walk.

    The walk needs DNSKEY and DS records. Many enterprise stub resolvers do not
    return them -- on a split-horizon network the internal resolver is often
    authoritative for the zone and answers DNSKEY empty -- so inheriting the
    system resolver made the walk report INDETERMINATE on exactly the networks
    DNS-AID targets, indistinguishable from a resolver stripping records under
    attack.

    Set DNS_AID_DNSSEC_RESOLVERS to a comma-separated list of addresses that do
    serve DNSSEC records. Without it the system resolver is used, which is the
    prior behaviour and correct wherever the resolver is DNSSEC-aware.
    """
    res = dns.asyncresolver.Resolver()
    raw = os.environ.get("DNS_AID_DNSSEC_RESOLVERS", "").strip()
    if raw:
        servers = [ip.strip() for ip in raw.split(",") if ip.strip()]
        if servers:
            res.nameservers = servers
    return res


async def validate_chain(
    fqdn: str,
    rdtype: str = "SVCB",
    *,
    resolver: dns.asyncresolver.Resolver | None = None,
) -> ChainResult:
    """Prove an answer from the IANA root anchor down, without trusting AD.

    Walks label by label: each zone's DNSKEY is proved against the DS its parent
    published, and each DS is proved under the parent's keys. The target RRset is
    then validated under the keys of the zone that serves it.

    Returns INSECURE at the first unsigned delegation -- that is the zone owner's
    choice, not an attack, and it must not read the same as a broken signature.
    """
    name = dns.name.from_text(fqdn)
    if len(name) > MAX_CHAIN_LABELS:
        return ChainResult(ChainStatus.INDETERMINATE, "name has too many labels to walk")

    res = resolver or _default_resolver()
    res.use_edns(0, dns.flags.DO, 4096)
    # CD, not just DO. DO asks the upstream for the DNSSEC records; CD tells it
    # not to apply its own judgement first. Without CD a validating upstream
    # SERVFAILs on a bogus zone and hands us nothing, so the walk cannot tell a
    # forged signature from an unreachable server and has to say INDETERMINATE
    # -- the one verdict a local validator exists to avoid. We are the validator
    # here, so we want the unvalidated bytes and we judge them ourselves.
    # RFC 4035 3.2.2 and RFC 6840 5.9. Every answer fetched under CD is proved
    # below or the walk fails closed; nothing reaches a caller unvalidated.
    # RD stays set explicitly: res.flags defaults to None, which makes dnspython
    # supply RD itself. Assigning any value takes that default over, so dropping
    # RD here would stop the recursive resolver recursing at all.
    res.flags = (res.flags if res.flags is not None else dns.flags.RD) | dns.flags.CD

    try:
        keys = await _validated_dnskey(res, dns.name.root, _anchor_ds_rrset())
        zone = dns.name.root

        # Descend while the parent publishes a DS. A name with no DS is either
        # an unsigned delegation OR simply not a zone cut -- ddi-agent.ai.
        # infoblox.com is a record inside the signed ai.infoblox.com zone, not a
        # zone of its own. Treating "no DS" as "unsigned" reported the signed
        # zone as insecure, so descent stops there and the answer is proved
        # under the keys of the deepest zone that actually exists.
        for depth in range(len(name) - 1, 0, -1):
            child = dns.name.Name(name.labels[depth - 1 :])
            ds = await _child_ds(res, child, keys, zone)
            if ds is None:
                break
            keys = await _validated_dnskey(res, child, ds)
            zone = child

        response = await _query(res, name, dns.rdatatype.from_text(rdtype))
        rrset, answer_name = _follow_cname(
            response, name, dns.rdatatype.from_text(rdtype), zone, keys
        )
        if rrset is None:
            return ChainResult(
                ChainStatus.INDETERMINATE, f"no {rdtype} answer for {fqdn}", zone=str(zone)
            )
        rrsig = _find_rrset(
            response, answer_name, dns.rdatatype.RRSIG, covers=dns.rdatatype.from_text(rdtype)
        )
        if rrsig is None:
            # Reached a zone the chain stopped at and the answer is unsigned.
            # The zone owner opted out; that is not an attack.
            return ChainResult(
                ChainStatus.INSECURE,
                f"{fqdn} is served unsigned below {zone}",
                zone=str(zone),
            )
        if not answer_name.is_subdomain(zone):
            # A CNAME left the zone we hold keys for. Proving it needs a separate
            # walk to that zone, so this is unknown rather than secure -- and
            # unknown must not read as either proof or attack.
            return ChainResult(
                ChainStatus.INDETERMINATE,
                f"{fqdn} resolves via CNAME to {answer_name}, outside {zone}; "
                "validate that name separately",
                zone=str(zone),
            )
        dns.dnssec.validate(rrset, rrsig, {zone: keys})

        return ChainResult(ChainStatus.SECURE, "validated to the root anchor", zone=str(zone))

    except _BogusError as e:
        logger.warning("DNSSEC chain is bogus", fqdn=fqdn, reason=str(e))
        return ChainResult(ChainStatus.BOGUS, str(e))
    except _IndeterminateError as e:
        return ChainResult(ChainStatus.INDETERMINATE, str(e))
    except dns.dnssec.ValidationFailure as e:
        logger.warning("DNSSEC signature did not validate", fqdn=fqdn, reason=str(e))
        return ChainResult(ChainStatus.BOGUS, f"signature validation failed: {e}")
    except TimeoutError:
        return ChainResult(ChainStatus.INDETERMINATE, "chain walk timed out")
    except Exception as e:  # noqa: BLE001 - transport or parse failure is unknown
        return ChainResult(ChainStatus.INDETERMINATE, f"chain walk failed: {e}")
