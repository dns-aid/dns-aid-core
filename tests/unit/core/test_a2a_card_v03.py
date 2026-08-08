# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""A2A 0.3 agent cards, without breaking 0.2.

0.3 restructured the card: `authentication` became the `securitySchemes` map,
the single `url` gained `preferredTransport` beside it plus `additionalInterfaces`
for every other binding, and `capabilities`, `signatures` and `protocolVersion`
appeared. A 0.2-only parser drops all of it into untyped metadata, so a caller
cannot tell JSONRPC from gRPC, cannot read the auth requirement, and cannot see
that the card is signed.

Version naming is genuinely messy in the wild and the tests reflect that rather
than assuming: 0.3 calls the interface list `additionalInterfaces`, 1.0 renamed
it `supportedInterfaces`, and the extended-card flag moved from a top-level
field into `capabilities`. Real cards carry either -- the Infoblox ddi-agent
card declares protocolVersion 0.3 and uses the 1.0 interface name.
"""

import pytest

from dns_aid.core.a2a_card import A2AAgentCard, A2AAuthentication

V02 = {
    "name": "Legacy Agent",
    "url": "https://old.example.com/",
    "version": "1.0.0",
    "authentication": {"schemes": ["bearer"], "credentials": "https://old.example.com/token"},
    "skills": [{"id": "s1", "name": "Skill One"}],
    "defaultInputModes": ["text"],
    "defaultOutputModes": ["text"],
}

V03 = {
    "name": "Modern Agent",
    "protocolVersion": "0.3",
    "url": "https://new.example.com/",
    "version": "2.0.0",
    "preferredTransport": "JSONRPC",
    "additionalInterfaces": [
        {"url": "https://new.example.com/", "protocolBinding": "JSONRPC"},
        {"url": "https://new.example.com/grpc", "protocolBinding": "GRPC"},
    ],
    "securitySchemes": {
        "svc": {
            "oauth2SecurityScheme": {
                "flows": {"clientCredentials": {"tokenUrl": "https://idp.example.com/token"}}
            }
        }
    },
    "capabilities": {"streaming": True, "pushNotifications": False, "extendedAgentCard": True},
    "signatures": [{"protected": "eyJ...", "signature": "abc"}],
    "iconUrl": "https://new.example.com/icon.png",
    "documentationUrl": "https://docs.example.com/",
    "skills": [
        {
            "id": "route",
            "name": "Router",
            "tags": ["maps"],
            "examples": ["Plan a route", '{"origin": "A"}'],
            "securityRequirements": [{"svc": ["read"]}],
        }
    ],
}


class TestZeroTwoStillParses:
    """The whole point of a version bump is not breaking the previous one."""

    def test_a_legacy_card_is_unchanged(self):
        card = A2AAgentCard.from_dict(V02)

        assert card.name == "Legacy Agent"
        assert card.url == "https://old.example.com/"
        assert card.authentication is not None
        assert card.authentication.schemes == ["bearer"]
        assert card.skill_ids == ["s1"]

    def test_absent_0_3_fields_read_as_absent_not_empty_strings(self):
        card = A2AAgentCard.from_dict(V02)

        assert card.protocol_version is None, "a 0.2 card declares no version"
        assert card.preferred_transport is None
        assert card.interfaces == []
        assert card.signatures == []
        assert card.supports_extended_card is False


class TestZeroThreeFields:
    def test_the_declared_version_is_captured(self):
        assert A2AAgentCard.from_dict(V03).protocol_version == "0.3"

    def test_transport_is_readable(self):
        card = A2AAgentCard.from_dict(V03)

        assert card.preferred_transport == "JSONRPC"
        assert [i.protocol_binding for i in card.interfaces] == ["JSONRPC", "GRPC"]
        assert card.interfaces[1].url.endswith("/grpc")

    def test_capabilities_and_signatures_are_typed(self):
        card = A2AAgentCard.from_dict(V03)

        assert card.capabilities["streaming"] is True
        assert len(card.signatures) == 1
        assert card.icon_url and card.documentation_url

    def test_skills_carry_examples_and_their_own_security(self):
        skill = A2AAgentCard.from_dict(V03).skills[0]

        assert len(skill.examples) == 2
        assert skill.security_requirements == [{"svc": ["read"]}]

    def test_nothing_known_is_left_in_untyped_metadata(self):
        card = A2AAgentCard.from_dict(V03)

        for key in (
            "protocolVersion",
            "preferredTransport",
            "additionalInterfaces",
            "securitySchemes",
            "capabilities",
            "signatures",
        ):
            assert key not in card.metadata, f"{key} should be a typed field, not metadata"

    def test_a_vendor_extension_still_reaches_metadata(self):
        card = A2AAgentCard.from_dict({**V03, "x-custom": {"a": 1}})

        assert card.metadata["x-custom"] == {"a": 1}


class TestSecuritySchemes:
    """Two shapes appear in the wild; guessing which would break half of them."""

    def test_the_proto_derived_shape(self):
        auth = A2AAuthentication.from_security_schemes(
            {
                "svc": {
                    "oauth2SecurityScheme": {
                        "flows": {"clientCredentials": {"tokenUrl": "https://t/"}}
                    }
                }
            }
        )

        assert auth.schemes == ["oauth2"]
        assert auth.credentials == "https://t/"

    def test_the_openapi_shape(self):
        auth = A2AAuthentication.from_security_schemes(
            {"svc": {"type": "http", "scheme": "bearer"}}
        )

        assert auth.schemes == ["http"]

    def test_openid_connect_url_is_taken_as_the_credential_endpoint(self):
        auth = A2AAuthentication.from_security_schemes(
            {
                "g": {
                    "openIdConnectSecurityScheme": {
                        "openIdConnectUrl": "https://accounts/.well-known/x"
                    }
                }
            }
        )

        assert auth.schemes == ["openIdConnect"]
        assert auth.credentials == "https://accounts/.well-known/x"

    def test_0_3_schemes_win_over_the_legacy_object(self):
        """A card carrying both describes one requirement twice."""
        card = A2AAgentCard.from_dict({**V03, "authentication": {"schemes": ["bearer"]}})

        assert card.authentication is not None
        assert card.authentication.schemes == ["oauth2"], "the 0.3 map is the richer one"

    def test_malformed_entries_do_not_raise(self):
        auth = A2AAuthentication.from_security_schemes({"a": "not-a-dict", "b": {}})

        assert auth.schemes == []


class TestInterfaceListNaming:
    """0.3 says additionalInterfaces; 1.0 renamed it supportedInterfaces."""

    def test_the_1_0_name_is_accepted(self):
        card = A2AAgentCard.from_dict(
            {
                **{k: v for k, v in V03.items() if k != "additionalInterfaces"},
                "supportedInterfaces": [{"url": "https://x/", "protocolBinding": "HTTP+JSON"}],
            }
        )

        assert [i.protocol_binding for i in card.interfaces] == ["HTTP+JSON"]

    def test_the_0_3_name_wins_when_both_are_present(self):
        card = A2AAgentCard.from_dict(
            {**V03, "supportedInterfaces": [{"url": "https://ignored/", "protocolBinding": "GRPC"}]}
        )

        assert len(card.interfaces) == 2, "additionalInterfaces is the 0.3 spelling"

    def test_entries_without_a_url_are_dropped(self):
        card = A2AAgentCard.from_dict(
            {**V03, "additionalInterfaces": [{"protocolBinding": "GRPC"}]}
        )

        assert card.interfaces == []


class TestExtendedCardFlag:
    """Top-level in 0.3, relocated under capabilities in 1.0."""

    @pytest.mark.parametrize(
        "patch",
        [
            {"supportsAuthenticatedExtendedCard": True},
            {"supportsExtendedAgentCard": True},
            {"capabilities": {"extendedAgentCard": True}},
        ],
    )
    def test_every_spelling_is_recognised(self, patch):
        base = {k: v for k, v in V03.items() if k != "capabilities"}

        assert A2AAgentCard.from_dict({**base, **patch}).supports_extended_card is True

    def test_absent_means_false(self):
        base = {k: v for k, v in V03.items() if k != "capabilities"}

        assert A2AAgentCard.from_dict(base).supports_extended_card is False
