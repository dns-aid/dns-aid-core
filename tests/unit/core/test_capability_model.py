# Copyright 2024-2026 The DNS-AID Authors
# SPDX-License-Identifier: Apache-2.0

"""Tests for the capability model (Phase 5.5)."""

from dns_aid.core.capability_model import (
    Action,
    ActionIntent,
    ActionSemantics,
    CapabilitySpec,
)


class TestActionIntent:
    """Test ActionIntent enum."""

    def test_values(self):
        assert ActionIntent.query == "query"
        assert ActionIntent.command == "command"
        assert ActionIntent.transaction == "transaction"
        assert ActionIntent.subscription == "subscription"

    def test_all_members(self):
        assert len(ActionIntent) == 4


class TestActionSemantics:
    """Test ActionSemantics enum."""

    def test_values(self):
        assert ActionSemantics.read == "read"
        assert ActionSemantics.write == "write"
        assert ActionSemantics.idempotent == "idempotent"

    def test_all_members(self):
        assert len(ActionSemantics) == 3


class TestAction:
    """Test Action model."""

    def test_minimal_action(self):
        action = Action(name="get-data")
        assert action.name == "get-data"
        assert action.intent == ActionIntent.query
        assert action.semantics == ActionSemantics.read
        assert action.tags == []
        assert action.description is None

    def test_full_action(self):
        action = Action(
            name="create-order",
            description="Creates a new order in the system",
            intent=ActionIntent.command,
            semantics=ActionSemantics.write,
            tags=["billing", "orders"],
        )
        assert action.name == "create-order"
        assert action.description == "Creates a new order in the system"
        assert action.intent == ActionIntent.command
        assert action.semantics == ActionSemantics.write
        assert action.tags == ["billing", "orders"]

    def test_name_validation_empty(self):
        import pytest
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            Action(name="")

    def test_serialization(self):
        action = Action(name="lookup", intent=ActionIntent.query, tags=["dns"])
        data = action.model_dump()
        assert data["name"] == "lookup"
        assert data["intent"] == "query"
        assert data["tags"] == ["dns"]


class TestCapabilitySpec:
    """Test CapabilitySpec model."""

    def test_defaults(self):
        spec = CapabilitySpec()
        assert spec.schema_discovery is None
        assert spec.supports_streaming is False
        assert spec.actions == []

    def test_with_actions(self):
        spec = CapabilitySpec(
            schema_discovery="https://example.com/.well-known/agent-cap.json",
            supports_streaming=True,
            actions=[
                Action(name="query-dns", intent=ActionIntent.query),
                Action(
                    name="update-record",
                    intent=ActionIntent.command,
                    semantics=ActionSemantics.idempotent,
                ),
            ],
        )
        assert spec.schema_discovery == "https://example.com/.well-known/agent-cap.json"
        assert spec.supports_streaming is True
        assert len(spec.actions) == 2
        assert spec.actions[0].name == "query-dns"
        assert spec.actions[1].semantics == ActionSemantics.idempotent

    def test_serialization_roundtrip(self):
        spec = CapabilitySpec(
            actions=[Action(name="test", tags=["a", "b"])],
        )
        data = spec.model_dump()
        restored = CapabilitySpec.model_validate(data)
        assert restored.actions[0].name == "test"
        assert restored.actions[0].tags == ["a", "b"]
