"""Tests for the Node ABC, registry, and context."""

from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError

from btagent_engine import (
    Node,
    NodeAlreadyRegisteredError,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)

# --------------------------------------------------------------------------- #
# Test fixtures: a minimal Node implementation
# --------------------------------------------------------------------------- #


class _EchoIn(BaseModel):
    text: str


class _EchoOut(BaseModel):
    echoed: str


class _EchoNode(Node[_EchoIn, _EchoOut]):
    meta = NodeMeta(
        id="test.echo",
        name="Echo",
        version="0.1.0",
        category=NodeCategory.DATA,
    )
    input_schema = _EchoIn
    output_schema = _EchoOut

    async def run(self, input: _EchoIn, ctx: NodeContext) -> _EchoOut:
        return _EchoOut(echoed=input.text)


# --------------------------------------------------------------------------- #
# Node ABC
# --------------------------------------------------------------------------- #


async def test_node_run_returns_typed_output():
    node = _EchoNode()
    ctx = NodeContext(run_id="r1", org_id="org_test")
    result = await node.run(_EchoIn(text="hi"), ctx)
    assert isinstance(result, _EchoOut)
    assert result.echoed == "hi"


def test_node_meta_is_class_level_not_instance():
    """Two instances share metadata; metadata belongs to the class."""
    a = _EchoNode()
    b = _EchoNode()
    assert a.meta is b.meta is _EchoNode.meta


def test_node_cannot_be_instantiated_without_run():
    """The ABC enforces that subclasses implement run()."""

    class _Incomplete(Node[_EchoIn, _EchoOut]):
        meta = NodeMeta(
            id="test.incomplete",
            name="Incomplete",
            version="0.1.0",
            category=NodeCategory.DATA,
        )
        input_schema = _EchoIn
        output_schema = _EchoOut
        # no run() implementation

    with pytest.raises(TypeError):
        _Incomplete()  # type: ignore[abstract]


# --------------------------------------------------------------------------- #
# NodeContext
# --------------------------------------------------------------------------- #


def test_context_is_immutable():
    ctx = NodeContext(run_id="r", org_id="o")
    with pytest.raises(ValidationError):
        ctx.run_id = "tampered"  # type: ignore[misc]


def test_context_rejects_unknown_fields():
    """Frozen + extra=forbid means typos in spawning code fail loud."""
    with pytest.raises(ValidationError):
        NodeContext(run_id="r", org_id="o", typoed_field=True)  # type: ignore[call-arg]


def test_context_defaults_are_safe():
    """Defaults shouldn't accidentally elevate privilege."""
    ctx = NodeContext(run_id="r", org_id="org_default")
    assert ctx.tlp_level == "green"
    assert ctx.investigation_id is None
    assert ctx.user_id is None
    assert ctx.metadata == {}


# --------------------------------------------------------------------------- #
# NodeRegistry
# --------------------------------------------------------------------------- #


def test_registry_register_and_get():
    NodeRegistry.unregister("test.echo")  # idempotent reset
    NodeRegistry.register(_EchoNode)
    assert NodeRegistry.get("test.echo") is _EchoNode


def test_registry_blocks_collision():
    NodeRegistry.register(_EchoNode)

    class _OtherEcho(Node[_EchoIn, _EchoOut]):
        meta = NodeMeta(
            id="test.echo",  # collides
            name="Other Echo",
            version="0.1.0",
            category=NodeCategory.DATA,
        )
        input_schema = _EchoIn
        output_schema = _EchoOut

        async def run(self, input, ctx):
            return _EchoOut(echoed=input.text)

    with pytest.raises(NodeAlreadyRegisteredError):
        NodeRegistry.register(_OtherEcho)


def test_registry_idempotent_for_same_class():
    """Re-registering the same class is a no-op (handles repeated imports)."""
    NodeRegistry.register(_EchoNode)
    NodeRegistry.register(_EchoNode)  # must not raise


def test_registry_all_returns_read_only_view():
    NodeRegistry.register(_EchoNode)
    view = NodeRegistry.all()
    with pytest.raises(TypeError):
        view["malicious"] = _EchoNode  # type: ignore[index]


def test_registry_get_unknown_returns_none():
    assert NodeRegistry.get("nope.does.not.exist") is None
