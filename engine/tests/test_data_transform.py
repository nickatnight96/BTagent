"""Tests for TransformNode -- the rename / drop / set / keep_only shape bridge.

Covers each rule type in isolation, multi-rule ordering, the unknown-rule-key
fail-loud contract, the empty-rules identity case, and an end-to-end pass
through ``Runner`` with a dict payload (so the schema validation hand-off
the canvas / API rely on is exercised).
"""

from __future__ import annotations

import pytest

from btagent_engine import NodeContext, Runner
from btagent_engine.data import TransformInput, TransformNode, TransformOutput


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_transform", org_id="org_test")


# --------------------------------------------------------------------------- #
# Single-rule behaviour
# --------------------------------------------------------------------------- #


async def test_rename_rule_moves_field():
    out = await TransformNode().run(
        TransformInput(
            payload={"src_field": 42, "other": "kept"},
            rules=[{"rename": "src_field -> dst_field"}],
        ),
        _ctx(),
    )
    assert isinstance(out, TransformOutput)
    assert out.payload == {"dst_field": 42, "other": "kept"}


async def test_rename_rule_missing_source_is_noop():
    out = await TransformNode().run(
        TransformInput(
            payload={"keep": 1},
            rules=[{"rename": "missing -> dst"}],
        ),
        _ctx(),
    )
    assert out.payload == {"keep": 1}


async def test_drop_rule_removes_field():
    out = await TransformNode().run(
        TransformInput(
            payload={"a": 1, "b": 2, "c": 3},
            rules=[{"drop": "b"}],
        ),
        _ctx(),
    )
    assert out.payload == {"a": 1, "c": 3}


async def test_set_rule_assigns_static_values():
    out = await TransformNode().run(
        TransformInput(
            payload={"existing": "untouched"},
            rules=[{"set": {"new_field": "hello", "answer": 42}}],
        ),
        _ctx(),
    )
    assert out.payload == {
        "existing": "untouched",
        "new_field": "hello",
        "answer": 42,
    }


async def test_keep_only_rule_drops_everything_else():
    out = await TransformNode().run(
        TransformInput(
            payload={"a": 1, "b": 2, "c": 3, "d": 4},
            rules=[{"keep_only": ["a", "c"]}],
        ),
        _ctx(),
    )
    assert out.payload == {"a": 1, "c": 3}


# --------------------------------------------------------------------------- #
# Ordering, identity, error-handling
# --------------------------------------------------------------------------- #


async def test_rules_apply_in_declaration_order():
    """A later rule sees the result of earlier rules. Rename then drop the
    new name should net to the field disappearing."""
    out = await TransformNode().run(
        TransformInput(
            payload={"src": "value", "other": "kept"},
            rules=[
                {"rename": "src -> dst"},
                {"drop": "dst"},
                {"set": {"injected": True}},
            ],
        ),
        _ctx(),
    )
    assert out.payload == {"other": "kept", "injected": True}


async def test_unknown_rule_key_raises_value_error():
    """Unknown rule keys are workflow-author bugs; fail loud."""
    with pytest.raises(ValueError, match="unknown key"):
        await TransformNode().run(
            TransformInput(
                payload={"a": 1},
                rules=[{"obliterate": "a"}],
            ),
            _ctx(),
        )


async def test_empty_rules_is_identity():
    payload = {"a": 1, "nested": {"b": 2}}
    out = await TransformNode().run(
        TransformInput(payload=payload, rules=[]),
        _ctx(),
    )
    assert out.payload == payload


async def test_input_payload_is_not_mutated():
    """The node operates on a copy; caller's dict survives unchanged."""
    original = {"src": 1, "drop_me": "bye"}
    snapshot = dict(original)
    await TransformNode().run(
        TransformInput(
            payload=original,
            rules=[{"rename": "src -> dst"}, {"drop": "drop_me"}],
        ),
        _ctx(),
    )
    assert original == snapshot


# --------------------------------------------------------------------------- #
# End-to-end through the Runner with a dict payload
# --------------------------------------------------------------------------- #


async def test_dict_payload_through_runner():
    """Dict payloads get validated to TransformInput by the Runner."""
    runner = Runner()
    out = await runner.execute(
        TransformNode(),
        {
            "payload": {"old": 99, "noise": "drop"},
            "rules": [
                {"rename": "old -> new"},
                {"drop": "noise"},
                {"set": {"flag": True}},
            ],
        },
        _ctx(),
    )
    assert isinstance(out, TransformOutput)
    assert out.payload == {"new": 99, "flag": True}
