"""Tests for the ManualTriggerNode -- analyst-initiated workflow entry point.

Covers:

* Empty payload round-trips as empty payload (no implicit defaults).
* Arbitrary nested dict payloads round-trip unchanged.
* Registration: id is ``trigger.manual`` and category is ``TRIGGER``.
* End-to-end through the Runner: input/output validation defensively
  allows dict payloads (the canvas / API hand JSON over the wire).
"""

from __future__ import annotations

from btagent_engine import NodeCategory, NodeContext, NodeRegistry, Runner
from btagent_engine.triggers import (
    ManualTriggerInput,
    ManualTriggerNode,
    ManualTriggerOutput,
)


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_trigger", org_id="org_default")


# --------------------------------------------------------------------------- #
# Payload round-trip
# --------------------------------------------------------------------------- #


async def test_manual_trigger_empty_payload_returns_empty_payload():
    out = await ManualTriggerNode().run(ManualTriggerInput(), _ctx())
    assert isinstance(out, ManualTriggerOutput)
    assert out.payload == {}


async def test_manual_trigger_arbitrary_payload_round_trips_unchanged():
    """Triggers do no work -- they exist to seed the workflow run with
    whatever JSON the analyst handed over. The output must be byte-equal
    to the input (downstream nodes do their own schema validation)."""
    payload = {
        "incident_id": "inv_01HXYZ",
        "iocs": ["8.8.8.8", "evil.com"],
        "metadata": {"priority": "high", "tlp": "amber"},
    }
    out = await ManualTriggerNode().run(ManualTriggerInput(payload=payload), _ctx())
    assert out.payload == payload


# --------------------------------------------------------------------------- #
# Registration + metadata
# --------------------------------------------------------------------------- #


def test_manual_trigger_is_registered_under_canonical_id():
    """Workflow files reference nodes by ``meta.id`` -- ``trigger.manual``
    is the stable contract; renaming would break existing workflows."""
    cls = NodeRegistry.get("trigger.manual")
    assert cls is ManualTriggerNode
    assert cls.meta.category == NodeCategory.TRIGGER


# --------------------------------------------------------------------------- #
# End-to-end through Runner with no middleware
# --------------------------------------------------------------------------- #


async def test_manual_trigger_through_runner_validates_dict_payload():
    """The Runner accepts a dict payload (workflow files / API requests
    pass JSON, not pre-typed pydantic models) and round-trips it through
    input + output validation. This is the defensive path that protects
    downstream nodes from receiving anything other than a dict."""
    out = await Runner().execute(
        ManualTriggerNode(),
        {"payload": {"hello": "world", "count": 42}},
        _ctx(),
    )
    assert isinstance(out, ManualTriggerOutput)
    assert out.payload == {"hello": "world", "count": 42}


async def test_manual_trigger_output_is_independent_of_input_object():
    """The Node returns a *fresh* ManualTriggerOutput -- mutating the
    input dict after the call must not change the output. This guards
    against accidental aliasing if a future variant adds output-only
    fields."""
    payload = {"k": "v"}
    out = await ManualTriggerNode().run(ManualTriggerInput(payload=payload), _ctx())
    payload["k"] = "mutated"
    assert out.payload == {"k": "v"}
