"""Per-step-type Node tests: DecisionNode, ParallelNode, HITLGateNode."""

from __future__ import annotations

import pytest

from btagent_engine import NodeCategory, NodeContext
from btagent_engine.compiler import (
    DecisionNode,
    DecisionNodeInput,
    HITLGateNode,
    HITLGateNodeInput,
    ParallelNode,
    ParallelNodeInput,
)


def _ctx() -> NodeContext:
    return NodeContext(run_id="r1", org_id="org_test")


# --------------------------------------------------------------------------- #
# DecisionNode
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (True, "true"),
        (False, "false"),
        ("custom_branch", "custom_branch"),
        (3, "3"),
    ],
)
async def test_decision_node_picks_branch(value, expected):
    node = DecisionNode()
    out = await node.run(DecisionNodeInput(value=value), _ctx())
    assert out.branch == expected
    assert out.value == value


def test_decision_node_meta_is_decision_category():
    assert DecisionNode.meta.category is NodeCategory.DECISION
    assert DecisionNode.meta.id == "decision.branch"


# --------------------------------------------------------------------------- #
# ParallelNode
# --------------------------------------------------------------------------- #


async def test_parallel_node_merges_branch_results():
    node = ParallelNode()
    branch_results = [
        {"branch": 0, "ok": True},
        {"branch": 1, "ok": True},
        {"branch": 2, "ok": False, "error": "timeout"},
    ]
    out = await node.run(ParallelNodeInput(branch_results=branch_results), _ctx())
    assert out.branch_count == 3
    assert out.merged == branch_results


async def test_parallel_node_handles_empty_branches():
    node = ParallelNode()
    out = await node.run(ParallelNodeInput(branch_results=[]), _ctx())
    assert out.branch_count == 0
    assert out.merged == []


def test_parallel_node_meta_is_decision_category():
    assert ParallelNode.meta.category is NodeCategory.DECISION
    assert ParallelNode.meta.id == "decision.parallel"


# --------------------------------------------------------------------------- #
# HITLGateNode
# --------------------------------------------------------------------------- #


async def test_hitl_gate_node_is_pass_through():
    """Without the HITL middleware, the Node forwards its payload unchanged."""
    node = HITLGateNode()
    payload = {"alert_id": "alert_123", "severity": "high"}
    out = await node.run(
        HITLGateNodeInput(
            payload=payload,
            prompt="Approve containment?",
            required_role="incident_commander",
        ),
        _ctx(),
    )
    assert out.approved is True
    assert out.payload == payload
    # And the merged dict is a copy, not the same identity (defensive).
    assert out.payload is not payload


def test_hitl_gate_node_meta_category_is_decision_for_middleware_dispatch():
    """The HITL middleware (Sprint 2B) gates on category + id; verify the contract."""
    assert HITLGateNode.meta.category is NodeCategory.DECISION
    assert HITLGateNode.meta.id == "decision.hitl_gate"


async def test_hitl_gate_node_default_payload_is_empty_dict():
    node = HITLGateNode()
    out = await node.run(HITLGateNodeInput(), _ctx())
    assert out.approved is True
    assert out.payload == {}
