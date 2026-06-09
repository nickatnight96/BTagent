"""Engine-level tests for workflow resume (checkpoint + approved-step bypass).

Covers the novel/risky executor mechanics added for Phase-4 follow-up #1:

* A step that completed in a prior run is REUSED on resume, never re-run
  (so integration side effects don't double-fire).
* A step listed in ``approved_steps`` skips its HITL gate exactly once.
* Resuming without approving the paused step pauses again.

Uses purpose-built test nodes (registered under unique ids) so the test
controls run-counts and categories precisely, independent of the real
connector catalog.
"""

from __future__ import annotations

from typing import ClassVar

import pytest
from btagent_engine.compiler.workflow import Workflow, WorkflowEdge, WorkflowNode
from btagent_engine.middleware import HITLMiddleware, step_is_approved
from btagent_engine.node import (
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)
from btagent_engine.runtime import WorkflowExecutor, WorkflowPaused, WorkflowState
from btagent_shared.types.config import AutonomyLevel
from pydantic import BaseModel

# --------------------------------------------------------------------------- #
# Test nodes (registered once at import; unique ids avoid registry clashes)
# --------------------------------------------------------------------------- #

_SOURCE_RUNS = {"n": 0}
_GATED_RUNS = {"n": 0}


class _SourceIn(BaseModel):
    seed: int = 0


class _SourceOut(BaseModel):
    value: int = 0


class _GatedIn(BaseModel):
    value: int = 0


class _GatedOut(BaseModel):
    value: int = 0
    ran: bool = True


@NodeRegistry.register
class _SourceNode(Node[_SourceIn, _SourceOut]):
    """Non-integration entry node (never gated). Counts its executions."""

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="test.resume.source",
        name="Resume Test Source",
        version="0.1.0",
        category=NodeCategory.REASONING,
        description="test source",
    )
    input_schema: ClassVar[type[BaseModel]] = _SourceIn
    output_schema: ClassVar[type[BaseModel]] = _SourceOut

    async def run(self, input: _SourceIn, ctx: NodeContext) -> _SourceOut:
        _SOURCE_RUNS["n"] += 1
        return _SourceOut(value=input.seed)


@NodeRegistry.register
class _GatedNode(Node[_GatedIn, _GatedOut]):
    """Integration node -> HITLMiddleware gates it at L2 autonomy."""

    meta: ClassVar[NodeMeta] = NodeMeta(
        # "isolate" maps to host_isolation (L1_ASSISTED) in the HITL autonomy
        # table, so an L2_SUPERVISED agent gates it -> the node pauses.
        id="test.resume.isolate_host",
        name="Resume Test Gated",
        version="0.1.0",
        category=NodeCategory.INTEGRATION,
        description="test gated integration",
    )
    input_schema: ClassVar[type[BaseModel]] = _GatedIn
    output_schema: ClassVar[type[BaseModel]] = _GatedOut

    async def run(self, input: _GatedIn, ctx: NodeContext) -> _GatedOut:
        _GATED_RUNS["n"] += 1
        return _GatedOut(value=input.value + 1, ran=True)


def _workflow() -> Workflow:
    return Workflow(
        name="resume-test",
        nodes=(
            WorkflowNode(step_id="s1", node_id="test.resume.source", name="src"),
            WorkflowNode(step_id="g1", node_id="test.resume.isolate_host", name="gate"),
        ),
        edges=(WorkflowEdge(source="s1", target="g1", label="next"),),
    )


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_resume", org_id="org_test")


def _hitl_chain() -> list:
    # L2 supervised -> the integration node's autonomy (default L2 for unknown
    # ids) requires approval, so the gate fires.
    return [HITLMiddleware(agent_autonomy=AutonomyLevel.L2_SUPERVISED)]


def _reset_counts() -> None:
    _SOURCE_RUNS["n"] = 0
    _GATED_RUNS["n"] = 0


def test_step_is_approved_helper():
    ctx = _ctx()
    assert step_is_approved(ctx) is False
    ctx.metadata["approved_steps"] = {"g1"}
    ctx.metadata["current_step_id"] = "g1"
    assert step_is_approved(ctx) is True
    ctx.metadata["current_step_id"] = "other"
    assert step_is_approved(ctx) is False


async def test_first_run_pauses_at_integration_node():
    _reset_counts()
    with pytest.raises(WorkflowPaused) as ei:
        await WorkflowExecutor(_hitl_chain()).execute(_workflow(), {"seed": 5}, _ctx())
    pause = ei.value
    assert pause.node_id == "g1"
    assert pause.state.nodes_executed == ["s1"]
    assert _SOURCE_RUNS["n"] == 1
    assert _GATED_RUNS["n"] == 0  # gated never executed -- it paused first


async def test_resume_reuses_completed_node_and_runs_approved_gate():
    _reset_counts()
    # Run 1 -> pause, capturing the checkpoint state.
    with pytest.raises(WorkflowPaused) as ei:
        await WorkflowExecutor(_hitl_chain()).execute(_workflow(), {"seed": 5}, _ctx())
    checkpoint = ei.value.state
    assert _SOURCE_RUNS["n"] == 1

    # Resume with g1 approved.
    result = await WorkflowExecutor(_hitl_chain()).execute(
        _workflow(),
        {"seed": 5},
        _ctx(),
        resume_state=checkpoint,
        approved_steps={"g1"},
    )
    # Source was NOT re-run (reused from checkpoint); gate ran exactly once.
    assert _SOURCE_RUNS["n"] == 1, "completed node must not re-execute on resume"
    assert _GATED_RUNS["n"] == 1
    assert result.nodes_executed == ["s1", "g1"]
    # value = seed (5) carried through source, +1 in the gate.
    assert result.final_output is not None
    assert result.final_output.value == 6


async def test_resume_without_approval_pauses_again():
    _reset_counts()
    with pytest.raises(WorkflowPaused) as ei:
        await WorkflowExecutor(_hitl_chain()).execute(_workflow(), {"seed": 1}, _ctx())
    checkpoint = ei.value.state

    # Resume but DON'T approve g1 -> it must pause again, and the source
    # still isn't re-run.
    with pytest.raises(WorkflowPaused) as ei2:
        await WorkflowExecutor(_hitl_chain()).execute(
            _workflow(),
            {"seed": 1},
            _ctx(),
            resume_state=checkpoint,
            approved_steps=set(),
        )
    assert ei2.value.node_id == "g1"
    assert _SOURCE_RUNS["n"] == 1  # never re-run across either attempt


async def test_resume_state_can_be_rehydrated_from_plain_dicts():
    """Simulate the backend path: checkpoint outputs come back as loose dicts.

    The run service persists outputs as JSON and rehydrates them into a
    permissive BaseModel before resuming. Mirror that here to prove the
    reuse path doesn't depend on the original output class.
    """
    from pydantic import ConfigDict

    class _Rehydrated(BaseModel):
        model_config = ConfigDict(extra="allow")

    _reset_counts()
    with pytest.raises(WorkflowPaused) as ei:
        await WorkflowExecutor(_hitl_chain()).execute(_workflow(), {"seed": 9}, _ctx())
    original = ei.value.state

    # Rebuild state from dumped JSON (what the DB round-trip produces).
    rebuilt = WorkflowState(
        outputs={
            sid: _Rehydrated.model_validate(out.model_dump())
            for sid, out in original.outputs.items()
        },
        nodes_executed=list(original.nodes_executed),
        metadata={"trigger_payload": {"seed": 9}},
    )

    result = await WorkflowExecutor(_hitl_chain()).execute(
        _workflow(),
        {"seed": 9},
        _ctx(),
        resume_state=rebuilt,
        approved_steps={"g1"},
    )
    assert _SOURCE_RUNS["n"] == 1  # reused from the rehydrated dict, not re-run
    assert result.nodes_executed == ["s1", "g1"]
    assert result.final_output is not None
    assert result.final_output.value == 10
