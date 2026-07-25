"""Regression test for GH #389 -- explicit ``hitl_gate`` steps must pause.

Before the fix the ``hitl_gate`` playbook step compiled to
:class:`HITLGateNode` whose ``run`` unconditionally returned
``approved=True``: no middleware gated it (``HITLMiddleware`` only touches
INTEGRATION nodes, ``ConnectorPolicyMiddleware`` only touches nodes with a
manifest), so an explicit human-approval gate was silently auto-approved.

This exercises the whole path the production backend uses: compile a
playbook with a ``hitl_gate`` followed by an ``action``, run it through the
same middleware chain
(``workflow_run_service._build_middleware_chain``), and assert:

* the run PAUSES at the gate (``WorkflowPaused``) and the downstream
  ``action`` step does NOT run, and
* a resume that approves the gate (the executor's ``approved_steps`` /
  ``resume_state`` contract) completes the run and the action fires.

Follows the register/unregister-node pattern of ``test_workflow_executor``.
"""

from __future__ import annotations

from typing import ClassVar

import pytest
from btagent_shared.types.config import TLP, AutonomyLevel, IntegrationAutonomy
from pydantic import BaseModel, ConfigDict

from btagent_engine import (
    Middleware,
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
    WorkflowPaused,
    WorkflowState,
)
from btagent_engine.compiler import compile_playbook
from btagent_engine.compiler.steps import HITLGateNode
from btagent_engine.middleware.connector_policy import ConnectorPolicyMiddleware
from btagent_engine.middleware.evidence_chain import EvidenceChainMiddleware
from btagent_engine.middleware.hitl import HITLGateMiddleware, HITLGatePause, HITLMiddleware
from btagent_engine.runtime import WorkflowExecutor

# --------------------------------------------------------------------------- #
# Test action node the gated playbook routes into
# --------------------------------------------------------------------------- #


class _ActInput(BaseModel):
    # extra=ignore so the gate's pass-through output (approved / payload)
    # doesn't fail validation when it flows in as the upstream payload.
    model_config = ConfigDict(extra="ignore")


class _ActOutput(BaseModel):
    ran: bool = True


class _ActionNode(Node[_ActInput, _ActOutput]):
    """The post-gate action -- its execution is the thing the gate must block."""

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="test.gate.action",
        name="Gated Action",
        version="0.1.0",
        category=NodeCategory.OUTPUT,
    )
    input_schema = _ActInput
    output_schema = _ActOutput

    async def run(self, input: _ActInput, ctx: NodeContext) -> _ActOutput:
        return _ActOutput(ran=True)


@pytest.fixture(autouse=True)
def _register_action_node():
    NodeRegistry.unregister(_ActionNode.meta.id)
    NodeRegistry.register(_ActionNode)
    yield
    NodeRegistry.unregister(_ActionNode.meta.id)


_GATE_PLAYBOOK = """
name: Gate Playbook
trigger:
  type: manual
steps:
  - id: gate
    type: hitl_gate
    required_role: incident_commander
    next_step: act
  - id: act
    type: action
    tool_name: test.gate.action
"""


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_gate", org_id="org_test")


def _production_chain() -> list[Middleware]:
    """Mirror ``workflow_run_service._build_middleware_chain`` (the backend's
    production chain) so the test proves the gate pauses in situ, not just in
    isolation."""
    return [
        HITLMiddleware(
            agent_autonomy=AutonomyLevel.L4_FULL_AUTO,  # most permissive: gate must still pause
            integration_autonomy=IntegrationAutonomy(),
        ),
        HITLGateMiddleware(),
        ConnectorPolicyMiddleware(active_tlp=TLP.GREEN),
        EvidenceChainMiddleware(records=[]),
    ]


# --------------------------------------------------------------------------- #
# Pause: the gate blocks; the downstream action never runs
# --------------------------------------------------------------------------- #


async def test_hitl_gate_pauses_and_does_not_auto_run_downstream_action():
    wf = compile_playbook(_GATE_PLAYBOOK)
    executor = WorkflowExecutor(middlewares=_production_chain())

    with pytest.raises(WorkflowPaused) as ei:
        await executor.execute(wf, {}, _ctx())

    paused = ei.value
    # Paused AT the gate step id, and the downstream action did NOT execute.
    assert paused.node_id == "gate"
    assert isinstance(paused.state, WorkflowState)
    assert "act" not in paused.state.outputs
    assert "act" not in paused.state.nodes_executed
    # required_role / prompt were propagated onto the pause for the card.
    assert isinstance(paused.cause, HITLGatePause)
    assert paused.cause.required_role == "incident_commander"


# --------------------------------------------------------------------------- #
# Resume: approving the gate lets the run complete and the action fires
# --------------------------------------------------------------------------- #


async def test_hitl_gate_resumes_and_completes_when_approved():
    wf = compile_playbook(_GATE_PLAYBOOK)
    executor = WorkflowExecutor(middlewares=_production_chain())

    # 1. First run pauses at the gate.
    with pytest.raises(WorkflowPaused) as ei:
        await executor.execute(wf, {}, _ctx())
    paused_state = ei.value.state
    paused_node_id = ei.value.node_id  # "gate"

    # 2. Resume: reuse the checkpoint, approve the paused gate step. This is
    # exactly the (resume_state, approved_steps) contract resume_run() uses.
    result = await WorkflowExecutor(middlewares=_production_chain()).execute(
        wf,
        {},
        _ctx(),
        resume_state=paused_state,
        approved_steps={paused_node_id},
    )

    # The gate's pass-through ran (approved) and the action fired after it.
    assert "gate" in result.outputs
    assert result.outputs["gate"].approved is True  # type: ignore[attr-defined]
    assert "act" in result.outputs
    assert result.outputs["act"].ran is True  # type: ignore[attr-defined]
    assert result.nodes_executed == ["gate", "act"]


# --------------------------------------------------------------------------- #
# Guard: WITHOUT the gate middleware the bug reproduces (auto-approve)
# --------------------------------------------------------------------------- #


async def test_without_gate_middleware_the_bug_reproduces_auto_approve():
    """Documents #389: drop HITLGateMiddleware and the gate silently
    auto-approves, running the downstream action with no human in the loop."""
    wf = compile_playbook(_GATE_PLAYBOOK)
    chain: list[Middleware] = [
        HITLMiddleware(agent_autonomy=AutonomyLevel.L0_MANUAL),  # even L0 doesn't gate a DECISION
        ConnectorPolicyMiddleware(active_tlp=TLP.GREEN),
        EvidenceChainMiddleware(records=[]),
    ]
    result = await WorkflowExecutor(middlewares=chain).execute(wf, {}, _ctx())
    # No pause -- the action ran unapproved. This is the vulnerability the
    # HITLGateMiddleware closes.
    assert "act" in result.outputs
    assert result.outputs["gate"].approved is True  # type: ignore[attr-defined]


# --------------------------------------------------------------------------- #
# Sanity: the gate node id the middleware keys off is the compiled one
# --------------------------------------------------------------------------- #


def test_hitl_gate_step_compiles_to_the_expected_node_id():
    wf = compile_playbook(_GATE_PLAYBOOK)
    gate = wf.step("gate")
    assert gate is not None
    assert gate.node_id == HITLGateNode.meta.id
    # required_role flows into the node config the executor feeds as input.
    assert gate.config.get("required_role") == "incident_commander"
