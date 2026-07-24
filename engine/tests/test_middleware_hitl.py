"""Tests for the HITL middleware -- pauses on autonomy policy."""

from __future__ import annotations

import pytest
from btagent_shared.types.config import AutonomyLevel, IntegrationAutonomy
from pydantic import BaseModel

from btagent_engine import Node, NodeCategory, NodeContext, NodeMeta, Runner
from btagent_engine.compiler.steps import HITLGateNode
from btagent_engine.middleware.hitl import (
    HITLGateMiddleware,
    HITLGatePause,
    HITLMiddleware,
    HITLPause,
    requires_approval,
)


class _In(BaseModel):
    q: str


class _Out(BaseModel):
    ok: bool


def _make_node(node_id: str, category: NodeCategory) -> type[Node]:
    """Build a one-off Node class with the given id/category."""

    class _N(Node[_In, _Out]):
        meta = NodeMeta(
            id=node_id,
            name=node_id,
            version="0.1.0",
            category=category,
        )
        input_schema = _In
        output_schema = _Out

        async def run(self, input, ctx):
            return _Out(ok=True)

    return _N


def _ctx() -> NodeContext:
    return NodeContext(run_id="r1", org_id="org_test")


# --------------------------------------------------------------------------- #
# Happy path: non-integration nodes are never paused
# --------------------------------------------------------------------------- #


async def test_hitl_passes_through_non_integration_nodes():
    """A reasoning/data/decision node should never trigger HITL even at L0."""
    mw = HITLMiddleware(agent_autonomy=AutonomyLevel.L0_MANUAL)
    runner = Runner([mw])
    node = _make_node("reason.summarise", NodeCategory.REASONING)()
    out = await runner.execute(node, _In(q="hello"), _ctx())
    assert out.ok is True


# --------------------------------------------------------------------------- #
# Negative: integration node + restrictive autonomy raises HITLPause
# --------------------------------------------------------------------------- #


async def test_hitl_pauses_account_disable_at_default_autonomy():
    """``account_disable`` defaults to L0_MANUAL -- should always pause."""
    mw = HITLMiddleware(agent_autonomy=AutonomyLevel.L3_AUTONOMOUS)
    runner = Runner([mw])
    node = _make_node("integration.disable_account.run", NodeCategory.INTEGRATION)()
    with pytest.raises(HITLPause) as exc:
        await runner.execute(node, _In(q=""), _ctx())
    assert exc.value.node_id == "integration.disable_account.run"
    assert exc.value.required_level == AutonomyLevel.L0_MANUAL
    assert exc.value.agent_level == AutonomyLevel.L3_AUTONOMOUS


# --------------------------------------------------------------------------- #
# Edge: an L3-autonomous SIEM query at agent level L2 should NOT pause
# (legacy parity check -- the policy table is the contract).
# --------------------------------------------------------------------------- #


async def test_hitl_l2_supervised_allows_autonomous_siem_query():
    mw = HITLMiddleware(
        agent_autonomy=AutonomyLevel.L2_SUPERVISED,
        integration_autonomy=IntegrationAutonomy(),  # SIEM defaults to L3
    )
    runner = Runner([mw])
    node = _make_node("integration.splunk.search", NodeCategory.INTEGRATION)()
    out = await runner.execute(node, _In(q="index=*"), _ctx())
    assert out.ok is True


# --------------------------------------------------------------------------- #
# Pure-policy unit checks (avoid having to drive the runner for each cell)
# --------------------------------------------------------------------------- #


def test_requires_approval_l0_blocks_everything():
    ia = IntegrationAutonomy()
    assert requires_approval("integration.splunk.search", AutonomyLevel.L0_MANUAL, ia)
    assert requires_approval("integration.virustotal.lookup", AutonomyLevel.L0_MANUAL, ia)


def test_requires_approval_l4_only_blocks_l0_actions():
    ia = IntegrationAutonomy()
    # account_disable is L0 by default -> blocked at L4
    assert requires_approval("integration.disable_account", AutonomyLevel.L4_FULL_AUTO, ia)
    # virustotal lookup is L3 by default -> not blocked at L4
    assert not requires_approval("integration.virustotal.lookup", AutonomyLevel.L4_FULL_AUTO, ia)


# --------------------------------------------------------------------------- #
# Regression: destructive containment is always gated, even at L3/L4 (#377)
# --------------------------------------------------------------------------- #


def test_requires_approval_containment_gated_at_high_autonomy():
    """host_isolation / firewall_rule nodes are destructive containment and
    must be gated even at L3_AUTONOMOUS / L4_FULL_AUTO — the manifest marks them
    hitl_required=True, so the autonomy table never auto-approves them (#377).

    ``integration.crowdstrike.isolate_host`` also proves the token scan is
    immune to autonomy-map ordering: ``crowdstrike`` would otherwise resolve it
    to a benign L3 edr_query before the ``isolate`` token is ever considered.
    """
    ia = IntegrationAutonomy()
    for level in (AutonomyLevel.L3_AUTONOMOUS, AutonomyLevel.L4_FULL_AUTO):
        assert requires_approval("integration.crowdstrike.isolate_host", level, ia)
        assert requires_approval("integration.defender.quarantine", level, ia)
        assert requires_approval("integration.paloalto.firewall_block", level, ia)
        assert requires_approval("integration.edge.block_domain", level, ia)


def test_requires_approval_containment_gated_even_with_loosened_config():
    """Even a config that sets host_isolation/firewall_rule to L4 cannot
    auto-approve containment -- the code gates it, not the default (#377)."""
    ia = IntegrationAutonomy(
        host_isolation=AutonomyLevel.L4_FULL_AUTO,
        firewall_rule=AutonomyLevel.L4_FULL_AUTO,
    )
    assert requires_approval("integration.crowdstrike.isolate_host", AutonomyLevel.L4_FULL_AUTO, ia)
    assert requires_approval("integration.paloalto.firewall_block", AutonomyLevel.L4_FULL_AUTO, ia)


def test_requires_approval_benign_query_not_gated_at_high_autonomy():
    """A benign SIEM query stays ungated at L3/L4 (non-containment unchanged)."""
    ia = IntegrationAutonomy()
    assert not requires_approval("integration.splunk.search", AutonomyLevel.L3_AUTONOMOUS, ia)
    assert not requires_approval("integration.splunk.search", AutonomyLevel.L4_FULL_AUTO, ia)


async def test_hitl_pauses_isolation_at_l4_autonomy():
    """End-to-end: an isolate node paused via the middleware even at L4 (#377)."""
    mw = HITLMiddleware(agent_autonomy=AutonomyLevel.L4_FULL_AUTO)
    runner = Runner([mw])
    node = _make_node("integration.crowdstrike.isolate_host", NodeCategory.INTEGRATION)()
    with pytest.raises(HITLPause) as exc:
        await runner.execute(node, _In(q=""), _ctx())
    assert exc.value.node_id == "integration.crowdstrike.isolate_host"


# --------------------------------------------------------------------------- #
# HITLGateMiddleware -- explicit hitl_gate step gating (GH #389)
# --------------------------------------------------------------------------- #


async def test_gate_middleware_ignores_non_gate_nodes():
    """A gate middleware must be a no-op for anything that isn't the gate.

    Even an INTEGRATION node at L0 (which the *autonomy* HITL would pause)
    passes straight through the gate middleware -- gating that node is the
    other middleware's job, not this one's.
    """
    mw = HITLGateMiddleware()
    runner = Runner([mw])
    node = _make_node("integration.disable_account.run", NodeCategory.INTEGRATION)()
    out = await runner.execute(node, _In(q=""), _ctx())
    assert out.ok is True


async def test_gate_middleware_pauses_the_hitl_gate_node():
    """Reaching the ``decision.hitl_gate`` node raises HITLGatePause and the
    node's ``run`` (which would return approved=True) never executes."""
    mw = HITLGateMiddleware()
    runner = Runner([mw])
    node = HITLGateNode()
    with pytest.raises(HITLGatePause) as ei:
        await runner.execute(
            node,
            {"required_role": "incident_commander", "prompt": "Approve containment?"},
            _ctx(),
        )
    # required_role / prompt are propagated onto the pause for the approval card.
    assert ei.value.node_id == HITLGateNode.meta.id
    assert ei.value.required_role == "incident_commander"
    assert ei.value.prompt == "Approve containment?"
    # HITLGatePause is a HITLPause subclass so the executor's existing catch
    # translates it to WorkflowPaused with no executor change.
    assert isinstance(ei.value, HITLPause)


async def test_gate_middleware_bypasses_when_step_is_approved():
    """A resume that approved this step skips the pause -- the gate's
    pass-through ``run`` proceeds and returns approved=True."""
    mw = HITLGateMiddleware()
    runner = Runner([mw])
    node = HITLGateNode()
    ctx = NodeContext(
        run_id="r1",
        org_id="org_test",
        metadata={"current_step_id": "gate", "approved_steps": {"gate"}},
    )
    out = await runner.execute(node, {"required_role": "incident_commander"}, ctx)
    assert out.approved is True
