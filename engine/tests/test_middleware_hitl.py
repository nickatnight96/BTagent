"""Tests for the HITL middleware -- pauses on autonomy policy."""

from __future__ import annotations

import pytest
from btagent_shared.types.config import AutonomyLevel, IntegrationAutonomy
from pydantic import BaseModel

from btagent_engine import Node, NodeCategory, NodeContext, NodeMeta, Runner
from btagent_engine.middleware.hitl import (
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
    assert not requires_approval(
        "integration.virustotal.lookup", AutonomyLevel.L4_FULL_AUTO, ia
    )
