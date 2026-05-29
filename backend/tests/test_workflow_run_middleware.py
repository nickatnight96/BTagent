"""Tests for the workflow-run middleware chain wiring.

Drives the run service directly so each test can pin the security posture
(active TLP, agent autonomy) the API route doesn't yet expose. Covers the
three behaviours we want to lock in:

1. Integration node with manifest ``hitl_required=True`` (CrowdStrike
   ``isolate_host``) → run is recorded ``status=paused``, nothing executes
   downstream of the gate.
2. Integration node whose capability declares ``tlp_egress=AMBER`` (GreyNoise
   ``lookup_ip``) executed at ``active_tlp=AMBER_STRICT`` → ``status=failed``
   with the policy violation surfaced in ``error``.
3. Advisory-tier run (no integration nodes) → still succeeds and now produces
   a non-empty hash-linked evidence chain (one entry per executed step).
"""

from __future__ import annotations

from typing import Any

import pytest
from btagent_shared.types.config import TLP, AutonomyLevel
from btagent_shared.types.workflow import WorkflowRunStatus
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models_workflow import WorkflowRow, WorkflowVersionRow
from btagent_backend.services import workflow_run_service, workflow_service

# Echo trigger only — the advisory baseline.
ECHO_DEF: dict[str, Any] = {
    "name": "echo-wf",
    "version": "1.0",
    "nodes": [{"step_id": "t1", "node_id": "trigger.manual", "name": "start", "config": {}}],
    "edges": [],
}

# Manual trigger -> CrowdStrike isolate_host (manifest hitl_required=True).
HITL_DEF: dict[str, Any] = {
    "name": "hitl-wf",
    "version": "1.0",
    "nodes": [
        {"step_id": "t1", "node_id": "trigger.manual", "name": "start", "config": {}},
        {
            "step_id": "iso",
            "node_id": "integration.crowdstrike.isolate_host",
            "name": "isolate",
            "config": {"hostname": "WS-12"},
        },
    ],
    "edges": [{"source": "t1", "target": "iso", "label": "next"}],
}

# Manual trigger -> GreyNoise lookup_ip (capability tlp_egress=AMBER).
GN_DEF: dict[str, Any] = {
    "name": "gn-wf",
    "version": "1.0",
    "nodes": [
        {"step_id": "t1", "node_id": "trigger.manual", "name": "start", "config": {}},
        {
            "step_id": "gn",
            "node_id": "integration.greynoise.lookup_ip",
            "name": "lookup",
            "config": {"ip": "185.220.101.42"},
        },
    ],
    "edges": [{"source": "t1", "target": "gn", "label": "next"}],
}


async def _seed_workflow(
    db: AsyncSession, *, org_id: str, definition: dict[str, Any]
) -> tuple[WorkflowRow, WorkflowVersionRow]:
    wf, version = await workflow_service.create_workflow(
        db,
        name="t",
        description="",
        org_id=org_id,
        created_by=None,
        initial_definition=definition,
    )
    await db.commit()
    return wf, version


@pytest.mark.asyncio
async def test_advisory_run_records_evidence_chain(db_session: AsyncSession, sample_user):
    wf, version = await _seed_workflow(db_session, org_id=sample_user.org_id, definition=ECHO_DEF)
    run = await workflow_run_service.execute_version(
        db_session,
        workflow=wf,
        version=version,
        trigger_payload={"payload": {"foo": "bar"}},
        triggered_by=sample_user.id,
        active_tlp=TLP.GREEN,
    )
    assert run.status == WorkflowRunStatus.SUCCEEDED.value
    assert run.nodes_executed == ["t1"]
    # One evidence record per executed step. The hash chain starts at GENESIS.
    assert len(run.evidence_chain) == 1
    rec = run.evidence_chain[0]
    assert rec["node_id"] == "trigger.manual"
    assert rec["prev_hash"] == "0" * 64
    assert isinstance(rec["link_hash"], str) and len(rec["link_hash"]) == 64


@pytest.mark.asyncio
async def test_hitl_required_capability_pauses(db_session: AsyncSession, sample_user):
    """A manifest-driven hitl_required action pauses, doesn't execute."""
    wf, version = await _seed_workflow(db_session, org_id=sample_user.org_id, definition=HITL_DEF)
    run = await workflow_run_service.execute_version(
        db_session,
        workflow=wf,
        version=version,
        trigger_payload={"payload": {}},
        triggered_by=sample_user.id,
        # Default GREEN posture; CrowdStrike declares tlp_egress=RED which
        # comfortably allows it.
        active_tlp=TLP.GREEN,
        # L3 autonomy so HITLMiddleware doesn't pre-pause this on the
        # autonomy-policy path — we want to exercise the manifest path
        # (ConnectorPolicyMiddleware -> PendingHITLApproval).
        agent_autonomy=AutonomyLevel.L3_AUTONOMOUS,
    )
    assert run.status == WorkflowRunStatus.PAUSED.value
    # Trigger executed; isolate paused before running.
    assert run.nodes_executed == ["t1"]
    assert "isolate_host" in (run.error or "") or "approval" in (run.error or "")


@pytest.mark.asyncio
async def test_hitl_autonomy_pauses_isolation(db_session: AsyncSession, sample_user):
    """HITLMiddleware pauses host_isolation on the default L2 autonomy."""
    wf, version = await _seed_workflow(db_session, org_id=sample_user.org_id, definition=HITL_DEF)
    run = await workflow_run_service.execute_version(
        db_session,
        workflow=wf,
        version=version,
        trigger_payload={"payload": {}},
        triggered_by=sample_user.id,
        active_tlp=TLP.GREEN,
        agent_autonomy=AutonomyLevel.L2_SUPERVISED,  # default; pauses host_isolation
    )
    assert run.status == WorkflowRunStatus.PAUSED.value
    assert run.nodes_executed == ["t1"]


@pytest.mark.asyncio
async def test_connector_policy_tlp_violation_fails(db_session: AsyncSession, sample_user):
    """Capability tlp_egress=AMBER refused at active_tlp=AMBER_STRICT → failed run.

    GreyNoise lookup_ip declares tlp_egress=AMBER (capability max). At an
    active context of AMBER_STRICT the active TLP is *stricter* than the cap
    permits, so ConnectorPolicyMiddleware refuses execution before the node
    runs.
    """
    wf, version = await _seed_workflow(db_session, org_id=sample_user.org_id, definition=GN_DEF)
    run = await workflow_run_service.execute_version(
        db_session,
        workflow=wf,
        version=version,
        trigger_payload={"payload": {}},
        triggered_by=sample_user.id,
        active_tlp=TLP.AMBER_STRICT,
        # Doesn't matter for this case; L3 so HITL doesn't intercept first.
        agent_autonomy=AutonomyLevel.L3_AUTONOMOUS,
    )
    assert run.status == WorkflowRunStatus.FAILED.value
    assert "Connector policy violation" in (run.error or "")
    assert "tlp_egress" in (run.error or "")
    # The error is bound to the greynoise step (the one that was refused),
    # not the upstream trigger.
    assert "gn" in (run.error or "")
