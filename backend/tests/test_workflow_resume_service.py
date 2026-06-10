"""Service-level resume tests for the codex P1/P2 fixes on #189.

These exercise mechanics the API-level tests (test_workflow_resume_api.py)
don't reach: evidence chain continuity, concurrency-claim, and checkpoint
preservation on a failed resumed execution. They drive
``workflow_run_service.resume_run`` directly so they can inspect (and in
some cases construct) the row state precisely.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from btagent_engine.middleware import GENESIS_HASH
from btagent_shared.types.config import TLP, AutonomyLevel
from btagent_shared.types.workflow import WorkflowRunStatus
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.services import workflow_run_service, workflow_service
from btagent_backend.services.workflow_run_service import RunNotResumable

# Same pause-on-isolate workflow as the API tests.
PAUSING_DEF: dict[str, Any] = {
    "name": "pause-wf",
    "version": "1.0",
    "trigger": {},
    "nodes": [
        {"step_id": "t1", "node_id": "trigger.manual", "name": "start", "config": {}},
        {
            "step_id": "iso",
            "node_id": "integration.crowdstrike.isolate_host",
            "name": "isolate",
            "config": {"hostname": "WS-1"},
        },
    ],
    "edges": [{"source": "t1", "target": "iso", "label": "next"}],
}


async def _seed(db: AsyncSession, *, org_id: str):
    wf, version = await workflow_service.create_workflow(
        db,
        name="t",
        description="",
        org_id=org_id,
        created_by=None,
        initial_definition=PAUSING_DEF,
    )
    await db.commit()
    return wf, version


async def _execute_and_pause(db: AsyncSession, wf, version, *, triggered_by: str):
    run = await workflow_run_service.execute_version(
        db,
        workflow=wf,
        version=version,
        trigger_payload={},
        triggered_by=triggered_by,
        active_tlp=TLP.GREEN,
    )
    await db.commit()
    assert run.status == WorkflowRunStatus.PAUSED.value, run.status
    return run


# --------------------------------------------------------------------------- #
# P1: evidence chain preserved + linked across the pause/resume boundary
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_resume_preserves_and_links_evidence_chain(db_session: AsyncSession, sample_user):
    """Codex P1: prior evidence must survive the resume; the new records'
    ``prev_hash`` must point to the prior chain's tail (no GENESIS restart)."""
    wf, version = await _seed(db_session, org_id=sample_user.org_id)
    paused = await _execute_and_pause(db_session, wf, version, triggered_by=sample_user.id)

    # Pre-resume invariant: pause produced at least the trigger's evidence
    # record, chain starts at GENESIS.
    pre_chain = paused.evidence_chain
    assert len(pre_chain) >= 1
    assert pre_chain[0]["prev_hash"] == GENESIS_HASH
    pre_tail_hash = pre_chain[-1]["link_hash"]
    pre_node_ids = [e["node_id"] for e in pre_chain]

    resumed = await workflow_run_service.resume_run(
        db_session,
        workflow=wf,
        version=version,
        run=paused,
        approver_id=sample_user.id,
    )
    await db_session.commit()
    assert resumed.status == WorkflowRunStatus.SUCCEEDED.value

    post_chain = resumed.evidence_chain
    # Strictly grew (added at least one record for the resumed isolate step).
    assert len(post_chain) > len(pre_chain), (
        f"chain shrank/stagnated: {len(pre_chain)} -> {len(post_chain)}"
    )
    # Prior records survived verbatim.
    assert [e["node_id"] for e in post_chain[: len(pre_chain)]] == pre_node_ids
    assert post_chain[0]["prev_hash"] == GENESIS_HASH
    # The first NEW record's prev_hash chains to the prior tail.
    first_new = post_chain[len(pre_chain)]
    assert first_new["prev_hash"] == pre_tail_hash, (
        "first resumed record must link to the prior tail's link_hash, not restart at GENESIS"
    )


# --------------------------------------------------------------------------- #
# P1: concurrent resume attempts are serialized -- the integration node only
# fires once across racing approvers
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_concurrent_resume_attempts_only_one_succeeds(db_session: AsyncSession, sample_user):
    """Codex P1: two approvers calling resume simultaneously must not both
    pass the status check and both execute the approved integration node.

    The SQLite test backend is single-writer, so the two tasks serialize at
    the connection level rather than at row-level FOR UPDATE; the observable
    behaviour we lock in is the same: exactly one resume reaches the engine
    (the other 409s seeing the no-longer-paused status)."""
    wf, version = await _seed(db_session, org_id=sample_user.org_id)
    paused = await _execute_and_pause(db_session, wf, version, triggered_by=sample_user.id)
    pre_isolate_count = sum(1 for sid in (paused.nodes_executed or []) if sid == "iso")
    assert pre_isolate_count == 0  # paused before the gate ran

    # Drive two concurrent resumes against the same row. The second is
    # expected to raise RunNotResumable once the first commits.
    async def _attempt():
        try:
            r = await workflow_run_service.resume_run(
                db_session,
                workflow=wf,
                version=version,
                run=paused,
                approver_id=sample_user.id,
            )
            await db_session.commit()
            return ("ok", r)
        except RunNotResumable as exc:
            return ("conflict", exc)
        except Exception as exc:  # noqa: BLE001
            return ("error", exc)

    results = await asyncio.gather(_attempt(), _attempt())
    outcomes = {r[0] for r in results}
    # At least one must succeed; the other should observe the conflict.
    assert "ok" in outcomes, f"no resume succeeded: {results}"

    # Independently inspect the final persisted row -- the integration node
    # ("iso") must appear in nodes_executed at most ONCE (no double-fire).
    refreshed = await workflow_run_service.get_run(db_session, run_id=paused.id)
    assert refreshed is not None
    iso_count = sum(1 for sid in (refreshed.nodes_executed or []) if sid == "iso")
    assert iso_count == 1, (
        f"isolate fired {iso_count} times across concurrent resumes "
        f"(expected exactly 1); nodes_executed={refreshed.nodes_executed}"
    )


# --------------------------------------------------------------------------- #
# P2: a failed resume retains the prior checkpoint (outputs / nodes_executed)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_failed_resume_retains_prior_checkpoint(
    db_session: AsyncSession, sample_user, monkeypatch
):
    """Codex P2: if the resumed execution fails (e.g. the connector TLP
    check rejects the approved action mid-resume, or any later step
    structurally fails), the pre-resume checkpoint (outputs + nodes_executed
    + evidence chain) must NOT be erased -- the row needs to show what
    completed before the pause so analysts/auditors can see the failure
    context.

    We force-fail the resumed execution by patching ``_run_capture`` to
    return a FAILED ``_Outcome`` with empty fields (which is the exact
    shape a real ``WorkflowExecutionError`` produces today -- the executor
    doesn't expose partial state on a mid-walk failure). This isolates the
    test to the persistence invariant rather than engine internals.
    """
    wf, version = await _seed(db_session, org_id=sample_user.org_id)
    paused = await _execute_and_pause(db_session, wf, version, triggered_by=sample_user.id)

    pre_outputs = dict(paused.outputs or {})
    pre_nodes = list(paused.nodes_executed or [])
    pre_chain = list(paused.evidence_chain or [])
    assert pre_nodes  # something completed before the pause

    async def _force_failed(**_kwargs):
        return workflow_run_service._Outcome(
            status=WorkflowRunStatus.FAILED,
            error="forced failure for P2 test",
            # Empty fields -- this is exactly the shape an unhandled
            # WorkflowExecutionError mid-walk produces.
            outputs={},
            nodes_executed=[],
            evidence_chain=[],
        )

    monkeypatch.setattr(workflow_run_service, "_run_capture", _force_failed)

    resumed = await workflow_run_service.resume_run(
        db_session,
        workflow=wf,
        version=version,
        run=paused,
        approver_id=sample_user.id,
    )
    await db_session.commit()

    # Failed outcome, but the pre-pause checkpoint survived.
    assert resumed.status == WorkflowRunStatus.FAILED.value
    assert resumed.error == "forced failure for P2 test"
    assert dict(resumed.outputs or {}) == pre_outputs, "failed resume erased the prior outputs"
    assert list(resumed.nodes_executed or []) == pre_nodes, (
        "failed resume erased the prior nodes_executed"
    )
    # Evidence chain preserved -- _run_capture returned an empty list but
    # the resume_run fallback re-serialises the prior records so the audit
    # trail of what completed before the pause survives.
    assert len(resumed.evidence_chain or []) >= len(pre_chain), (
        "failed resume erased the prior evidence chain"
    )
