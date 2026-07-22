"""Tests for background workflow execution (async offload).

Service level: ``create_pending_run`` persists a ``running`` row without
touching the engine; ``execute_pending_run`` drives it to a terminal (or
paused) state and is idempotent against arq redelivery. Route level:
``?background=true`` returns immediately with ``status=running`` and hands
off to a (monkeypatched) enqueue; a broker outage marks the run failed and
503s rather than leaving an orphaned running row.
"""

from __future__ import annotations

from typing import Any

from btagent_shared.types.config import TLP
from btagent_shared.types.workflow import WorkflowRunStatus
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.services import workflow_run_service, workflow_service
from tests.helpers import auth_header

# trigger.manual -> crowdstrike.isolate_host: pauses at the HITL gate under
# the default L2 posture (same definition the resume-API suite uses).
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

# Trigger-only graph: succeeds immediately, no gates.
TRIVIAL_DEF: dict[str, Any] = {
    "name": "trivial-wf",
    "version": "1.0",
    "trigger": {},
    "nodes": [{"step_id": "t1", "node_id": "trigger.manual", "name": "start", "config": {}}],
    "edges": [],
}


async def _seed(db: AsyncSession, definition: dict):
    wf, version = await workflow_service.create_workflow(
        db,
        name=definition["name"],
        description="",
        org_id=DEFAULT_ORG_ID,
        created_by=None,
        initial_definition=definition,
    )
    await db.commit()
    return wf, version


# --------------------------------------------------------------------------- #
# Service level
# --------------------------------------------------------------------------- #


async def test_create_pending_run_persists_running_row_without_executing(
    db_session: AsyncSession, sample_user
):
    wf, version = await _seed(db_session, TRIVIAL_DEF)
    run = await workflow_run_service.create_pending_run(
        db_session,
        workflow=wf,
        version=version,
        trigger_payload={"k": "v"},
        triggered_by=sample_user.id,
        active_tlp=TLP.GREEN,
    )
    assert run.status == WorkflowRunStatus.RUNNING.value
    assert run.nodes_executed == []
    assert run.completed_at is None
    assert run.active_tlp == "green"
    assert run.trigger_payload == {"k": "v"}


async def test_execute_pending_run_drives_to_terminal_state(db_session: AsyncSession, sample_user):
    wf, version = await _seed(db_session, TRIVIAL_DEF)
    run = await workflow_run_service.create_pending_run(
        db_session,
        workflow=wf,
        version=version,
        trigger_payload={},
        triggered_by=sample_user.id,
        active_tlp=TLP.GREEN,
    )
    await db_session.commit()

    executed = await workflow_run_service.execute_pending_run(db_session, run_id=run.id)
    assert executed is not None
    assert executed.status == WorkflowRunStatus.SUCCEEDED.value
    assert executed.nodes_executed == ["t1"]
    assert executed.completed_at is not None


async def test_execute_pending_run_pauses_at_hitl_gate(db_session: AsyncSession, sample_user):
    wf, version = await _seed(db_session, PAUSING_DEF)
    run = await workflow_run_service.create_pending_run(
        db_session,
        workflow=wf,
        version=version,
        trigger_payload={},
        triggered_by=sample_user.id,
        active_tlp=TLP.GREEN,
    )
    await db_session.commit()

    executed = await workflow_run_service.execute_pending_run(db_session, run_id=run.id)
    assert executed is not None
    assert executed.status == WorkflowRunStatus.PAUSED.value
    assert executed.paused_node_id == "iso"
    # A background pause is resumable exactly like a sync one.
    assert executed.nodes_executed == ["t1"]


async def test_execute_pending_run_is_idempotent(db_session: AsyncSession, sample_user):
    wf, version = await _seed(db_session, TRIVIAL_DEF)
    run = await workflow_run_service.create_pending_run(
        db_session,
        workflow=wf,
        version=version,
        trigger_payload={},
        triggered_by=sample_user.id,
        active_tlp=TLP.GREEN,
    )
    await db_session.commit()

    first = await workflow_run_service.execute_pending_run(db_session, run_id=run.id)
    assert first is not None and first.status == WorkflowRunStatus.SUCCEEDED.value
    # Redelivery: the run is no longer running — engine must not re-fire.
    assert await workflow_run_service.execute_pending_run(db_session, run_id=run.id) is None
    assert await workflow_run_service.execute_pending_run(db_session, run_id="wfrun_NOPE") is None


# --------------------------------------------------------------------------- #
# Route level
# --------------------------------------------------------------------------- #


async def _create_workflow_via_api(client: AsyncClient, admin_token: str, definition: dict) -> str:
    resp = await client.post(
        "/api/v1/workflows",
        json={"name": "wf", "description": "", "definition": definition},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["id"]


async def test_background_run_returns_running_and_enqueues(
    client: AsyncClient, admin_token: str, analyst_token: str, monkeypatch
):
    from btagent_backend.api.v1 import workflows as wf_module

    enqueued: list[str] = []

    async def fake_enqueue(run_id: str) -> None:
        enqueued.append(run_id)

    monkeypatch.setattr(wf_module, "_enqueue_background_run", fake_enqueue)

    wf_id = await _create_workflow_via_api(client, admin_token, PAUSING_DEF)
    resp = await client.post(
        f"/api/v1/workflows/{wf_id}/versions/1/run?background=true",
        json={"trigger_payload": {}},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 201, resp.text
    run = resp.json()
    assert run["status"] == "running"
    assert run["nodes_executed"] == []
    assert enqueued == [run["id"]]

    # The row is pollable immediately.
    resp = await client.get(
        f"/api/v1/workflows/{wf_id}/runs/{run['id']}", headers=auth_header(analyst_token)
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "running"


async def test_background_enqueue_failure_marks_run_failed_and_503s(
    client: AsyncClient, admin_token: str, analyst_token: str, monkeypatch
):
    from btagent_backend.api.v1 import workflows as wf_module

    async def broken_enqueue(run_id: str) -> None:
        raise ConnectionError("redis down")

    monkeypatch.setattr(wf_module, "_enqueue_background_run", broken_enqueue)

    wf_id = await _create_workflow_via_api(client, admin_token, TRIVIAL_DEF)
    resp = await client.post(
        f"/api/v1/workflows/{wf_id}/versions/1/run?background=true",
        json={"trigger_payload": {}},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 503, resp.text

    # No orphaned running row: the persisted run is terminal-failed.
    listing = await client.get(
        f"/api/v1/workflows/{wf_id}/runs", headers=auth_header(analyst_token)
    )
    assert listing.status_code == 200
    runs = listing.json()["items"]
    assert len(runs) == 1
    assert runs[0]["status"] == "failed"
    assert "queue" in (runs[0]["error"] or "").lower()
