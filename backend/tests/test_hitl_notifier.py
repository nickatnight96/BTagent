"""Tests for the workflow HITL-pause notification producer.

Service level: ``notify_workflow_paused`` targets the run's triggering
analyst when (and only when) the run is paused. Route level: the pausing
workflow from the resume-API suite must leave a ``hitl_checkpoint``
notification for the analyst who launched it, and a successful resume must
not add another.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock

from btagent_shared.utils.ids import generate_id
from httpx import AsyncClient
from sqlalchemy import select

from btagent_backend.db.models import DEFAULT_ORG_ID, NotificationRow
from btagent_backend.db.models_workflow import WorkflowRow, WorkflowRunRow
from btagent_backend.services import workflow_service
from btagent_backend.services.hitl_notifier import (
    notify_workflow_paused,
    notify_workflow_paused_approvers,
)
from tests.helpers import auth_header

# --------------------------------------------------------------------------- #
# Service level
# --------------------------------------------------------------------------- #


async def _seed_workflow_and_run(
    db_session,
    *,
    status: str = "paused",
    triggered_by: str | None,
    paused_node_id: str | None = "iso",
    investigation_id: str | None = None,
) -> tuple[WorkflowRow, WorkflowRunRow]:
    wf, version = await workflow_service.create_workflow(
        db_session,
        name="Containment sweep",
        description="",
        org_id=DEFAULT_ORG_ID,
        created_by=None,
        initial_definition={},
    )
    run = WorkflowRunRow(
        id=generate_id("wfrun"),
        workflow_id=wf.id,
        version_id=version.id,
        version_number=version.version_number,
        org_id=DEFAULT_ORG_ID,
        triggered_by=triggered_by,
        investigation_id=investigation_id,
        status=status,
        paused_node_id=paused_node_id,
    )
    db_session.add(run)
    await db_session.flush()
    return wf, run


async def test_paused_run_notifies_triggering_analyst(db_session, sample_user):
    wf, run = await _seed_workflow_and_run(db_session, triggered_by=sample_user.id)
    row = await notify_workflow_paused(db_session, workflow=wf, run=run)
    assert row is not None
    assert row.user_id == sample_user.id
    assert row.type == "hitl_checkpoint"
    assert row.title == "Workflow Awaiting Approval"
    assert "Containment sweep" in row.message
    assert "'iso'" in row.message
    assert run.id in row.message
    assert row.link == f"/workflows/{wf.id}"  # bell deep-link to run history


async def test_non_paused_run_is_noop(db_session, sample_user):
    wf, run = await _seed_workflow_and_run(
        db_session, status="succeeded", triggered_by=sample_user.id, paused_node_id=None
    )
    assert await notify_workflow_paused(db_session, workflow=wf, run=run) is None


async def test_run_without_trigger_user_is_noop(db_session):
    wf, run = await _seed_workflow_and_run(db_session, triggered_by=None)
    assert await notify_workflow_paused(db_session, workflow=wf, run=run) is None


async def test_investigation_link_carries_through(db_session, sample_user, sample_investigation):
    wf, run = await _seed_workflow_and_run(
        db_session, triggered_by=sample_user.id, investigation_id=sample_investigation.id
    )
    row = await notify_workflow_paused(db_session, workflow=wf, run=run)
    assert row is not None
    assert row.investigation_id == sample_investigation.id


async def test_redis_push_targets_trigger_users_channel(db_session, sample_user):
    wf, run = await _seed_workflow_and_run(db_session, triggered_by=sample_user.id)
    redis = AsyncMock()
    row = await notify_workflow_paused(db_session, workflow=wf, run=run, redis=redis)
    assert row is not None
    redis.publish.assert_awaited_once()
    channel, payload = redis.publish.await_args.args
    assert channel == f"btagent:notifications:{sample_user.id}"
    assert json.loads(payload)["type"] == "hitl_checkpoint"


# --------------------------------------------------------------------------- #
# Approver fan-out
# --------------------------------------------------------------------------- #
# The default org is shared across the test session, so other files' senior+
# users may also appear in the fan-out — assertions are membership-based,
# never exact-count.


async def test_approver_fanout_reaches_senior_roles(db_session, sample_user, admin_user):
    wf, run = await _seed_workflow_and_run(db_session, triggered_by=sample_user.id)
    rows = await notify_workflow_paused_approvers(db_session, workflow=wf, run=run)
    targets = {r.user_id for r in rows}
    assert admin_user.id in targets
    assert sample_user.id not in targets  # analyst — not an approver
    assert all(r.title == "Approval Requested" for r in rows)
    assert all(r.type == "hitl_checkpoint" for r in rows)
    assert all(run.id in r.message for r in rows)
    assert all(r.link == f"/workflows/{wf.id}" for r in rows)


async def test_approver_fanout_excludes_the_triggering_approver(db_session, admin_user):
    wf, run = await _seed_workflow_and_run(db_session, triggered_by=admin_user.id)
    rows = await notify_workflow_paused_approvers(db_session, workflow=wf, run=run)
    assert admin_user.id not in {r.user_id for r in rows}


async def test_approver_fanout_noop_when_not_paused(db_session, sample_user, admin_user):
    wf, run = await _seed_workflow_and_run(
        db_session, status="succeeded", triggered_by=sample_user.id, paused_node_id=None
    )
    assert await notify_workflow_paused_approvers(db_session, workflow=wf, run=run) == []


# --------------------------------------------------------------------------- #
# Route level — reuses the pausing workflow from the resume-API suite
# --------------------------------------------------------------------------- #

_PAUSING_DEF = {
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


async def _pause_notifications(db_session, user_id: str) -> list[NotificationRow]:
    result = await db_session.execute(
        select(NotificationRow).where(
            NotificationRow.user_id == user_id,
            NotificationRow.type == "hitl_checkpoint",
        )
    )
    return list(result.scalars().all())


async def test_run_route_creates_pause_notification(
    client: AsyncClient, admin_token: str, analyst_token: str, sample_user, admin_user, db_session
):
    resp = await client.post(
        "/api/v1/workflows",
        json={"name": "wf", "description": "", "definition": _PAUSING_DEF},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 201, resp.text
    wf_id = resp.json()["id"]

    resp = await client.post(
        f"/api/v1/workflows/{wf_id}/versions/1/run",
        json={"trigger_payload": {}},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 201, resp.text
    run = resp.json()
    assert run["status"] == "paused"

    rows = await _pause_notifications(db_session, sample_user.id)
    assert len(rows) == 1
    assert run["id"] in rows[0].message

    # The admin (an approver) gets the approval-requested fan-out for this run.
    admin_rows = [
        r for r in await _pause_notifications(db_session, admin_user.id) if run["id"] in r.message
    ]
    assert len(admin_rows) == 1
    assert admin_rows[0].title == "Approval Requested"

    # Approving through to completion must NOT add a second notification.
    resp = await client.post(
        f"/api/v1/workflows/{wf_id}/runs/{run['id']}/resume",
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "succeeded"
    rows = await _pause_notifications(db_session, sample_user.id)
    assert len(rows) == 1
