"""Tests for the cloud control-plane hunt ingest service + API (#117, cloud slice 2).

Covers the backend shell that runs the cloud hunt over the (mock) demo bundle
and lands its findings in the #119 store, plus the ``POST /hunt/cloud/run``
route:

* end-to-end over the demo bundle → findings persisted, every one in the
  ``cloud`` domain;
* the run summary counts (emitted == created absent suppression; severity
  breakdown reconciles);
* active suppression flags matching findings on insert;
* the API route lands findings, is RBAC-gated, and the ``cloud`` domain filter
  surfaces them.
"""

from btagent_shared.types.hunt import HuntSource
from btagent_shared.types.hunt_finding import SuppressionMatch
from conftest import auth_header
from sqlalchemy import select

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.db.models_hunt import HuntFindingRow
from btagent_backend.services import cloud_hunt_run_service as svc
from btagent_backend.services import hunt_triage_service


async def _cloud_findings(db_session) -> list[HuntFindingRow]:
    rows = (
        (
            await db_session.execute(
                select(HuntFindingRow).where(
                    HuntFindingRow.org_id == DEFAULT_ORG_ID,
                    HuntFindingRow.domain == "cloud",
                )
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


# --- service ---


async def test_run_and_ingest_lands_cloud_findings(db_session):
    summary = await svc.run_cloud_hunt_and_ingest(db_session, org_id=DEFAULT_ORG_ID)
    assert summary["findings_created"] >= 1
    assert summary["findings_emitted"] == summary["findings_created"]
    # The demo bundle carries identities + workloads.
    assert summary["total_identities"] >= 1
    assert summary["total_workloads"] >= 1
    assert sum(summary["counts_by_severity"].values()) == summary["findings_emitted"]

    rows = await _cloud_findings(db_session)
    assert rows
    assert all(r.source == "cloud" for r in rows)
    assert all(r.domain == "cloud" for r in rows)


async def test_active_suppression_marks_findings_suppressed(db_session):
    # Suppress the cloud source; the findings still land but suppressed.
    await hunt_triage_service.create_suppression(
        db_session,
        org_id=DEFAULT_ORG_ID,
        name="mute-cloud",
        reason="test — mute cloud source",
        match=SuppressionMatch(source=HuntSource.CLOUD),
        created_by=None,
        acknowledge_overbroad=True,
        caller_role="admin",
    )
    summary = await svc.run_cloud_hunt_and_ingest(db_session, org_id=DEFAULT_ORG_ID)
    assert summary["findings_created"] >= 1
    rows = await _cloud_findings(db_session)
    assert rows
    assert all(r.state == "suppressed" for r in rows)


# --- API ---


async def test_run_cloud_hunt_route_lands_findings(client, analyst_token):
    resp = await client.post("/api/v1/hunt/cloud/run", headers=auth_header(analyst_token))
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["findings_created"] >= 1
    assert sum(data["counts_by_severity"].values()) == data["findings_emitted"]

    inbox = await client.get(
        "/api/v1/hunt/findings?domain=cloud", headers=auth_header(analyst_token)
    )
    assert inbox.status_code == 200, inbox.text
    assert inbox.json()["clusters"]


async def test_run_cloud_requires_auth(client):
    resp = await client.post("/api/v1/hunt/cloud/run")
    assert resp.status_code in (401, 403)
