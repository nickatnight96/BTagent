"""Tests for the NDR-hunt ingest service + API (NDR vertical, slice 3).

Covers the backend shell that runs the NDR hunt over the (mock-first) Vectra
connector and lands its findings in the #119 store, plus the
``POST /hunt/ndr/run`` route:

* end-to-end over the default mock Vectra connector → findings persisted, every
  one in the ``ndr`` domain;
* the run summary counts + campaign headline;
* active suppression flags matching findings on insert;
* the API route lands findings, is RBAC-gated, and the ``ndr`` domain filter
  surfaces them.
"""

from btagent_shared.types.hunt import HuntSource
from btagent_shared.types.hunt_finding import SuppressionMatch
from conftest import auth_header
from sqlalchemy import select

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.db.models_hunt import HuntFindingRow
from btagent_backend.services import hunt_triage_service
from btagent_backend.services import ndr_hunt_run_service as svc


async def _ndr_findings(db_session) -> list[HuntFindingRow]:
    rows = (
        (
            await db_session.execute(
                select(HuntFindingRow).where(
                    HuntFindingRow.org_id == DEFAULT_ORG_ID,
                    HuntFindingRow.domain == "ndr",
                )
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


# --- service ---


async def test_run_and_ingest_lands_ndr_findings(db_session):
    summary = await svc.run_ndr_hunt_and_ingest(db_session, org_id=DEFAULT_ORG_ID)
    assert summary["findings_created"] >= 1
    assert summary["findings_emitted"] == summary["findings_created"]
    # The Vectra fixture host walks the full kill chain → a campaign.
    assert summary["campaign_count"] >= 1
    assert sum(summary["counts_by_severity"].values()) == summary["findings_emitted"]

    rows = await _ndr_findings(db_session)
    assert rows
    assert all(r.source == "ndr" for r in rows)
    assert all(r.domain == "ndr" for r in rows)


async def test_active_suppression_marks_findings_suppressed(db_session):
    # Suppress the NDR source; the findings still land but suppressed.
    await hunt_triage_service.create_suppression(
        db_session,
        org_id=DEFAULT_ORG_ID,
        name="mute-ndr",
        reason="test — mute ndr source",
        match=SuppressionMatch(source=HuntSource.NDR),
        created_by=None,
        acknowledge_overbroad=True,
        caller_role="admin",
    )
    summary = await svc.run_ndr_hunt_and_ingest(db_session, org_id=DEFAULT_ORG_ID)
    assert summary["findings_created"] >= 1
    rows = await _ndr_findings(db_session)
    assert rows
    assert all(r.state == "suppressed" for r in rows)


def test_default_server_is_vectra():
    server = svc._default_ndr_server()
    assert getattr(server, "server_id", "") == "vectra"


# --- API ---


async def test_run_ndr_hunt_route_lands_findings(client, analyst_token):
    resp = await client.post("/api/v1/hunt/ndr/run", headers=auth_header(analyst_token))
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["findings_created"] >= 1
    assert data["campaign_count"] >= 1
    assert sum(data["counts_by_severity"].values()) == data["findings_emitted"]

    inbox = await client.get("/api/v1/hunt/findings?domain=ndr", headers=auth_header(analyst_token))
    assert inbox.status_code == 200, inbox.text
    assert inbox.json()["clusters"]


async def test_run_ndr_requires_auth(client):
    resp = await client.post("/api/v1/hunt/ndr/run")
    assert resp.status_code in (401, 403)
