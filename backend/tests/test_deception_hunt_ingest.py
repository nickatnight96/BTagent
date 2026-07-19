"""Tests for the deception-hunt ingest service + API (deception vertical, slice 3).

Covers the backend shell that runs the deception hunt over the (mock-first)
Canary connector and lands its findings in the #119 store, plus the
``POST /hunt/deception/run`` route:

* end-to-end over the default mock Canary connector → findings persisted, every
  one in the ``deception`` domain;
* the run summary counts + active-intruder headline;
* active suppression flags matching findings on insert;
* the API route lands findings, is RBAC-gated, and the ``deception`` domain
  filter surfaces them.
"""

from btagent_shared.types.hunt import HuntSource
from btagent_shared.types.hunt_finding import SuppressionMatch
from conftest import auth_header
from sqlalchemy import select

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.db.models_hunt import HuntFindingRow
from btagent_backend.services import deception_hunt_run_service as svc
from btagent_backend.services import hunt_triage_service


async def _deception_findings(db_session) -> list[HuntFindingRow]:
    rows = (
        (
            await db_session.execute(
                select(HuntFindingRow).where(
                    HuntFindingRow.org_id == DEFAULT_ORG_ID,
                    HuntFindingRow.domain == "deception",
                )
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


# --- service ---


async def test_run_and_ingest_lands_deception_findings(db_session):
    summary = await svc.run_deception_hunt_and_ingest(db_session, org_id=DEFAULT_ORG_ID)
    assert summary["findings_created"] >= 1
    assert summary["findings_emitted"] == summary["findings_created"]
    # The Canary fixture attacker moves across 2 decoys → an active intruder.
    assert summary["active_intruder_count"] == 1
    assert sum(summary["counts_by_severity"].values()) == summary["findings_emitted"]

    rows = await _deception_findings(db_session)
    assert rows
    assert all(r.source == "deception" for r in rows)
    assert all(r.domain == "deception" for r in rows)


async def test_active_suppression_marks_findings_suppressed(db_session):
    # Suppress the deception source; the findings still land but suppressed.
    await hunt_triage_service.create_suppression(
        db_session,
        org_id=DEFAULT_ORG_ID,
        name="mute-deception",
        reason="test — mute deception source",
        match=SuppressionMatch(source=HuntSource.DECEPTION),
        created_by=None,
        acknowledge_overbroad=True,
        caller_role="admin",
    )
    summary = await svc.run_deception_hunt_and_ingest(db_session, org_id=DEFAULT_ORG_ID)
    assert summary["findings_created"] >= 1
    rows = await _deception_findings(db_session)
    assert rows
    assert all(r.state == "suppressed" for r in rows)


def test_default_server_is_canary():
    server = svc._default_deception_server()
    assert getattr(server, "server_id", "") == "canary"


# --- API ---


async def test_run_deception_hunt_route_lands_findings(client, analyst_token):
    resp = await client.post("/api/v1/hunt/deception/run", headers=auth_header(analyst_token))
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["findings_created"] >= 1
    assert data["active_intruder_count"] == 1
    assert sum(data["counts_by_severity"].values()) == data["findings_emitted"]

    inbox = await client.get(
        "/api/v1/hunt/findings?domain=deception", headers=auth_header(analyst_token)
    )
    assert inbox.status_code == 200, inbox.text
    assert inbox.json()["clusters"]


async def test_run_deception_requires_auth(client):
    resp = await client.post("/api/v1/hunt/deception/run")
    assert resp.status_code in (401, 403)
