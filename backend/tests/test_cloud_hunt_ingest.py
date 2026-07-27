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

from datetime import UTC, datetime

from btagent_shared.types.hunt import HuntSource
from btagent_shared.types.hunt_finding import SuppressionMatch
from btagent_shared.utils.ids import generate_id
from conftest import auth_header
from sqlalchemy import select

from btagent_backend.db.models import DEFAULT_ORG_ID, OrganizationRow
from btagent_backend.db.models_cti import DetectionProposalRow
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


# --- clean-TTP → #113 detection-proposal routing (#117 task D) ---


async def test_clean_cloud_ttps_routed_to_detection_proposals(db_session):
    """Covered cloud TTPs with zero findings this run become #113 draft proposals.

    Mirrors the hunt-plan clean-TTP path. Seeds a dedicated per-test org (the
    shared in-memory DB persists committed rows across the run, so an exact
    proposal-count assertion MUST be org-scoped, never on DEFAULT_ORG_ID).
    """
    org_id = generate_id("org")
    db_session.add(OrganizationRow(id=org_id, name="cloud-clean-ttp", created_at=datetime.now(UTC)))
    await db_session.flush()

    summary = await svc.run_cloud_hunt_and_ingest(db_session, org_id=org_id)
    # The demo bundle fires cross-account trust + shadow-workload + overprivileged
    # (T1078.004 / T1550.001 / T1098.001); the remaining covered techniques are
    # clean and must each yield a proposal.
    assert summary["clean_ttp_proposals"] >= 4

    rows = (
        (
            await db_session.execute(
                select(DetectionProposalRow).where(DetectionProposalRow.org_id == org_id)
            )
        )
        .scalars()
        .all()
    )
    proposed_ttps = {t for r in rows for t in (r.technique_ids or [])}
    # Clean (hunted, no finding) → proposal filed.
    assert {"T1098.003", "T1537", "T1562.008", "T1580"}.issubset(proposed_ttps)
    # Fired techniques (had findings) → NOT filed as clean-coverage gaps.
    assert "T1078.004" not in proposed_ttps
    assert "T1098.001" not in proposed_ttps
    # All are cloud-hunt-sourced drafts in the review queue.
    for r in rows:
        assert r.source_stix_id.startswith("cloud-hunt--")
        assert r.state == "proposed"


async def test_clean_cloud_ttp_proposals_upsert_not_duplicate(db_session):
    """Re-running the cloud hunt upserts the clean-TTP proposals (no duplicates)."""
    org_id = generate_id("org")
    db_session.add(
        OrganizationRow(id=org_id, name="cloud-clean-upsert", created_at=datetime.now(UTC))
    )
    await db_session.flush()

    await svc.run_cloud_hunt_and_ingest(db_session, org_id=org_id)
    first = (
        (
            await db_session.execute(
                select(DetectionProposalRow).where(DetectionProposalRow.org_id == org_id)
            )
        )
        .scalars()
        .all()
    )
    await svc.run_cloud_hunt_and_ingest(db_session, org_id=org_id)
    second = (
        (
            await db_session.execute(
                select(DetectionProposalRow).where(DetectionProposalRow.org_id == org_id)
            )
        )
        .scalars()
        .all()
    )
    # Deterministic source ids → the second run refreshes the same rows.
    assert len(second) == len(first)
    assert {r.source_stix_id for r in second} == {r.source_stix_id for r in first}
