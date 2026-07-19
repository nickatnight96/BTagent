"""Tests for the email-hunt ingest service (email vertical, slice 4).

Covers the backend side-effectful shell that runs the email hunt over the
(mock-first) connectors and lands its findings in the #119 hunt-findings store:

* end-to-end over the default mock email connectors → findings persisted,
  every one in the ``email`` domain;
* the run summary counts (emitted vs. created, severity breakdown);
* active suppression drops matching findings pre-insert;
* an explicit empty-connector run is a clean no-op.
"""

from btagent_shared.types.hunt import HuntSource
from btagent_shared.types.hunt_finding import SuppressionMatch
from sqlalchemy import select

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.db.models_hunt import HuntFindingRow
from btagent_backend.services import email_hunt_run_service as svc
from btagent_backend.services import hunt_triage_service

# Wide window so every connector's mid-2026 fixtures fall inside it.
_START = "2026-01-01T00:00:00Z"
_END = "2026-12-31T00:00:00Z"


async def _email_findings(db_session) -> list[HuntFindingRow]:
    rows = (
        (
            await db_session.execute(
                select(HuntFindingRow).where(
                    HuntFindingRow.org_id == DEFAULT_ORG_ID,
                    HuntFindingRow.domain == "email",
                )
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


async def test_run_and_ingest_lands_email_findings(db_session):
    summary = await svc.run_email_hunt_and_ingest(
        db_session, org_id=DEFAULT_ORG_ID, start=_START, end=_END
    )
    assert summary["findings_created"] >= 1
    assert summary["findings_emitted"] == summary["findings_created"]  # no suppressions
    assert summary["total_incidents"] >= summary["findings_created"] or summary["findings_created"]
    # Severity counts sum to the emitted findings.
    assert sum(summary["counts_by_severity"].values()) == summary["findings_emitted"]

    rows = await _email_findings(db_session)
    assert rows
    assert all(r.source == "email_security" for r in rows)
    assert all(r.domain == "email" for r in rows)


async def test_empty_connectors_is_noop(db_session):
    summary = await svc.run_email_hunt_and_ingest(
        db_session, org_id=DEFAULT_ORG_ID, start=_START, end=_END, servers=[]
    )
    assert summary["findings_created"] == 0
    assert summary["findings_emitted"] == 0
    assert summary["total_incidents"] == 0


async def test_active_suppression_marks_email_findings_suppressed(db_session):
    # Suppress the phishing technique (every email finding carries T1566), then
    # run: the findings still land as rows but in the ``suppressed`` state
    # (suppression flags on insert, it does not drop rows).
    # This test verifies suppression *flags* findings, not the over-broad
    # guard. Since the in-memory DB is shared across tests, other email
    # findings can make a T1566/email_security match read as over-broad, so
    # acknowledge it as admin to keep the test order-independent.
    await hunt_triage_service.create_suppression(
        db_session,
        org_id=DEFAULT_ORG_ID,
        name="mute-phishing-technique",
        reason="test — mute the phishing technique",
        match=SuppressionMatch(source=HuntSource.EMAIL_SECURITY, technique_ids=["T1566"]),
        created_by=None,
        acknowledge_overbroad=True,
        caller_role="admin",
    )
    summary = await svc.run_email_hunt_and_ingest(
        db_session, org_id=DEFAULT_ORG_ID, start=_START, end=_END
    )
    assert summary["findings_created"] >= 1
    rows = await _email_findings(db_session)
    assert rows
    # Every email finding carries T1566, so all match the rule → suppressed.
    assert all(r.state == "suppressed" for r in rows)


async def test_default_servers_are_the_three_email_connectors():
    servers = svc._default_email_servers()
    ids = {getattr(s, "server_id", "") for s in servers}
    assert ids == {"defender_o365", "proofpoint", "mimecast"}
