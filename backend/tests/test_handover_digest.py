"""Tests for the shift-handover digest producer (#108 UC-5.1).

Covers ``notify_shift_handover``: an active window notifies every analyst
with the headline + PunchList deep link, and a quiet window (no activity,
no open backlog) stays silent. Also covers the rollup's 8h shift-boundary —
the cadence the arq cron fires on (06:00 / 14:00 / 22:00 UTC).
"""

from datetime import UTC, datetime, timedelta

from btagent_shared.types.enums import InvestigationStatus, Severity
from btagent_shared.utils.ids import generate_id

from btagent_backend.db.models import (
    DEFAULT_ORG_ID,
    InvestigationRow,
    NotificationRow,
    OrganizationRow,
)
from btagent_backend.services.handover_notifier import notify_shift_handover
from btagent_backend.services.handover_service import build_handover_summary


async def test_active_window_notifies_analysts(db_session, sample_user):
    inv = InvestigationRow(
        id=generate_id("inv"),
        org_id=DEFAULT_ORG_ID,
        title="Digest Test — overnight phishing case",
        description="",
        status=InvestigationStatus.INVESTIGATING.value,
        severity=Severity.HIGH.value,
        tlp_level="green",
        assigned_to=sample_user.id,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    db_session.add(inv)
    await db_session.flush()

    created = await notify_shift_handover(db_session, org_id=DEFAULT_ORG_ID)

    assert created, "an active window must notify"
    row = created[0]
    assert isinstance(row, NotificationRow)
    assert row.type == "shift_handover"
    assert "hunt finding(s)" in row.message
    assert row.link == "/"
    # The seeded analyst is among the recipients.
    assert sample_user.id in {r.user_id for r in created}


async def test_quiet_window_stays_silent(db_session):
    quiet_org = OrganizationRow(id="org_quiet_digest", name="Quiet Digest Org")
    db_session.add(quiet_org)
    await db_session.flush()

    created = await notify_shift_handover(db_session, org_id="org_quiet_digest")
    assert created == []


async def test_handover_window_respects_the_8h_shift_boundary(db_session):
    """The rollup's activity list is bounded by an 8h shift window: a case last
    touched 7h ago (inside) is rolled up, one touched 9h ago (outside) is not.

    This is the boundary the arq cron leans on — it fires at 06:00 / 14:00 /
    22:00 UTC, exactly 8h apart, so a run at a boundary summarises the shift
    that just ended and nothing from the shift before it.
    """
    org_id = "org_window_boundary"
    db_session.add(OrganizationRow(id=org_id, name="Window Boundary Org"))
    await db_session.flush()

    now = datetime.now(UTC)

    def _make(title: str, *, age_hours: int, severity: Severity) -> InvestigationRow:
        touched = now - timedelta(hours=age_hours)
        return InvestigationRow(
            id=generate_id("inv"),
            org_id=org_id,
            title=title,
            description="",
            status=InvestigationStatus.INVESTIGATING.value,
            severity=severity.value,
            tlp_level="green",
            created_at=touched,
            updated_at=touched,
        )

    inside = _make("Handover window — fresh case (7h old)", age_hours=7, severity=Severity.HIGH)
    outside = _make("Handover window — stale case (9h old)", age_hours=9, severity=Severity.MEDIUM)
    db_session.add_all([inside, outside])
    await db_session.flush()

    summary = await build_handover_summary(db_session, org_id=org_id, window_hours=8)

    window_ids = {item["id"] for item in summary["investigations"]}
    assert inside.id in window_ids, "activity inside the 8h window must be rolled up"
    assert outside.id not in window_ids, "activity before the 8h boundary must be excluded"
    # The in-window case was also created in-window, so it reads as new.
    inside_item = next(i for i in summary["investigations"] if i["id"] == inside.id)
    assert inside_item["is_new"] is True
