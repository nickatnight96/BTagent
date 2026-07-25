"""Tests for the shift-handover digest producer (#108 UC-5.1).

Covers ``notify_shift_handover``: an active window notifies every analyst
with the headline + PunchList deep link, and a quiet window (no activity,
no open backlog) stays silent.
"""

from datetime import UTC, datetime

from btagent_shared.types.enums import InvestigationStatus, Severity
from btagent_shared.utils.ids import generate_id

from btagent_backend.db.models import (
    DEFAULT_ORG_ID,
    InvestigationRow,
    NotificationRow,
    OrganizationRow,
)
from btagent_backend.services.handover_notifier import notify_shift_handover


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
