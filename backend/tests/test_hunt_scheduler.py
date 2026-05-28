"""Tests for the Phase 6 scheduler foundation (#119).

Covers the dependency-free schedule helpers and the stale-suppression
sweep service function the arq cron job delegates to.
"""

from datetime import UTC, datetime, timedelta

from btagent_shared.hunt import schedule
from btagent_shared.utils.ids import generate_id

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.db.models_hunt import SuppressionRuleRow
from btagent_backend.services import hunt_triage_service as svc

# --- pure schedule helpers ---


def test_first_run_is_due_immediately():
    now = datetime.now(UTC)
    assert schedule.next_run_at(last_run=None, interval=timedelta(hours=1), now=now) == now
    assert schedule.is_due(last_run=None, interval=timedelta(hours=1), now=now)


def test_not_due_before_interval():
    now = datetime.now(UTC)
    last = now - timedelta(minutes=10)
    assert not schedule.is_due(last_run=last, interval=timedelta(hours=1), now=now)


def test_due_after_interval():
    now = datetime.now(UTC)
    last = now - timedelta(hours=2)
    assert schedule.is_due(last_run=last, interval=timedelta(hours=1), now=now)


def test_catch_up_clamps_to_now_not_past():
    now = datetime.now(UTC)
    last = now - timedelta(hours=5)
    # a long-down worker catches up to a single next slot (== now), not 5h ago
    assert schedule.next_run_at(last_run=last, interval=timedelta(hours=1), now=now) == now


# --- sweep service ---


async def _add_rule(db, *, state="active", expires_at=None, reconfirm_at=None):
    rule = SuppressionRuleRow(
        id=generate_id("supp"),
        org_id=DEFAULT_ORG_ID,
        name="r",
        reason="because",
        match={"source": "hunt_pack"},
        state=state,
        expires_at=expires_at,
        reconfirm_at=reconfirm_at,
        created_at=datetime.now(UTC),
    )
    db.add(rule)
    await db.flush()
    return rule


async def test_sweep_expires_and_flags(db_session):
    now = datetime.now(UTC)
    expired = await _add_rule(db_session, expires_at=now - timedelta(hours=1))
    reconfirm = await _add_rule(db_session, reconfirm_at=now - timedelta(hours=1))
    fresh = await _add_rule(
        db_session, reconfirm_at=now + timedelta(days=30), expires_at=now + timedelta(days=60)
    )

    counts = await svc.sweep_stale_suppressions(db_session, now=now)

    assert counts["expired"] == 1
    assert counts["needs_reconfirm"] == 1
    await db_session.refresh(expired)
    await db_session.refresh(reconfirm)
    await db_session.refresh(fresh)
    assert expired.state == "expired"
    assert reconfirm.state == "needs_reconfirm"
    assert fresh.state == "active"


async def test_sweep_accepts_naive_now(db_session):
    # A naive `now` must not raise "can't compare offset-naive and aware".
    aware_now = datetime.now(UTC)
    expired = await _add_rule(db_session, expires_at=aware_now - timedelta(hours=1))

    naive_now = aware_now.replace(tzinfo=None)
    counts = await svc.sweep_stale_suppressions(db_session, now=naive_now)

    assert counts["expired"] == 1
    await db_session.refresh(expired)
    assert expired.state == "expired"
