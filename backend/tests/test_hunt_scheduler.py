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


# --- Codex #202 P1: hunt_schedule_enabled derived default + cron gate ---


def _settings(**env):
    from btagent_backend.config import Settings

    return Settings(env="test", **env)


def test_hunt_schedule_enabled_derives_from_mock_connectors():
    # Mocks on → schedule enabled; mocks off → schedule disabled (default).
    assert _settings(mock_connectors=True).hunt_schedule_enabled is True
    assert _settings(mock_connectors=False).hunt_schedule_enabled is False


def test_hunt_schedule_enabled_explicit_override_wins():
    # An operator with live connectors can force it on despite mocks off.
    assert (
        _settings(mock_connectors=False, hunt_schedule_enabled=True).hunt_schedule_enabled is True
    )
    # ...and force it off despite mocks on.
    assert (
        _settings(mock_connectors=True, hunt_schedule_enabled=False).hunt_schedule_enabled is False
    )


async def test_scheduled_cron_skips_and_warns_when_disabled(monkeypatch, caplog):
    """When hunt_schedule_enabled is false the cron must no-op with one warning
    and never touch the engine/runner (which would NotImplementedError live)."""
    import logging

    from btagent_backend.config import get_settings
    from btagent_backend.scheduler import jobs

    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")
    get_settings.cache_clear()
    try:
        with caplog.at_level(logging.WARNING, logger="btagent.scheduler.jobs"):
            result = await jobs.scheduled_hunt_pack_run({})
        assert result == {
            "packs_run": 0,
            "findings_created": 0,
            "hits": 0,
            "failed_packs": 0,
        }
        warnings = [r for r in caplog.records if "hunt schedule disabled" in r.message]
        assert len(warnings) == 1
        assert "BTAGENT_HUNT_SCHEDULE_ENABLED=true" in warnings[0].message
    finally:
        get_settings.cache_clear()


# --- email-hunt scheduled scan (email vertical, slice 7) ---


async def test_email_hunt_scan_skips_and_warns_when_disabled(monkeypatch, caplog):
    """With email_hunt_schedule_enabled false (mocks off) the cron no-ops with
    one warning and never touches the connectors (which would refuse live)."""
    import logging

    from btagent_backend.config import get_settings
    from btagent_backend.scheduler import jobs

    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")
    get_settings.cache_clear()
    try:
        with caplog.at_level(logging.WARNING, logger="btagent.scheduler.jobs"):
            result = await jobs.scheduled_email_hunt_scan({})
        assert result == {
            "total_incidents": 0,
            "findings_created": 0,
            "findings_emitted": 0,
        }
        warnings = [r for r in caplog.records if "email hunt schedule disabled" in r.message]
        assert len(warnings) == 1
        assert "BTAGENT_EMAIL_HUNT_SCHEDULE_ENABLED=true" in warnings[0].message
    finally:
        get_settings.cache_clear()


async def test_email_hunt_scan_lands_findings_when_enabled(monkeypatch, caplog, db_session):
    """With mocks on, the scan gathers the mock email connectors and lands
    ``email``-domain findings in the inbox."""
    from contextlib import asynccontextmanager

    from sqlalchemy import select

    from btagent_backend.config import get_settings
    from btagent_backend.db.models_hunt import HuntFindingRow
    from btagent_backend.scheduler import jobs

    @asynccontextmanager
    async def _session_cm():
        yield db_session

    monkeypatch.setattr(jobs, "async_session_factory", _session_cm)
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    # A wide lookback so the connectors' mid-2026 fixtures fall in the window.
    monkeypatch.setenv("BTAGENT_EMAIL_HUNT_LOOKBACK_HOURS", "12000")
    get_settings.cache_clear()
    try:
        result = await jobs.scheduled_email_hunt_scan({})
        assert result["findings_created"] >= 1
        assert result["findings_emitted"] == result["findings_created"]

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
        assert rows
        assert all(r.source == "email_security" for r in rows)
    finally:
        get_settings.cache_clear()


# --- deception-hunt scheduled scan (deception vertical, slice 5) ---


async def test_deception_hunt_scan_skips_and_warns_when_disabled(monkeypatch, caplog):
    """With deception_hunt_schedule_enabled false (mocks off) the cron no-ops
    with one warning and never touches the connector (which would refuse live)."""
    import logging

    from btagent_backend.config import get_settings
    from btagent_backend.scheduler import jobs

    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")
    get_settings.cache_clear()
    try:
        with caplog.at_level(logging.WARNING, logger="btagent.scheduler.jobs"):
            result = await jobs.scheduled_deception_hunt_scan({})
        assert result == {
            "total_incidents": 0,
            "findings_created": 0,
            "findings_emitted": 0,
        }
        warnings = [r for r in caplog.records if "deception hunt schedule disabled" in r.message]
        assert len(warnings) == 1
        assert "BTAGENT_DECEPTION_HUNT_SCHEDULE_ENABLED=true" in warnings[0].message
    finally:
        get_settings.cache_clear()


async def test_deception_hunt_scan_lands_findings_when_enabled(monkeypatch, db_session):
    """With mocks on, the scan gathers the mock Canary connector and lands
    ``deception``-domain findings in the inbox."""
    from contextlib import asynccontextmanager

    from sqlalchemy import select

    from btagent_backend.config import get_settings
    from btagent_backend.db.models_hunt import HuntFindingRow
    from btagent_backend.scheduler import jobs

    @asynccontextmanager
    async def _session_cm():
        yield db_session

    monkeypatch.setattr(jobs, "async_session_factory", _session_cm)
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")
    get_settings.cache_clear()
    try:
        result = await jobs.scheduled_deception_hunt_scan({})
        assert result["findings_created"] >= 1
        assert result["findings_emitted"] == result["findings_created"]

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
        assert rows
        assert all(r.source == "deception" for r in rows)
    finally:
        get_settings.cache_clear()
