"""Tests for the investigation-outcome notification producer.

``notify_investigation_outcome`` is the first real producer for the in-app
notification pipeline: terminal investigation states notify the assigned
analyst (DB row + per-user Redis channel for the WebSocket push).
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock

from btagent_shared.types.enums import InvestigationStatus, Severity
from btagent_shared.utils.ids import generate_id
from sqlalchemy import select

from btagent_backend.db.models import DEFAULT_ORG_ID, InvestigationRow, NotificationRow
from btagent_backend.services.investigation_notifier import (
    _format_duration,
    notify_investigation_outcome,
)


async def _notifications_for(db_session, user_id: str) -> list[NotificationRow]:
    result = await db_session.execute(
        select(NotificationRow).where(NotificationRow.user_id == user_id)
    )
    return list(result.scalars().all())


async def test_complete_notifies_assigned_analyst(db_session, sample_user, sample_investigation):
    row = await notify_investigation_outcome(
        db_session,
        investigation_id=sample_investigation.id,
        final_status="closed",
        duration_seconds=93,
        finding_count=2,
    )
    assert row is not None
    assert row.user_id == sample_user.id
    assert row.type == "investigation_complete"
    assert row.investigation_id == sample_investigation.id
    assert "closed" in row.message
    assert "2 finding(s)" in row.message
    assert "1m 33s" in row.message
    assert not row.read


async def test_failed_routes_to_failure_notification(db_session, sample_user, sample_investigation):
    row = await notify_investigation_outcome(
        db_session,
        investigation_id=sample_investigation.id,
        final_status="failed",
        error="RuntimeError: LLM provider unreachable",
    )
    assert row is not None
    assert row.type == "investigation_failed"
    assert row.title == "Investigation Failed"
    assert "RuntimeError: LLM provider unreachable" in row.message
    assert row.user_id == sample_user.id


async def test_unassigned_investigation_is_skipped(db_session):
    inv = InvestigationRow(
        id=generate_id("inv"),
        org_id=DEFAULT_ORG_ID,
        title="Unassigned investigation",
        status=InvestigationStatus.INVESTIGATING.value,
        severity=Severity.LOW.value,
        tlp_level="green",
        assigned_to=None,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    db_session.add(inv)
    await db_session.flush()

    row = await notify_investigation_outcome(
        db_session, investigation_id=inv.id, final_status="closed"
    )
    assert row is None
    result = await db_session.execute(
        select(NotificationRow).where(NotificationRow.investigation_id == inv.id)
    )
    assert result.scalars().all() == []


async def test_unknown_investigation_returns_none(db_session):
    row = await notify_investigation_outcome(
        db_session, investigation_id="inv_DOESNOTEXIST", final_status="closed"
    )
    assert row is None


async def test_redis_publish_targets_the_users_channel(
    db_session, sample_user, sample_investigation
):
    redis = AsyncMock()
    row = await notify_investigation_outcome(
        db_session,
        investigation_id=sample_investigation.id,
        final_status="closed",
        finding_count=1,
        redis=redis,
    )
    assert row is not None
    redis.publish.assert_awaited_once()
    channel, payload = redis.publish.await_args.args
    assert channel == f"btagent:notifications:{sample_user.id}"
    parsed = json.loads(payload)
    assert parsed["id"] == row.id
    assert parsed["type"] == "investigation_complete"
    assert parsed["investigation_id"] == sample_investigation.id


async def test_redis_failure_is_nonfatal(db_session, sample_user, sample_investigation):
    redis = AsyncMock()
    redis.publish.side_effect = ConnectionError("redis down")
    row = await notify_investigation_outcome(
        db_session,
        investigation_id=sample_investigation.id,
        final_status="failed",
        error="boom",
        redis=redis,
    )
    # The DB row is the source of truth; the push is best-effort.
    assert row is not None
    rows = await _notifications_for(db_session, sample_user.id)
    assert any(r.id == row.id for r in rows)


def test_format_duration():
    assert _format_duration(None) == "unknown"
    assert _format_duration(45) == "45s"
    assert _format_duration(93) == "1m 33s"
    assert _format_duration(3605) == "60m 5s"
