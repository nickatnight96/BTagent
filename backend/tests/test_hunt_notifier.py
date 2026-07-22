"""Tests for the critical hunt-finding notification producer.

``persist_hunt_findings`` batches with unsuppressed critical rows must
leave one summary ``critical_finding`` notification per hunt senior; lower
severities and suppressed rows stay silent. The shared role-targeting
resolver is covered directly too.

The default org is shared across the test session, so assertions scope by
a per-test unique finding title carried in the notification message —
never by absolute notification counts.
"""

from __future__ import annotations

from types import SimpleNamespace

from btagent_shared.types.hunt_finding import RecordFindingRequest
from btagent_shared.utils.ids import generate_id
from sqlalchemy import select

from btagent_backend.db.models import DEFAULT_ORG_ID, NotificationRow
from btagent_backend.services.hunt_notifier import notify_critical_findings
from btagent_backend.services.hunt_triage_service import persist_hunt_findings
from btagent_backend.services.role_targeting import (
    roles_with_permission,
    user_ids_with_permission,
)


def _request(title: str, severity: str) -> RecordFindingRequest:
    return RecordFindingRequest(
        source="hunt_pack",
        domain="sigma",
        title=title,
        severity=severity,
        technique_ids=["T1059.001"],
        entities=[{"kind": "host", "value": "WS-1"}],
        evidence={"pack_id": "sigmahq-windows", "rule_id": "rule_1"},
    )


async def _notifications_mentioning(db_session, user_id: str, marker: str) -> list[NotificationRow]:
    result = await db_session.execute(
        select(NotificationRow).where(
            NotificationRow.user_id == user_id,
            NotificationRow.type == "critical_finding",
        )
    )
    return [r for r in result.scalars().all() if marker in r.message]


# --------------------------------------------------------------------------- #
# role_targeting
# --------------------------------------------------------------------------- #


def test_roles_with_permission_matches_hierarchy():
    roles = roles_with_permission("hitl:approve")
    assert "senior_analyst" in roles
    assert "incident_commander" in roles
    assert "admin" in roles
    assert "analyst" not in roles


async def test_user_ids_with_permission_and_exclusion(db_session, sample_user, admin_user):
    ids = await user_ids_with_permission(
        db_session, org_id=DEFAULT_ORG_ID, permission="hunt:promote"
    )
    assert admin_user.id in ids
    assert sample_user.id not in ids

    excluded = await user_ids_with_permission(
        db_session,
        org_id=DEFAULT_ORG_ID,
        permission="hunt:promote",
        exclude=(admin_user.id, None),
    )
    assert admin_user.id not in excluded


# --------------------------------------------------------------------------- #
# hunt_notifier via the ingest chokepoint
# --------------------------------------------------------------------------- #


async def test_critical_ingest_notifies_hunt_seniors(db_session, sample_user, admin_user):
    marker = f"Critical beacon {generate_id('mk')}"
    rows = await persist_hunt_findings(
        db_session,
        org_id=DEFAULT_ORG_ID,
        findings=[_request(marker, "critical"), _request(f"{marker} low", "low")],
    )
    assert len(rows) == 2

    admin_rows = await _notifications_mentioning(db_session, admin_user.id, marker)
    assert len(admin_rows) == 1
    assert admin_rows[0].title == "Critical Hunt Findings"
    # Analysts don't hold hunt:promote — no fan-out to them.
    assert await _notifications_mentioning(db_session, sample_user.id, marker) == []


async def test_non_critical_ingest_stays_silent(db_session, admin_user):
    marker = f"High-only sweep {generate_id('mk')}"
    await persist_hunt_findings(
        db_session,
        org_id=DEFAULT_ORG_ID,
        findings=[_request(marker, "high"), _request(f"{marker} b", "medium")],
    )
    assert await _notifications_mentioning(db_session, admin_user.id, marker) == []


async def test_batch_summary_counts_multiple_criticals(db_session, admin_user):
    marker = f"Multi-critical {generate_id('mk')}"
    await persist_hunt_findings(
        db_session,
        org_id=DEFAULT_ORG_ID,
        findings=[
            _request(f"{marker} one", "critical"),
            _request(f"{marker} two", "critical"),
            _request(f"{marker} three", "critical"),
        ],
    )
    rows = await _notifications_mentioning(db_session, admin_user.id, marker)
    assert len(rows) == 1  # one summary per recipient, not one per finding
    assert "3 critical hunt findings" in rows[0].message
    assert "2 more" in rows[0].message


async def test_suppressed_critical_rows_do_not_notify(db_session, admin_user):
    # Direct service-level check: a critical row already in the suppressed
    # state (pre-insert suppression match) must not trigger the fan-out.
    marker = f"Suppressed critical {generate_id('mk')}"
    suppressed_row = SimpleNamespace(severity="critical", state="suppressed", title=marker)
    created = await notify_critical_findings(
        db_session,
        org_id=DEFAULT_ORG_ID,
        rows=[suppressed_row],  # type: ignore[list-item]
    )
    assert created == []
    assert await _notifications_mentioning(db_session, admin_user.id, marker) == []
