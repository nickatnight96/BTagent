"""Tenant scoping for the data-retention service (B6, P2.3).

Before the fix ``POST /config/retention/run`` (gated only on ``config:edit`` —
admin of *any* org) deleted events and archived investigations across every
tenant: org B's admin could irreversibly delete org A's events, and the audit
row stamped org B so org A's ledger showed nothing. These tests pin the
service-level scoping: a retention pass for one org never touches another's
rows, and the stats endpoint reports only the caller's tenant.

Uses a dedicated per-test org pair (never exact counts over shared orgs) per
the shared-in-memory-DB isolation convention.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from btagent_shared.utils.ids import generate_id
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.config import get_settings
from btagent_backend.db.models import (
    AuditLogRow,
    EventRow,
    InvestigationRow,
    OrganizationRow,
)
from btagent_backend.services.data_retention import DataRetentionService

_OLD = datetime.now(UTC) - timedelta(days=400)


async def _ensure_org(db: AsyncSession, org_id: str) -> None:
    if await db.get(OrganizationRow, org_id) is None:
        db.add(OrganizationRow(id=org_id, name=org_id, created_at=datetime.now(UTC)))
        await db.commit()


async def _seed_org(db: AsyncSession, org_id: str) -> tuple[str, str]:
    """Give ``org_id`` one old closed investigation with one old event.

    Returns (investigation_id, event_id).
    """
    await _ensure_org(db, org_id)
    inv = InvestigationRow(
        id=generate_id("inv"),
        org_id=org_id,
        title=f"retention-{org_id}",
        status="closed",
        created_at=_OLD,
        closed_at=_OLD,
    )
    db.add(inv)
    await db.flush()
    evt = EventRow(
        id=generate_id("evt"),
        investigation_id=inv.id,
        type="agent_thought",
        data={"org": org_id},
        timestamp=_OLD,
    )
    db.add(evt)
    # ``seq`` is only DB-autoincremented on Postgres; assign it explicitly so
    # the in-memory SQLite suite can insert directly.
    max_seq = (await db.execute(select(func.max(AuditLogRow.seq)))).scalar() or 0
    db.add(
        AuditLogRow(
            id=generate_id("aud"),
            org_id=org_id,
            seq=max_seq + 1,
            actor="tester",
            category="config_change",
            action="seed",
            timestamp=_OLD,
        )
    )
    await db.commit()
    return inv.id, evt.id


@pytest_asyncio.fixture()
async def retention_orgs(db_session: AsyncSession):
    # ULIDs lead with a millisecond timestamp — take the random *tail* so two
    # tests in the same millisecond can't reuse (and re-seed) the same org.
    org_a = f"org_ret_a_{generate_id('x').split('_', 1)[1][-10:]}"
    org_b = f"org_ret_b_{generate_id('x').split('_', 1)[1][-10:]}"
    inv_a, evt_a = await _seed_org(db_session, org_a)
    inv_b, evt_b = await _seed_org(db_session, org_b)
    return {
        "org_a": org_a,
        "org_b": org_b,
        "inv_a": inv_a,
        "inv_b": inv_b,
        "evt_a": evt_a,
        "evt_b": evt_b,
    }


@pytest.fixture()
def svc() -> DataRetentionService:
    return DataRetentionService(get_settings())


@pytest.mark.asyncio
async def test_event_cleanup_only_touches_callers_org(
    db_session: AsyncSession, svc: DataRetentionService, retention_orgs
):
    result = await svc.archive_old_events(db_session, days=30, org_id=retention_orgs["org_a"])
    await db_session.commit()

    assert result["deleted_count"] == 1
    assert await db_session.get(EventRow, retention_orgs["evt_a"]) is None
    # Org B's equally-stale event survives an org-A retention run.
    survivor = await db_session.execute(
        select(EventRow).where(EventRow.id == retention_orgs["evt_b"])
    )
    assert survivor.scalar_one_or_none() is not None


@pytest.mark.asyncio
async def test_investigation_archival_only_touches_callers_org(
    db_session: AsyncSession, svc: DataRetentionService, retention_orgs
):
    result = await svc.cleanup_old_investigations(
        db_session, days=30, org_id=retention_orgs["org_a"]
    )
    await db_session.commit()

    assert result["archived_count"] == 1
    assert result["investigation_ids"] == [retention_orgs["inv_a"]]

    inv_a = await db_session.get(InvestigationRow, retention_orgs["inv_a"])
    inv_b = await db_session.get(InvestigationRow, retention_orgs["inv_b"])
    assert inv_a is not None and inv_a.status == "archived"
    assert inv_b is not None and inv_b.status == "closed"


@pytest.mark.asyncio
async def test_retention_stats_scoped_to_callers_org(
    db_session: AsyncSession, svc: DataRetentionService, retention_orgs
):
    stats = await svc.get_retention_stats(db_session, org_id=retention_orgs["org_a"])

    # Exactly the org's own rows — the sibling org's identical seed data must
    # not inflate any counter.
    assert stats["events"]["total"] == 1
    assert stats["events"]["stale"] == 1
    assert stats["audit_logs"]["total"] == 1
    assert stats["investigations"]["total"] == 1
    assert stats["investigations"]["archivable"] == 1


@pytest.mark.asyncio
async def test_audit_retention_verification_scoped_to_callers_org(
    db_session: AsyncSession, svc: DataRetentionService, retention_orgs
):
    result = await svc.verify_audit_retention(db_session, org_id=retention_orgs["org_a"])
    assert result["total_entries"] == 1
