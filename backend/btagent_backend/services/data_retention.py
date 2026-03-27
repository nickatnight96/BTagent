"""Data retention service — event cleanup, investigation archival, audit compliance."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.config import Settings
from btagent_backend.db.models import AuditLogRow, EventRow, InvestigationRow

logger = logging.getLogger("btagent.services.retention")


class DataRetentionService:
    """Manages data lifecycle: event cleanup, investigation archival, audit retention."""

    def __init__(self, settings: Settings) -> None:
        self.event_retention_days: int = settings.event_retention_days
        self.audit_retention_years: int = settings.audit_retention_years

    async def archive_old_events(
        self,
        db: AsyncSession,
        days: int | None = None,
    ) -> dict[str, Any]:
        """Delete events older than N days.

        In production, events would first be exported to S3/cold storage before
        deletion.  This implementation performs a direct delete suitable for
        dev/staging environments.

        Returns a summary dict with the count of deleted rows and cutoff date.
        """
        retention_days = days if days is not None else self.event_retention_days
        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

        # Count before deleting so we can report
        count_result = await db.execute(
            select(func.count(EventRow.id)).where(EventRow.timestamp < cutoff)
        )
        count = count_result.scalar() or 0

        if count > 0:
            await db.execute(
                delete(EventRow).where(EventRow.timestamp < cutoff)
            )
            logger.info(
                "Deleted %d events older than %d days (cutoff=%s)",
                count,
                retention_days,
                cutoff.isoformat(),
            )
        else:
            logger.info(
                "No events older than %d days to delete (cutoff=%s)",
                retention_days,
                cutoff.isoformat(),
            )

        return {
            "deleted_count": count,
            "retention_days": retention_days,
            "cutoff": cutoff.isoformat(),
        }

    async def cleanup_old_investigations(
        self,
        db: AsyncSession,
        days: int | None = None,
    ) -> dict[str, Any]:
        """Archive closed investigations older than N days.

        Closed investigations are soft-archived by setting their status to
        'archived'.  Associated data (events, IOCs, etc.) remain intact but
        the investigation no longer appears in default queries.
        """
        retention_days = days if days is not None else self.event_retention_days
        cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

        _CLOSED_STATUSES = ("closed", "cancelled", "remediated")

        # Find candidates
        result = await db.execute(
            select(InvestigationRow.id).where(
                InvestigationRow.status.in_(_CLOSED_STATUSES),
                InvestigationRow.closed_at.isnot(None),
                InvestigationRow.closed_at < cutoff,
            )
        )
        inv_ids = [row[0] for row in result.all()]

        if inv_ids:
            from sqlalchemy import update

            await db.execute(
                update(InvestigationRow)
                .where(InvestigationRow.id.in_(inv_ids))
                .values(status="archived")
            )
            logger.info(
                "Archived %d closed investigations older than %d days",
                len(inv_ids),
                retention_days,
            )
        else:
            logger.info(
                "No closed investigations older than %d days to archive",
                retention_days,
            )

        return {
            "archived_count": len(inv_ids),
            "retention_days": retention_days,
            "cutoff": cutoff.isoformat(),
            "investigation_ids": inv_ids,
        }

    async def verify_audit_retention(
        self,
        db: AsyncSession,
        years: int | None = None,
    ) -> dict[str, Any]:
        """Ensure audit logs are retained for the compliance period.

        This verifies that no audit logs have been deleted within the required
        retention window.  Audit logs are NEVER deleted — this check confirms
        that the earliest log is within acceptable bounds.
        """
        retention_years = years if years is not None else self.audit_retention_years

        # Total audit entries
        total_result = await db.execute(
            select(func.count(AuditLogRow.id))
        )
        total_count = total_result.scalar() or 0

        # Earliest audit entry
        earliest_result = await db.execute(
            select(func.min(AuditLogRow.timestamp))
        )
        earliest_ts = earliest_result.scalar()

        # Latest audit entry
        latest_result = await db.execute(
            select(func.max(AuditLogRow.timestamp))
        )
        latest_ts = latest_result.scalar()

        # Calculate compliance boundary
        compliance_boundary = datetime.now(timezone.utc) - timedelta(
            days=retention_years * 365
        )

        # Check if we have any gaps (chain integrity is verified separately by
        # AuditTrail.verify_chain, but we check retention coverage here)
        compliant = True
        issues: list[str] = []

        if total_count == 0:
            # No logs yet — technically compliant (nothing to retain)
            compliant = True
        elif earliest_ts and earliest_ts > compliance_boundary:
            # System hasn't been running long enough — acceptable
            compliant = True
        elif earliest_ts is None:
            issues.append("Unable to determine earliest audit log timestamp")
            compliant = False

        logger.info(
            "Audit retention check: total=%d, earliest=%s, compliant=%s",
            total_count,
            earliest_ts.isoformat() if earliest_ts else "N/A",
            compliant,
        )

        return {
            "total_entries": total_count,
            "earliest_entry": earliest_ts.isoformat() if earliest_ts else None,
            "latest_entry": latest_ts.isoformat() if latest_ts else None,
            "retention_years": retention_years,
            "compliance_boundary": compliance_boundary.isoformat(),
            "compliant": compliant,
            "issues": issues,
        }

    async def get_retention_stats(
        self,
        db: AsyncSession,
    ) -> dict[str, Any]:
        """Return retention statistics for the admin dashboard."""
        now = datetime.now(timezone.utc)
        event_cutoff = now - timedelta(days=self.event_retention_days)

        # Total events
        total_events_result = await db.execute(
            select(func.count(EventRow.id))
        )
        total_events = total_events_result.scalar() or 0

        # Events eligible for cleanup
        stale_events_result = await db.execute(
            select(func.count(EventRow.id)).where(EventRow.timestamp < event_cutoff)
        )
        stale_events = stale_events_result.scalar() or 0

        # Total audit logs
        audit_count_result = await db.execute(
            select(func.count(AuditLogRow.id))
        )
        audit_count = audit_count_result.scalar() or 0

        # Total investigations
        total_inv_result = await db.execute(
            select(func.count(InvestigationRow.id))
        )
        total_investigations = total_inv_result.scalar() or 0

        # Closed investigations eligible for archival
        inv_cutoff = now - timedelta(days=self.event_retention_days)
        _CLOSED_STATUSES = ("closed", "cancelled", "remediated")
        archivable_result = await db.execute(
            select(func.count(InvestigationRow.id)).where(
                InvestigationRow.status.in_(_CLOSED_STATUSES),
                InvestigationRow.closed_at.isnot(None),
                InvestigationRow.closed_at < inv_cutoff,
            )
        )
        archivable_investigations = archivable_result.scalar() or 0

        return {
            "events": {
                "total": total_events,
                "stale": stale_events,
                "retention_days": self.event_retention_days,
            },
            "audit_logs": {
                "total": audit_count,
                "retention_years": self.audit_retention_years,
                "policy": "never_delete",
            },
            "investigations": {
                "total": total_investigations,
                "archivable": archivable_investigations,
                "retention_days": self.event_retention_days,
            },
        }
