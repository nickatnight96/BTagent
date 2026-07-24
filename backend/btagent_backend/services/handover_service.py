"""Shift-handover summary builder (EPIC-5 UC-5.1).

Aggregates the prior shift window (default 8h) into a structured, org-scoped
handover: investigations opened or touched, open high-severity case counts,
and hunt findings that landed in the triage inbox. Deterministic — a plain
aggregation over the DB, no LLM. The reasoning-node narrative polish is a
follow-up; this substrate is what it will summarize.

Read-only: never commits (the ``get_db`` dependency owns transactions).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import InvestigationRow
from btagent_backend.db.models_hunt import HuntFindingRow

# Statuses that count as "still needs attention" for the open-case rollup.
_OPEN_STATUSES = ("pending", "running", "paused", "awaiting_approval")

_MAX_ITEMS = 20


def _as_utc(dt: datetime) -> datetime:
    """Treat naive DB datetimes as UTC (SQLite drops tzinfo in tests)."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


async def build_handover_summary(
    db: AsyncSession, *, org_id: str, window_hours: int = 8
) -> dict[str, Any]:
    """Aggregate the shift window into a handover summary dict.

    The dict matches the ``HandoverSummary`` response model in
    ``api/v1/handover.py``; it is built here so the arq/report layers can
    reuse it without going through HTTP.
    """
    cutoff = datetime.now(UTC) - timedelta(hours=window_hours)

    # Investigations created or updated inside the window, newest first.
    inv_result = await db.execute(
        select(InvestigationRow)
        .where(
            InvestigationRow.org_id == org_id,
            (InvestigationRow.created_at >= cutoff) | (InvestigationRow.updated_at >= cutoff),
        )
        .order_by(InvestigationRow.updated_at.desc())
        .limit(_MAX_ITEMS)
    )
    inv_rows = list(inv_result.scalars())
    investigations = [
        {
            "id": r.id,
            "title": r.title,
            "severity": r.severity,
            "status": r.status,
            "is_new": _as_utc(r.created_at) >= cutoff,
            "updated_at": r.updated_at,
        }
        for r in inv_rows
    ]

    # Open high-priority backlog (not window-bound — the incoming shift owns
    # everything still open, however old).
    open_result = await db.execute(
        select(InvestigationRow.severity, func.count())
        .where(
            InvestigationRow.org_id == org_id,
            InvestigationRow.status.in_(_OPEN_STATUSES),
        )
        .group_by(InvestigationRow.severity)
    )
    open_by_severity = {severity: count for severity, count in open_result.all()}

    # Hunt findings that landed inside the window, bucketed by severity, plus
    # how many still sit untriaged.
    sev_result = await db.execute(
        select(HuntFindingRow.severity, func.count())
        .where(HuntFindingRow.org_id == org_id, HuntFindingRow.created_at >= cutoff)
        .group_by(HuntFindingRow.severity)
    )
    findings_by_severity = {severity: count for severity, count in sev_result.all()}
    # "Untriaged" = nobody has acted on it yet. Findings auto-cluster on
    # insert, so both pre-cluster ("new") and clustered-but-unreviewed
    # ("clustered") states count.
    untriaged_result = await db.execute(
        select(func.count())
        .select_from(HuntFindingRow)
        .where(
            HuntFindingRow.org_id == org_id,
            HuntFindingRow.created_at >= cutoff,
            HuntFindingRow.state.in_(("new", "clustered")),
        )
    )
    findings_untriaged = int(untriaged_result.scalar_one())

    new_count = sum(1 for i in investigations if i["is_new"])
    findings_total = sum(findings_by_severity.values())
    open_total = sum(open_by_severity.values())
    headline = (
        f"Last {window_hours}h: {new_count} new investigation(s), "
        f"{len(investigations) - new_count} updated; {findings_total} hunt finding(s) "
        f"landed ({findings_untriaged} untriaged); {open_total} case(s) still open."
    )

    return {
        "window_hours": window_hours,
        "window_start": cutoff,
        "generated_at": datetime.now(UTC),
        "headline": headline,
        "investigations": investigations,
        "open_by_severity": open_by_severity,
        "findings_by_severity": findings_by_severity,
        "findings_untriaged": findings_untriaged,
    }
