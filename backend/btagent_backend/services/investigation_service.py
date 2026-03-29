"""Investigation business logic layer.

Provides high-level operations that coordinate between the database and the
TaskManager.  Endpoint handlers call into this module rather than manipulating
DB rows and tasks directly.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from btagent_shared.types.config import TLP
from btagent_shared.types.enums import InvestigationStatus, Severity
from btagent_shared.utils.ids import generate_id
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import InvestigationRow

logger = logging.getLogger("btagent.services.investigation")


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------


async def create_investigation(
    db: AsyncSession,
    *,
    title: str,
    description: str = "",
    severity: Severity = Severity.MEDIUM,
    tlp_level: TLP = TLP.GREEN,
    template: str | None = None,
    assigned_to: str | None = None,
    extra_config: dict[str, Any] | None = None,
) -> InvestigationRow:
    """Insert a new investigation row and return it.

    The caller (endpoint handler) is responsible for starting the agent via
    ``TaskManager.start_investigation`` after the DB transaction commits.

    Parameters
    ----------
    db : AsyncSession
        Request-scoped async DB session.
    title : str
        Investigation title.
    description : str
        Free-form description.
    severity : Severity
        Initial severity assessment.
    tlp_level : TLP
        Traffic Light Protocol classification.
    template : str | None
        Optional investigation template identifier.
    assigned_to : str | None
        User ID of the analyst who created/owns the investigation.
    extra_config : dict | None
        Additional configuration stored in the JSONB ``config`` column.

    Returns
    -------
    InvestigationRow
        The newly created DB row (flushed but not yet committed).
    """
    config: dict[str, Any] = extra_config or {}
    config.setdefault("severity", severity.value)
    config.setdefault("tlp_level", tlp_level.value)
    if template:
        config.setdefault("template", template)

    inv = InvestigationRow(
        id=generate_id("inv"),
        title=title,
        description=description,
        severity=severity.value,
        tlp_level=tlp_level.value,
        template=template,
        assigned_to=assigned_to,
        status=InvestigationStatus.PENDING.value,
        config=config,
    )
    db.add(inv)
    await db.flush()

    logger.info(
        "Created investigation %s (title=%r, severity=%s, tlp=%s)",
        inv.id,
        title,
        severity.value,
        tlp_level.value,
    )
    return inv


# ---------------------------------------------------------------------------
# Read helpers
# ---------------------------------------------------------------------------


async def get_investigation_summary(db: AsyncSession) -> dict[str, Any]:
    """Return aggregate counts for the PunchList dashboard.

    Returns a dict with status counts and totals suitable for rendering the
    investigation overview widget.
    """
    result = await db.execute(
        select(InvestigationRow.status, func.count(InvestigationRow.id)).group_by(
            InvestigationRow.status
        )
    )
    status_counts: dict[str, int] = {}
    total = 0
    for row_status, count in result.all():
        status_counts[row_status] = count
        total += count

    # Derive convenience aggregates.
    active = sum(
        status_counts.get(s, 0)
        for s in (
            InvestigationStatus.INVESTIGATING.value,
            InvestigationStatus.TRIAGING.value,
        )
    )
    paused = sum(
        status_counts.get(s, 0)
        for s in (
            InvestigationStatus.PAUSED.value,
            InvestigationStatus.PAUSED_HITL.value,
        )
    )
    closed = sum(
        status_counts.get(s, 0)
        for s in (
            InvestigationStatus.CLOSED.value,
            InvestigationStatus.CANCELLED.value,
            InvestigationStatus.REMEDIATED.value,
        )
    )
    failed = status_counts.get(InvestigationStatus.FAILED.value, 0)

    return {
        "total": total,
        "active": active,
        "paused": paused,
        "closed": closed,
        "failed": failed,
        "by_status": status_counts,
    }


# ---------------------------------------------------------------------------
# Status update
# ---------------------------------------------------------------------------


async def update_investigation_status(
    db: AsyncSession,
    investigation_id: str,
    status: InvestigationStatus,
    *,
    close: bool = False,
) -> None:
    """Update the status of an investigation.

    Parameters
    ----------
    db : AsyncSession
        Request-scoped async DB session.
    investigation_id : str
        The investigation to update.
    status : InvestigationStatus
        New status value.
    close : bool
        If True, set ``closed_at`` to the current UTC time.
    """
    values: dict[str, Any] = {
        "status": status.value,
        "updated_at": datetime.now(UTC),
    }
    if close:
        values["closed_at"] = datetime.now(UTC)

    stmt = update(InvestigationRow).where(InvestigationRow.id == investigation_id).values(**values)
    await db.execute(stmt)

    logger.info(
        "Updated investigation %s status to %s%s",
        investigation_id,
        status.value,
        " (closed)" if close else "",
    )
