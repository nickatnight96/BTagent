"""Detection-validation run persistence (#118).

The DB-facing companion to :mod:`validation_service`. ``run_validation`` stays a
pure engine call that returns a transient ``ValidationReport``; this module
writes that report into the ``detection_validation_runs`` history table so
analysts can diff coverage over time (the "persistence" item deferred in
``validation_service``'s TODO).

Like the other history writers (``plan_runs``, ``hunt_pack_runs``), the persist
helper never commits — the caller (an API route or job) owns the commit.
"""

from __future__ import annotations

import logging

from btagent_shared.types.detection_validation import ValidationReport
from btagent_shared.utils.ids import generate_id
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.db.models_validation import DetectionValidationRunRow

logger = logging.getLogger("btagent.services.validation_run")


async def persist_validation_report(
    db: AsyncSession,
    report: ValidationReport,
    *,
    org_id: str = DEFAULT_ORG_ID,
    packs: tuple[str, ...] | list[str] = (),
) -> DetectionValidationRunRow:
    """Write a ``ValidationReport`` into the run-history table and return the row.

    Denormalises the summary pivots into columns and stores the full
    per-technique payload as JSONB. Does not commit — the caller owns that.
    """
    row = DetectionValidationRunRow(
        id=generate_id("dvr"),
        org_id=org_id,
        run_id=report.run_id,
        packs=list(packs),
        scenarios_run=report.scenarios_run,
        total_techniques=report.summary.total_techniques,
        detected_pct=report.summary.detected_pct,
        gaps=list(report.summary.gaps),
        coverage_by_technique=[c.model_dump() for c in report.coverage_by_technique],
        generated_at=report.generated_at,
    )
    db.add(row)
    await db.flush()
    logger.info(
        "persisted validation run %s (org=%s): detected_pct=%.1f techniques=%d",
        report.run_id,
        org_id,
        report.summary.detected_pct,
        report.summary.total_techniques,
    )
    return row
