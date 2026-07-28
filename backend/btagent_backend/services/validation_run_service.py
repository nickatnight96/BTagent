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
from collections.abc import Awaitable, Callable

from btagent_shared.types.detection_validation import ValidationReport
from btagent_shared.utils.ids import generate_id
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.db.models_validation import DetectionValidationRunRow

logger = logging.getLogger("btagent.services.validation_run")

# Injectable feedback hook: (db, org_id=, report=) -> awaitable. Defaults to the
# real Phase-C dispatcher; tests pass a spy (or a no-op) to isolate it.
FeedbackDispatch = Callable[..., Awaitable[object]]


async def persist_validation_report(
    db: AsyncSession,
    report: ValidationReport,
    *,
    org_id: str = DEFAULT_ORG_ID,
    packs: tuple[str, ...] | list[str] = (),
    feedback_dispatch: FeedbackDispatch | None = None,
) -> DetectionValidationRunRow:
    """Write a ``ValidationReport`` into the run-history table and return the row.

    Denormalises the summary pivots into columns and stores the full
    per-technique payload as JSONB. Does not commit — the caller owns that.

    Once the row is flushed, the Phase-C feedback loops are fired best-effort
    (#118): ``silent_gap`` verdicts file #113 detection proposals and
    ``late`` / ``wrong_severity`` verdicts file #112 hunt-pack tuning
    suggestions. Feedback is wrapped so a failure can never sink the run write,
    and ``feedback_dispatch`` is injectable so tests can spy on or disable it.
    Pure in-process replay reports carry no verdicts and are a no-op.
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
        # Emulation-path fields (#118). Pure replay reports leave these at the
        # replay defaults (emulated=False, target_env=None, verdicts=[]).
        emulated=report.emulation_target_env is not None,
        target_env=(
            report.emulation_target_env.value if report.emulation_target_env is not None else None
        ),
        verdicts=[v.model_dump(mode="json") for v in report.verdicts],
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

    # Phase-C closed loop (#118): drive silent_gap → #113 and late/wrong_severity
    # → #112 off the just-persisted verdicts. Best-effort — the run row is
    # already flushed, so a feedback fault must never propagate out and sink it.
    dispatch = feedback_dispatch
    if dispatch is None:
        from btagent_backend.services.validation_feedback_service import (
            dispatch_validation_feedback,
        )

        dispatch = dispatch_validation_feedback
    try:
        await dispatch(db, org_id=org_id, report=report)
    except Exception:  # noqa: BLE001 — feedback is auxiliary to the run write
        logger.warning(
            "validation feedback dispatch failed for run %s (org=%s)",
            report.run_id,
            org_id,
            exc_info=True,
        )

    return row
