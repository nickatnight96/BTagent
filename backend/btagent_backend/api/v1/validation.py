"""Detection-validation API (#118).

``POST /api/v1/validation/runs``
    Replay the built-in simulation scenarios through the ``windows_baseline``
    Sigma pack, persist the coverage report to ``detection_validation_runs``,
    and return it. RBAC ``hunt:run`` — replaying scenarios is a run action,
    same as the CTI proposal validate route.

``GET /api/v1/validation/runs``
    List the persisted run history newest-first (org-scoped, paginated).
    RBAC ``hunt:view``.

Mock-first: the scenario set is deterministic and synthetic (no live Atomic Red
Team / Caldera execution yet — deferred). ``run_validation`` stays a pure engine
call; persistence flows through ``validation_run_service`` (which never commits —
the ``get_db`` dependency owns the commit on success).
"""

from __future__ import annotations

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.db.models_validation import DetectionValidationRunRow
from btagent_backend.services import validation_run_service
from btagent_backend.services.validation_scenarios import default_validation_scenarios
from btagent_backend.services.validation_service import run_validation

logger = logging.getLogger("btagent.api.validation")

router = APIRouter(prefix="/validation", tags=["validation"])

# Packs the default run validates against (mirrors validation_service defaults).
_DEFAULT_PACKS = ("windows_baseline",)


class ValidationRunSummary(BaseModel):
    id: str
    run_id: str
    packs: list[str]
    scenarios_run: int
    total_techniques: int
    detected_pct: float
    gaps: list[str]
    generated_at: datetime
    created_at: datetime


class ValidationRunResponse(ValidationRunSummary):
    # The POST response carries the full per-technique payload; the list view
    # omits it to stay light.
    coverage_by_technique: list[dict]


class ValidationRunListResponse(BaseModel):
    items: list[ValidationRunSummary]
    total: int


def _summary(row: DetectionValidationRunRow) -> ValidationRunSummary:
    return ValidationRunSummary(
        id=row.id,
        run_id=row.run_id,
        packs=list(row.packs or []),
        scenarios_run=row.scenarios_run,
        total_techniques=row.total_techniques,
        detected_pct=row.detected_pct,
        gaps=list(row.gaps or []),
        generated_at=row.generated_at,
        created_at=row.created_at,
    )


@router.post("/runs", response_model=ValidationRunResponse, status_code=201)
async def create_validation_run(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Replay the default scenarios, persist the coverage report, and return it."""
    user.require_permission("hunt:run")

    report = await run_validation(default_validation_scenarios(), _DEFAULT_PACKS)
    row = await validation_run_service.persist_validation_report(
        db, report, org_id=user.org_id, packs=_DEFAULT_PACKS
    )
    return ValidationRunResponse(
        **_summary(row).model_dump(),
        coverage_by_technique=list(row.coverage_by_technique or []),
    )


@router.get("/runs", response_model=ValidationRunListResponse)
async def list_validation_runs(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """List persisted detection-validation runs, newest-first."""
    user.require_permission("hunt:view")

    total = (
        await db.execute(
            select(func.count())
            .select_from(DetectionValidationRunRow)
            .where(DetectionValidationRunRow.org_id == user.org_id)
        )
    ).scalar_one()

    rows = (
        (
            await db.execute(
                select(DetectionValidationRunRow)
                .where(DetectionValidationRunRow.org_id == user.org_id)
                .order_by(DetectionValidationRunRow.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return ValidationRunListResponse(items=[_summary(r) for r in rows], total=int(total))
