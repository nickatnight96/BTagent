"""MITRE ATT&CK API endpoints — techniques, tactics, groups, coverage, and export."""

from __future__ import annotations

import logging
from pathlib import Path

from btagent_shared.types.mitre import (
    CoverageMap,
    DetectionGap,
    MitreGroup,
    MitreTactic,
    MitreTechnique,
)
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.auth.scoping import assert_can_access_investigation
from btagent_backend.db.models import InvestigationRow, IOCRow, TimelineEntryRow
from btagent_backend.services.mitre_service import MitreService
from btagent_backend.services.org_profile import get_org_profile

logger = logging.getLogger("btagent.api.mitre")

router = APIRouter(prefix="/mitre", tags=["mitre"])

# Default path for the vendored STIX bundle
_DEFAULT_STIX_PATH = (
    Path(__file__).resolve().parent.parent.parent / "data" / "enterprise-attack.json"
)

# Repo-relative form of the directory above, quoted in the seed 404 so an
# operator troubleshooting an offline data refresh is told where the code
# actually looks. #506: the message used to say ``backend/data/`` -- a
# directory that does not exist -- while the resolution above lands in
# ``backend/btagent_backend/data/``. Derived from the resolved path rather
# than written out again so the two cannot drift apart a second time.
_STIX_DIR_HINT = "/".join(_DEFAULT_STIX_PATH.parent.parts[-3:]) + "/"


# ---------------------------------------------------------------------------
# Org scoping helpers (GH #375)
# ---------------------------------------------------------------------------


async def _load_scoped_investigation(
    db: AsyncSession,
    user: CurrentUser,
    investigation_id: str,
    *,
    write: bool = False,
) -> InvestigationRow:
    """Fetch an investigation and enforce org/role scoping (404 on miss/cross-org).

    The coverage / gap / export routes accept an arbitrary ``investigation_id``
    from the query string; without this check any caller could read another
    org's coverage. Mirrors the report/workflow scoping helpers: a 404 is
    raised both for "no such row" and "belongs to another tenant" so
    investigation existence never leaks across orgs.
    """
    inv = (
        await db.execute(select(InvestigationRow).where(InvestigationRow.id == investigation_id))
    ).scalar_one_or_none()
    if inv is None:
        raise HTTPException(status_code=404, detail="Not found")
    assert_can_access_investigation(user, inv, write=write)
    return inv


async def _assert_can_tag_entity(
    db: AsyncSession,
    user: CurrentUser,
    entity_type: str,
    entity_id: str,
) -> None:
    """Ensure the caller may tag ``entity_type/entity_id``.

    Technique tags carry no ``org_id`` of their own, so we resolve the target
    entity to its owning investigation and reuse
    :func:`assert_can_access_investigation` (404 on miss/cross-org). Entity
    kinds with no investigation linkage cannot be ownership-checked, so they
    are refused (fail closed) rather than allow a cross-org write.
    """
    if entity_type == "ioc":
        ioc = (await db.execute(select(IOCRow).where(IOCRow.id == entity_id))).scalar_one_or_none()
        if ioc is None:
            raise HTTPException(status_code=404, detail="Not found")
        await _load_scoped_investigation(db, user, ioc.investigation_id, write=True)
        return
    if entity_type == "timeline":
        entry = (
            await db.execute(select(TimelineEntryRow).where(TimelineEntryRow.id == entity_id))
        ).scalar_one_or_none()
        if entry is None:
            raise HTTPException(status_code=404, detail="Not found")
        await _load_scoped_investigation(db, user, entry.investigation_id, write=True)
        return
    # Unknown entity kind: no investigation linkage to verify ownership against.
    # Fail closed rather than allow a cross-org write to an arbitrary entity_id.
    raise HTTPException(status_code=404, detail="Not found")


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------


class TechniqueListResponse(BaseModel):
    items: list[MitreTechnique]
    total: int
    page: int
    page_size: int


class TechniqueExercise(BaseModel):
    """When this org last exercised a technique via a hunt (#99 Phase C)."""

    technique_id: str
    last_exercised_at: str
    last_plan_id: str
    last_run_id: str
    last_outcome: str
    exercise_count: int


class TechniqueExerciseListResponse(BaseModel):
    items: list[TechniqueExercise]
    total: int


class TagRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    entity_type: str = Field(..., description="Entity kind (ioc, timeline, alert, etc.)")
    entity_id: str = Field(..., description="Entity primary key")
    technique_id: str = Field(..., description="MITRE technique ID (e.g. T1059.001)")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class TagResponse(BaseModel):
    id: str
    entity_type: str
    entity_id: str
    technique_id: str
    confidence: float
    tagged_by: str
    created_at: str | None


class SeedResponse(BaseModel):
    techniques: int
    tactics: int
    groups: int


class CoverageScoreResponse(BaseModel):
    score: float
    investigation_id: str | None = None


# ---------------------------------------------------------------------------
# Techniques
# ---------------------------------------------------------------------------


@router.get("/techniques", response_model=TechniqueListResponse)
async def list_techniques(
    page: int = Query(1, ge=1),
    # Cap raised from 200 → 1000 because the matrix UI requests every
    # technique up front (TACTIC_ORDER × N grid). Full ATT&CK
    # Enterprise has ~600 techniques + sub-techniques, so 200 truncates
    # the matrix and the frontend's ``page_size=500`` request was
    # 422'ing.
    page_size: int = Query(50, ge=1, le=1000),
    tactic: str | None = Query(None, description="Filter by tactic shortname"),
    q: str | None = Query(None, description="Search query"),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """List or search MITRE ATT&CK techniques with pagination."""
    user.require_permission("mitre:view")

    offset = (page - 1) * page_size

    if q:
        items = await MitreService.search_techniques(
            db, q, tactic_filter=tactic, limit=page_size, offset=offset
        )
        total = len(items)  # search returns filtered set
    else:
        items, total = await MitreService.list_techniques(
            db, tactic_filter=tactic, limit=page_size, offset=offset
        )

    return TechniqueListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/techniques/{technique_id}", response_model=MitreTechnique)
async def get_technique(
    technique_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Get a single technique by ID."""
    user.require_permission("mitre:view")

    tech = await MitreService.get_technique_by_id(db, technique_id)
    if not tech:
        raise HTTPException(status_code=404, detail="Technique not found")
    return tech


# ---------------------------------------------------------------------------
# Tactics
# ---------------------------------------------------------------------------


@router.get("/tactics", response_model=list[MitreTactic])
async def list_tactics(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """List all ATT&CK tactics in kill-chain order."""
    user.require_permission("mitre:view")
    return await MitreService.list_tactics(db)


# ---------------------------------------------------------------------------
# Groups
# ---------------------------------------------------------------------------


@router.get("/groups", response_model=list[MitreGroup])
async def list_groups(
    technique_id: str | None = Query(None, description="Filter groups by technique ID"),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """List threat groups, optionally filtered by technique."""
    user.require_permission("mitre:view")
    return await MitreService.get_threat_groups(db, technique_id)


@router.get("/groups/{group_id}", response_model=MitreGroup)
async def get_group(
    group_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Get a single threat group with associated techniques."""
    user.require_permission("mitre:view")

    group = await MitreService.get_group_by_id(db, group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Threat group not found")
    return group


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------


@router.get("/coverage", response_model=CoverageMap)
async def get_coverage(
    investigation_id: str | None = Query(None, description="Scope coverage to an investigation"),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Get ATT&CK coverage heatmap data."""
    user.require_permission("mitre:view")
    if investigation_id:
        await _load_scoped_investigation(db, user, investigation_id)
    return await MitreService.get_coverage(db, investigation_id, org_id=user.org_id)


@router.get("/coverage/score", response_model=CoverageScoreResponse)
async def get_coverage_score(
    investigation_id: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Get coverage percentage score."""
    user.require_permission("mitre:view")
    if investigation_id:
        await _load_scoped_investigation(db, user, investigation_id)
    score = await MitreService.get_coverage_score(db, investigation_id, org_id=user.org_id)
    return CoverageScoreResponse(score=score, investigation_id=investigation_id)


# ---------------------------------------------------------------------------
# Technique exercise tracking (#99 Phase C)
# ---------------------------------------------------------------------------


@router.get("/exercises", response_model=TechniqueExerciseListResponse)
async def list_technique_exercises(
    older_than_days: int | None = Query(
        None,
        ge=1,
        description="Only exercises last run more than N days ago (stale coverage).",
    ),
    outcome: str | None = Query(None, description="Filter by last outcome: hit/clean/errored."),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> TechniqueExerciseListResponse:
    """Org-scoped technique exercise records, most recently exercised first.

    Every hunt-plan execution stamps its TTPs here — coverage says a
    detection exists, exercise says the hunt machinery actually looked
    recently. ``older_than_days`` surfaces stale coverage ("untested for
    >90 days" lists).
    """
    user.require_permission("mitre:view")

    from datetime import UTC, datetime, timedelta

    from sqlalchemy import select

    from btagent_backend.db.models_mitre import TechniqueExerciseRow

    where = [TechniqueExerciseRow.org_id == user.org_id]
    if older_than_days is not None:
        cutoff = datetime.now(UTC) - timedelta(days=older_than_days)
        where.append(TechniqueExerciseRow.last_exercised_at < cutoff)
    if outcome is not None:
        where.append(TechniqueExerciseRow.last_outcome == outcome)

    rows = (
        (
            await db.execute(
                select(TechniqueExerciseRow)
                .where(*where)
                .order_by(TechniqueExerciseRow.last_exercised_at.desc())
            )
        )
        .scalars()
        .all()
    )
    items = [
        TechniqueExercise(
            technique_id=r.technique_id,
            last_exercised_at=r.last_exercised_at.isoformat(),
            last_plan_id=r.last_plan_id,
            last_run_id=r.last_run_id,
            last_outcome=r.last_outcome,
            exercise_count=r.exercise_count,
        )
        for r in rows
    ]
    return TechniqueExerciseListResponse(items=items, total=len(items))


class ExerciseGap(BaseModel):
    """A technique the org has never exercised via a hunt (#99 Phase C)."""

    technique_id: str
    name: str
    tactic: str


class ExerciseGapListResponse(BaseModel):
    items: list[ExerciseGap]
    total: int


@router.get("/exercises/gaps", response_model=ExerciseGapListResponse)
async def list_exercise_gaps(
    tactic: str | None = Query(None, description="Filter by tactic shortname."),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> ExerciseGapListResponse:
    """Techniques in the seeded corpus this org has *never* exercised.

    Complements ``GET /mitre/exercises``: that route lists what the hunt
    machinery has looked at (with ``older_than_days`` for staleness); this
    one lists what it has never looked at. Alphabetical by technique id
    for stable pagination.
    """
    user.require_permission("mitre:view")

    from sqlalchemy import exists, func, select

    from btagent_backend.db.models_mitre import MitreTechniqueRow, TechniqueExerciseRow

    exercised = exists().where(
        TechniqueExerciseRow.org_id == user.org_id,
        TechniqueExerciseRow.technique_id == MitreTechniqueRow.id,
    )
    where = [~exercised]
    if tactic:
        where.append(MitreTechniqueRow.tactic == tactic)

    total = (
        await db.execute(select(func.count()).select_from(MitreTechniqueRow).where(*where))
    ).scalar_one() or 0
    rows = (
        (
            await db.execute(
                select(MitreTechniqueRow)
                .where(*where)
                .order_by(MitreTechniqueRow.id)
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        )
        .scalars()
        .all()
    )
    return ExerciseGapListResponse(
        items=[ExerciseGap(technique_id=r.id, name=r.name, tactic=r.tactic) for r in rows],
        total=int(total),
    )


# ---------------------------------------------------------------------------
# Detection gaps
# ---------------------------------------------------------------------------


@router.get("/gaps", response_model=list[DetectionGap])
async def get_detection_gaps(
    investigation_id: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Identify techniques without detection data."""
    user.require_permission("mitre:view")
    if investigation_id:
        await _load_scoped_investigation(db, user, investigation_id)
    return await MitreService.get_detection_gaps(db, investigation_id, org_id=user.org_id)


# ---------------------------------------------------------------------------
# TTP search for environment
# ---------------------------------------------------------------------------


@router.get("/search-ttps", response_model=list[MitreTechnique])
async def search_ttps_for_environment(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Suggest TTPs relevant to the organisation's tech stack."""
    user.require_permission("mitre:view")

    profile = await get_org_profile(db, user.org_id)
    return await MitreService.search_ttps_for_environment(db, profile.model_dump(mode="json"))


# ---------------------------------------------------------------------------
# Navigator export
# ---------------------------------------------------------------------------


@router.get("/export/navigator")
async def export_navigator_layer(
    investigation_id: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Export an ATT&CK Navigator compatible JSON layer for download."""
    user.require_permission("mitre:view")
    if investigation_id:
        await _load_scoped_investigation(db, user, investigation_id)

    layer = await MitreService.export_navigator_layer(db, investigation_id, org_id=user.org_id)
    return JSONResponse(
        content=layer.model_dump(mode="json"),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=btagent_navigator_layer.json"},
    )


# ---------------------------------------------------------------------------
# Admin: seed matrix
# ---------------------------------------------------------------------------


@router.post("/seed", response_model=SeedResponse, status_code=200)
async def seed_matrix(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Admin-only: reload the MITRE ATT&CK matrix from the vendored STIX bundle."""
    user.require_permission("mitre:seed")

    if not _DEFAULT_STIX_PATH.exists():
        raise HTTPException(
            status_code=404,
            detail=(
                f"STIX bundle not found at {_DEFAULT_STIX_PATH}. "
                f"Place enterprise-attack.json in {_STIX_DIR_HINT}."
            ),
        )

    counts = await MitreService.load_attack_matrix(db, _DEFAULT_STIX_PATH)
    logger.info("MITRE matrix seeded by user %s: %s", user.id, counts)

    return SeedResponse(**counts)


# ---------------------------------------------------------------------------
# Tagging
# ---------------------------------------------------------------------------


@router.post("/tag", response_model=TagResponse, status_code=201)
async def tag_technique(
    body: TagRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Tag a MITRE technique to an entity."""
    user.require_permission("mitre:tag")

    # Verify the target entity's investigation belongs to the caller's org
    # before writing (404 on miss/cross-org). Closes the unchecked-write hole
    # where any caller could tag an arbitrary entity_id in another tenant.
    await _assert_can_tag_entity(db, user, body.entity_type, body.entity_id)

    row = await MitreService.tag_technique(
        db,
        entity_type=body.entity_type,
        entity_id=body.entity_id,
        technique_id=body.technique_id,
        confidence=body.confidence,
        tagged_by=user.id,
    )

    return TagResponse(
        id=row.id,
        entity_type=row.entity_type,
        entity_id=row.entity_id,
        technique_id=row.technique_id,
        confidence=row.confidence,
        tagged_by=row.tagged_by,
        created_at=row.created_at.isoformat() if row.created_at else None,
    )
