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
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.services.mitre_service import MitreService
from btagent_backend.services.org_profile import get_org_profile

logger = logging.getLogger("btagent.api.mitre")

router = APIRouter(prefix="/mitre", tags=["mitre"])

# Default path for the vendored STIX bundle
_DEFAULT_STIX_PATH = (
    Path(__file__).resolve().parent.parent.parent / "data" / "enterprise-attack.json"
)


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------


class TechniqueListResponse(BaseModel):
    items: list[MitreTechnique]
    total: int
    page: int
    page_size: int


class TagRequest(BaseModel):
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
    return await MitreService.get_coverage(db, investigation_id)


@router.get("/coverage/score", response_model=CoverageScoreResponse)
async def get_coverage_score(
    investigation_id: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Get coverage percentage score."""
    user.require_permission("mitre:view")
    score = await MitreService.get_coverage_score(db, investigation_id)
    return CoverageScoreResponse(score=score, investigation_id=investigation_id)


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
    return await MitreService.get_detection_gaps(db, investigation_id)


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

    profile = await get_org_profile(db)
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

    layer = await MitreService.export_navigator_layer(db, investigation_id)
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
                "Place enterprise-attack.json in backend/data/."
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
