"""Threat-hunting API — first engine-backed vertical slice (UC-2.2, #105).

Exposes the HuntPackageNode over HTTP: paste an advisory's text, get
back a hunt package (extracted indicators + 90-day sighting check +
pre-built per-backend queries + Sigma drafts). This is the first
endpoint to run an engine reasoning node inside a real request, proving
the engine -> backend -> frontend path end to end.

Runs mock-mode in dev (BTAGENT_MOCK_CONNECTORS / BTAGENT_MOCK_LLM
default to true); the live path raises NotImplementedError until the
connector live-wiring + LLM router land, which the handler surfaces as
a 501.
"""

from __future__ import annotations

import logging

from btagent_engine import NodeContext
from btagent_engine.reasoning import HuntPackageInput, HuntPackageNode
from btagent_engine.reasoning.correlation_workbench import (
    CorrelationWorkbenchInput,
    CorrelationWorkbenchNode,
)
from btagent_shared.types.config import TLP, AutonomyLevel
from btagent_shared.types.correlation import CorrelationTimeline
from btagent_shared.types.enums import InvestigationStatus, IOCType, Severity
from btagent_shared.types.hunt import Backend
from btagent_shared.types.hunt_package import HuntPackage
from btagent_shared.utils.ids import generate_id
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.db.models import InvestigationRow
from btagent_backend.services import hunt_package_store
from btagent_backend.services.task_manager import TaskManager

logger = logging.getLogger("btagent.api.hunts")

router = APIRouter(prefix="/hunts", tags=["hunts"])


class HuntPackageRequest(BaseModel):
    text: str = Field(
        ...,
        min_length=1,
        max_length=200_000,
        description="Advisory text to analyze (decoded from a PDF/CSV client-side or pasted).",
    )
    source_label: str = Field(default="advisory", max_length=200)
    backends: list[Backend] = Field(default_factory=list)
    window_days: int = Field(default=90, ge=1, le=730)


@router.post("/package", response_model=HuntPackage)
async def generate_hunt_package(
    body: HuntPackageRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> HuntPackage:
    """Generate a hunt package from advisory text (UC-2.2).

    The package is persisted to the org-scoped store (#99 follow-through) —
    the response carries its ``id`` so the analyst can re-open it from
    ``GET /hunts/packages`` later instead of losing the artifact on
    navigation.
    """
    user.require_permission("hunt:run")

    node = HuntPackageNode()
    ctx = NodeContext(run_id=generate_id("run"), org_id=user.org_id)
    try:
        out = await node.run(
            HuntPackageInput(
                text=body.text,
                source_label=body.source_label,
                initiated_by=user.id,
                backends=body.backends,
                window_days=body.window_days,
            ),
            ctx,
        )
    except NotImplementedError as exc:
        # Live path not wired yet — surface as 501 rather than 500.
        raise HTTPException(
            status_code=501,
            detail="Live hunt-package generation is not yet wired; "
            "the deployment must run in mock mode.",
        ) from exc

    await hunt_package_store.save_package(
        db, org_id=user.org_id, created_by=user.id, package=out.package
    )

    logger.info(
        "hunt_package generated",
        extra={
            "investigation_id": None,
            "extracted_iocs": out.package.extracted_ioc_count,
            "techniques": len(out.package.derived_techniques),
        },
    )
    return out.package


class HuntPackageSummary(BaseModel):
    """History-list projection of a stored package (no query/draft bodies)."""

    id: str
    source_label: str
    extracted_ioc_count: int
    deduped_count: int
    techniques: list[str]
    mock_mode: bool
    created_by: str | None
    created_at: str
    investigation_id: str | None


class HuntPackageListResponse(BaseModel):
    items: list[HuntPackageSummary]
    total: int


def _to_summary(row) -> HuntPackageSummary:
    return HuntPackageSummary(
        id=row.id,
        source_label=row.source_label,
        extracted_ioc_count=row.extracted_ioc_count,
        deduped_count=row.deduped_count,
        techniques=list(row.techniques or []),
        mock_mode=row.mock_mode,
        created_by=row.created_by,
        created_at=row.created_at.isoformat(),
        investigation_id=row.investigation_id,
    )


@router.get("/packages", response_model=HuntPackageListResponse)
async def list_hunt_packages(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> HuntPackageListResponse:
    """Org-scoped hunt-package history, newest first. RBAC: ``hunt:view``."""
    user.require_permission("hunt:view")
    rows, total = await hunt_package_store.list_packages(
        db, org_id=user.org_id, page=page, page_size=page_size
    )
    return HuntPackageListResponse(items=[_to_summary(r) for r in rows], total=total)


@router.get("/packages/{package_id}", response_model=HuntPackage)
async def get_hunt_package(
    package_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> HuntPackage:
    """Re-open a stored package. 404 on miss or cross-org access."""
    user.require_permission("hunt:view")
    row = await hunt_package_store.get_package(db, org_id=user.org_id, package_id=package_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Hunt package not found")
    package = HuntPackage.model_validate(row.package)
    package.id = row.id  # older dumps may predate the id field
    package.investigation_id = row.investigation_id  # row-level lineage, never in the dump
    return package


class PromotePackageResponse(BaseModel):
    """Result of promoting a stored package into an investigation."""

    investigation_id: str
    package_id: str
    title: str
    severity: str
    status: str


def _get_task_manager(request: Request) -> TaskManager:
    tm: TaskManager | None = getattr(request.app.state, "task_manager", None)
    if tm is None:
        raise HTTPException(
            status_code=503,
            detail="TaskManager not initialised -- server is starting up",
        )
    return tm


@router.post(
    "/packages/{package_id}/promote",
    response_model=PromotePackageResponse,
    status_code=201,
)
async def promote_hunt_package(
    package_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> PromotePackageResponse:
    """Open an investigation from a stored hunt package (#99 payoff).

    Severity derives from the retro-hunt verdict: historical sightings
    (``compromise_suspected``) open a HIGH case, a clean package a MEDIUM
    one. The package records the case id (one promote per package — 409
    on a second attempt) and the investigation agent starts immediately,
    same as a manual create.
    """
    user.require_permission("investigation:create")
    row = await hunt_package_store.get_package(db, org_id=user.org_id, package_id=package_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Hunt package not found")
    if row.investigation_id is not None:
        raise HTTPException(
            status_code=409,
            detail=f"Package already promoted to investigation {row.investigation_id}",
        )

    package = HuntPackage.model_validate(row.package)
    compromise = bool(package.retro_report and package.retro_report.compromise_suspected)
    severity = Severity.HIGH if compromise else Severity.MEDIUM
    sightings = len(package.retro_report.sightings) if package.retro_report else 0

    title = f"Hunt: {package.source_label}"
    description = (
        f"Promoted from hunt package {row.id} ({package.source_label}). "
        f"{package.extracted_ioc_count} indicators extracted, "
        f"{len(package.derived_techniques)} ATT&CK techniques derived "
        f"({', '.join(package.derived_techniques[:5])}"
        f"{'…' if len(package.derived_techniques) > 5 else ''}). "
        + (
            f"Retro-hunt found {sightings} historical sighting(s) — possible prior compromise."
            if compromise
            else "Retro-hunt found no historical sightings."
        )
    )

    task_manager = _get_task_manager(request)
    config = {
        "severity": severity.value,
        "tlp_level": TLP.GREEN.value,
        "autonomy_level": AutonomyLevel.L2_SUPERVISED.value,
        "template": None,
        "hunt_package_id": row.id,
    }
    # AUTH-B1: org_id from the authenticated user, never the request.
    inv = InvestigationRow(
        id=generate_id("inv"),
        title=title,
        description=description,
        severity=severity.value,
        tlp_level=TLP.GREEN.value,
        autonomy_level=AutonomyLevel.L2_SUPERVISED.value,
        template=None,
        assigned_to=user.id,
        org_id=user.org_id,
        status=InvestigationStatus.PENDING.value,
        config=config,
    )
    db.add(inv)
    await db.flush()
    await hunt_package_store.link_investigation(db, row=row, investigation_id=inv.id)

    await task_manager.start_investigation(inv.id, config)
    logger.info(
        "hunt package %s promoted to investigation %s by user %s",
        row.id,
        inv.id,
        user.id,
    )
    return PromotePackageResponse(
        investigation_id=inv.id,
        package_id=row.id,
        title=title,
        severity=severity.value,
        status=inv.status,
    )


class CorrelateRequest(BaseModel):
    entity_type: IOCType = Field(..., description="Entity kind: ip / domain / hash_* / other.")
    entity_value: str = Field(..., min_length=1, max_length=500)
    mitre_confidence_threshold: float = Field(default=0.6, ge=0.0, le=1.0)


@router.post("/correlate", response_model=CorrelationTimeline)
async def correlate_entity(
    body: CorrelateRequest,
    user: CurrentUser = Depends(get_current_user),
) -> CorrelationTimeline:
    """Cross-platform IOC pivot + correlation (UC-1.2).

    Fans out an entity across SIEM/EDR/firewall/identity, normalizes into
    one OCSF-aligned timeline, auto-tags MITRE techniques, and suggests
    next pivots. Read-only (L1) — the analyst directs every pivot.
    """
    user.require_permission("hunt:run")

    node = CorrelationWorkbenchNode()
    ctx = NodeContext(run_id=generate_id("run"), org_id=user.org_id)
    try:
        out = await node.run(
            CorrelationWorkbenchInput(
                entity_type=body.entity_type,
                entity_value=body.entity_value,
                mitre_confidence_threshold=body.mitre_confidence_threshold,
            ),
            ctx,
        )
    except NotImplementedError as exc:
        raise HTTPException(
            status_code=501,
            detail="Live correlation is not yet wired; deployment must run in mock mode.",
        ) from exc

    return out.timeline
