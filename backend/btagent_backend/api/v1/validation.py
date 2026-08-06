"""Detection-validation API (#118).

``POST /api/v1/validation/runs``
    Replay the built-in simulation scenario library (26+ ATT&CK techniques)
    through the Sigma packs those scenarios target — Windows endpoint, AWS
    control plane, Kubernetes audit and identity (see
    ``validation_scenarios.default_validation_packs``) — persist the coverage
    report to ``detection_validation_runs``, and return it. RBAC ``hunt:run`` —
    replaying scenarios is a run action, same as the CTI proposal validate route.

``GET /api/v1/validation/runs``
    List the persisted run history newest-first (org-scoped, paginated).
    RBAC ``hunt:view``.

``POST /api/v1/validation/emulate``
    SANDBOX-GATED adversary-emulation validation of one ATT&CK technique
    (#118). The sandbox-enforcement service refuses any non-sandbox
    ``target_env`` with an AUDITED 403 denial before any emulator runs; an
    approved sandbox audits the trigger, drives the mock-first
    ``ValidationOrchestrator`` (trigger -> observe -> score), persists the
    verdict, and returns it. RBAC ``validation:emulate`` (incident_commander) —
    triggering an emulation is a containment-class action.

Mock-first: the scenario set is deterministic and synthetic and the emulators
honour ``BTAGENT_MOCK_CONNECTORS`` (default on) — no real technique fires.
``run_validation`` stays a pure engine call; persistence flows through
``validation_run_service`` (which never commits — the ``get_db`` dependency owns
the commit on success).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from btagent_shared.types.detection_validation import (
    EmulationRequest,
    Emulator,
    TargetEnv,
)
from btagent_shared.types.enums import Severity
from btagent_shared.utils.ids import generate_id
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.db.models_validation import DetectionValidationRunRow
from btagent_backend.services import validation_coverage_service, validation_run_service
from btagent_backend.services.detection_emulation_service import run_emulation_validation
from btagent_backend.services.validation_scenarios import (
    default_validation_packs,
    default_validation_scenarios,
)
from btagent_backend.services.validation_service import build_emulation_report, run_validation

logger = logging.getLogger("btagent.api.validation")

router = APIRouter(prefix="/validation", tags=["validation"])

# Packs the default run validates against — every pack the built-in scenario
# library targets, so the coverage heat-map spans the full technique breadth
# (#118 scenario library) instead of one pack.
_DEFAULT_PACKS = default_validation_packs()


class ValidationRunSummary(BaseModel):
    id: str
    run_id: str
    packs: list[str]
    scenarios_run: int
    total_techniques: int
    detected_pct: float
    gaps: list[str]
    # Emulation-path fields (#118). False / None for pure in-process replay runs.
    emulated: bool = False
    target_env: str | None = None
    generated_at: datetime
    created_at: datetime


class ValidationRunResponse(ValidationRunSummary):
    # The POST response carries the full per-technique payload; the list view
    # omits it to stay light.
    coverage_by_technique: list[dict]
    verdicts: list[dict] = Field(default_factory=list)


class ValidationRunListResponse(BaseModel):
    items: list[ValidationRunSummary]
    total: int


class CoverageMapEntryResponse(BaseModel):
    """One technique's coverage/staleness row (#118 Phase C coverage map)."""

    technique_id: str
    name: str | None = None
    last_validated: datetime | None = None
    last_verdict: str | None = None
    days_since_validated: int | None = None
    stale: bool
    has_detection: bool


class CoverageMapResponse(BaseModel):
    items: list[CoverageMapEntryResponse]
    total: int
    stale_count: int
    stale_days: int
    only_stale: bool


class EmulationRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    """Body for a sandbox-gated adversary-emulation validation run."""

    technique_id: str = Field(..., min_length=1, max_length=20)
    # No default sandbox: the caller must state the target explicitly, and the
    # sandbox-enforcement layer refuses anything that is not an approved sandbox.
    target_env: TargetEnv = Field(
        default=TargetEnv.UNKNOWN,
        description="Where to emulate. Only 'sandbox' is approved; anything "
        "else is refused with an audited denial before any emulator runs.",
    )
    emulator: Emulator = Field(default=Emulator.ATOMIC_RED_TEAM)
    expected_severity: Severity = Field(default=Severity.HIGH)
    latency_sla_seconds: float = Field(default=300.0, gt=0)


class EmulationDenied(BaseModel):
    """403 body returned when a non-sandbox target is refused (audited)."""

    status: str = "denied"
    technique_id: str
    target_env: str
    reason: str
    audit_id: str


def _summary(row: DetectionValidationRunRow) -> ValidationRunSummary:
    return ValidationRunSummary(
        id=row.id,
        run_id=row.run_id,
        packs=list(row.packs or []),
        scenarios_run=row.scenarios_run,
        total_techniques=row.total_techniques,
        detected_pct=row.detected_pct,
        gaps=list(row.gaps or []),
        emulated=bool(getattr(row, "emulated", False)),
        target_env=getattr(row, "target_env", None),
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
        verdicts=list(getattr(row, "verdicts", []) or []),
    )


@router.post(
    "/emulate",
    response_model=ValidationRunResponse,
    status_code=201,
    responses={403: {"model": EmulationDenied}},
)
async def create_emulation_run(
    body: EmulationRunRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Sandbox-gated adversary-emulation validation of one ATT&CK technique.

    SAFETY: the sandbox-enforcement service is the sole path to an emulator. A
    non-sandbox ``target_env`` is refused with an AUDITED 403 denial and NO
    emulator is invoked. An approved sandbox audits the trigger, drives the
    mock-first orchestrator, persists the verdict, and returns it. Org-scoped.
    """
    # containment-class RBAC gate (incident_commander) — triggering an
    # emulation is as privileged as executing containment.
    user.require_permission("validation:emulate")

    request = EmulationRequest(
        technique_id=body.technique_id,
        target_env=body.target_env,
        emulator=body.emulator,
        expected_severity=body.expected_severity,
        latency_sla_seconds=body.latency_sla_seconds,
    )

    outcome = await run_emulation_validation(
        db, actor_id=user.id, org_id=user.org_id, request=request
    )

    if not outcome.approved:
        # The audited denial row is already written; surface a 403 whose body
        # carries the audit id so the refusal is traceable end to end.
        raise HTTPException(
            status_code=outcome.http_status,
            detail={
                "status": "denied",
                "technique_id": outcome.technique_id,
                "target_env": outcome.target_env,
                "reason": outcome.reason,
                "audit_id": outcome.audit_id,
            },
        )

    assert outcome.verdict is not None  # approved path always carries a verdict
    report = build_emulation_report(
        run_id=generate_id("valrun"),
        request=request,
        verdict=outcome.verdict,
        generated_at=datetime.now(UTC),
    )
    row = await validation_run_service.persist_validation_report(
        db, report, org_id=user.org_id, packs=()
    )
    return ValidationRunResponse(
        **_summary(row).model_dump(),
        coverage_by_technique=list(row.coverage_by_technique or []),
        verdicts=list(getattr(row, "verdicts", []) or []),
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


@router.get("/coverage-map", response_model=CoverageMapResponse)
async def get_coverage_map(
    stale_days: int = Query(90, ge=1, le=3650),
    only_stale: bool = Query(
        False,
        description="Return only techniques validated >stale_days ago or never validated.",
    ),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Per-technique detection coverage map derived from validation history (#118).

    For each ATT&CK technique the org has a detection for (or has validated),
    reports its ``last_validated`` timestamp (max over ``detection_validation_runs``,
    non-errored) and a ``stale`` flag for techniques validated >``stale_days`` days
    ago OR never validated. ``only_stale=true`` is the ">90d untested /
    never-validated" filter. Read-only, org-scoped. RBAC ``hunt:view``.
    """
    user.require_permission("hunt:view")

    entries = await validation_coverage_service.build_coverage_map(
        db, org_id=user.org_id, stale_days=stale_days, only_stale=only_stale
    )
    items = [
        CoverageMapEntryResponse(
            technique_id=e.technique_id,
            name=e.name,
            last_validated=e.last_validated,
            last_verdict=e.last_verdict,
            days_since_validated=e.days_since_validated,
            stale=e.stale,
            has_detection=e.has_detection,
        )
        for e in entries
    ]
    return CoverageMapResponse(
        items=items,
        total=len(items),
        stale_count=sum(1 for e in items if e.stale),
        stale_days=stale_days,
        only_stale=only_stale,
    )
