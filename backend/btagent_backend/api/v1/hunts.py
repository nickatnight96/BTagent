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

import csv
import io
import logging
import os
from datetime import datetime
from typing import Literal

from btagent_engine import NodeContext
from btagent_engine.reasoning import HuntPackageInput, HuntPackageNode
from btagent_engine.reasoning.correlation_workbench import (
    CorrelationWorkbenchInput,
    CorrelationWorkbenchNode,
)
from btagent_shared.types.config import TLP, AutonomyLevel
from btagent_shared.types.correlation import CorrelationTimeline
from btagent_shared.types.enums import InvestigationStatus, IOCType, Severity
from btagent_shared.types.hunt import Backend, HuntInput, HuntPlan, HuntScope
from btagent_shared.types.hunt_package import HuntPackage
from btagent_shared.types.investigation import IOC
from btagent_shared.utils.ids import generate_id
from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
)
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.db.models import InvestigationRow
from btagent_backend.services import hunt_package_store, hunt_plan_service
from btagent_backend.services.cti_detection_service import get_deployed_technique_ids
from btagent_backend.services.mitre_service import build_adversary_ttp_resolver
from btagent_backend.services.proposal_huntplan import compile_huntinput_to_huntplan
from btagent_backend.services.task_manager import TaskManager

logger = logging.getLogger("btagent.api.hunts")

router = APIRouter(prefix="/hunts", tags=["hunts"])


# Upper bound on advisory text fed to the engine, shared by the paste path
# (validated on the request model) and the server-side decode path (enforced
# after PDF/CSV -> text). Keeps a runaway upload from ballooning the run.
_MAX_ADVISORY_CHARS = 200_000


class HuntPackageRequest(BaseModel):
    text: str = Field(
        ...,
        min_length=1,
        max_length=_MAX_ADVISORY_CHARS,
        description="Advisory text to analyze (decoded from a PDF/CSV server-side or pasted).",
    )
    source_label: str = Field(default="advisory", max_length=200)
    backends: list[Backend] = Field(default_factory=list)
    window_days: int = Field(default=90, ge=1, le=730)


def _decode_pdf(data: bytes) -> str:
    """Extract text from an uploaded PDF (pypdf, pure-Python, no system libs)."""
    from pypdf import PdfReader

    try:
        reader = PdfReader(io.BytesIO(data))
        return "\n".join((page.extract_text() or "") for page in reader.pages)
    except Exception as exc:  # noqa: BLE001 — any parse failure is a bad upload
        raise HTTPException(status_code=400, detail="Uploaded PDF could not be decoded.") from exc


def _decode_csv(data: bytes) -> str:
    """Flatten an uploaded CSV to whitespace-delimited text for extraction.

    Joining cells with spaces (rows with newlines) means indicators packed
    into adjacent columns tokenise cleanly for the regex-based extractor.
    """
    text = data.decode("utf-8", errors="replace")
    try:
        rows = csv.reader(io.StringIO(text))
        return "\n".join(" ".join(cell for cell in row) for row in rows)
    except csv.Error:
        return text


def _decode_upload(filename: str | None, content_type: str | None, data: bytes) -> str:
    """Dispatch an uploaded advisory to the right decoder (PDF / CSV / text)."""
    name = (filename or "").lower()
    ctype = (content_type or "").lower()
    if ctype == "application/pdf" or name.endswith(".pdf"):
        return _decode_pdf(data)
    if "csv" in ctype or name.endswith(".csv"):
        return _decode_csv(data)
    # Fallback: treat anything else as UTF-8 text (a pasted .txt advisory).
    return data.decode("utf-8", errors="replace")


async def _generate_and_store_package(
    db: AsyncSession,
    user: CurrentUser,
    *,
    text: str,
    source_label: str,
    backends: list[Backend],
    window_days: int,
) -> HuntPackage:
    """Run HuntPackageNode over decoded/pasted advisory text and persist it.

    Shared by the paste path (``POST /hunts/package``) and the server-side
    decode path (``POST /hunts/package/upload``); both persist to the same
    org-scoped store so the artifact is re-openable from history.
    """
    node = HuntPackageNode()
    ctx = NodeContext(run_id=generate_id("run"), org_id=user.org_id)
    try:
        out = await node.run(
            HuntPackageInput(
                text=text,
                source_label=source_label,
                initiated_by=user.id,
                backends=backends,
                window_days=window_days,
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
            "yara_rules": len(out.package.yara_rules),
        },
    )
    return out.package


@router.post("/package", response_model=HuntPackage)
async def generate_hunt_package(
    body: HuntPackageRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> HuntPackage:
    """Generate a hunt package from pasted advisory text (UC-2.2).

    The package is persisted to the org-scoped store (#99 follow-through) —
    the response carries its ``id`` so the analyst can re-open it from
    ``GET /hunts/packages`` later instead of losing the artifact on
    navigation. Uploading a PDF/CSV file instead of pasting text is
    ``POST /hunts/package/upload``.
    """
    user.require_permission("hunt:run")
    return await _generate_and_store_package(
        db,
        user,
        text=body.text,
        source_label=body.source_label,
        backends=body.backends,
        window_days=body.window_days,
    )


@router.post("/package/upload", response_model=HuntPackage)
async def generate_hunt_package_from_upload(
    file: UploadFile = File(..., description="Advisory file — PDF or CSV."),
    source_label: str | None = Form(default=None, max_length=200),
    backends: list[Backend] = Form(default=[]),
    window_days: int = Form(default=90, ge=1, le=730),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> HuntPackage:
    """Generate a hunt package from an uploaded advisory file (UC-2.2, #105).

    Decodes the upload server-side — PDF via pypdf, CSV flattened to text —
    then runs the same HuntPackageNode flow as the paste path (extracted
    indicators + YARA rules + 90-day sighting check + per-backend queries +
    Sigma drafts) and persists the result. ``source_label`` defaults to the
    uploaded filename. 400 on an undecodable PDF; 422 on an empty upload or
    one that yields no text.
    """
    user.require_permission("hunt:run")

    data = await file.read()
    if not data:
        raise HTTPException(status_code=422, detail="Uploaded file is empty.")

    text = _decode_upload(file.filename, file.content_type, data)
    if not text.strip():
        raise HTTPException(
            status_code=422,
            detail="No text could be extracted from the uploaded file.",
        )
    if len(text) > _MAX_ADVISORY_CHARS:
        text = text[:_MAX_ADVISORY_CHARS]

    label = source_label or file.filename or "advisory"
    return await _generate_and_store_package(
        db,
        user,
        text=text,
        source_label=label,
        backends=backends,
        window_days=window_days,
    )


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


class HuntPlanIOC(BaseModel):
    """One indicator supplied as hunt input (#99).

    Deliberately *not* the full :class:`btagent_shared.types.investigation.IOC`:
    that model requires ``id`` and ``investigation_id``, and an ad-hoc hunt
    has neither — the analyst is hunting *before* there is a case. The route
    synthesises the missing identity fields.
    """

    type: IOCType
    value: str = Field(..., min_length=1, max_length=2048)


class HuntPlanRequest(BaseModel):
    """Direct hunt-plan generation (#99 Phase A) — analyst names the target."""

    adversaries: list[str] = Field(
        default_factory=list,
        max_length=10,
        description="Threat-actor names ('APT29', 'FIN7', ...).",
    )
    ttps: list[str] = Field(
        default_factory=list,
        max_length=50,
        description="ATT&CK technique ids ('T1059.001', ...).",
    )
    iocs: list[HuntPlanIOC] = Field(
        default_factory=list,
        max_length=100,
        description=(
            "Indicators to hunt from. HypothesisGen maps each to a plausible "
            "technique (ip/url -> T1071.001, domain -> T1071.004, hashes -> "
            "T1027, cve -> T1190, ...), so an analyst holding only indicators "
            "can still get a plan. Types with no mapping are ignored."
        ),
    )
    backends: list[Backend] = Field(
        default_factory=list,
        description="Backends to synthesise queries for. Empty == default fan-out.",
    )

    @model_validator(mode="after")
    def _at_least_one_target(self) -> HuntPlanRequest:
        if not self.adversaries and not self.ttps and not self.iocs:
            raise ValueError("at least one of adversaries / ttps / iocs must be non-empty")
        return self


@router.post("/plan", response_model=HuntPlan)
async def generate_hunt_plan(
    body: HuntPlanRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> HuntPlan:
    """Generate a full hunt plan from adversaries and/or TTPs (#99 Phase A).

    Runs HypothesisGen → per-TTP QuerySynth + NoiseBaseline →
    RunbookCompiler — the same pipeline pattern-hunt proposals compile
    through — and returns the ready-to-run runbook. The plan is persisted
    (proposal-less ``hunt_plans`` row keyed by the plan's own id) so it can
    be re-opened from ``GET /hunts/plans`` later.
    """
    user.require_permission("hunt:run")

    hunt_input = HuntInput(
        adversaries=body.adversaries,
        ttps=body.ttps,
        # A direct hunt has no case yet, so there is no investigation to
        # attach these to. The sentinel keeps the shared IOC model's contract
        # (both fields are required) without inventing a plausible-looking
        # investigation id that would later be mistaken for a real one.
        iocs=[
            IOC(
                id=generate_id("ioc"),
                investigation_id="",
                type=i.type,
                value=i.value,
                source=f"hunt_plan:{user.id}",
            )
            for i in body.iocs
        ],
        scope=HuntScope(backends=body.backends),
        initiated_by=user.id,
    )
    # #99: resolve named actors against the seeded ATT&CK Groups table, and
    # cross-reference the org's deployed detections so the plan's exec summary
    # carries a real coverage delta. Both are built here (with the DB session)
    # and injected into the side-effect-free compiler.
    resolver = await build_adversary_ttp_resolver(db, hunt_input.adversaries)
    deployed = await get_deployed_technique_ids(db, org_id=user.org_id)
    try:
        plan = await compile_huntinput_to_huntplan(
            hunt_input,
            org_id=user.org_id,
            log_ref=f"direct plan by {user.id}",
            adversary_resolver=resolver,
            deployed_technique_ids=deployed,
        )
    except NotImplementedError as exc:
        raise HTTPException(
            status_code=501,
            detail="Live hunt-plan generation is not yet wired; "
            "the deployment must run in mock mode.",
        ) from exc

    await hunt_plan_service.store_direct_plan(db, org_id=user.org_id, plan=plan)

    logger.info(
        "hunt_plan generated",
        extra={
            "investigation_id": None,
            "hypotheses": len(plan.hypotheses),
            "ttp_entries": len(plan.ttp_entries),
        },
    )
    return plan


class HuntPlanSummary(BaseModel):
    """History-list projection of a stored plan (no runbook bodies)."""

    id: str
    status: str
    adversaries: list[str]
    ttps: list[str]
    hypothesis_count: int
    entry_count: int
    from_proposal: bool
    created_at: str
    # Quick-glance outcome of the most recent execution (from the stored
    # last_run blob); None until the plan has been executed.
    last_run_findings: int | None
    last_run_at: str | None


class HuntPlanListResponse(BaseModel):
    items: list[HuntPlanSummary]
    total: int


def _plan_to_summary(row) -> HuntPlanSummary:
    plan = row.plan or {}
    hunt_input = plan.get("input") or {}
    last_run = plan.get("last_run") or {}
    return HuntPlanSummary(
        id=row.id,
        status=row.status,
        adversaries=list(hunt_input.get("adversaries") or []),
        ttps=list(hunt_input.get("ttps") or []),
        hypothesis_count=len(plan.get("hypotheses") or []),
        entry_count=len(plan.get("ttp_entries") or []),
        from_proposal=row.proposal_id is not None,
        created_at=row.created_at.isoformat(),
        last_run_findings=last_run.get("findings_created"),
        last_run_at=last_run.get("completed_at") or last_run.get("started_at"),
    )


@router.get("/plans", response_model=HuntPlanListResponse)
async def list_hunt_plans(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> HuntPlanListResponse:
    """Org-scoped hunt-plan history (direct + proposal-compiled), newest first."""
    user.require_permission("hunt:view")
    rows, total = await hunt_plan_service.list_plans(
        db, org_id=user.org_id, page=page, page_size=page_size
    )
    return HuntPlanListResponse(items=[_plan_to_summary(r) for r in rows], total=total)


@router.get("/plans/{plan_id}", response_model=HuntPlan)
async def get_hunt_plan(
    plan_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> HuntPlan:
    """Re-open a stored plan. 404 on miss, cross-org access, or un-compiled row."""
    user.require_permission("hunt:view")
    row = await hunt_plan_service.get_plan(db, org_id=user.org_id, plan_row_id=plan_id)
    if row is None or row.plan is None:
        raise HTTPException(status_code=404, detail="Hunt plan not found")
    # ``last_run`` rides alongside the plan fields in the stored JSON
    # (HuntPlan is extra=forbid) — pop it so an executed plan re-opens.
    plan_data = dict(row.plan)
    plan_data.pop("last_run", None)
    return HuntPlan.model_validate(plan_data)


class HuntPlanRunResponse(BaseModel):
    """One plan-execution history row (mirrors pattern_hunt's PlanRunResponse,
    with ``proposal_id`` optional — NULL on direct-plan runs)."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    plan_row_id: str
    proposal_id: str | None
    plan_id: str
    run_id: str
    ttp_stats: dict
    hit_count: int
    error_count: int
    findings_created: int
    status: str
    error: str | None
    started_at: datetime
    completed_at: datetime | None


class HuntPlanRunListResponse(BaseModel):
    items: list[HuntPlanRunResponse]
    total: int


@router.get("/plans/{plan_id}/runs", response_model=HuntPlanRunListResponse)
async def list_hunt_plan_runs(
    plan_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> HuntPlanRunListResponse:
    """Per-run execution history for a stored plan (#99 Phase B).

    Newest-first, paginated. 404 on miss/cross-org; a stored-but-never-
    executed plan returns an empty list. The summary's ``last_run_*``
    fields are the quick glance; this is the full history behind them.
    """
    user.require_permission("hunt:view")
    row = await hunt_plan_service.get_plan(db, org_id=user.org_id, plan_row_id=plan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Hunt plan not found")
    rows, total = await hunt_plan_service.list_plan_runs(
        db, org_id=user.org_id, plan_row_id=row.id, page=page, page_size=page_size
    )
    return HuntPlanRunListResponse(
        items=[HuntPlanRunResponse.model_validate(r) for r in rows], total=total
    )


@router.get("/plans/{plan_id}/export", response_model=None)
async def export_hunt_plan(
    plan_id: str,
    format: Literal["md", "pdf"] = Query("md"),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> Response:
    """Export a stored plan's runbook as Markdown or PDF (#99 Phase B).

    The runbook is a team-coordination artifact — this is how it leaves
    the app for tickets, wikis, and IR reports. 404 on miss/cross-org or
    an un-compiled row. Requires ``hunt:view``.
    """
    user.require_permission("hunt:view")
    row = await hunt_plan_service.get_plan(db, org_id=user.org_id, plan_row_id=plan_id)
    if row is None or row.plan is None:
        raise HTTPException(status_code=404, detail="Hunt plan not found")
    plan_data = dict(row.plan)
    plan_data.pop("last_run", None)  # rides alongside the extra=forbid model
    plan = HuntPlan.model_validate(plan_data)

    from btagent_backend.services import hunt_plan_export

    if format == "md":
        markdown = hunt_plan_export.plan_to_markdown(plan)
        return Response(
            content=markdown,
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="hunt_plan_{plan.id}.md"'},
        )

    # PDF path reuses the report renderer (TLP stamping + egress gate).
    # Plans carry no TLP column; they are internal runbooks, stamped GREEN.
    from btagent_backend.services.report_pdf import render_report_pdf

    pdf_bytes = render_report_pdf(
        hunt_plan_export.plan_to_report_sections(plan),
        tlp_level="green",
        severity="medium",
        org_id=row.org_id,
    )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="hunt_plan_{plan.id}.pdf"'},
    )


def _mock_connectors_mode() -> bool:
    """Same flag the engine integration nodes read (default: mock on)."""
    return os.getenv("BTAGENT_MOCK_CONNECTORS", "true").strip().lower() == "true"


class ExecuteHuntPlanResponse(BaseModel):
    """Outcome of kicking a direct-plan execution (#99 Phase B).

    ``queued`` is True on the live-connector path — the run happens on the
    arq worker and ``findings_created`` is None; re-open the plan for the
    ``last_run`` summary. Mock mode executes inline and reports counts.
    """

    plan_id: str
    status: str
    queued: bool
    findings_created: int | None


@router.post("/plans/{plan_id}/execute", response_model=ExecuteHuntPlanResponse)
async def execute_hunt_plan(
    plan_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> ExecuteHuntPlanResponse:
    """Execute a stored plan's runbook (#99 Phase B).

    Runs the per-TTP queries through the engine integration nodes and lands
    every hit in the triage inbox (clustering + suppressions apply), exactly
    like proposal-compiled plans. Inline under mock connectors; enqueued to
    the arq worker on the live path. 404 on miss/cross-org; 409 when the
    plan row is not ``ready``.
    """
    user.require_permission("hunt:run")
    row = await hunt_plan_service.get_plan(db, org_id=user.org_id, plan_row_id=plan_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Hunt plan not found")
    if row.status != hunt_plan_service.STATUS_READY:
        raise HTTPException(
            status_code=409,
            detail=f"Hunt plan is not ready to execute (status={row.status})",
        )

    if _mock_connectors_mode():
        row, findings_created = await hunt_plan_service.execute_plan_and_ingest(
            db, plan_row_id=row.id
        )
        await db.commit()
        return ExecuteHuntPlanResponse(
            plan_id=row.id,
            status=row.status,
            queued=False,
            findings_created=findings_created,
        )

    try:
        from arq import create_pool

        from btagent_backend.scheduler.worker import redis_settings

        pool = await create_pool(redis_settings())
        try:
            await pool.enqueue_job("execute_hunt_plan", row.id)
        finally:
            await pool.aclose()
    except Exception as exc:  # noqa: BLE001 — infra failure surfaces as 503
        logger.exception("Failed to enqueue HuntPlan execution for %s", row.id)
        raise HTTPException(
            status_code=503,
            detail=f"Could not queue plan execution: {type(exc).__name__}",
        ) from exc
    return ExecuteHuntPlanResponse(
        plan_id=row.id, status=row.status, queued=True, findings_created=None
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


# --------------------------------------------------------------------------- #
# Hunt-pack suggestions (#120 Phase C -> #112)
# --------------------------------------------------------------------------- #


class HuntPackSuggestionSummary(BaseModel):
    """A suggested recurring pack — the draft manifest plus its provenance."""

    id: str
    proposal_id: str
    plan_id: str
    title: str
    technique_ids: list[str]
    rationale: str
    state: str
    hit_count: int
    created_at: str
    updated_at: str
    # The promotable HuntPackManifest draft, so an analyst can review the
    # actual Sigma before arming anything.
    manifest: dict


class HuntPackSuggestionListResponse(BaseModel):
    items: list[HuntPackSuggestionSummary]
    total: int


class DecideHuntPackSuggestionRequest(BaseModel):
    state: Literal["accepted", "dismissed"] = Field(
        ...,
        description=(
            "Analyst decision. 'suggested' is the writer's initial value, not a "
            "decision, so it cannot be selected here."
        ),
    )


def _suggestion_to_summary(row) -> HuntPackSuggestionSummary:
    return HuntPackSuggestionSummary(
        id=row.id,
        proposal_id=row.proposal_id,
        plan_id=row.plan_id,
        title=row.title,
        technique_ids=list(row.technique_ids or []),
        rationale=row.rationale or "",
        state=row.state,
        hit_count=row.hit_count,
        created_at=row.created_at.isoformat(),
        updated_at=row.updated_at.isoformat(),
        manifest=dict(row.manifest or {}),
    )


@router.get("/pack-suggestions", response_model=HuntPackSuggestionListResponse)
async def list_hunt_pack_suggestions(
    state: str | None = Query(
        None,
        description="Filter by review state: suggested / accepted / dismissed.",
    ),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> HuntPackSuggestionListResponse:
    """Recurring-pack suggestions filed by confirmed-HIT pattern hunts (#120).

    A confirmed HIT means a cross-investigation shape both recurred across
    closed cases *and* fired against current telemetry — a strong candidate
    for a scheduled #112 pack. Nothing is auto-armed; this is the queue an
    analyst reviews before promoting one.

    Most-reinforced first: a shape several separate hunts confirmed outranks
    one confirmed once.
    """
    user.require_permission("hunt:view")
    if state is not None and state not in hunt_plan_service.SUGGESTION_STATES:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Unknown state {state!r}; expected one of "
                f"{list(hunt_plan_service.SUGGESTION_STATES)}."
            ),
        )
    rows, total = await hunt_plan_service.list_pack_suggestions(
        db, org_id=user.org_id, state=state, page=page, page_size=page_size
    )
    return HuntPackSuggestionListResponse(
        items=[_suggestion_to_summary(r) for r in rows], total=total
    )


@router.post(
    "/pack-suggestions/{suggestion_id}/decide",
    response_model=HuntPackSuggestionSummary,
)
async def decide_hunt_pack_suggestion(
    suggestion_id: str,
    body: DecideHuntPackSuggestionRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> HuntPackSuggestionSummary:
    """Accept or dismiss a suggestion (senior-analyst).

    Gated on ``hunt:promote`` rather than the ``hunt:view`` used to read the
    queue, because the decision is **durable**: the HIT write-back path
    deliberately never overwrites a decided row, so a dismiss permanently
    stops a confirmed-HIT shape from re-surfacing however many times it
    recurs. That is the same "shapes what the SOC does (and doesn't) look
    at" reasoning the RBAC map already uses to put suppress/promote at
    senior-analyst.

    Accepting records the intent to schedule the draft; it does not itself
    arm a pack.
    """
    user.require_permission("hunt:promote")
    row = await hunt_plan_service.decide_pack_suggestion(
        db, org_id=user.org_id, suggestion_id=suggestion_id, state=body.state
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Hunt-pack suggestion not found")
    await db.commit()
    return _suggestion_to_summary(row)
