"""Reports API — report generation, summarization, and remediation endpoints."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Literal

from btagent_shared.security import EgressKind, TLPViolation
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.auth.scoping import assert_can_access_investigation
from btagent_backend.db.models import (
    ContainmentActionRow,
    InvestigationRow,
    IOCRow,
    TimelineEntryRow,
)
from btagent_backend.services.report_service import ReportService
from btagent_backend.services.tlp_egress_guard import assert_org_policy_allows_egress


async def _load_scoped_investigation(
    db: AsyncSession, user: CurrentUser, investigation_id: str
) -> InvestigationRow:
    """Look up an investigation, 404 if missing, 403 if out of scope.

    AUTH-B1: report endpoints take ``investigation_id`` from the request, so
    each one needs an explicit scope check before delegating to the report
    plugin (which doesn't know about tenants). Returns the row so callers that
    need its ``tlp_level`` / ``severity`` (e.g. PDF export) don't re-query.
    """
    result = await db.execute(
        select(InvestigationRow).where(InvestigationRow.id == investigation_id)
    )
    inv = result.scalar_one_or_none()
    if inv is None:
        raise HTTPException(status_code=404, detail="Not found")
    assert_can_access_investigation(user, inv)
    return inv


async def _scope_or_404(db: AsyncSession, user: CurrentUser, investigation_id: str) -> None:
    """Backwards-compatible wrapper that discards the loaded row."""
    await _load_scoped_investigation(db, user, investigation_id)


async def _report_payload(db: AsyncSession, inv: InvestigationRow) -> dict[str, Any]:
    """The case, in the shape the report section generators consume (#554).

    The generators are plain functions over a dict — they were only ever fed
    a fixture, so the API had no way to report on a real case. This is that
    mapping, and it is deliberately a *projection of stored facts*: anything
    the case does not have comes back empty and shows up as a completeness
    gap, which is the honest answer and exactly what the gap list is for.

    Loaded with explicit queries rather than ORM relationship access: the
    session is async, so touching ``inv.iocs`` here would lazy-load outside a
    greenlet and raise.
    """
    iocs = (
        (await db.execute(select(IOCRow).where(IOCRow.investigation_id == inv.id))).scalars().all()
    )
    timeline = (
        (
            await db.execute(
                select(TimelineEntryRow)
                .where(TimelineEntryRow.investigation_id == inv.id)
                .order_by(TimelineEntryRow.timestamp)
            )
        )
        .scalars()
        .all()
    )
    actions = (
        (
            await db.execute(
                select(ContainmentActionRow).where(ContainmentActionRow.investigation_id == inv.id)
            )
        )
        .scalars()
        .all()
    )

    # Techniques are recorded per timeline entry; the report wants the case's
    # distinct set. Sorted so a regenerated report is byte-stable.
    techniques = sorted({e.technique_id for e in timeline if e.technique_id})

    return {
        "id": inv.id,
        "title": inv.title,
        "severity": inv.severity,
        "status": inv.status,
        "iocs": [{"type": i.type, "value": i.value} for i in iocs],
        "timeline": [
            {
                "timestamp": e.timestamp.isoformat() if e.timestamp else "",
                "description": e.description,
            }
            for e in timeline
        ],
        "mitre_techniques": techniques,
        "containment_actions": [
            {"action_type": a.action_type, "target": a.target} for a in actions
        ],
        # Per-IOC enrichment, keyed by indicator value the way the findings
        # section expects. Empty payloads are dropped rather than rendered as
        # a bare value with nothing behind it.
        "enrichment": {i.value: i.enrichment for i in iocs if i.enrichment},
    }


logger = logging.getLogger("btagent.api.reports")

router = APIRouter(prefix="/reports", tags=["reports"])

# Service singleton
_report_service = ReportService()


# --------------------------------------------------------------------------- #
# Request/response models
# --------------------------------------------------------------------------- #


class GenerateReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    investigation_id: str = Field(..., pattern=r"^[a-zA-Z0-9_-]+$")
    template: Literal[
        "incident_report",
        "ioc_report",
        "executive_briefing",
        "regulatory_notification",
        "cisa_incident",
        "external_advisory",
    ] = "incident_report"


class ListTemplatesResponse(BaseModel):
    templates: list[dict[str, Any]]
    count: int
    status: str


class SummarizeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    investigation_ids: list[str] = Field(..., min_length=1)
    format: Literal["cisa", "fbi_ic3", "isac", "generic"] = "generic"


class RemediationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    investigation_id: str = Field(..., pattern=r"^[a-zA-Z0-9_-]+$")
    audience: Literal["executive", "technical", "compliance"] = "technical"


class DetectionContentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    investigation_id: str = Field(..., pattern=r"^[a-zA-Z0-9_-]+$")
    platform: Literal["splunk", "elastic", "sentinel"] = "splunk"


class ReportDistributionOut(BaseModel):
    id: str
    report_id: str
    audience: str
    recipient: str
    sent_at: datetime
    tlp_applied: str
    approver_id: str | None = None


class ListDistributionsResponse(BaseModel):
    distributions: list[ReportDistributionOut]
    count: int
    status: str


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #


@router.post("/generate")
async def generate_report(
    body: GenerateReportRequest,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Generate a full report from investigation data using a template.

    Requires ``report:generate`` permission.
    """
    user.require_permission("report:generate")
    inv = await _load_scoped_investigation(db, user, body.investigation_id)

    result = await _report_service.generate_report(
        investigation_id=body.investigation_id,
        template=body.template,
        investigation=await _report_payload(db, inv),
    )

    if result.get("status") == "failed":
        raise HTTPException(
            status_code=400,
            detail=result.get("error", "Report generation failed"),
        )

    return result


@router.get("/{investigation_id}/export", response_model=None)
async def export_report(
    investigation_id: str,
    format: Literal["pdf"] = Query("pdf"),
    template: Literal[
        "incident_report",
        "ioc_report",
        "executive_briefing",
        "regulatory_notification",
        "cisa_incident",
        "external_advisory",
    ] = Query("incident_report"),
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Export an investigation's report as a downloadable file.

    Currently only ``format=pdf`` is supported. The PDF preserves the report's
    section structure and stamps the investigation's severity and TLP marking
    on every page.

    Respects TLP enforcement the same way other egress paths do: TLP:RED is
    refused with a 403 up front (mirroring ``GET /iocs/export``), and the
    renderer calls the shared ``assert_tlp_allows_egress`` gate as a
    defense-in-depth backstop.

    Requires ``report:export`` permission.
    """
    user.require_permission("report:export")

    inv = await _load_scoped_investigation(db, user, investigation_id)

    # TLP enforcement, mirroring api/v1/iocs.py:export_stix — refuse TLP:RED
    # egress at the API boundary so the caller gets a clean 403 rather than a
    # 500 from the backstop gate inside the renderer.
    if (inv.tlp_level or "").lower() == "red":
        raise HTTPException(
            status_code=403,
            detail="Cannot export a TLP:RED report. Downgrade the classification before export.",
        )

    # UC-7.2: an org policy may forbid report_export carrying this
    # classification even when the universal gate permits it. Org policies can
    # only ever *subtract* permission — see services/tlp_egress_guard.py.
    try:
        await assert_org_policy_allows_egress(
            db,
            org_id=inv.org_id or user.org_id,
            tlp=inv.tlp_level or "green",
            egress_kind=EgressKind.REPORT_EXPORT.value,
        )
    except TLPViolation as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    if format != "pdf":
        raise HTTPException(status_code=400, detail=f"Unsupported export format: {format}")

    try:
        pdf_bytes = await _report_service.export_report_pdf(
            investigation_id=investigation_id,
            template=template,
            tlp_level=inv.tlp_level or "green",
            severity=inv.severity or "medium",
            org_id=inv.org_id,
            investigation=await _report_payload(db, inv),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    filename = f"report_{investigation_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/templates")
async def list_templates(
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    """List available report templates.

    Requires ``report:view`` permission.
    """
    user.require_permission("report:view")
    return await _report_service.list_templates()


@router.get("/distributions")
async def list_report_distributions(
    report_id: str | None = Query(None, pattern=r"^[a-zA-Z0-9_-]+$"),
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> ListDistributionsResponse:
    """List report distributions for the caller's org (read-only audit surface).

    Returns the distribution ledger — who received which report, when, under
    which TLP marking, and who approved the release — newest first. Strictly
    org-scoped: a caller only ever sees their own tenant's rows. Pass
    ``report_id`` to narrow to a single report.

    Requires ``report:view`` permission.
    """
    user.require_permission("report:view")

    rows = await _report_service.list_distributions(db, org_id=user.org_id, report_id=report_id)

    distributions = [
        ReportDistributionOut(
            id=row.id,
            report_id=row.report_id,
            audience=row.audience,
            recipient=row.recipient,
            sent_at=row.sent_at,
            tlp_applied=row.tlp_applied,
            approver_id=row.approver_id,
        )
        for row in rows
    ]
    return ListDistributionsResponse(
        distributions=distributions,
        count=len(distributions),
        status="success",
    )


@router.post("/summarize")
async def summarize_investigations(
    body: SummarizeRequest,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Summarize investigation(s) for agency submission.

    Supports CISA, FBI IC3, ISAC, and generic formats.
    Requires ``report:summarize`` permission.
    """
    user.require_permission("report:summarize")

    if not body.investigation_ids:
        raise HTTPException(
            status_code=400,
            detail="At least one investigation ID is required",
        )

    # AUTH-B1: every investigation in the request must be in-scope.
    payloads = [
        await _report_payload(db, await _load_scoped_investigation(db, user, inv_id))
        for inv_id in body.investigation_ids
    ]

    result = await _report_service.summarize_investigations(
        investigation_ids=body.investigation_ids,
        format=body.format,
        investigations=payloads,
    )

    if result.get("status") == "failed":
        raise HTTPException(
            status_code=400,
            detail=result.get("error", "Summarization failed"),
        )

    return result


@router.post("/remediation")
async def generate_remediation(
    body: RemediationRequest,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Generate customer-facing remediation guidance.

    Audience options: executive, technical, compliance.
    Requires ``remediation:generate`` permission.
    """
    user.require_permission("remediation:generate")
    inv = await _load_scoped_investigation(db, user, body.investigation_id)

    result = await _report_service.generate_remediation(
        investigation_id=body.investigation_id,
        audience=body.audience,
        investigation=await _report_payload(db, inv),
    )

    if result.get("status") == "failed":
        raise HTTPException(
            status_code=400,
            detail=result.get("error", "Remediation generation failed"),
        )

    return result


@router.post("/detection-content")
async def generate_detection_content(
    body: DetectionContentRequest,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Generate SIEM detection rules from investigation findings.

    Platform options: splunk, elastic, sentinel.
    Requires ``remediation:generate`` permission.
    """
    user.require_permission("remediation:generate")
    inv = await _load_scoped_investigation(db, user, body.investigation_id)

    result = await _report_service.generate_detection_content(
        investigation_id=body.investigation_id,
        platform=body.platform,
        investigation=await _report_payload(db, inv),
    )

    if result.get("status") == "failed":
        raise HTTPException(
            status_code=400,
            detail=result.get("error", "Detection content generation failed"),
        )

    return result
