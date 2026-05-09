"""Reports API — report generation, summarization, and remediation endpoints."""

from __future__ import annotations

import logging
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.auth.scoping import assert_can_access_investigation
from btagent_backend.db.models import InvestigationRow
from btagent_backend.services.report_service import ReportService


async def _scope_or_404(db: AsyncSession, user: CurrentUser, investigation_id: str) -> None:
    """Look up an investigation and 404 if the caller cannot access it.

    AUTH-B1: report endpoints take ``investigation_id`` from the request body,
    so each one needs an explicit scope check before delegating to the report
    plugin (which doesn't know about tenants).
    """
    result = await db.execute(
        select(InvestigationRow).where(InvestigationRow.id == investigation_id)
    )
    inv = result.scalar_one_or_none()
    if inv is None:
        raise HTTPException(status_code=404, detail="Not found")
    assert_can_access_investigation(user, inv)


logger = logging.getLogger("btagent.api.reports")

router = APIRouter(prefix="/reports", tags=["reports"])

# Service singleton
_report_service = ReportService()


# --------------------------------------------------------------------------- #
# Request/response models
# --------------------------------------------------------------------------- #


class GenerateReportRequest(BaseModel):
    investigation_id: str = Field(..., pattern=r"^[a-zA-Z0-9_-]+$")
    template: Literal[
        "incident_report", "ioc_report", "executive_briefing", "regulatory_notification"
    ] = "incident_report"


class ListTemplatesResponse(BaseModel):
    templates: list[dict[str, Any]]
    count: int
    status: str


class SummarizeRequest(BaseModel):
    investigation_ids: list[str] = Field(..., min_length=1)
    format: Literal["cisa", "fbi_ic3", "isac", "generic"] = "generic"


class RemediationRequest(BaseModel):
    investigation_id: str = Field(..., pattern=r"^[a-zA-Z0-9_-]+$")
    audience: Literal["executive", "technical", "compliance"] = "technical"


class DetectionContentRequest(BaseModel):
    investigation_id: str = Field(..., pattern=r"^[a-zA-Z0-9_-]+$")
    platform: Literal["splunk", "elastic", "sentinel"] = "splunk"


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
    await _scope_or_404(db, user, body.investigation_id)

    result = await _report_service.generate_report(
        investigation_id=body.investigation_id,
        template=body.template,
    )

    if result.get("status") == "failed":
        raise HTTPException(
            status_code=400,
            detail=result.get("error", "Report generation failed"),
        )

    return result


@router.get("/templates")
async def list_templates(
    user: CurrentUser = Depends(get_current_user),
) -> dict[str, Any]:
    """List available report templates.

    Requires ``report:view`` permission.
    """
    user.require_permission("report:view")
    return await _report_service.list_templates()


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
    for inv_id in body.investigation_ids:
        await _scope_or_404(db, user, inv_id)

    result = await _report_service.summarize_investigations(
        investigation_ids=body.investigation_ids,
        format=body.format,
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
    await _scope_or_404(db, user, body.investigation_id)

    result = await _report_service.generate_remediation(
        investigation_id=body.investigation_id,
        audience=body.audience,
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
    await _scope_or_404(db, user, body.investigation_id)

    result = await _report_service.generate_detection_content(
        investigation_id=body.investigation_id,
        platform=body.platform,
    )

    if result.get("status") == "failed":
        raise HTTPException(
            status_code=400,
            detail=result.get("error", "Detection content generation failed"),
        )

    return result
