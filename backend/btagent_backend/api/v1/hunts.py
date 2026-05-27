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

from btagent_shared.types.enums import IOCType
from btagent_shared.types.hunt import Backend
from btagent_shared.types.hunt_package import HuntPackage
from btagent_shared.types.correlation import CorrelationTimeline
from btagent_shared.utils.ids import generate_id
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from btagent_backend.api.deps import CurrentUser, get_current_user

from btagent_engine import NodeContext
from btagent_engine.reasoning import HuntPackageInput, HuntPackageNode
from btagent_engine.reasoning.correlation_workbench import (
    CorrelationWorkbenchInput,
    CorrelationWorkbenchNode,
)

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
    user: CurrentUser = Depends(get_current_user),
) -> HuntPackage:
    """Generate a hunt package from advisory text (UC-2.2)."""
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

    logger.info(
        "hunt_package generated",
        extra={
            "investigation_id": None,
            "extracted_iocs": out.package.extracted_ioc_count,
            "techniques": len(out.package.derived_techniques),
        },
    )
    return out.package


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
