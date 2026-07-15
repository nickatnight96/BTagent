"""CTI → Detection proposal API (issue #113 slice).

POST /api/v1/cti/propose-detections
    Accept a STIX 2.1 bundle, return Sigma rule proposals.

RBAC: ``hunt:create`` (analyst+).  Proposing detections is a read/generate
action equivalent to creating a new hunt — no execution side-effects.

TLP enforcement:
    TLP:RED bundles are refused with HTTP 403.  The gate is applied in the
    shared :func:`process_stix_bundle` and surfaced here as a 403 response
    so callers get a consistent error.  This matches the existing ioc export
    endpoint (``api/v1/iocs.py:export_stix``) which also 403s on TLP:RED.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from btagent_shared.security.tlp import TLPViolation
from btagent_shared.types.config import TLP
from btagent_shared.types.detection_proposal import (
    CTIToDetectionRequest,
    CTIToDetectionResponse,
    PersistedCounts,
    ProposalState,
)
from btagent_shared.types.enums import AuditCategory, AuditOutcome
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.services import cti_detection_service as svc
from btagent_backend.services.audit_trail import AuditTrail
from btagent_backend.services.cti_detection_service import CTIDetectionService

logger = logging.getLogger("btagent.api.cti_detection")

router = APIRouter(prefix="/cti", tags=["cti-detection"])

_service = CTIDetectionService()


@router.post(
    "/propose-detections",
    response_model=CTIToDetectionResponse,
    summary="Generate Sigma rule proposals from a STIX 2.1 bundle",
    response_description="List of Sigma rule proposals pending analyst review.",
)
async def propose_detections(
    body: CTIToDetectionRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> CTIToDetectionResponse:
    """Convert a STIX 2.1 bundle into Sigma rule proposals.

    Proposals are returned to the caller **and persisted** to the
    org-scoped proposal store (#113 back half, slice 1). Re-submitting a
    bundle upserts still-``proposed`` rows; proposals an analyst has already
    decided keep their decision. Review happens via
    ``GET /cti/proposals`` + ``POST /cti/proposals/{id}/accept|reject``.

    The endpoint refuses TLP:RED bundles (HTTP 403) and bundles that are
    not valid STIX 2.1 (HTTP 422).  Exactly one of ``stix_bundle`` or
    ``stix_bundle_id`` must be supplied; passing ``stix_bundle_id`` without
    a persisted bundle resolution path returns HTTP 501.

    RBAC: ``hunt:create`` (analyst+).
    """
    user.require_permission("hunt:create")

    # Validate that exactly one input variant is provided
    if body.stix_bundle is None and body.stix_bundle_id is None:
        raise HTTPException(
            status_code=422,
            detail="Exactly one of 'stix_bundle' or 'stix_bundle_id' must be supplied.",
        )

    if body.stix_bundle is not None and body.stix_bundle_id is not None:
        raise HTTPException(
            status_code=422,
            detail="Supply exactly one of 'stix_bundle' or 'stix_bundle_id', not both.",
        )

    # Inline TLP gate for bundle_id (deferred path)
    if body.stix_bundle_id is not None:
        raise HTTPException(
            status_code=501,
            detail=(
                "Bundle-by-id resolution is not yet implemented. "
                "Pass the raw bundle dict in 'stix_bundle' instead."
            ),
        )

    bundle: dict[str, Any] = body.stix_bundle  # type: ignore[assignment]

    try:
        response = _service.propose_from_bundle(bundle=bundle, active_tlp=body.active_tlp)
    except TLPViolation as exc:
        logger.warning(
            "CTI detect proposal refused: TLP violation from user %s — %s",
            user.id,
            exc,
        )
        raise HTTPException(
            status_code=403,
            detail=f"TLP:RED bundles are not permitted for detection proposal. {exc}",
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    # #113 back half slice 1: proposals now land in the org-scoped store so
    # the review lifecycle (accept / reject) survives the request. Re-imports
    # upsert; analyst decisions are never clobbered.
    created, updated, unchanged = await svc.persist_proposals(
        db,
        org_id=user.org_id,
        proposals=response.proposals,
        bundle_id=bundle.get("id"),
    )
    response.persisted = PersistedCounts(created=created, updated=updated, unchanged=unchanged)
    return response


# --------------------------------------------------------------------------- #
# Proposal store — list + review lifecycle (#113 back half, slice 1)
# --------------------------------------------------------------------------- #


class DetectionProposalRecord(BaseModel):
    """API shape of a persisted proposal row."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    org_id: str
    proposal_id: str
    source_stix_id: str
    bundle_id: str | None
    title: str
    sigma_yaml: str
    technique_ids: list[str]
    confidence: float
    rationale: str
    state: str
    validation: dict | None
    validated_at: datetime | None
    review_rationale: str
    reviewed_by: str | None
    reviewed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class DetectionProposalListResponse(BaseModel):
    items: list[DetectionProposalRecord]
    total: int


class ProposalReviewRequest(BaseModel):
    """Optional rationale for an accept / reject decision."""

    rationale: str = Field(default="", max_length=8192)


@router.get("/proposals", response_model=DetectionProposalListResponse)
async def list_detection_proposals(
    state: str | None = Query(
        None, pattern="^(proposed|accepted|rejected|modified)$", description="State filter."
    ),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> DetectionProposalListResponse:
    """Org-scoped, paginated proposal store listing (newest-updated first)."""
    user.require_permission("hunt:view")
    rows, total = await svc.list_proposals(
        db, org_id=user.org_id, state=state, page=page, page_size=page_size
    )
    return DetectionProposalListResponse(
        items=[DetectionProposalRecord.model_validate(r) for r in rows], total=total
    )


async def _review(
    db: AsyncSession,
    *,
    user: CurrentUser,
    row_id: str,
    state: ProposalState,
    rationale: str,
) -> DetectionProposalRecord:
    """Shared accept/reject shell: RBAC, state guard, audit, response shape."""
    user.require_permission("hunt:triage")
    try:
        row = await svc.set_proposal_state(
            db,
            org_id=user.org_id,
            row_id=row_id,
            state=state,
            review_rationale=rationale,
            reviewed_by=user.id,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    await AuditTrail(db).record(
        actor=user.id,
        category=AuditCategory.HUNT,
        action=f"detection_proposal_{state.value}",
        resource=f"detection_proposal:{row.id}",
        outcome=AuditOutcome.SUCCESS,
        details={
            "org_id": user.org_id,
            "source_stix_id": row.source_stix_id,
            "title": row.title,
            "rationale": rationale,
        },
    )
    return DetectionProposalRecord.model_validate(row)


@router.post("/proposals/{row_id}/accept", response_model=DetectionProposalRecord)
async def accept_detection_proposal(
    row_id: str,
    body: ProposalReviewRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> DetectionProposalRecord:
    """Accept a proposal — marks the rule as approved for the detection repo.

    409 once decided (accept / reject are one-shot); the PR-composer slice
    consumes ``accepted`` rows.
    """
    return await _review(
        db, user=user, row_id=row_id, state=ProposalState.ACCEPTED, rationale=body.rationale
    )


@router.post("/proposals/{row_id}/reject", response_model=DetectionProposalRecord)
async def reject_detection_proposal(
    row_id: str,
    body: ProposalReviewRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> DetectionProposalRecord:
    """Reject a proposal with a rationale — same decision authority as accept."""
    return await _review(
        db, user=user, row_id=row_id, state=ProposalState.REJECTED, rationale=body.rationale
    )


class ProposalValidateRequest(BaseModel):
    """Optional overrides for the historical-telemetry validation run."""

    backends: list[str] | None = Field(
        default=None,
        description="Backend names to validate against; omit for all supported.",
    )
    lookback_hours: int = Field(default=24 * 30, ge=1, le=24 * 365)


def _mock_connectors_mode() -> bool:
    """Same flag the engine integration nodes read (default: mock on)."""
    import os

    return os.getenv("BTAGENT_MOCK_CONNECTORS", "true").strip().lower() == "true"


@router.post("/proposals/{row_id}/validate", response_model=DetectionProposalRecord)
async def validate_detection_proposal(
    row_id: str,
    body: ProposalValidateRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> DetectionProposalRecord:
    """Validate the proposal's Sigma rule against historical telemetry.

    Transpiles per backend and executes over the lookback window through the
    engine integration nodes; the per-backend hit counts + verdict
    (``matched`` / ``clean`` / ``error``) land on the row's ``validation``
    field. Inline under mock connectors; enqueued to the arq worker on the
    live path (503 when the queue is unreachable — validation state is then
    unchanged). Does not alter the review state.
    """
    user.require_permission("hunt:run")

    if _mock_connectors_mode():
        try:
            row = await svc.validate_proposal(
                db,
                org_id=user.org_id,
                row_id=row_id,
                backends=body.backends,
                lookback_hours=body.lookback_hours,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return DetectionProposalRecord.model_validate(row)

    # Live path: confirm the row exists (404 masking), then queue the run.
    row = await svc.get_proposal(db, org_id=user.org_id, row_id=row_id)
    if row is None:
        raise HTTPException(status_code=404, detail=f"Detection proposal not found: {row_id}")
    try:
        from arq import create_pool

        from btagent_backend.scheduler.worker import redis_settings

        pool = await create_pool(redis_settings())
        try:
            await pool.enqueue_job(
                "validate_detection_proposal",
                row_id,
                user.org_id,
                body.backends,
                body.lookback_hours,
            )
        finally:
            await pool.aclose()
    except Exception as exc:  # noqa: BLE001 — infra failure surfaces as 503
        logger.exception("Failed to enqueue proposal validation for %s", row_id)
        raise HTTPException(
            status_code=503,
            detail=f"Could not queue proposal validation: {type(exc).__name__}",
        ) from exc
    # The queued run updates ``validation`` asynchronously; return the row
    # as-is so the caller can poll GET /cti/proposals for the outcome.
    return DetectionProposalRecord.model_validate(row)
