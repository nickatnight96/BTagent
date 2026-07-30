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

from btagent_shared.hunt.cti_to_detection import stix_bundle_from_report_text
from btagent_shared.security.tlp import TLPViolation
from btagent_shared.types.config import TLP
from btagent_shared.types.detection_proposal import (
    CTIToDetectionRequest,
    CTIToDetectionResponse,
    PersistedCounts,
    ProposalState,
    PROutcome,
)
from btagent_shared.types.enums import AuditCategory, AuditOutcome
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.services import cti_detection_service as svc
from btagent_backend.services import detection_edit_export_service as edit_export
from btagent_backend.services import stix_bundle_store
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
    not valid STIX 2.1 (HTTP 422).  Exactly one of ``stix_bundle``,
    ``stix_bundle_id`` or ``report_text`` must be supplied; ``stix_bundle_id``
    resolves a bundle previously stored by an inline-bundle propose call
    (HTTP 404 if unknown); ``report_text`` extracts IOCs/TTPs from
    unstructured CTI prose (defanged forms handled) into a synthetic bundle
    that runs the identical pipeline (#113) — 422 when no IOCs are found.

    RBAC: ``hunt:create`` (analyst+).
    """
    user.require_permission("hunt:create")

    # Validate that exactly one input variant is provided.
    provided = [
        v for v in (body.stix_bundle, body.stix_bundle_id, body.report_text) if v is not None
    ]
    if len(provided) != 1:
        raise HTTPException(
            status_code=422,
            detail="Exactly one of 'stix_bundle', 'stix_bundle_id' or 'report_text' "
            "must be supplied.",
        )

    # Resolve the bundle: inline dict, a previously-stored bundle by id, or a
    # synthetic bundle extracted from unstructured report text (#113).
    if body.report_text is not None:
        try:
            report_bundle = stix_bundle_from_report_text(
                body.report_text, report_name=body.report_name
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        body = body.model_copy(update={"stix_bundle": report_bundle, "report_text": None})

    if body.stix_bundle_id is not None:
        stored = await stix_bundle_store.get_bundle(
            db, org_id=user.org_id, bundle_id=body.stix_bundle_id
        )
        if stored is None:
            raise HTTPException(
                status_code=404,
                detail=f"No stored STIX bundle with id {body.stix_bundle_id!r}.",
            )
        bundle: dict[str, Any] = stored
    else:
        bundle = body.stix_bundle  # type: ignore[assignment]

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

    # Persist the raw bundle so a later request can re-run by stix_bundle_id.
    # Only for the inline path (a resolved-by-id bundle is already stored);
    # ad-hoc bundles with no id are skipped inside store_bundle.
    if body.stix_bundle is not None:
        await stix_bundle_store.store_bundle(
            db, org_id=user.org_id, bundle=bundle, tlp=body.active_tlp.value
        )
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
    # Analyst-edited "final" rule body (#113 Phase C). None until edited.
    final_sigma_yaml: str | None
    technique_ids: list[str]
    confidence: float
    rationale: str
    state: str
    # Persisted #113 DataSourceMatcher output (#501). ``None`` means the matcher
    # never ran for this row (it predates 0066_proposal_ds_gaps, or the rule's
    # logsource gave nothing to reconcile) — NOT "no gaps"; ``[]`` is "no gaps".
    data_sources_required: list[str] | None
    data_source_gaps: list[str] | None
    validation: dict | None
    validated_at: datetime | None
    pr_url: str | None
    # Detection-repo PR lifecycle: proposed / pr_opened / merged / rejected.
    pr_outcome: str
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


# --------------------------------------------------------------------------- #
# Draft → final edit-pair export (#113 drafter-quality signal)
#
# Declared BEFORE any ``/proposals/{row_id}`` route so the literal path segment
# is never swallowed by the path parameter (FastAPI matches in declaration
# order). Read-only: no row is written, no schema is added.
# --------------------------------------------------------------------------- #


class EditPairMetrics(BaseModel):
    """Edit distance between a drafted rule and the analyst's final body."""

    char_distance: int
    normalized_distance: float
    similarity: float
    draft_chars: int
    final_chars: int
    lines_added: int
    lines_removed: int
    lines_changed: int
    truncated: bool


class EditPairRecord(BaseModel):
    """One (draft → analyst-final) preference pair.

    ``chosen`` / ``rejected`` mirror the DPO framing: the analyst's edited rule
    is the chosen completion, the drafter's original is the rejected one.
    """

    proposal_row_id: str
    proposal_id: str
    org_id: str
    title: str
    technique_ids: list[str]
    source_stix_id: str
    bundle_id: str | None
    state: str
    pr_outcome: str
    edited: bool
    chosen: str
    rejected: str
    draft_sigma_yaml: str
    final_sigma_yaml: str
    metrics: EditPairMetrics
    review_rationale: str
    reviewed_by: str | None
    reviewed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class EditPairSummaryRecord(BaseModel):
    """Aggregate drafter-quality signal across the exported pairs."""

    total_pairs: int
    edited_pairs: int
    unedited_pairs: int
    edited_fraction: float
    mean_normalized_distance: float
    median_normalized_distance: float
    max_normalized_distance: float
    mean_char_distance: float
    techniques_covered: list[str]


class EditPairExportResponse(BaseModel):
    items: list[EditPairRecord]
    total: int
    summary: EditPairSummaryRecord


@router.get("/proposals/edit-pairs", response_model=EditPairExportResponse)
async def export_detection_edit_pairs(
    include_unedited: bool = Query(
        False,
        description="Also emit rules shipped unchanged (distance 0) as positive pairs.",
    ),
    only_shipped: bool = Query(
        False, description="Restrict to rules that reached a detection-repo PR."
    ),
    limit: int = Query(edit_export.DEFAULT_EXPORT_LIMIT, ge=1, le=edit_export.MAX_EXPORT_LIMIT),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> EditPairExportResponse:
    """Export ``(drafted rule → analyst-edited final rule)`` pairs with edit distance.

    The drafter-quality signal for #113: each pair is a DPO-style preference
    record (analyst body = ``chosen``, drafted body = ``rejected``) carrying a
    Levenshtein character distance, its length-normalised form, and line-level
    add/remove/change counts. The ``summary`` block aggregates them — mean /
    median normalised distance and the share of drafts an analyst had to edit.

    Read-only and strictly org-scoped: the query filters on the caller's org, so
    an export can never contain another tenant's detection content. RBAC
    ``hunt:view`` (analyst+), the same gate as reading the proposal store.
    """
    user.require_permission("hunt:view")
    pairs, summary = await edit_export.export_edit_pairs(
        db,
        org_id=user.org_id,
        include_unedited=include_unedited,
        only_shipped=only_shipped,
        limit=limit,
    )
    return EditPairExportResponse(
        items=[EditPairRecord.model_validate(p.to_dict()) for p in pairs],
        total=len(pairs),
        summary=EditPairSummaryRecord.model_validate(summary.to_dict()),
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
        org_id=user.org_id,
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


class ProposalEditRequest(BaseModel):
    """An analyst-edited Sigma rule body for a proposal (Engineer UI edit path)."""

    sigma_yaml: str = Field(min_length=1, max_length=64 * 1024)
    rationale: str = Field(default="", max_length=8192)


@router.post("/proposals/{row_id}/edit", response_model=DetectionProposalRecord)
async def edit_detection_proposal(
    row_id: str,
    body: ProposalEditRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> DetectionProposalRecord:
    """Edit a proposal's Sigma rule via the Engineer UI (#113 Phase C draft-edit).

    The edited body must parse as a Sigma rule (a YAML mapping with ``title`` and
    ``detection``) — a body that does not parse is rejected 422. On success the
    row flips to ``modified``, the edited body lands on ``final_sigma_yaml``, and
    the composer ships it (cited as *edited from draft*). Editing is refused 409
    for a rejected row or one already shipped in a PR. 404 masks unknown /
    cross-org rows.

    RBAC: ``hunt:triage`` — same review authority as accept / reject.
    """
    user.require_permission("hunt:triage")
    try:
        row = await svc.set_proposal_sigma(
            db,
            org_id=user.org_id,
            row_id=row_id,
            sigma_yaml=body.sigma_yaml,
            edited_by=user.id,
            review_rationale=body.rationale,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        # A parse failure is a bad edit payload (422); a state / shipped guard is
        # a lifecycle conflict (409).
        message = str(exc)
        status = 422 if "does not parse" in message else 409
        raise HTTPException(status_code=status, detail=message) from exc

    await AuditTrail(db).record(
        org_id=user.org_id,
        actor=user.id,
        category=AuditCategory.HUNT,
        action="detection_proposal_edited",
        resource=f"detection_proposal:{row.id}",
        outcome=AuditOutcome.SUCCESS,
        details={
            "org_id": user.org_id,
            "source_stix_id": row.source_stix_id,
            "title": row.title,
            "rationale": body.rationale,
        },
    )
    return DetectionProposalRecord.model_validate(row)


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


class ComposePRRequest(BaseModel):
    """Accepted proposal rows to ship in one detection-repo PR."""

    row_ids: list[str] = Field(min_length=1, max_length=50)
    title: str | None = Field(default=None, max_length=300)


class ComposePRResponse(BaseModel):
    pr_url: str
    branch: str
    commit: str
    rule_count: int
    row_ids: list[str]
    is_mock: bool


@router.post("/proposals/compose-pr", response_model=ComposePRResponse)
async def compose_detection_pr(
    body: ComposePRRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> ComposePRResponse:
    """Ship accepted proposals as one detection-repo pull request.

    The mandatory HITL from issue #113 is enforced twice: every row must be
    ``accepted`` (a one-shot analyst decision) and this route requires
    ``hunt:promote`` (senior_analyst+). Rows that already shipped are refused
    (409) — a rule ships once; the PR URL lands on each row as the back-link.
    501 when live git mode is enabled but not yet implemented.
    """
    user.require_permission("hunt:promote")
    try:
        result = await svc.compose_detection_pr(
            db, org_id=user.org_id, row_ids=body.row_ids, title=body.title
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except NotImplementedError as exc:
        raise HTTPException(status_code=501, detail=str(exc)) from exc

    await AuditTrail(db).record(
        org_id=user.org_id,
        actor=user.id,
        category=AuditCategory.HUNT,
        action="detection_pr_composed",
        resource=f"detection_pr:{result['pr_url']}",
        outcome=AuditOutcome.SUCCESS,
        details={
            "org_id": user.org_id,
            "row_ids": result["row_ids"],
            "rule_count": result["rule_count"],
            "branch": result["branch"],
        },
    )
    return ComposePRResponse(**result)


class PROutcomeRequest(BaseModel):
    """Record the detection-repo PR outcome for a composed proposal."""

    outcome: PROutcome = Field(
        description="Recordable PR outcome: 'merged' or 'rejected'.",
    )


class PROutcomeResponse(BaseModel):
    """The updated proposal plus a summary of the merge closed loop (if any)."""

    proposal: DetectionProposalRecord
    closed_loop: dict


@router.post("/proposals/{row_id}/pr-outcome", response_model=PROutcomeResponse)
async def record_proposal_pr_outcome(
    row_id: str,
    body: PROutcomeRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> PROutcomeResponse:
    """Record a composed proposal's detection-repo PR outcome (#113 Phase C).

    ``merged`` / ``rejected`` are recordable, and only once a PR is open — a
    409 otherwise (not shipped, or already terminal). On ``merged`` the closed
    loop fires: the rule is auto-installed as a #112 hunt-pack entry AND a #118
    SANDBOX-gated detection-validation run is triggered for every technique the
    rule claims (one persisted run, sandbox gate + audit enforced per technique
    by ``detection_emulation_service``) — both best-effort, so a hook failure
    never sinks the merge write. 404 masks unknown / cross-org rows.

    RBAC: ``hunt:promote`` (senior_analyst+) — recording a merge arms a live
    recurring detection, the same authority as composing the PR.
    """
    user.require_permission("hunt:promote")
    try:
        row, closed_loop = await svc.record_pr_outcome(
            db,
            org_id=user.org_id,
            row_id=row_id,
            outcome=body.outcome,
            actor_id=user.id,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    await AuditTrail(db).record(
        org_id=user.org_id,
        actor=user.id,
        category=AuditCategory.HUNT,
        action=f"detection_pr_{body.outcome.value}",
        resource=f"detection_proposal:{row.id}",
        outcome=AuditOutcome.SUCCESS,
        details={
            "org_id": user.org_id,
            "title": row.title,
            "technique_ids": list(row.technique_ids or []),
            "closed_loop": closed_loop,
        },
    )
    return PROutcomeResponse(
        proposal=DetectionProposalRecord.model_validate(row), closed_loop=closed_loop
    )
