"""Cloud IAM containment proposals API (#117 Phase C bullet 2 — IAM → IR).

Promotion of a cloud IAM/STS hunt finding seeds the Investigation with **inert**
containment proposals (revoke role / freeze access key / detach policy) — see
``hunt_triage_service.promote_to_investigation`` and
``btagent_shared.hunt.cloud.build_cloud_containment_proposal``. This module is
the decision surface over that data, mirroring the identity-hunt
``RevocationProposal`` routes (#116) one layer up.

**This module executes nothing itself.** Acceptance delegates every action to
the EXISTING #106 containment execute path
(:mod:`btagent_backend.services.containment_execute_service`), so it inherits —
unweakened and un-duplicated — all five of that path's guarantees:

1. ``containment:execute`` RBAC (incident-commander+) is required *here* on the
   accept route, exactly as on ``/containment/execute/*``.
2. The approved-flag second gate: the request must carry ``approved=true`` and
   the execute service independently refuses anything not marked approved. A
   fully-denied accept does NOT consume the proposal (it stays ``proposed``), so
   an un-approved attempt can never launder itself into a decided state.
3. Mock-by-default dispatch — ``_dispatch`` honours ``BTAGENT_MOCK_CONNECTORS``
   and raises ``NotImplementedError`` in live mode. Live cloud control-plane
   connectors are deferred (#100); nothing here unbolts them.
4. Org-safelist screened before dispatch: a safelisted principal (break-glass
   role, CI/CD identity, account root) is refused with an audited denial.
5. An audit row on every execute AND every denial, stamping the acting user as
   approver — written by the execute service, on its hash chain.

There is deliberately **no second dispatch path**: this module's only outbound
call is ``containment_execute_service.execute_response_action``.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from btagent_shared.types.cloud_hunt import (
    CloudContainmentAction,
    CloudContainmentActionStatus,
    CloudContainmentProposal,
    CloudContainmentProposalStatus,
)
from btagent_shared.types.enums import AuditCategory, AuditOutcome
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.auth.scoping import assert_can_access_investigation
from btagent_backend.db.models import InvestigationRow
from btagent_backend.services import containment_execute_service
from btagent_backend.services.audit_trail import AuditTrail

logger = logging.getLogger("btagent.api.cloud_containment")

router = APIRouter(prefix="/cloud", tags=["cloud"])

_PROPOSAL_KEY = "cloud_containment_proposal"


class ContainmentDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    """Accept/reject body.

    ``approved`` is the explicit HITL half of the double gate — the same flag the
    ``/containment/execute/*`` routes carry. It defaults to ``False`` so a body
    that merely omits it can never execute anything.
    """

    approved: bool = Field(
        default=False,
        description="Must be true to execute — the HITL half of the containment double-gate.",
    )
    rationale: str = Field(default="", max_length=8192)
    action_ids: list[str] = Field(
        default_factory=list,
        description="Subset of proposal action ids to act on; empty = all of them.",
    )


async def _load_investigation_proposal(
    db: AsyncSession,
    *,
    investigation_id: str,
    user: CurrentUser,
) -> tuple[InvestigationRow, CloudContainmentProposal]:
    """Fetch the org-scoped investigation and its containment proposal (404 on either miss)."""
    result = await db.execute(
        select(InvestigationRow).where(InvestigationRow.id == investigation_id)
    )
    inv = result.scalar_one_or_none()
    # 404 on miss OR cross-org — same no-leak posture as the identity routes.
    if inv is None or inv.org_id != user.org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Investigation not found")
    assert_can_access_investigation(user, inv)

    raw = (inv.config or {}).get(_PROPOSAL_KEY)
    if not isinstance(raw, dict):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Investigation has no cloud containment proposal",
        )
    try:
        proposal = CloudContainmentProposal.model_validate(raw)
    except ValidationError:
        logger.exception("Malformed cloud containment proposal on investigation %s", inv.id)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Stored cloud containment proposal is malformed",
        ) from None
    return inv, proposal


def _store_proposal(inv: InvestigationRow, proposal: CloudContainmentProposal) -> None:
    """Write the proposal back into the investigation config.

    Reassigns ``config`` wholesale so SQLAlchemy's JSON change detection (which
    doesn't track nested mutation) sees the update.
    """
    inv.config = {**(inv.config or {}), _PROPOSAL_KEY: proposal.model_dump(mode="json")}
    inv.updated_at = datetime.now(UTC)


def _select_actions(
    proposal: CloudContainmentProposal, action_ids: list[str]
) -> list[CloudContainmentAction]:
    """Resolve the requested action subset (empty request = every action)."""
    if not action_ids:
        return list(proposal.actions)
    wanted = set(action_ids)
    selected = [a for a in proposal.actions if a.id in wanted]
    missing = wanted - {a.id for a in selected}
    if missing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown containment action id(s): {sorted(missing)}",
        )
    return selected


@router.get(
    "/investigations/{investigation_id}/containment-proposal",
    response_model=CloudContainmentProposal,
)
async def get_cloud_containment_proposal(
    investigation_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> CloudContainmentProposal:
    """Read the inert containment proposal attached to an investigation."""
    user.require_permission("hunt:view")
    _, proposal = await _load_investigation_proposal(
        db, investigation_id=investigation_id, user=user
    )
    return proposal


@router.post("/investigations/{investigation_id}/containment-proposal/accept")
async def accept_cloud_containment_proposal(
    investigation_id: str,
    body: ContainmentDecisionRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Accept the proposal — routes every selected action through the #106 path.

    Gate 1 (RBAC): ``containment:execute``, the same incident-commander+ scope
    the direct containment routes require — accepting is executing.

    Gate 2 (HITL): ``approved`` is passed through to
    ``containment_execute_service.execute_response_action``, which refuses
    anything not explicitly approved and audits the refusal.

    Gates 3-5 (mock-first dispatch, org safelist screen, audit on execute AND
    denial) live entirely inside that service; this route adds none of its own
    and bypasses none of them.

    Outcome semantics: if at least one action executed, the proposal is
    ``accepted`` (subsequent accepts 409, so nothing double-executes). If every
    selected action was denied, the proposal stays ``proposed`` — a refused
    attempt must not consume the analyst's decision — and the route returns 403
    with the per-action denials and their audit ids.
    """
    user.require_permission("containment:execute")
    inv, proposal = await _load_investigation_proposal(
        db, investigation_id=investigation_id, user=user
    )
    if proposal.status is not CloudContainmentProposalStatus.PROPOSED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cloud containment proposal already {proposal.status.value}",
        )
    selected = _select_actions(proposal, body.action_ids)

    executed_any = False
    for action in selected:
        # The ONE outbound call in this module: the existing #106 execute path.
        result = await containment_execute_service.execute_response_action(
            db,
            actor_id=user.id,
            org_id=user.org_id,
            action_id=f"{inv.id}:{action.id}",
            action_type=action.action_type.value,
            connector=action.connector,
            target=action.target,
            description=action.description,
            approved=body.approved,
        )
        action.audit_id = result.get("audit_id")
        action.outcome = str(result.get("outcome", ""))
        action.message = str(result.get("message", ""))[:2048]
        if result.get("executed") is True:
            action.status = CloudContainmentActionStatus.EXECUTED
            executed_any = True
        else:
            action.status = CloudContainmentActionStatus.DENIED

    if executed_any:
        proposal.status = CloudContainmentProposalStatus.ACCEPTED
        proposal.decided_by = user.id
        proposal.decided_at = datetime.now(UTC)
        proposal.decision_rationale = body.rationale
    _store_proposal(inv, proposal)

    # A summary row on the *decision* itself, alongside the per-action rows the
    # execute service already wrote. Category CONTAINMENT so the whole loop
    # reads back off one ledger slice.
    await AuditTrail(db).record(
        org_id=user.org_id,
        actor=user.id,
        category=AuditCategory.CONTAINMENT,
        action="cloud_containment_accept",
        resource=f"investigation:{inv.id}",
        outcome=AuditOutcome.SUCCESS if executed_any else AuditOutcome.DENIED,
        details={
            "org_id": user.org_id,
            "approved": body.approved,
            "action_count": len(selected),
            "executed_count": sum(
                1 for a in selected if a.status is CloudContainmentActionStatus.EXECUTED
            ),
            "denied_count": sum(
                1 for a in selected if a.status is CloudContainmentActionStatus.DENIED
            ),
            "rationale": body.rationale,
        },
    )

    payload = proposal.model_dump(mode="json")
    if executed_any:
        return payload
    # Nothing ran: return (never raise) so the denial audit rows commit, and
    # surface 403 like the direct containment routes do.
    return JSONResponse(status_code=status.HTTP_403_FORBIDDEN, content=payload)


@router.post(
    "/investigations/{investigation_id}/containment-proposal/reject",
    response_model=CloudContainmentProposal,
)
async def reject_cloud_containment_proposal(
    investigation_id: str,
    body: ContainmentDecisionRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> CloudContainmentProposal:
    """Reject the proposal — same decision authority as accept, executes nothing."""
    user.require_permission("containment:execute")
    inv, proposal = await _load_investigation_proposal(
        db, investigation_id=investigation_id, user=user
    )
    if proposal.status is not CloudContainmentProposalStatus.PROPOSED:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Cloud containment proposal already {proposal.status.value}",
        )

    proposal.status = CloudContainmentProposalStatus.REJECTED
    proposal.decided_by = user.id
    proposal.decided_at = datetime.now(UTC)
    proposal.decision_rationale = body.rationale
    _store_proposal(inv, proposal)

    await AuditTrail(db).record(
        org_id=user.org_id,
        actor=user.id,
        category=AuditCategory.CONTAINMENT,
        action="cloud_containment_reject",
        resource=f"investigation:{inv.id}",
        outcome=AuditOutcome.SUCCESS,
        details={
            "org_id": user.org_id,
            "action_count": len(proposal.actions),
            "rationale": body.rationale,
        },
    )
    return proposal
