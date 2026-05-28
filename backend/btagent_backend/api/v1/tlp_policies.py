"""TLP egress policy CRUD API (EPIC-7 UC-7.2).

Org-scoped, CISO-approved exceptions to the default-deny TLP egress gate.

  * GET    /tlp-policies          — list this org's policies (policy:view)
  * POST   /tlp-policies          — create a policy (policy:manage / CISO)
  * DELETE /tlp-policies/{id}     — revoke a policy (policy:manage / CISO)
  * POST   /tlp-policies/evaluate — dry-run a (tlp, egress_kind) decision

Reads are senior-analyst+ so analysts can see what exceptions exist;
writes are admin-only because a policy widens what may leave the enclave
and therefore requires CISO sign-off.
"""

from __future__ import annotations

import logging
from datetime import datetime

from btagent_shared.security.tlp import EgressKind
from btagent_shared.security.tlp_policy import TLPPolicy, TLPPolicyAction
from btagent_shared.types.config import TLP
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, model_validator
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.services.tlp_policy_service import TLPPolicyService

logger = logging.getLogger("btagent.api.tlp_policies")

router = APIRouter(prefix="/tlp-policies", tags=["tlp-policies"])

_VALID_EGRESS_KINDS = set(EgressKind.__args__)  # type: ignore[attr-defined]


class CreateTLPPolicyRequest(BaseModel):
    action: TLPPolicyAction
    egress_kinds: list[str] = Field(default_factory=list)
    applies_to_tlp: list[TLP] = Field(default_factory=list)
    downgrade_to: TLP | None = None
    rationale: str = ""
    valid_until: datetime | None = None

    @model_validator(mode="after")
    def _check(self) -> CreateTLPPolicyRequest:
        bad = [k for k in self.egress_kinds if k not in _VALID_EGRESS_KINDS]
        if bad:
            raise ValueError(
                f"Unknown egress_kind(s) {bad}; expected subset of {sorted(_VALID_EGRESS_KINDS)}"
            )
        if self.action == TLPPolicyAction.DOWNGRADE_THEN_ALLOW and self.downgrade_to is None:
            raise ValueError("downgrade_then_allow policies require a downgrade_to target")
        return self


class EvaluateRequest(BaseModel):
    tlp: TLP
    egress_kind: str


class PolicyDecisionResponse(BaseModel):
    allowed: bool
    effective_tlp: TLP
    action: TLPPolicyAction
    matched_policy_id: str | None
    reason: str


@router.get("", response_model=list[TLPPolicy])
async def list_policies(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> list[TLPPolicy]:
    """List the calling org's TLP egress policies (newest first)."""
    user.require_permission("policy:view")
    return await TLPPolicyService(db).list_policies(user.org_id)


@router.post("", response_model=TLPPolicy, status_code=status.HTTP_201_CREATED)
async def create_policy(
    body: CreateTLPPolicyRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> TLPPolicy:
    """Create a CISO-approved egress policy (admin only)."""
    user.require_permission("policy:manage")
    policy = await TLPPolicyService(db).create_policy(
        org_id=user.org_id,
        action=body.action,
        egress_kinds=body.egress_kinds,
        applies_to_tlp=body.applies_to_tlp,
        downgrade_to=body.downgrade_to,
        approver_id=user.username,
        rationale=body.rationale,
        valid_until=body.valid_until,
        created_by=user.id,
    )
    await db.commit()
    logger.info("TLP policy %s created by %s (org=%s)", policy.id, user.username, user.org_id)
    return policy


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_policy(
    policy_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> None:
    """Revoke a policy (admin only). 404 if it isn't this org's."""
    user.require_permission("policy:manage")
    deleted = await TLPPolicyService(db).delete_policy(user.org_id, policy_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found")
    await db.commit()


@router.post("/evaluate", response_model=PolicyDecisionResponse)
async def evaluate_policy(
    body: EvaluateRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> PolicyDecisionResponse:
    """Dry-run an egress decision for this org against its policies."""
    user.require_permission("policy:view")
    decision = await TLPPolicyService(db).evaluate(
        org_id=user.org_id, tlp=body.tlp, egress_kind=body.egress_kind
    )
    return PolicyDecisionResponse(
        allowed=decision.allowed,
        effective_tlp=decision.effective_tlp,
        action=decision.action,
        matched_policy_id=decision.matched_policy_id,
        reason=decision.reason,
    )
