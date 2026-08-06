"""TLP egress policy CRUD API (EPIC-7 UC-7.2).

Org-scoped, CISO-approved exceptions to the default-deny TLP egress gate.

  * GET    /tlp-policies              — list this org's policies (policy:view)
  * GET    /tlp-policies/egress-kinds — the governable channels + whether each
    is enforced at runtime (policy:view)
  * POST   /tlp-policies              — create a policy (policy:manage / CISO)
  * DELETE /tlp-policies/{id}         — revoke a policy (policy:manage / CISO)
  * POST   /tlp-policies/evaluate     — dry-run a (tlp, egress_kind) decision

Reads are senior-analyst+ so analysts can see what exceptions exist;
writes are admin-only because a policy widens what may leave the enclave
and therefore requires CISO sign-off.

**The dry-run answers for channels the runtime does not consult.** Two of the
five :class:`~btagent_shared.security.tlp_policy.EgressKind` members —
``mcp_return`` and ``event_emit`` — have no ``assert_org_policy_allows_egress``
call site (see :data:`POLICY_ENFORCED_EGRESS_KINDS` for why). A policy naming
them evaluates exactly like an enforced one and governs nothing, so every
response that carries a decision or accepts a channel says which it is:
``/egress-kinds`` labels the vocabulary, ``/evaluate`` returns
``policy_enforced``, and creating a policy records the advisory channels on the
audit ledger. Silently answering "BLOCKED" for an ungoverned channel is how a
CISO comes to believe a control exists.
"""

from __future__ import annotations

import logging
from datetime import datetime

from btagent_shared.security.tlp_policy import (
    EgressKind,
    TLPPolicy,
    TLPPolicyAction,
    advisory_egress_kinds,
    is_policy_enforced,
)
from btagent_shared.types.config import TLP
from btagent_shared.types.enums import AuditCategory, AuditOutcome
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.services.audit_trail import AuditTrail
from btagent_backend.services.tlp_policy_service import TLPPolicyService

logger = logging.getLogger("btagent.api.tlp_policies")

router = APIRouter(prefix="/tlp-policies", tags=["tlp-policies"])

_VALID_EGRESS_KINDS = {k.value for k in EgressKind}


class CreateTLPPolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
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
    model_config = ConfigDict(extra="forbid")
    tlp: TLP
    egress_kind: str

    @model_validator(mode="after")
    def _check_kind(self) -> EvaluateRequest:
        if self.egress_kind not in _VALID_EGRESS_KINDS:
            raise ValueError(
                f"Unknown egress_kind {self.egress_kind!r}; expected one of "
                f"{sorted(_VALID_EGRESS_KINDS)}"
            )
        return self


class PolicyDecisionResponse(BaseModel):
    allowed: bool
    effective_tlp: TLP
    action: TLPPolicyAction
    matched_policy_id: str | None
    reason: str
    policy_enforced: bool = Field(
        description=(
            "Whether this decision is applied when the egress actually happens. "
            "False means the channel has no org-policy gate: the decision below "
            "is what the policy says, not what the system does."
        )
    )


class EgressKindInfo(BaseModel):
    """One governable channel, and whether a policy on it does anything."""

    kind: EgressKind
    policy_enforced: bool


@router.get("/egress-kinds", response_model=list[EgressKindInfo])
async def list_egress_kinds(
    user: CurrentUser = Depends(get_current_user),
) -> list[EgressKindInfo]:
    """The channels a policy may name, each labelled enforced or advisory.

    Served rather than duplicated in the SPA on purpose. A hand-written copy
    of this vocabulary in ``api/tlpPolicies.ts`` is what hid ``report_export``
    from the picker until #597, and the enforced/advisory split is a property
    of where the backend's call sites are — the frontend cannot know it and
    would only be guessing.
    """
    user.require_permission("policy:view")
    return [EgressKindInfo(kind=k, policy_enforced=is_policy_enforced(k)) for k in EgressKind]


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
    # A policy is an exception to default-deny egress, so its creation is
    # itself a governance event: EPIC-7 requires the approval to be
    # defensible on the 7-year ledger, not just in an app log. ``resource``
    # is the policy id so an auditor can pull one policy's whole life via
    # /audit/entries?incident_id=<policy id>.
    await AuditTrail(db).record(
        actor=user.id,
        category=AuditCategory.CONFIG_CHANGE,
        action="tlp_policy_created",
        resource=policy.id,
        outcome=AuditOutcome.SUCCESS,
        details={
            "org_id": user.org_id,
            "policy_action": policy.action.value,
            "egress_kinds": list(policy.egress_kinds),
            "applies_to_tlp": [t.value for t in policy.applies_to_tlp],
            "downgrade_to": policy.downgrade_to.value if policy.downgrade_to else None,
            "approver_id": policy.approver_id,
            "rationale": policy.rationale,
            "valid_until": policy.valid_until.isoformat() if policy.valid_until else None,
            # Which of the approved channels this policy cannot actually
            # govern. An approval whose scope is partly inert is a different
            # governance fact from one that bites everywhere it names, and the
            # ledger is where an auditor reconstructs what was believed at
            # sign-off time. Empty ``egress_kinds`` means "any channel", so
            # the broadest policies list both advisory channels here.
            "advisory_egress_kinds": [k.value for k in advisory_egress_kinds(policy.egress_kinds)],
        },
        org_id=user.org_id,
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
    svc = TLPPolicyService(db)
    # Read before deleting: revocation is the more security-relevant half of
    # the policy lifecycle, and the ledger entry is worthless if it only says
    # "some policy was revoked". The row is gone after delete_policy(), so
    # the terms have to be captured first.
    policy = await svc.get_policy(user.org_id, policy_id)
    if policy is None or not await svc.delete_policy(user.org_id, policy_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found")
    await AuditTrail(db).record(
        actor=user.id,
        category=AuditCategory.CONFIG_CHANGE,
        action="tlp_policy_revoked",
        resource=policy.id,
        outcome=AuditOutcome.SUCCESS,
        details={
            "org_id": user.org_id,
            "policy_action": policy.action.value,
            "egress_kinds": list(policy.egress_kinds),
            "applies_to_tlp": [t.value for t in policy.applies_to_tlp],
            "downgrade_to": policy.downgrade_to.value if policy.downgrade_to else None,
            "approver_id": policy.approver_id,
        },
        org_id=user.org_id,
    )
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
        policy_enforced=is_policy_enforced(body.egress_kind),
    )
