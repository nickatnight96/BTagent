"""Containment execute-and-record API (EPIC-3 #106 — approve→execute→record).

The guarded execution layer over the proposal-only planning surfaces
(``/response-plan``, ``/mitigation``). Endpoints here are the ONLY ones that
dispatch a containment/mitigation action through the connector/MCP layer.

Every execution endpoint is **double-gated**: it requires the
``containment:execute`` RBAC scope (incident-commander+) *and* an explicit prior
approval carried on the request. The service layer refuses anything not marked
approved, enforces the org never-block safelist before any block dispatch, keeps
connectors mock-first, and writes a hash-chain audit row (stamping the acting
user as approver) for every execute and every denial. See
:mod:`btagent_backend.services.containment_execute_service`.
"""

from __future__ import annotations

import logging

from btagent_shared.types.enums import AuditCategory, AuditOutcome, SafelistEntryType
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.services import containment_execute_service, response_safelist_service
from btagent_backend.services.audit_trail import AuditTrail
from btagent_backend.services.response_safelist_service import SafelistValidationError

logger = logging.getLogger("btagent.api.containment")

router = APIRouter(prefix="/containment", tags=["containment"])


# --------------------------------------------------------------------------- #
# Request / response models
# --------------------------------------------------------------------------- #


class ExecuteResponseActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action_id: str = Field(..., description="Id of the approved ResponseAction step.")
    action_type: str = Field(..., description="e.g. isolate_host / block_ip / disable_account.")
    connector: str = Field(..., description="Connector that enforces it, e.g. 'crowdstrike'.")
    target: str = Field(default="", description="Entity acted on (host/ip/account/domain).")
    description: str = Field(default="")
    approved: bool = Field(
        default=False,
        description="Must be true — the HITL half of the double-gate (prior approval).",
    )


class ExecuteBulkBlockRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action_id: str = Field(..., description="Id of the approved MitigationAction (block) step.")
    ioc_type: str = Field(..., description="ip | domain | url | hash_* — the IOC kind.")
    ioc_value: str = Field(..., description="The IOC to block.")
    tool: str = Field(..., description="Connector that enforces the block, e.g. 'panorama'.")
    policy_object: str = Field(default="", description="Blocklist/policy name on that tool.")
    rollback: str | None = Field(default=None, description="How to undo the block.")
    approved: bool = Field(
        default=False,
        description="Must be true — the HITL half of the double-gate (prior approval).",
    )


class ExecutionResponse(BaseModel):
    executed: bool
    outcome: str
    tool: str
    target: str
    audit_id: str
    approver_id: str
    change_ref: str | None = None
    tool_response: dict = Field(default_factory=dict)


class SafelistEntryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    entry_type: SafelistEntryType = Field(
        ...,
        description=(
            "Kind of never-touch entry. IPs match exactly, domains by suffix, "
            "principals (cloud IAM ARN / service-account email / object id) "
            "exactly and case-insensitively."
        ),
    )
    value: str = Field(..., description="The IP, domain or principal to never touch.")
    reason: str = Field(default="", description="Why it must never be blocked.")


class SafelistEntryResponse(BaseModel):
    id: str
    org_id: str
    entry_type: str
    value: str
    reason: str
    created_by: str | None = None


def _entry_to_response(row) -> SafelistEntryResponse:
    return SafelistEntryResponse(
        id=row.id,
        org_id=row.org_id,
        entry_type=row.entry_type,
        value=row.value,
        reason=row.reason,
        created_by=row.created_by,
    )


def _to_http(result: dict):
    """Turn a result-returning service dict into a 200 body or a 4xx JSON denial.

    Denials RETURN (not raise) so the request commits its durable audit row
    before the 4xx status is sent — a raised exception would roll it back.
    """
    http_status = result.pop("http_status", 200)
    if http_status == 200:
        return ExecutionResponse(**result)
    # Denial: audit row already written; surface the refusal + its audit id.
    return JSONResponse(
        status_code=http_status,
        content={
            "detail": {
                "message": result.get("message", "Execution refused"),
                "outcome": result.get("outcome", "denied"),
                "target": result.get("target"),
                "tool": result.get("tool"),
                "audit_id": result.get("audit_id"),
                "approver_id": result.get("approver_id"),
            }
        },
    )


# --------------------------------------------------------------------------- #
# Execution endpoints (double-gated: RBAC scope + prior approval)
# --------------------------------------------------------------------------- #


@router.post("/execute/response-action", response_model=ExecutionResponse)
async def execute_response_action(
    body: ExecuteResponseActionRequest,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Execute an APPROVED response-plan tactical step (UC-3.2). Double-gated."""
    user.require_permission("containment:execute")
    result = await containment_execute_service.execute_response_action(
        db,
        actor_id=user.id,
        org_id=user.org_id,
        action_id=body.action_id,
        action_type=body.action_type,
        connector=body.connector,
        target=body.target,
        description=body.description,
        approved=body.approved,
    )
    return _to_http(result)


@router.post("/execute/bulk-block", response_model=ExecutionResponse)
async def execute_bulk_block(
    body: ExecuteBulkBlockRequest,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Execute an APPROVED bulk-block IOC step (UC-3.3). Safelist-guarded + audited."""
    user.require_permission("containment:execute")
    result = await containment_execute_service.execute_bulk_block(
        db,
        actor_id=user.id,
        org_id=user.org_id,
        action_id=body.action_id,
        ioc_type=body.ioc_type,
        ioc_value=body.ioc_value,
        tool=body.tool,
        policy_object=body.policy_object,
        rollback=body.rollback,
        approved=body.approved,
    )
    return _to_http(result)


# --------------------------------------------------------------------------- #
# Org-scoped safelist management
# --------------------------------------------------------------------------- #


@router.post("/safelist", response_model=SafelistEntryResponse, status_code=status.HTTP_201_CREATED)
async def add_safelist_entry(
    body: SafelistEntryRequest,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> SafelistEntryResponse:
    """Add an org-scoped never-block safelist entry (containment:execute / admin)."""
    user.require_permission("containment:execute")
    try:
        row = await response_safelist_service.add_entry(
            db,
            org_id=user.org_id,
            entry_type=body.entry_type.value,
            value=body.value,
            reason=body.reason,
            created_by=user.id,
        )
    except SafelistValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc))
    logger.info("safelist add org=%s by=%s %s=%s", user.org_id, user.id, row.entry_type, row.value)
    return _entry_to_response(row)


@router.get("/safelist", response_model=list[SafelistEntryResponse])
async def list_safelist_entries(
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[SafelistEntryResponse]:
    """List this org's never-block safelist entries (org-scoped read)."""
    user.require_permission("containment:execute")
    rows = await response_safelist_service.list_entries(db, org_id=user.org_id)
    return [_entry_to_response(r) for r in rows]


@router.delete("/safelist/{entry_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_safelist_entry(
    entry_id: str,
    user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Remove an org-scoped never-block entry (containment:execute / admin).

    The safelist was add-only, which made a mistake permanent: a typo'd
    domain or an over-broad CIDR shields a genuinely malicious target from
    containment forever, with no path to correct it short of direct DB
    access. Removal closes that.

    Audited under ``containment`` — deleting a never-block guard is itself a
    security-relevant act, because it *re-enables* containment against a
    target someone deliberately protected. The removed type/value go into
    the entry so the ledger records what stopped being protected, not merely
    that some row was deleted.

    Only org rows can be removed; the universal baseline (public resolvers,
    critical-infra domains, RFC1918/reserved ranges) lives in code and stays
    in force, so this can never drop an org below the shared floor.
    """
    user.require_permission("containment:execute")
    row = await response_safelist_service.remove_entry(db, org_id=user.org_id, entry_id=entry_id)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Safelist entry not found"
        )

    await AuditTrail(db).record(
        org_id=user.org_id,
        actor=user.id,
        category=AuditCategory.CONTAINMENT,
        action="safelist_entry_removed",
        resource=f"safelist:{row.entry_type}:{row.value}",
        outcome=AuditOutcome.SUCCESS,
        details={
            "org_id": user.org_id,
            "entry_id": entry_id,
            "entry_type": row.entry_type,
            "value": row.value,
            "reason": row.reason or "",
        },
    )
    await db.commit()
    logger.info(
        "safelist remove org=%s by=%s %s=%s", user.org_id, user.id, row.entry_type, row.value
    )
