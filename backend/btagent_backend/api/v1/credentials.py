"""Connector credential-reference API (#100).

CRUD over the per-org binding between a connector and the ``${secret:...}``
reference that resolves its credential material. The API stores and returns
**references only** — the secret itself lives in Vault / AWS SM / env and is
never persisted or exposed here.

RBAC: ``credential:view`` (senior_analyst+) to read which connectors are
wired; ``credential:manage`` (admin) to bind or unbind. Writes are audited.
"""

from __future__ import annotations

import logging
from datetime import datetime

from btagent_shared.types.enums import AuditCategory, AuditOutcome
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.db.models_connector import ConnectorCredentialRow
from btagent_backend.services import connector_credential_service as svc
from btagent_backend.services.audit_trail import AuditTrail

logger = logging.getLogger("btagent.api.credentials")

router = APIRouter(prefix="/credentials", tags=["credentials"])


class CredentialResponse(BaseModel):
    """A credential binding — the reference, never the material."""

    model_config = ConfigDict(from_attributes=True)

    connector_name: str
    secret_ref: str
    label: str
    created_by: str
    updated_by: str
    created_at: datetime
    updated_at: datetime


class CredentialListResponse(BaseModel):
    items: list[CredentialResponse]
    total: int


class UpsertCredentialRequest(BaseModel):
    secret_ref: str = Field(
        ...,
        description=(
            "A single ${secret:vault:...} / ${secret:aws:...} / ${env:VAR} "
            "reference. Raw secret material is rejected."
        ),
    )
    label: str = Field(default="", max_length=200)


def _response(row: ConnectorCredentialRow) -> CredentialResponse:
    return CredentialResponse.model_validate(row)


@router.get("", response_model=CredentialListResponse)
async def list_credentials(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> CredentialListResponse:
    """List the org's connector credential bindings (references only)."""
    user.require_permission("credential:view")
    rows = await svc.list_credentials(db, org_id=user.org_id)
    return CredentialListResponse(items=[_response(r) for r in rows], total=len(rows))


@router.get("/{connector_name}", response_model=CredentialResponse)
async def get_credential(
    connector_name: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> CredentialResponse:
    """Read one connector's credential binding."""
    user.require_permission("credential:view")
    row = await svc.get_credential(db, org_id=user.org_id, connector_name=connector_name)
    if row is None:
        raise HTTPException(status_code=404, detail=f"No credential bound for '{connector_name}'")
    return _response(row)


@router.put("/{connector_name}", response_model=CredentialResponse)
async def upsert_credential(
    connector_name: str,
    body: UpsertCredentialRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> CredentialResponse:
    """Bind (or re-bind) a connector's credential reference. Admin-only."""
    user.require_permission("credential:manage")
    try:
        row = await svc.upsert_credential(
            db,
            org_id=user.org_id,
            connector_name=connector_name,
            secret_ref=body.secret_ref,
            label=body.label,
            actor_id=user.id,
        )
        await AuditTrail(db).record(
            actor=user.id,
            category=AuditCategory.CONFIG_CHANGE,
            action="connector_credential_bound",
            resource=f"connector:{connector_name}",
            outcome=AuditOutcome.SUCCESS,
            details={"org_id": user.org_id, "label": body.label},
        )
        await db.commit()
    except svc.UnknownConnector as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except svc.InvalidCredentialReference as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return _response(row)


@router.delete("/{connector_name}", status_code=204)
async def delete_credential(
    connector_name: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> None:
    """Remove a connector's credential binding. Admin-only."""
    user.require_permission("credential:manage")
    deleted = await svc.delete_credential(db, org_id=user.org_id, connector_name=connector_name)
    if not deleted:
        raise HTTPException(status_code=404, detail=f"No credential bound for '{connector_name}'")
    await AuditTrail(db).record(
        actor=user.id,
        category=AuditCategory.CONFIG_CHANGE,
        action="connector_credential_removed",
        resource=f"connector:{connector_name}",
        outcome=AuditOutcome.SUCCESS,
        details={"org_id": user.org_id},
    )
    await db.commit()
