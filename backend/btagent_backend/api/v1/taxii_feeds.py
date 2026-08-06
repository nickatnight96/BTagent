"""TAXII 2.1 feed-configuration API (#105 / UC-2.1).

RBAC-gated CRUD over the org's ``taxii_feeds`` rows — the pull half of
"STIX/TAXII feeds". The scheduled sweep
(``scheduler.jobs.taxii_feed_poll_sweep``) is what actually polls; this
surface only configures it.

Security contract
-----------------
* **References only.** ``auth_secret_ref`` accepts one complete
  ``${secret:vault:...}`` / ``${secret:aws:...}`` / ``${env:VAR}`` reference and
  nothing else; raw material is rejected with 422 by the service layer, so a
  credential cannot be stored through this API. Responses echo the *reference*
  (that is config, not a secret) and never resolve it.
* **Org-scoped.** Every read and write is filtered by ``user.org_id``; a feed id
  belonging to another tenant 404s exactly like a nonexistent one.
* **RBAC.** ``taxii:view`` (senior_analyst+) to read, ``taxii:manage`` (admin)
  to create / edit / delete. Writes are audited as config changes.
"""

from __future__ import annotations

import logging
from datetime import datetime

from btagent_shared.types.enums import AuditCategory, AuditOutcome
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.db.models_cti import TaxiiFeedRow
from btagent_backend.services import taxii_feed_service as svc
from btagent_backend.services.audit_trail import AuditTrail

logger = logging.getLogger("btagent.api.taxii_feeds")

router = APIRouter(prefix="/taxii/feeds", tags=["taxii"])


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #


class TaxiiFeedResponse(BaseModel):
    """A feed's configuration + poll telemetry.

    ``auth_secret_ref`` is the reference string, never the credential it names.
    """

    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    server_url: str
    collection_id: str
    auth_style: str
    auth_secret_ref: str
    poll_interval_minutes: int
    enabled: bool
    last_cursor: str | None
    last_polled_at: datetime | None
    last_status: str
    last_error: str
    objects_ingested: int
    intake_investigation_id: str | None
    created_at: datetime
    updated_at: datetime


class TaxiiFeedListResponse(BaseModel):
    items: list[TaxiiFeedResponse]
    total: int


class CreateTaxiiFeedRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(..., max_length=200)
    server_url: str = Field(..., max_length=1000, description="TAXII 2.1 api-root URL.")
    collection_id: str = Field(..., max_length=200)
    auth_style: str = Field(default="none", description="none | bearer | basic")
    auth_secret_ref: str = Field(
        default="",
        max_length=500,
        description=(
            "A single ${secret:vault:...} / ${secret:aws:...} / ${env:VAR} reference. "
            "Raw credential material is rejected."
        ),
    )
    poll_interval_minutes: int = Field(default=60)
    enabled: bool = True


class UpdateTaxiiFeedRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    """Partial update — only supplied fields change (``exclude_unset``)."""

    name: str | None = Field(default=None, max_length=200)
    server_url: str | None = Field(default=None, max_length=1000)
    collection_id: str | None = Field(default=None, max_length=200)
    auth_style: str | None = None
    auth_secret_ref: str | None = Field(default=None, max_length=500)
    poll_interval_minutes: int | None = None
    enabled: bool | None = None


def _response(row: TaxiiFeedRow) -> TaxiiFeedResponse:
    return TaxiiFeedResponse.model_validate(row)


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #


@router.get("", response_model=TaxiiFeedListResponse)
async def list_taxii_feeds(
    enabled_only: bool = False,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> TaxiiFeedListResponse:
    """List the org's TAXII feed subscriptions."""
    user.require_permission("taxii:view")
    rows = await svc.list_feeds(db, org_id=user.org_id, enabled_only=enabled_only)
    return TaxiiFeedListResponse(items=[_response(r) for r in rows], total=len(rows))


@router.get("/{feed_id}", response_model=TaxiiFeedResponse)
async def get_taxii_feed(
    feed_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> TaxiiFeedResponse:
    """Read one feed. A foreign org's feed id 404s like a nonexistent one."""
    user.require_permission("taxii:view")
    row = await svc.get_feed(db, org_id=user.org_id, feed_id=feed_id)
    if row is None:
        raise HTTPException(status_code=404, detail="TAXII feed not found")
    return _response(row)


@router.post("", response_model=TaxiiFeedResponse, status_code=201)
async def create_taxii_feed(
    body: CreateTaxiiFeedRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> TaxiiFeedResponse:
    """Subscribe the org to a TAXII 2.1 collection. Admin-only."""
    user.require_permission("taxii:manage")
    try:
        row = await svc.create_feed(
            db,
            org_id=user.org_id,
            name=body.name,
            server_url=body.server_url,
            collection_id=body.collection_id,
            auth_style=body.auth_style,
            auth_secret_ref=body.auth_secret_ref,
            poll_interval_minutes=body.poll_interval_minutes,
            enabled=body.enabled,
            actor_id=user.id,
        )
    except svc.DuplicateFeedName as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except svc.InvalidFeedConfig as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    await AuditTrail(db).record(
        org_id=user.org_id,
        actor=user.id,
        category=AuditCategory.CONFIG_CHANGE,
        action="taxii_feed_created",
        resource=f"taxii_feed:{row.id}",
        outcome=AuditOutcome.SUCCESS,
        # Deliberately no secret_ref in the ledger: it names a Vault path.
        details={"org_id": user.org_id, "name": row.name, "auth_style": row.auth_style},
    )
    await db.commit()
    return _response(row)


@router.patch("/{feed_id}", response_model=TaxiiFeedResponse)
async def update_taxii_feed(
    feed_id: str,
    body: UpdateTaxiiFeedRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> TaxiiFeedResponse:
    """Update a feed's configuration. Admin-only."""
    user.require_permission("taxii:manage")
    changes = body.model_dump(exclude_unset=True, exclude_none=True)
    if not changes:
        raise HTTPException(status_code=422, detail="No fields to update")
    try:
        row = await svc.update_feed(
            db,
            org_id=user.org_id,
            feed_id=feed_id,
            changes=changes,
            actor_id=user.id,
        )
    except svc.DuplicateFeedName as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except svc.InvalidFeedConfig as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if row is None:
        raise HTTPException(status_code=404, detail="TAXII feed not found")

    await AuditTrail(db).record(
        org_id=user.org_id,
        actor=user.id,
        category=AuditCategory.CONFIG_CHANGE,
        action="taxii_feed_updated",
        resource=f"taxii_feed:{row.id}",
        outcome=AuditOutcome.SUCCESS,
        details={"org_id": user.org_id, "fields": sorted(changes)},
    )
    await db.commit()
    return _response(row)


@router.delete("/{feed_id}", status_code=204)
async def delete_taxii_feed(
    feed_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> None:
    """Remove a feed subscription. Admin-only."""
    user.require_permission("taxii:manage")
    deleted = await svc.delete_feed(db, org_id=user.org_id, feed_id=feed_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="TAXII feed not found")
    await AuditTrail(db).record(
        org_id=user.org_id,
        actor=user.id,
        category=AuditCategory.CONFIG_CHANGE,
        action="taxii_feed_deleted",
        resource=f"taxii_feed:{feed_id}",
        outcome=AuditOutcome.SUCCESS,
        details={"org_id": user.org_id},
    )
    await db.commit()
