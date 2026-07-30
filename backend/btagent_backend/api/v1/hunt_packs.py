"""Per-org hunt-pack install/enable API (#112).

``GET  /api/v1/hunt/packs``
    The builtin pack catalog joined with the caller's org install/enable
    state — the read behind the HuntPacks screen's enable/disable control.
    RBAC ``hunt:view`` (every analyst may see which packs run).

``PUT  /api/v1/hunt/packs/{pack_id}``
    Enable or disable one pack **for the caller's org**. RBAC
    ``huntpack:manage`` (senior_analyst+): flipping a pack changes what the
    scheduled runner hunts for the whole tenant, which is a detection-posture
    decision, not an individual analyst's view preference.

Org scoping is taken from the authenticated principal (``user.org_id``) and is
never accepted from the request — a caller cannot install or disable a pack for
another tenant. Every write is audited through the shared audit trail so
"who turned this pack off, and when" is answerable after the fact.

Thin route layer: all resolution semantics (the builtin-default fallback, the
unknown-pack rejection) live in
:mod:`btagent_backend.services.hunt_pack_store`.
"""

from __future__ import annotations

import logging

from btagent_shared.types.enums import AuditCategory, AuditOutcome
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.services import hunt_pack_store, org_custom_pack_service
from btagent_backend.services.audit_trail import AuditTrail

logger = logging.getLogger("btagent.api.hunt_packs")

router = APIRouter(prefix="/hunt/packs", tags=["hunt"])


class SetPackEnabledRequest(BaseModel):
    enabled: bool = Field(..., description="True installs/enables the pack; False disables it.")


@router.get("", response_model=hunt_pack_store.HuntPackCatalogResponse)
async def list_hunt_packs(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> hunt_pack_store.HuntPackCatalogResponse:
    """The shipped hunt packs + this org's enable state (#112).

    A pack with no explicit row reads ``installed=false`` and is ``enabled``
    only when it belongs to the builtin default set — the same fallback the
    scheduled runner applies, so the screen never disagrees with the runner.
    """
    user.require_permission("hunt:view")
    return await hunt_pack_store.pack_catalog(db, org_id=user.org_id)


@router.put("/{pack_id}", response_model=hunt_pack_store.HuntPackCatalogEntry)
async def set_hunt_pack_enabled(
    pack_id: str,
    body: SetPackEnabledRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> hunt_pack_store.HuntPackCatalogEntry:
    """Enable or disable one builtin pack for the caller's org (#112).

    Idempotent: re-sending the same state rewrites provenance only. Unknown
    pack names 404 rather than persisting a pack the runner cannot load.
    """
    user.require_permission("huntpack:manage")
    try:
        await hunt_pack_store.set_pack_enabled(
            db,
            org_id=user.org_id,
            pack_id=pack_id,
            enabled=body.enabled,
            updated_by=user.id,
        )
    except hunt_pack_store.UnknownPackError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))

    # Enabling/disabling a pack changes what the SOC hunts for on a schedule —
    # a detection-posture change, so it lands on the hash-chained ledger next
    # to suppressions and promotions rather than only in the app log.
    await AuditTrail(db).record(
        actor=user.id,
        category=AuditCategory.HUNT,
        action="hunt_pack_enabled" if body.enabled else "hunt_pack_disabled",
        resource=f"org_hunt_pack:{user.org_id}:{pack_id}",
        outcome=AuditOutcome.SUCCESS,
        details={"pack_id": pack_id, "enabled": body.enabled, "org_id": user.org_id},
        org_id=user.org_id,
    )

    catalog = await hunt_pack_store.pack_catalog(db, org_id=user.org_id)
    for entry in catalog.items:
        if entry.pack_id == pack_id:
            return entry
    # Only reachable if the catalog is empty (engine not installed in this
    # image) — the row is still persisted, so report it faithfully.
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="hunt pack catalog unavailable in this deployment",
    )


# --------------------------------------------------------------------------- #
# Org-custom pack bundles (#112 slice 2)
# --------------------------------------------------------------------------- #


class CustomPackUploadRequest(BaseModel):
    """A pack uploaded as content: pack.yaml text + rule files by name."""

    manifest_yaml: str = Field(..., min_length=1, max_length=200_000)
    rule_files: dict[str, str] = Field(
        ..., description="Rule filename (as pack.yaml references it) -> Sigma YAML text."
    )


class CustomPackResponse(BaseModel):
    id: str
    pack_id: str
    name: str
    version: str
    description: str
    rule_count: int
    created_by: str | None
    created_at: str
    updated_at: str


class CustomPackListResponse(BaseModel):
    items: list[CustomPackResponse]
    total: int


def _custom_response(row) -> CustomPackResponse:
    return CustomPackResponse(
        id=row.id,
        pack_id=row.pack_id,
        name=row.name,
        version=row.version,
        description=row.description or "",
        rule_count=row.rule_count,
        created_by=row.created_by,
        created_at=row.created_at.isoformat(),
        updated_at=row.updated_at.isoformat(),
    )


@router.get("/custom", response_model=CustomPackListResponse)
async def list_custom_packs(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> CustomPackListResponse:
    """The caller's org's uploaded packs (all of them run on the sweep)."""
    user.require_permission("hunt:view")
    rows = await org_custom_pack_service.list_packs(db, org_id=user.org_id)
    return CustomPackListResponse(items=[_custom_response(r) for r in rows], total=len(rows))


@router.post("/custom", response_model=CustomPackResponse, status_code=status.HTTP_201_CREATED)
async def upload_custom_pack(
    body: CustomPackUploadRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> CustomPackResponse:
    """Validate and store a pack bundle for the caller's org (#112).

    Validation IS the engine loader (``load_pack_from_bundle``): an upload
    that persists is an upload the scheduled sweep can run. Same-identity
    re-uploads update in place. RBAC ``huntpack:manage`` — adding a pack
    changes the org's scheduled detection posture.
    """
    user.require_permission("huntpack:manage")
    try:
        row, created = await org_custom_pack_service.create_or_update_pack(
            db,
            org_id=user.org_id,
            manifest_yaml=body.manifest_yaml,
            rule_files=body.rule_files,
            created_by=user.id,
        )
    except org_custom_pack_service.InvalidPackBundle as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    await AuditTrail(db).record(
        actor=user.id,
        category=AuditCategory.HUNT,
        action="custom_pack_uploaded" if created else "custom_pack_updated",
        resource=f"org_custom_pack:{user.org_id}:{row.pack_id}",
        outcome=AuditOutcome.SUCCESS,
        details={
            "pack_id": row.pack_id,
            "name": row.name,
            "version": row.version,
            "rule_count": row.rule_count,
            "org_id": user.org_id,
        },
        org_id=user.org_id,
    )
    return _custom_response(row)


@router.delete("/custom/{row_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_custom_pack(
    row_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> None:
    """Remove an uploaded pack (it stops running on the next sweep)."""
    user.require_permission("huntpack:manage")
    row = await org_custom_pack_service.get_pack(db, org_id=user.org_id, row_id=row_id)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Custom pack not found")
    pack_id = row.pack_id
    await org_custom_pack_service.delete_pack(db, org_id=user.org_id, row_id=row_id)

    await AuditTrail(db).record(
        actor=user.id,
        category=AuditCategory.HUNT,
        action="custom_pack_deleted",
        resource=f"org_custom_pack:{user.org_id}:{pack_id}",
        outcome=AuditOutcome.SUCCESS,
        details={"pack_id": pack_id, "org_id": user.org_id},
        org_id=user.org_id,
    )
