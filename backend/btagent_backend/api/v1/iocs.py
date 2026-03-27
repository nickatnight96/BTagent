"""IOC CRUD, enrichment, and STIX import/export endpoints."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.db.models import IOCRow
from btagent_backend.services import ioc_service, stix_service

logger = logging.getLogger("btagent.api.iocs")

router = APIRouter(prefix="/iocs", tags=["iocs"])


# --------------------------------------------------------------------------- #
# Request / Response schemas
# --------------------------------------------------------------------------- #


class CreateIOCRequest(BaseModel):
    investigation_id: str
    type: str
    value: str
    tlp_level: str = "green"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    context: str = ""
    source: str = ""


class BulkCreateIOCRequest(BaseModel):
    investigation_id: str
    iocs: list[CreateIOCRequest]


class UpdateIOCRequest(BaseModel):
    type: str | None = None
    value: str | None = None
    tlp_level: str | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    context: str | None = None
    source: str | None = None
    enrichment: dict[str, Any] | None = None


class IOCResponse(BaseModel):
    id: str
    investigation_id: str
    type: str
    value: str
    tlp_level: str
    confidence: float
    first_seen: str | None
    last_seen: str | None
    context: str
    source: str
    enrichment: dict[str, Any]


class IOCListResponse(BaseModel):
    items: list[IOCResponse]
    total: int
    page: int
    page_size: int


class EnrichRequest(BaseModel):
    pass  # No body needed; IOC ID comes from URL path


class BulkEnrichRequest(BaseModel):
    ioc_ids: list[str]


class STIXImportRequest(BaseModel):
    bundle: dict[str, Any]
    investigation_id: str


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _to_response(row: IOCRow) -> IOCResponse:
    return IOCResponse(
        id=row.id,
        investigation_id=row.investigation_id,
        type=row.type,
        value=row.value,
        tlp_level=row.tlp_level,
        confidence=row.confidence,
        first_seen=row.first_seen.isoformat() if row.first_seen else None,
        last_seen=row.last_seen.isoformat() if row.last_seen else None,
        context=row.context,
        source=row.source,
        enrichment=row.enrichment or {},
    )


# --------------------------------------------------------------------------- #
# CRUD Endpoints
# --------------------------------------------------------------------------- #


@router.get("", response_model=IOCListResponse)
async def list_iocs(
    ioc_type: str | None = Query(None, alias="type"),
    investigation_id: str | None = Query(None),
    confidence_min: float | None = Query(None, ge=0.0, le=1.0),
    enriched: bool | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """List IOCs with optional filters and pagination."""
    user.require_permission("ioc:view")

    rows, total = await ioc_service.list_iocs(
        db,
        investigation_id=investigation_id,
        ioc_type=ioc_type,
        confidence_min=confidence_min,
        enriched=enriched,
        page=page,
        page_size=page_size,
    )

    return IOCListResponse(
        items=[_to_response(r) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/search", response_model=IOCListResponse)
async def search_iocs(
    value: str | None = Query(None),
    ioc_type: str | None = Query(None, alias="type"),
    confidence_min: float | None = Query(None, ge=0.0, le=1.0),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Search IOCs across all investigations.

    Supports partial value matching and cross-investigation correlation.
    """
    user.require_permission("ioc:view")

    rows, total = await ioc_service.search_cross_investigation(
        db,
        value=value,
        ioc_type=ioc_type,
        confidence_min=confidence_min,
        page=page,
        page_size=page_size,
    )

    return IOCListResponse(
        items=[_to_response(r) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{ioc_id}", response_model=IOCResponse)
async def get_ioc(
    ioc_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Get IOC detail with enrichment data."""
    user.require_permission("ioc:view")

    row = await ioc_service.get_ioc(db, ioc_id)
    if not row:
        raise HTTPException(status_code=404, detail="IOC not found")

    return _to_response(row)


@router.post("", response_model=IOCResponse | list[IOCResponse], status_code=201)
async def create_ioc(
    body: CreateIOCRequest | BulkCreateIOCRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Create one or more IOCs."""
    user.require_permission("ioc:create")

    if isinstance(body, BulkCreateIOCRequest):
        rows = await ioc_service.create_iocs_bulk(
            db,
            investigation_id=body.investigation_id,
            iocs=[ioc.model_dump() for ioc in body.iocs],
        )
        return [_to_response(r) for r in rows]

    row = await ioc_service.create_ioc(
        db,
        investigation_id=body.investigation_id,
        ioc_type=body.type,
        value=body.value,
        tlp_level=body.tlp_level,
        confidence=body.confidence,
        context=body.context,
        source=body.source,
    )

    return _to_response(row)


@router.put("/{ioc_id}", response_model=IOCResponse)
async def update_ioc(
    ioc_id: str,
    body: UpdateIOCRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Update an existing IOC."""
    user.require_permission("ioc:edit")

    # Build update dict from non-None fields
    update_fields = {k: v for k, v in body.model_dump().items() if v is not None}

    if not update_fields:
        raise HTTPException(
            status_code=400,
            detail="No fields to update",
        )

    row = await ioc_service.update_ioc(db, ioc_id, **update_fields)
    if not row:
        raise HTTPException(status_code=404, detail="IOC not found")

    return _to_response(row)


@router.delete("/{ioc_id}", status_code=204)
async def delete_ioc(
    ioc_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Soft-delete an IOC (set confidence to 0 and clear enrichment)."""
    user.require_permission("ioc:delete")

    row = await ioc_service.get_ioc(db, ioc_id)
    if not row:
        raise HTTPException(status_code=404, detail="IOC not found")

    # Soft delete: zero out confidence and mark as deleted in context
    await ioc_service.update_ioc(
        db,
        ioc_id,
        confidence=0.0,
        context=f"[DELETED] {row.context}",
        enrichment={},
    )

    return None


# --------------------------------------------------------------------------- #
# Enrichment Endpoints
# --------------------------------------------------------------------------- #


@router.post("/{ioc_id}/enrich", status_code=202)
async def trigger_enrich(
    ioc_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Trigger enrichment for a single IOC.

    Returns 202 Accepted with task metadata. The enrichment runs
    asynchronously and results are written to the IOC's enrichment column.
    """
    user.require_permission("ioc:enrich")

    row = await ioc_service.get_ioc(db, ioc_id)
    if not row:
        raise HTTPException(status_code=404, detail="IOC not found")

    result = await ioc_service.trigger_enrichment(db, ioc_id)

    return result


@router.post("/bulk-enrich", status_code=202)
async def trigger_bulk_enrich(
    body: BulkEnrichRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Trigger enrichment for multiple IOCs.

    Returns 202 Accepted with task metadata. Each IOC is enriched
    asynchronously in the background.
    """
    user.require_permission("ioc:enrich")

    result = await ioc_service.trigger_bulk_enrichment(db, body.ioc_ids)

    return result


# --------------------------------------------------------------------------- #
# STIX Import / Export
# --------------------------------------------------------------------------- #


@router.post("/import", status_code=201)
async def import_stix(
    body: STIXImportRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Import IOCs from a STIX 2.1 JSON bundle.

    Parses the bundle, converts indicators to BTagent IOCs, and creates
    them in the specified investigation.
    """
    user.require_permission("ioc:create")

    ioc_dicts = stix_service.stix_to_iocs(
        body.bundle,
        investigation_id=body.investigation_id,
        source="stix_import",
    )

    if not ioc_dicts:
        return {"imported": 0, "message": "No valid indicators found in STIX bundle"}

    rows = await ioc_service.create_iocs_bulk(
        db,
        investigation_id=body.investigation_id,
        iocs=ioc_dicts,
    )

    return {
        "imported": len(rows),
        "ioc_ids": [r.id for r in rows],
        "investigation_id": body.investigation_id,
    }


@router.get("/export", response_model=None)
async def export_stix(
    investigation_id: str = Query(...),
    tlp_level: str = Query("green"),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Export IOCs as a STIX 2.1 JSON bundle.

    Respects TLP enforcement: TLP:RED IOCs are never included in exports.
    """
    user.require_permission("ioc:export")

    if tlp_level == "red":
        raise HTTPException(
            status_code=403,
            detail="Cannot export TLP:RED IOCs. Downgrade TLP level before export.",
        )

    rows, _ = await ioc_service.list_iocs(
        db,
        investigation_id=investigation_id,
        page=1,
        page_size=10000,  # Export all
    )

    # Filter out TLP:RED IOCs
    ioc_dicts = [
        {
            "id": r.id,
            "type": r.type,
            "value": r.value,
            "confidence": r.confidence,
            "context": r.context,
            "tlp_level": r.tlp_level,
            "enrichment": r.enrichment,
            "first_seen": r.first_seen.isoformat() if r.first_seen else None,
        }
        for r in rows
        if r.tlp_level != "red"
    ]

    bundle = stix_service.stix_bundle_from_iocs(ioc_dicts, tlp_level=tlp_level)

    return bundle
