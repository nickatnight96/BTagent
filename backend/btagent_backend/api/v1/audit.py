"""Audit-grade lineage API (UC-7.1, #110) — read-only ledger surface.

Exposes the existing SHA-256 hash-chain audit log (AuditTrail service +
audit_logs table) for forensics + compliance consumption:

  * GET /audit/entries  — paginated, filterable entry list
  * GET /audit/verify   — chain integrity check (tamper evidence)
  * GET /audit/export   — CSV export for external auditors

The ledger is always-on read-only infrastructure (autonomy L2 in the
catalog): nobody writes through this API, they only consume the lineage.
Gated to senior-analyst (view) / admin (export). The 7-year retention
requirement is handled by services/data_retention.py.
"""

from __future__ import annotations

import csv
import io
import logging

from btagent_shared.types.enums import AuditCategory
from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.services.audit_trail import AuditTrail

logger = logging.getLogger("btagent.api.audit")

router = APIRouter(prefix="/audit", tags=["audit"])


class AuditEntryResponse(BaseModel):
    id: str
    seq: int
    timestamp: str
    actor: str
    category: str
    action: str
    resource: str
    outcome: str
    prev_hash: str
    hash: str


class AuditEntryListResponse(BaseModel):
    items: list[AuditEntryResponse]
    limit: int
    offset: int


class ChainVerifyResponse(BaseModel):
    valid: bool
    errors: list[str]


def _to_response(row) -> AuditEntryResponse:
    return AuditEntryResponse(
        id=row.id,
        seq=row.seq,
        timestamp=row.timestamp.isoformat() if row.timestamp else "",
        actor=row.actor,
        category=row.category,
        action=row.action,
        resource=row.resource or "",
        outcome=row.outcome,
        prev_hash=row.prev_hash or "",
        hash=row.hash or "",
    )


@router.get("/entries", response_model=AuditEntryListResponse)
async def list_audit_entries(
    actor: str | None = Query(None),
    category: AuditCategory | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> AuditEntryListResponse:
    """List audit-ledger entries (newest first), filterable by actor/category."""
    user.require_permission("audit:view")
    rows = await AuditTrail(db).get_entries(
        actor=actor, category=category, limit=limit, offset=offset
    )
    return AuditEntryListResponse(items=[_to_response(r) for r in rows], limit=limit, offset=offset)


@router.get("/verify", response_model=ChainVerifyResponse)
async def verify_audit_chain(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> ChainVerifyResponse:
    """Verify the SHA-256 hash chain — tamper evidence for the whole ledger."""
    user.require_permission("audit:view")
    valid, errors = await AuditTrail(db).verify_chain()
    return ChainVerifyResponse(valid=valid, errors=errors)


@router.get("/export")
async def export_audit_csv(
    actor: str | None = Query(None),
    category: AuditCategory | None = Query(None),
    limit: int = Query(10000, ge=1, le=100000),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> StreamingResponse:
    """Export audit entries as CSV for external auditors (admin only)."""
    user.require_permission("audit:export")
    rows = await AuditTrail(db).get_entries(actor=actor, category=category, limit=limit, offset=0)

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        ["seq", "timestamp", "actor", "category", "action", "resource", "outcome", "hash"]
    )
    for r in rows:
        writer.writerow(
            [
                r.seq,
                r.timestamp.isoformat() if r.timestamp else "",
                r.actor,
                r.category,
                r.action,
                r.resource or "",
                r.outcome,
                r.hash or "",
            ]
        )
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_export.csv"},
    )
