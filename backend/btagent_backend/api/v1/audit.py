"""Audit-grade lineage API (UC-7.1, #110) — read-only ledger surface.

Exposes the existing SHA-256 hash-chain audit log (AuditTrail service +
audit_logs table) for forensics + compliance consumption:

  * GET /audit/entries  — paginated, filterable entry list
  * GET /audit/verify   — chain integrity check (tamper evidence)
  * GET /audit/lineage  — node/edge projection of the hash chain
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
import re

from btagent_shared.types.enums import AuditCategory
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.services.audit_trail import AuditTrail
from btagent_backend.services.lineage_service import (
    AuditLineageGraph,
    build_audit_lineage,
)

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


# ``incident_id`` reaches a response header, so it is never interpolated raw:
# anything outside the id alphabet (prefixed ULIDs are [A-Za-z0-9_-]) is
# dropped, which forecloses CR/LF header injection and quote-breaking on the
# Content-Disposition value.
_FILENAME_SAFE = re.compile(r"[^A-Za-z0-9_-]")
_MAX_FILENAME_ID = 64


def _export_filename(incident_id: str | None) -> str:
    """Attachment filename for the CSV export, safe for a header value."""
    if not incident_id:
        return "audit_export.csv"
    safe = _FILENAME_SAFE.sub("", incident_id)[:_MAX_FILENAME_ID]
    return f"audit_export_{safe}.csv" if safe else "audit_export.csv"


@router.get("/entries", response_model=AuditEntryListResponse)
async def list_audit_entries(
    actor: str | None = Query(None),
    category: AuditCategory | None = Query(None),
    incident_id: str | None = Query(
        None,
        description=(
            "Narrow to one audited object (UC-7.1 evidence package): matched "
            "against the entry's ``resource``, e.g. an investigation id."
        ),
    ),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> AuditEntryListResponse:
    """List audit-ledger entries (newest first), filterable by actor/category/incident."""
    user.require_permission("audit:view")
    # GH #385: scope to the caller's tenant so the ledger never leaks another
    # org's actor/action/resource.
    rows = await AuditTrail(db).get_entries(
        org_id=user.org_id,
        actor=actor,
        category=category,
        resource=incident_id,
        limit=limit,
        offset=offset,
    )
    return AuditEntryListResponse(items=[_to_response(r) for r in rows], limit=limit, offset=offset)


@router.get("/verify", response_model=ChainVerifyResponse)
async def verify_audit_chain(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> ChainVerifyResponse:
    """Verify the SHA-256 hash chain — tamper evidence for the whole ledger."""
    user.require_permission("audit:view")
    # GH #385: chain integrity is verified over the full global chain, but the
    # reported result is scoped to the caller's org.
    valid, errors = await AuditTrail(db).verify_chain(org_id=user.org_id)
    return ChainVerifyResponse(valid=valid, errors=errors)


@router.get("/lineage", response_model=AuditLineageGraph)
async def get_audit_lineage(
    up_to_hash: str | None = Query(
        None,
        description=(
            "Point-in-time replay: return the chain prefix up to and including "
            "the row with this hash. Omit for the full graph."
        ),
    ),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> AuditLineageGraph:
    """Project the audit hash chain into a node/edge lineage graph (UC-7.1)."""
    user.require_permission("audit:view")
    try:
        # GH #385: project only the caller's tenant rows into the lineage graph.
        return await build_audit_lineage(db, org_id=user.org_id, up_to_hash=up_to_hash)
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get("/export")
async def export_audit_csv(
    actor: str | None = Query(None),
    category: AuditCategory | None = Query(None),
    incident_id: str | None = Query(
        None,
        description=(
            "Export one incident's evidence package (UC-7.1): matched against "
            "the entry's ``resource``. Omit for the full tenant ledger."
        ),
    ),
    limit: int = Query(10000, ge=1, le=100000),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> StreamingResponse:
    """Export audit entries as CSV for external auditors (admin only).

    With ``incident_id`` the CSV is scoped to that object's ledger slice —
    the "evidence package for any incident on demand" in EPIC-7 UC-7.1 — and
    the attachment filename carries the id so downloaded packages stay
    distinguishable.
    """
    user.require_permission("audit:export")
    # GH #385: export only the caller's tenant ledger.
    rows = await AuditTrail(db).get_entries(
        org_id=user.org_id,
        actor=actor,
        category=category,
        resource=incident_id,
        limit=limit,
        offset=0,
    )

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
        headers={"Content-Disposition": f"attachment; filename={_export_filename(incident_id)}"},
    )
