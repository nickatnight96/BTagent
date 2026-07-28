"""Unified long-term Agent Memory API (#482).

Two org-scoped, RBAC-gated endpoints over the compact-fact memory store:

* ``POST /memory`` — record (upsert) a memory. Gated ``memory:write``
  (senior_analyst+): authoring a fact shapes what every future investigation in
  the org recalls.
* ``GET /memory`` — recall memories by subject / kind. Gated ``memory:read``
  (analyst+), recency-ranked and TLP-aware.

Both are strictly scoped to the caller's ``org_id`` (taken from the token, never
the request body) so one tenant can never read or write another tenant's memory.
"""

from __future__ import annotations

import logging

from btagent_shared.types.config import TLP
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.db.models_memory import MEMORY_KINDS, AgentMemoryRow
from btagent_backend.services.memory_service import (
    DEFAULT_RECALL_LIMIT,
    MemoryService,
)

logger = logging.getLogger("btagent.api.memory")

router = APIRouter(prefix="/memory", tags=["memory"])

# Sensible default clearance for API recall: an authenticated org member is
# treated as cleared for organization-only (AMBER_STRICT) content, so recall
# surfaces everything up to AMBER_STRICT but withholds TLP:RED (named recipients
# only) facts, which require out-of-band handling.
_API_RECALL_CLEARANCE = TLP.AMBER_STRICT


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #


class RecordMemoryRequest(BaseModel):
    kind: str = Field(..., description="One of entity_note|decision|learning|observation")
    subject: str = Field(..., min_length=1, max_length=512)
    content: str = Field(..., min_length=1, max_length=10_000)
    source: str = Field(default="", max_length=256)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    tlp_level: str = Field(default="green", max_length=20)


class MemoryResponse(BaseModel):
    id: str
    kind: str
    subject: str
    content: str
    source: str
    confidence: float | None
    tlp_level: str
    created_at: str | None
    updated_at: str | None


class MemoryListResponse(BaseModel):
    items: list[MemoryResponse]
    total: int


def _to_response(row: AgentMemoryRow) -> MemoryResponse:
    return MemoryResponse(
        id=row.id,
        kind=row.kind,
        subject=row.subject,
        content=row.content,
        source=row.source,
        confidence=row.confidence,
        tlp_level=row.tlp_level,
        created_at=row.created_at.isoformat() if row.created_at else None,
        updated_at=row.updated_at.isoformat() if row.updated_at else None,
    )


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #


@router.post("", response_model=MemoryResponse, status_code=status.HTTP_201_CREATED)
async def record_memory(
    body: RecordMemoryRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> MemoryResponse:
    """Record (upsert) a long-term memory for the caller's org."""
    user.require_permission("memory:write")

    if body.kind not in MEMORY_KINDS:
        raise HTTPException(
            status_code=422,
            detail=f"Unknown memory kind {body.kind!r}; expected one of {sorted(MEMORY_KINDS)}",
        )

    row = await MemoryService().record_memory(
        db,
        org_id=user.org_id,
        kind=body.kind,
        subject=body.subject,
        content=body.content,
        source=body.source,
        confidence=body.confidence,
        tlp_level=body.tlp_level,
    )
    logger.info("Recorded memory %s (org=%s) by user %s", row.id, user.org_id, user.id)
    return _to_response(row)


@router.get("", response_model=MemoryListResponse)
async def recall_memories(
    subject: str | None = Query(None, max_length=512),
    kind: str | None = Query(None, max_length=32),
    limit: int = Query(DEFAULT_RECALL_LIMIT, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> MemoryListResponse:
    """Recall recency-ranked, TLP-filtered memories for the caller's org."""
    user.require_permission("memory:read")

    rows = await MemoryService().recall_memories(
        db,
        user.org_id,
        subject=subject,
        kind=kind,
        limit=limit,
        caller_tlp=_API_RECALL_CLEARANCE,
    )
    return MemoryListResponse(items=[_to_response(r) for r in rows], total=len(rows))
