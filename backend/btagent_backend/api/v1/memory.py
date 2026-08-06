"""Unified long-term Agent Memory API (#482).

Three org-scoped, RBAC-gated endpoints over the compact-fact memory store:

* ``POST /memory`` — record (upsert) a memory. Gated ``memory:write``
  (senior_analyst+): authoring a fact shapes what every future investigation in
  the org recalls.
* ``GET /memory`` — recall memories by subject / kind. Gated ``memory:read``
  (analyst+), recency-ranked and TLP-aware. Passing ``?query=`` switches to
  SEMANTIC recall (embedding cosine similarity) with the identical org + TLP
  filtering; on a non-PostgreSQL dialect, or with no embedding provider
  available, it degrades to the recency ranking rather than failing.
* ``DELETE /memory/{id}`` — FORGET a memory. Also gated ``memory:write``: the
  store had no delete at all, so a wrong remembered fact could only be papered
  over by overwriting it. The delete is SOFT (``superseded_at`` stamped, the
  same mechanism consolidation uses) so the row drops out of every recall path
  while remaining on the table for audit, and it writes a hash-chain ledger
  entry — an analyst editing what the agent believes is a governance act, not
  a UI convenience.

All three are strictly scoped to the caller's ``org_id`` (taken from the token,
never the request body or path) so one tenant can never read, write, or delete
another tenant's memory. A cross-org id 404s — it is masked as "not found"
rather than refused as "forbidden", which would confirm the row exists.
"""

from __future__ import annotations

import logging

from btagent_shared.types.config import TLP
from btagent_shared.types.enums import AuditCategory, AuditOutcome
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.db.models_memory import MEMORY_KINDS, AgentMemoryRow
from btagent_backend.services.audit_trail import AuditTrail
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
    model_config = ConfigDict(extra="forbid")
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
    # Which ranking produced ``items``: "semantic" when a ``query`` was given
    # (and the vector path was usable), "recency" otherwise. Semantic recall
    # falls back to recency ranking transparently, so this reports the mode the
    # caller ASKED for, not the internal path taken.
    mode: str = "recency"


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
    query: str | None = Query(
        None,
        max_length=2000,
        description=(
            "Free-text query. When set, memories are ranked by semantic "
            "similarity instead of recency (same org + TLP filtering)."
        ),
    ),
    limit: int = Query(DEFAULT_RECALL_LIMIT, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> MemoryListResponse:
    """Recall TLP-filtered memories for the caller's org.

    Default ranking is recency. Supplying ``query`` switches to semantic
    (embedding-similarity) ranking — the org scope and TLP clearance filters
    are byte-for-byte the same on both paths, and the semantic path degrades to
    recency ranking when pgvector is unavailable.
    """
    user.require_permission("memory:read")

    service = MemoryService()
    if query:
        rows = await service.recall_semantic(
            db,
            user.org_id,
            query,
            subject=subject,
            kind=kind,
            limit=limit,
            caller_tlp=_API_RECALL_CLEARANCE,
        )
        mode = "semantic"
    else:
        rows = await service.recall_memories(
            db,
            user.org_id,
            subject=subject,
            kind=kind,
            limit=limit,
            caller_tlp=_API_RECALL_CLEARANCE,
        )
        mode = "recency"
    return MemoryListResponse(items=[_to_response(r) for r in rows], total=len(rows), mode=mode)


@router.delete("/{memory_id}", status_code=status.HTTP_204_NO_CONTENT)
async def forget_memory(
    memory_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> None:
    """Forget a memory (soft delete). 404 if it isn't this org's live memory.

    The missing trust primitive: a recalled fact is injected into every future
    investigation for the org, so an analyst who spots a wrong one needs a way
    to *remove* it, not just outvote it with an overwrite.

    Gated on ``memory:write`` (senior_analyst+) — the same bar as authoring a
    fact, because removing one changes future recall just as decisively.

    SOFT delete: the row is stamped ``superseded_at``, which excludes it from
    every recall path but keeps it on the table, so the removal is reviewable
    and the ledger entry below points at a row that still exists. Re-recording
    the same ``(kind, subject)`` revives it (``record_memory`` clears the
    stamp), which is the intended "I was wrong to forget that" path.
    """
    user.require_permission("memory:write")

    row = await MemoryService().forget_memory(
        db,
        user.org_id,
        memory_id,
        caller_tlp=_API_RECALL_CLEARANCE,
    )
    if row is None:
        # Unknown id, another org's row, one above the caller's TLP clearance,
        # or one already forgotten/consolidated — all indistinguishable from
        # outside, deliberately: a 403 here would confirm the row exists in
        # some other tenant.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Memory not found")

    # An analyst deleting agent memory is a governance-relevant act — it edits
    # what the agent will believe in every future investigation — so it lands
    # on the tamper-evident ledger, not just the app log. The ``details`` carry
    # enough to identify WHICH fact was removed (kind/subject/source/TLP) but
    # deliberately NOT its content: the row survives the soft delete, so the
    # content is still recoverable from the store, and copying an AMBER fact
    # into the ledger would widen its audience to every audit reader.
    await AuditTrail(db).record(
        actor=user.id,
        category=AuditCategory.CONFIG_CHANGE,
        action="memory_forgotten",
        resource=row.id,
        outcome=AuditOutcome.SUCCESS,
        details={
            "org_id": user.org_id,
            "kind": row.kind,
            "subject": row.subject,
            "source": row.source,
            "tlp_level": row.tlp_level,
            "confidence": row.confidence,
            "deletion": "soft",
        },
        org_id=user.org_id,
    )
    await db.commit()
    logger.info(
        "Memory %s forgotten by %s (org=%s, soft delete)", row.id, user.username, user.org_id
    )
