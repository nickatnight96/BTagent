"""Shift-handover API (EPIC-5 UC-5.1).

``GET /api/v1/handover``
    Aggregate the prior shift window (default 8h, ``window_hours`` query
    param) into a structured handover summary: investigations opened or
    touched, the open high-severity backlog, and hunt findings that landed in
    the triage inbox. Org-scoped; RBAC ``investigation:view`` (every analyst
    role) — the punch-list landing surface consumes this at shift start.

Deterministic aggregation over the DB (no LLM); the narrative reasoning-node
polish is a documented follow-up on #108.
"""

from __future__ import annotations

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.services.handover_service import build_handover_summary

logger = logging.getLogger("btagent.api.handover")

router = APIRouter(prefix="/handover", tags=["handover"])


class HandoverInvestigationItem(BaseModel):
    id: str
    title: str
    severity: str
    status: str
    is_new: bool
    updated_at: datetime


class HandoverSummary(BaseModel):
    window_hours: int
    window_start: datetime
    generated_at: datetime
    headline: str
    investigations: list[HandoverInvestigationItem]
    open_by_severity: dict[str, int]
    findings_by_severity: dict[str, int]
    findings_untriaged: int


@router.get("", response_model=HandoverSummary)
async def get_handover(
    window_hours: int = Query(8, ge=1, le=72),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
) -> HandoverSummary:
    """Build the shift-handover summary for the caller's org."""
    user.require_permission("investigation:view")
    summary = await build_handover_summary(db, org_id=user.org_id, window_hours=window_hours)
    return HandoverSummary(**summary)
