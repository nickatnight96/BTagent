"""In-app notifications API.

Surfaces the per-user in-app notification store that
:class:`btagent_backend.services.notification_service.NotificationService`
already writes to (HITL checkpoints, critical findings, investigation-complete
events) but which had no HTTP read surface — the service's ``get_user_
notifications`` / ``mark_read`` / ``mark_all_read`` helpers were documented "for
API endpoints" with no endpoints wired.

Every route is scoped to the authenticated user's own notifications (``user.id``)
— no cross-user access, so no extra RBAC permission beyond being signed in.
Real-time delivery still flows over the WebSocket hub; this API backs the
notification centre's initial load, pagination, and read receipts.
"""

from __future__ import annotations

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.db.models import NotificationRow
from btagent_backend.services.notification_service import NotificationService

logger = logging.getLogger("btagent.api.notifications")

router = APIRouter(prefix="/notifications", tags=["notifications"])


class NotificationRecord(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    type: str
    title: str
    message: str
    investigation_id: str | None
    link: str | None
    read: bool
    created_at: datetime


class NotificationListResponse(BaseModel):
    items: list[NotificationRecord]
    # Total unread across the user's whole store (not just this page) — the
    # notification-bell badge count.
    unread: int


class MarkAllReadResponse(BaseModel):
    marked: int


@router.get("", response_model=NotificationListResponse)
async def list_notifications(
    unread_only: bool = Query(False, description="Return only unread notifications."),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """List the current user's in-app notifications, newest-first."""
    rows = await NotificationService.get_user_notifications(
        db, user.id, unread_only=unread_only, limit=limit, offset=offset
    )
    unread = (
        await db.execute(
            select(func.count())
            .select_from(NotificationRow)
            .where(NotificationRow.user_id == user.id, NotificationRow.read.is_(False))
        )
    ).scalar_one()
    return NotificationListResponse(
        items=[NotificationRecord.model_validate(r) for r in rows], unread=int(unread)
    )


@router.post("/{notification_id}/read", status_code=status.HTTP_204_NO_CONTENT)
async def mark_notification_read(
    notification_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Mark one of the current user's notifications read (404 if not theirs)."""
    ok = await NotificationService.mark_read(db, notification_id, user.id)
    if not ok:
        raise HTTPException(status_code=404, detail="Notification not found")


@router.post("/read-all", response_model=MarkAllReadResponse)
async def mark_all_notifications_read(
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Mark all of the current user's unread notifications read."""
    marked = await NotificationService.mark_all_read(db, user.id)
    return MarkAllReadResponse(marked=int(marked))
