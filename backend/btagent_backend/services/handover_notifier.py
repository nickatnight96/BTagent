"""Shift-handover digest producer (EPIC-5 UC-5.1, #108).

At shift boundaries the scheduled sweep pushes each org's handover rollup to
every analyst (``investigation:view``) as an in-app notification: the same
deterministic headline the PunchList Handover card shows, so the incoming
shift gets pinged even before they open the app. Quiet windows stay silent —
a shift with no new activity, nothing untriaged, and an empty open backlog
is not wake-up-worthy.

Same conventions as the sibling producers (:mod:`hunt_notifier`,
:mod:`investigation_notifier`): flushes but never commits — rows ride the
caller's transaction.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.config import Settings, get_settings
from btagent_backend.db.models import NotificationRow
from btagent_backend.services.handover_service import build_handover_summary
from btagent_backend.services.notification_service import NotificationService
from btagent_backend.services.role_targeting import user_ids_with_permission

logger = logging.getLogger("btagent.services.handover_notifier")


async def notify_shift_handover(
    db: AsyncSession,
    *,
    org_id: str,
    window_hours: int = 8,
    redis: Any | None = None,
    settings: Settings | None = None,
) -> list[NotificationRow]:
    """Send the org's shift-handover headline to every analyst.

    Returns the created notification rows (empty for a quiet window or an
    org with no eligible recipients). Flushes but never commits.
    """
    summary = await build_handover_summary(db, org_id=org_id, window_hours=window_hours)

    had_activity = (
        bool(summary["investigations"])
        or summary["findings_untriaged"] > 0
        or sum(summary["findings_by_severity"].values()) > 0
        or sum(summary["open_by_severity"].values()) > 0
    )
    if not had_activity:
        return []

    recipients = await user_ids_with_permission(db, org_id=org_id, permission="investigation:view")
    if not recipients:
        return []

    service = NotificationService(settings or get_settings(), redis=redis)
    created: list[NotificationRow] = []
    for user_id in recipients:
        row = await service.send_inapp(
            db,
            user_id=user_id,
            notification={
                "type": "shift_handover",
                "title": "Shift Handover",
                "message": summary["headline"],
                "investigation_id": None,
                # The PunchList opens with the full Handover card.
                "link": "/",
            },
        )
        if row is not None:  # skipped when the user muted this type
            created.append(row)
    return created
