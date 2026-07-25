"""Investigation-outcome notification producer.

First real producer for the in-app notification pipeline (store → API →
bell → WebSocket push): when an investigation reaches a terminal state,
the analyst it is assigned to gets an in-app notification (and Slack,
when the workspace is configured).

Kept separate from :class:`~btagent_backend.services.task_manager.TaskManager`
so the target resolution + dispatch logic is testable with a plain DB
session; the TaskManager calls this from its background task with its own
session/redis and treats any failure as non-fatal (an investigation must
never fail because its completion notice couldn't be delivered).
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.config import Settings, get_settings
from btagent_backend.db.models import InvestigationRow, NotificationRow
from btagent_backend.services.notification_service import NotificationService

logger = logging.getLogger("btagent.services.investigation_notifier")

#: Terminal status that routes to the failure notification instead of the
#: completion one (matches ``InvestigationStatus.FAILED.value``).
FAILED_STATUS = "failed"


def _format_duration(duration_seconds: float | None) -> str:
    if duration_seconds is None:
        return "unknown"
    if duration_seconds >= 60:
        minutes, seconds = divmod(int(duration_seconds), 60)
        return f"{minutes}m {seconds}s"
    return f"{duration_seconds:.0f}s"


async def notify_investigation_outcome(
    db: AsyncSession,
    *,
    investigation_id: str,
    final_status: str,
    error: str | None = None,
    duration_seconds: float | None = None,
    finding_count: int = 0,
    redis: Any | None = None,
    settings: Settings | None = None,
    http: Any | None = None,
) -> NotificationRow | None:
    """Notify the assigned analyst that an investigation reached a terminal state.

    Resolves the target from ``InvestigationRow.assigned_to``; unassigned
    (or unknown) investigations produce no notification and return ``None``.
    ``final_status == "failed"`` routes to the failure notification (with
    ``error`` in the message), anything else to the completion one.

    Flushes but never commits — the caller owns the transaction.
    """
    row = await db.get(InvestigationRow, investigation_id)
    if row is None:
        logger.debug("notify_investigation_outcome: unknown investigation %s", investigation_id)
        return None
    if not row.assigned_to:
        logger.debug(
            "notify_investigation_outcome: investigation %s is unassigned — skipping",
            investigation_id,
        )
        return None

    service = NotificationService(settings or get_settings(), redis=redis)
    # The completion / failure dispatch fans out to Slack via
    # ``NotificationService.send_slack``, which no-ops unless the service's
    # httpx client is live. Unlike the in-app-only sibling producers
    # (hunt_notifier / hitl_notifier), this path actually needs that client —
    # without starting it the Slack leg was silently skipped. Start it here and
    # always close it. Tests inject a mock via ``http`` to assert dispatch
    # without real network I/O (and own the mock's lifecycle themselves).
    owns_http = http is None
    if owns_http:
        await service.start()
    else:
        service._http = http
    try:
        if final_status == FAILED_STATUS:
            return await service.notify_investigation_failed(
                db,
                investigation_id,
                error=error or "unknown error",
                user_id=row.assigned_to,
            )
        return await service.notify_investigation_complete(
            db,
            investigation_id,
            {
                "status": final_status,
                "finding_count": finding_count,
                "duration": _format_duration(duration_seconds),
            },
            user_id=row.assigned_to,
        )
    finally:
        if owns_http:
            await service.stop()
