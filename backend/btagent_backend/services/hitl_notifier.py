"""HITL-gate notification producer for workflow runs.

Counterpart to :mod:`investigation_notifier` for the workflow engine: when a
run pauses at a HITL gate (either on the initial execute or when a *later*
gate trips during a resume), the analyst who triggered the run gets an
in-app notification so the run doesn't sit unnoticed awaiting approval.

Two audiences per pause:

* the **triggering analyst** (``notify_workflow_paused``) — their run
  stopped and needs someone's sign-off;
* the org's **approvers** (``notify_workflow_paused_approvers``) — every
  user whose role grants ``hitl:approve`` (derived from the RBAC table,
  not hardcoded), because they are the ones who can actually unblock it.
  The triggering user is excluded from the fan-out so a self-approving
  senior doesn't get told twice.

The pure functions reuse the request's DB session — notification rows
commit atomically with the paused run row via ``get_db``. The best-effort
wrapper manages a short-lived Redis connection for the real-time WebSocket
push and swallows every failure after logging: a run's HTTP response must
never fail because its pause notice couldn't be delivered.
"""

from __future__ import annotations

import logging
from typing import Any

from btagent_shared.types.workflow import WorkflowRunStatus
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.auth.rbac import PERMISSIONS, ROLE_HIERARCHY
from btagent_backend.config import Settings, get_settings
from btagent_backend.db.models import NotificationRow, UserRow
from btagent_backend.db.models_workflow import WorkflowRow, WorkflowRunRow
from btagent_backend.services.notification_service import NotificationService

logger = logging.getLogger("btagent.services.hitl_notifier")

# Roles whose rank meets the hitl:approve threshold (senior_analyst+ today).
# Derived from the RBAC table so a future permission change propagates here.
_APPROVER_ROLES: tuple[str, ...] = tuple(
    role.value
    for role, rank in ROLE_HIERARCHY.items()
    if rank >= ROLE_HIERARCHY[PERMISSIONS["hitl:approve"]]
)


async def notify_workflow_paused(
    db: AsyncSession,
    *,
    workflow: WorkflowRow,
    run: WorkflowRunRow,
    redis: Any | None = None,
    settings: Settings | None = None,
) -> NotificationRow | None:
    """Notify the run's triggering analyst that it paused at a HITL gate.

    No-op (returns ``None``) when the run isn't paused or has no
    ``triggered_by`` (e.g. system-triggered runs). Flushes but never
    commits — the caller owns the transaction.
    """
    if run.status != WorkflowRunStatus.PAUSED.value:
        return None
    if not run.triggered_by:
        logger.debug("notify_workflow_paused: run %s has no triggered_by — skipping", run.id)
        return None

    service = NotificationService(settings or get_settings(), redis=redis)
    return await service.send_inapp(
        db,
        user_id=run.triggered_by,
        notification={
            "type": "hitl_checkpoint",
            "title": "Workflow Awaiting Approval",
            "message": (
                f"Workflow '{workflow.name}' paused at step "
                f"'{run.paused_node_id}' — approval required to continue "
                f"(run {run.id})."
            ),
            "investigation_id": run.investigation_id,
        },
    )


async def notify_workflow_paused_approvers(
    db: AsyncSession,
    *,
    workflow: WorkflowRow,
    run: WorkflowRunRow,
    redis: Any | None = None,
    settings: Settings | None = None,
) -> list[NotificationRow]:
    """Fan the pause out to every org user who can approve the gate.

    Targets users in the run's org whose role grants ``hitl:approve``,
    excluding ``triggered_by`` (already notified with the trigger-facing
    message by :func:`notify_workflow_paused`). Returns the created rows
    (empty when the run isn't paused or nobody qualifies). Flushes but
    never commits.
    """
    if run.status != WorkflowRunStatus.PAUSED.value:
        return []

    result = await db.execute(
        select(UserRow.id).where(
            UserRow.org_id == run.org_id,
            UserRow.role.in_(_APPROVER_ROLES),
        )
    )
    approver_ids = [uid for (uid,) in result.all() if uid != run.triggered_by]
    if not approver_ids:
        return []

    service = NotificationService(settings or get_settings(), redis=redis)
    rows: list[NotificationRow] = []
    for user_id in approver_ids:
        rows.append(
            await service.send_inapp(
                db,
                user_id=user_id,
                notification={
                    "type": "hitl_checkpoint",
                    "title": "Approval Requested",
                    "message": (
                        f"Workflow '{workflow.name}' is awaiting approval at step "
                        f"'{run.paused_node_id}' (run {run.id})."
                    ),
                    "investigation_id": run.investigation_id,
                },
            )
        )
    return rows


async def notify_workflow_paused_best_effort(
    db: AsyncSession,
    *,
    workflow: WorkflowRow,
    run: WorkflowRunRow,
) -> None:
    """Route-facing wrapper: own Redis connection, all failures swallowed."""
    redis: Redis | None = None
    try:
        settings = get_settings()
        redis = Redis.from_url(settings.redis_url, decode_responses=True)
        await notify_workflow_paused(db, workflow=workflow, run=run, redis=redis, settings=settings)
        await notify_workflow_paused_approvers(
            db, workflow=workflow, run=run, redis=redis, settings=settings
        )
    except Exception:
        logger.exception("Failed to send workflow-pause notification for run %s", run.id)
    finally:
        if redis is not None:
            try:
                await redis.aclose()
            except Exception:
                logger.debug("Redis close after pause notification failed", exc_info=True)
