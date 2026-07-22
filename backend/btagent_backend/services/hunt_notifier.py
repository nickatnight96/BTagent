"""Critical hunt-finding notification producer.

When a hunt ingest (vertical runner, all-hunts sweep, or scheduled pack run)
lands **critical**-severity findings in the triage inbox, the org's hunt
seniors — everyone holding ``hunt:promote`` — get one summary notification
per ingest batch. Suppressed rows never notify (the analyst already decided
that signal is noise), and non-critical severities stay silent: the bell is
for wake-up-worthy signal, not a mirror of the inbox.

Same conventions as the sibling producers (:mod:`investigation_notifier`,
:mod:`hitl_notifier`): the pure function flushes but never commits — rows
ride the caller's transaction, so a rolled-back ingest can't leave phantom
notifications — and the best-effort wrapper owns a short-lived Redis
connection for the real-time push and swallows every failure after logging.
"""

from __future__ import annotations

import logging
from typing import Any

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.config import Settings, get_settings
from btagent_backend.db.models import NotificationRow
from btagent_backend.db.models_hunt import HuntFindingRow
from btagent_backend.services.notification_service import NotificationService
from btagent_backend.services.role_targeting import user_ids_with_permission

logger = logging.getLogger("btagent.services.hunt_notifier")

_CRITICAL = "critical"
_SUPPRESSED = "suppressed"


def _summary_message(critical: list[HuntFindingRow]) -> str:
    first = critical[0].title
    if len(critical) == 1:
        return f"A critical hunt finding landed in the triage inbox: '{first}'."
    return (
        f"{len(critical)} critical hunt findings landed in the triage inbox: "
        f"'{first}' and {len(critical) - 1} more."
    )


async def notify_critical_findings(
    db: AsyncSession,
    *,
    org_id: str,
    rows: list[HuntFindingRow],
    redis: Any | None = None,
    settings: Settings | None = None,
) -> list[NotificationRow]:
    """One summary notification per hunt senior for a batch's critical rows.

    No-op (returns ``[]``) when the batch has no unsuppressed critical
    findings or the org has no ``hunt:promote`` holders. Flushes but never
    commits — the caller owns the transaction.
    """
    critical = [r for r in rows if r.severity == _CRITICAL and r.state != _SUPPRESSED]
    if not critical:
        return []

    recipients = await user_ids_with_permission(db, org_id=org_id, permission="hunt:promote")
    if not recipients:
        return []

    service = NotificationService(settings or get_settings(), redis=redis)
    message = _summary_message(critical)
    created: list[NotificationRow] = []
    for user_id in recipients:
        row = await service.send_inapp(
            db,
            user_id=user_id,
            notification={
                "type": "critical_finding",
                "title": "Critical Hunt Findings",
                "message": message,
                "investigation_id": None,
                # Bell click lands on the triage inbox where the rows are.
                "link": "/hunt",
            },
        )
        if row is not None:  # skipped when the user muted this type
            created.append(row)
    return created


async def notify_newly_noisy_rules(
    db: AsyncSession,
    *,
    org_id: str,
    rules: list,  # NoisyRule models from services.noise_baseline
    redis: Any | None = None,
    settings: Settings | None = None,
) -> list[NotificationRow]:
    """One digest notification per hunt senior for newly-noisy rules (#112).

    Called by the scheduled noise-digest sweep with the rules that turned
    chronically noisy since the previous run. Advisory: the bell entry
    deep-links to the triage page where the Noisy Rules panel offers the
    one-click rule suppression. Flushes but never commits.
    """
    if not rules:
        return []
    recipients = await user_ids_with_permission(db, org_id=org_id, permission="hunt:promote")
    if not recipients:
        return []

    first = rules[0]
    detail = (
        f"'{first.rule_title}' (hit {round(first.hit_rate * 100)}% of {first.runs_observed} runs)"
    )
    if len(rules) == 1:
        message = f"A pack rule turned chronically noisy: {detail}."
    else:
        message = (
            f"{len(rules)} pack rules turned chronically noisy: {detail} and {len(rules) - 1} more."
        )

    service = NotificationService(settings or get_settings(), redis=redis)
    created: list[NotificationRow] = []
    for user_id in recipients:
        row = await service.send_inapp(
            db,
            user_id=user_id,
            notification={
                "type": "noise_digest",
                "title": "Newly Noisy Rules",
                "message": message,
                "investigation_id": None,
                "link": "/hunt",
            },
        )
        if row is not None:  # skipped when the user muted this type
            created.append(row)
    return created


async def notify_critical_findings_best_effort(
    db: AsyncSession,
    *,
    org_id: str,
    rows: list[HuntFindingRow],
) -> None:
    """Ingest-facing wrapper: own Redis connection, all failures swallowed."""
    redis: Redis | None = None
    try:
        settings = get_settings()
        redis = Redis.from_url(settings.redis_url, decode_responses=True)
        await notify_critical_findings(db, org_id=org_id, rows=rows, redis=redis, settings=settings)
    except Exception:
        logger.exception("Failed to send critical-finding notifications (org=%s)", org_id)
    finally:
        if redis is not None:
            try:
                await redis.aclose()
            except Exception:
                logger.debug(
                    "Redis close after critical-finding notification failed", exc_info=True
                )
