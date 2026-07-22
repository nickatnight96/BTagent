"""Notification service — Slack Block Kit + in-app notifications via Redis pub/sub."""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx
from btagent_shared.utils.ids import generate_id
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.config import Settings
from btagent_backend.db.models import NotificationPrefRow, NotificationRow

logger = logging.getLogger("btagent.services.notifications")


class NotificationService:
    """Send notifications via Slack and/or in-app (DB + Redis WebSocket push)."""

    def __init__(self, settings: Settings, redis: Any | None = None) -> None:
        self.slack_token: str = settings.slack_bot_token
        self.slack_channel: str = settings.slack_channel
        self._redis = redis
        self._http: httpx.AsyncClient | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        self._http = httpx.AsyncClient(timeout=10.0)

    async def stop(self) -> None:
        if self._http:
            await self._http.aclose()
            self._http = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def notify_hitl_checkpoint(
        self,
        db: AsyncSession,
        investigation_id: str,
        checkpoint_data: dict[str, Any],
        *,
        user_id: str | None = None,
    ) -> None:
        """Send HITL approval request to Slack + in-app."""
        action = checkpoint_data.get("action", "Unknown action")
        reason = checkpoint_data.get("reason", "Agent requires human approval.")
        checkpoint_id = checkpoint_data.get("checkpoint_id", "")

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": ":rotating_light: HITL Approval Required",
                },
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Investigation:*\n`{investigation_id}`",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Action:*\n{action}",
                    },
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Reason:*\n{reason}",
                },
            },
            {
                "type": "actions",
                "block_id": f"hitl_{checkpoint_id}",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Approve"},
                        "style": "primary",
                        "action_id": "hitl_approve",
                        "value": json.dumps(
                            {
                                "investigation_id": investigation_id,
                                "checkpoint_id": checkpoint_id,
                            }
                        ),
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Reject"},
                        "style": "danger",
                        "action_id": "hitl_reject",
                        "value": json.dumps(
                            {
                                "investigation_id": investigation_id,
                                "checkpoint_id": checkpoint_id,
                            }
                        ),
                    },
                ],
            },
        ]

        await self.send_slack(blocks, text=f"HITL approval required for {investigation_id}")

        if user_id:
            await self.send_inapp(
                db,
                user_id=user_id,
                notification={
                    "type": "hitl_checkpoint",
                    "title": "HITL Approval Required",
                    "message": f"Action '{action}' needs approval: {reason}",
                    "investigation_id": investigation_id,
                },
            )

    async def notify_critical_finding(
        self,
        db: AsyncSession,
        investigation_id: str,
        finding: dict[str, Any],
        *,
        user_id: str | None = None,
    ) -> None:
        """Alert on critical/high severity findings."""
        severity = finding.get("severity", "high")
        title = finding.get("title", "Critical finding detected")
        description = finding.get("description", "")
        emoji = ":red_circle:" if severity == "critical" else ":large_orange_circle:"

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} {severity.upper()} Finding",
                },
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Investigation:*\n`{investigation_id}`",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:*\n{severity.upper()}",
                    },
                ],
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{title}*\n{description}",
                },
            },
        ]

        await self.send_slack(
            blocks,
            text=f"{severity.upper()} finding in {investigation_id}: {title}",
        )

        if user_id:
            await self.send_inapp(
                db,
                user_id=user_id,
                notification={
                    "type": "critical_finding",
                    "title": f"{severity.upper()}: {title}",
                    "message": description,
                    "investigation_id": investigation_id,
                },
            )

    async def notify_investigation_complete(
        self,
        db: AsyncSession,
        investigation_id: str,
        summary: dict[str, Any],
        *,
        user_id: str | None = None,
    ) -> NotificationRow | None:
        """Notify when investigation completes.

        Returns the created in-app :class:`NotificationRow` when ``user_id``
        was given, else ``None`` (Slack-only path).
        """
        status = summary.get("status", "completed")
        finding_count = summary.get("finding_count", 0)
        duration = summary.get("duration", "unknown")

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": ":white_check_mark: Investigation Complete",
                },
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Investigation:*\n`{investigation_id}`",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Status:*\n{status}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Findings:*\n{finding_count}",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Duration:*\n{duration}",
                    },
                ],
            },
        ]

        await self.send_slack(
            blocks,
            text=f"Investigation {investigation_id} complete ({finding_count} findings)",
        )

        if user_id:
            return await self.send_inapp(
                db,
                user_id=user_id,
                notification={
                    "type": "investigation_complete",
                    "title": "Investigation Complete",
                    "message": (
                        f"Investigation finished with status '{status}'. "
                        f"{finding_count} finding(s) in {duration}."
                    ),
                    "investigation_id": investigation_id,
                },
            )
        return None

    async def notify_investigation_failed(
        self,
        db: AsyncSession,
        investigation_id: str,
        *,
        error: str,
        user_id: str | None = None,
    ) -> NotificationRow | None:
        """Notify when an investigation fails (unexpected engine error)."""
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": ":x: Investigation Failed",
                },
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Investigation:*\n`{investigation_id}`",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Error:*\n{error}",
                    },
                ],
            },
        ]

        await self.send_slack(
            blocks,
            text=f"Investigation {investigation_id} failed: {error}",
        )

        if user_id:
            return await self.send_inapp(
                db,
                user_id=user_id,
                notification={
                    "type": "investigation_failed",
                    "title": "Investigation Failed",
                    "message": f"Investigation stopped with an error: {error}",
                    "investigation_id": investigation_id,
                },
            )
        return None

    # ------------------------------------------------------------------
    # Slack
    # ------------------------------------------------------------------

    async def send_slack(
        self,
        blocks: list[dict[str, Any]],
        *,
        text: str = "",
        channel: str | None = None,
    ) -> bool:
        """Send Slack message using Block Kit. Gracefully skip if not configured."""
        if not self.slack_token or not self.slack_channel:
            logger.debug("Slack not configured — skipping notification")
            return False

        if self._http is None:
            logger.debug("HTTP client not initialised — skipping Slack notification")
            return False

        target_channel = channel or self.slack_channel
        payload = {
            "channel": target_channel,
            "text": text,
            "blocks": blocks,
        }

        try:
            resp = await self._http.post(
                "https://slack.com/api/chat.postMessage",
                json=payload,
                headers={
                    "Authorization": f"Bearer {self.slack_token}",
                    "Content-Type": "application/json",
                },
            )
            data = resp.json()
            if not data.get("ok"):
                logger.warning(
                    "Slack API error: %s",
                    data.get("error", "unknown"),
                )
                return False

            logger.info("Slack message sent to channel %s", target_channel)
            return True

        except httpx.HTTPError as exc:
            logger.warning("Slack HTTP error (non-fatal): %s", exc)
            return False

    # ------------------------------------------------------------------
    # In-app
    # ------------------------------------------------------------------

    async def send_inapp(
        self,
        db: AsyncSession,
        *,
        user_id: str,
        notification: dict[str, Any],
    ) -> NotificationRow | None:
        """Store in-app notification in DB and push via Redis WebSocket channel.

        Respects the user's mute preferences: a type the user muted (see
        :class:`NotificationPrefRow`) is silently skipped and ``None`` is
        returned — the single chokepoint every producer flows through.
        """
        ntf_type = notification.get("type", "info")
        pref = await db.get(NotificationPrefRow, user_id)
        if pref is not None and ntf_type in (pref.muted_types or []):
            logger.debug("Notification type %s muted by user %s — skipping", ntf_type, user_id)
            return None

        row = NotificationRow(
            id=generate_id("ntf"),
            user_id=user_id,
            type=notification.get("type", "info"),
            title=notification.get("title", ""),
            message=notification.get("message", ""),
            investigation_id=notification.get("investigation_id"),
            link=notification.get("link"),
            read=False,
        )
        db.add(row)
        await db.flush()

        # Push via Redis pub/sub so the WebSocket hub can deliver in real-time
        if self._redis:
            ws_payload = json.dumps(
                {
                    "id": row.id,
                    "type": row.type,
                    "title": row.title,
                    "message": row.message,
                    "investigation_id": row.investigation_id,
                    "link": row.link,
                    "read": False,
                    "created_at": row.created_at.isoformat() if row.created_at else None,
                }
            )
            channel = f"btagent:notifications:{user_id}"
            try:
                await self._redis.publish(channel, ws_payload)
                logger.debug("Pushed notification %s to %s", row.id, channel)
            except Exception:
                logger.warning("Failed to push notification %s via Redis (non-fatal)", row.id)

        logger.info(
            "In-app notification %s created for user %s (type=%s)",
            row.id,
            user_id,
            row.type,
        )
        return row

    # ------------------------------------------------------------------
    # Read helpers (for API endpoints)
    # ------------------------------------------------------------------

    @staticmethod
    async def get_user_notifications(
        db: AsyncSession,
        user_id: str,
        *,
        unread_only: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> list[NotificationRow]:
        """Fetch notifications for a user."""
        query = (
            select(NotificationRow)
            .where(NotificationRow.user_id == user_id)
            .order_by(NotificationRow.created_at.desc())
        )
        if unread_only:
            query = query.where(NotificationRow.read.is_(False))
        query = query.offset(offset).limit(limit)
        result = await db.execute(query)
        return list(result.scalars().all())

    @staticmethod
    async def mark_read(
        db: AsyncSession,
        notification_id: str,
        user_id: str,
    ) -> bool:
        """Mark a single notification as read. Returns True if found."""
        result = await db.execute(
            update(NotificationRow)
            .where(
                NotificationRow.id == notification_id,
                NotificationRow.user_id == user_id,
            )
            .values(read=True)
        )
        return result.rowcount > 0

    @staticmethod
    async def mark_all_read(db: AsyncSession, user_id: str) -> int:
        """Mark all notifications as read for a user. Returns count updated."""
        result = await db.execute(
            update(NotificationRow)
            .where(
                NotificationRow.user_id == user_id,
                NotificationRow.read.is_(False),
            )
            .values(read=True)
        )
        return result.rowcount
