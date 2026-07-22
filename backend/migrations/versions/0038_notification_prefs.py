"""Add ``notification_prefs`` — per-user muted in-app notification types.

Enforced inside ``NotificationService.send_inapp`` so every producer
respects a mute without knowing about it. One row per user, created
lazily on first PUT; no backfill (absent row = nothing muted). Fully
reversible.

Revision ID: 0038_notification_prefs
Revises: 0037_noise_digest_state
Create Date: 2026-07-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0038_notification_prefs"
down_revision: str | None = "0037_noise_digest_state"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "notification_prefs",
        sa.Column(
            "user_id",
            sa.String(length=64),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("muted_types", JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("notification_prefs")
