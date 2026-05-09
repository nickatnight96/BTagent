"""Add notifications and org_config tables.

Revision ID: 0002
Revises: 0001
Create Date: 2026-03-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Notifications — in-app notifications for HITL, findings, investigation status
    op.create_table(
        "notifications",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "user_id",
            sa.String(64),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("type", sa.String(50), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("message", sa.Text, server_default=""),
        sa.Column(
            "investigation_id",
            sa.String(64),
            sa.ForeignKey("investigations.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("read", sa.Boolean, server_default="false", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )
    op.create_index("idx_notifications_user", "notifications", ["user_id"])
    op.create_index(
        "idx_notifications_user_read",
        "notifications",
        ["user_id", "read"],
    )
    op.create_index(
        "idx_notifications_created",
        "notifications",
        ["created_at"],
    )

    # Org config — key/value store for admin-configurable settings (org profile, etc.)
    op.create_table(
        "org_config",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("key", sa.String(200), unique=True, nullable=False),
        sa.Column("value", JSONB, server_default="{}"),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.Column("updated_by", sa.String(64), nullable=True),
    )
    op.create_index("idx_org_config_key", "org_config", ["key"], unique=True)


def downgrade() -> None:
    op.drop_table("org_config")
    op.drop_table("notifications")
