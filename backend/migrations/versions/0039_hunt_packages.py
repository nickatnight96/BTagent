"""Add ``hunt_packages`` — persisted advisory hunt packages (#99 / UC-2.2).

``POST /hunts/package`` previously returned a transient object; this table
makes the artifact durable so packages are listable and re-openable from
history. Full package as JSON + denormalised list columns. No backfill
(pre-table packages were never stored anywhere), fully reversible.

Revision ID: 0039_hunt_packages
Revises: 0038_notification_prefs
Create Date: 2026-07-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0039_hunt_packages"
down_revision: str | None = "0038_notification_prefs"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "hunt_packages",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(length=64),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "created_by",
            sa.String(length=64),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("source_label", sa.String(length=200), nullable=False),
        sa.Column("extracted_ioc_count", sa.Integer(), nullable=False),
        sa.Column("deduped_count", sa.Integer(), nullable=False),
        sa.Column("techniques", JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("mock_mode", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("package", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("idx_hunt_packages_org_created", "hunt_packages", ["org_id", "created_at"])


def downgrade() -> None:
    op.drop_index("idx_hunt_packages_org_created", table_name="hunt_packages")
    op.drop_table("hunt_packages")
