"""Per-user PunchList layout preference table (EPIC-5 role-tuned views, #108).

``dashboard_prefs`` stores a user's saved ``DashboardLayout`` payload; the
absence of a row means "use the role default", resolved at read time by the
config API. One row per user (PK = user_id), cascade-deleted with the user.
Fully reversible.

Revision ID: 0050_dashboard_prefs
Revises: 0049_playbook_exec_org_id
Create Date: 2026-07-25
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0050_dashboard_prefs"
down_revision: str | None = "0049_playbook_exec_org_id"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "dashboard_prefs",
        sa.Column(
            "user_id",
            sa.String(64),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("layout", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("dashboard_prefs")
