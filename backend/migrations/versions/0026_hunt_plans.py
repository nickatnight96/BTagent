"""Add ``hunt_plans`` — persisted HuntPlan per accepted proposal (#120 Phase C slice 2).

Accepting a pattern-hunt proposal now compiles its ``HuntInput`` into a
runnable ``HuntPlan`` (see ``services/proposal_huntplan.py``). This table is
where the compiled plan lands: one row per proposal (unique index), with a
row-level compile lifecycle (``pending`` → ``ready`` | ``failed``) separate
from the plan JSON's own ``HuntPlanState`` execution lifecycle.

Revision ID: 0026_hunt_plans
Revises: 0025_behavioral_pattern_key
Create Date: 2026-07-05
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0026_hunt_plans"
down_revision: str | None = "0025_behavioral_pattern_key"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "hunt_plans",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(length=64),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "proposal_id",
            sa.String(length=64),
            sa.ForeignKey("pattern_hunt_proposals.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="pending"),
        sa.Column("plan", JSONB, nullable=True),
        sa.Column("error", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("idx_hunt_plans_org_id", "hunt_plans", ["org_id"])
    op.create_index("idx_hunt_plans_proposal", "hunt_plans", ["proposal_id"], unique=True)
    op.create_index("idx_hunt_plans_status", "hunt_plans", ["org_id", "status"])


def downgrade() -> None:
    op.drop_index("idx_hunt_plans_status", table_name="hunt_plans")
    op.drop_index("idx_hunt_plans_proposal", table_name="hunt_plans")
    op.drop_index("idx_hunt_plans_org_id", table_name="hunt_plans")
    op.drop_table("hunt_plans")
