"""Add ``technique_exercises`` — per-org TTP exercise tracking (#99 Phase C).

Every hunt-plan execution upserts one row per hunted technique so the
coverage map can answer "which techniques haven't been exercised in
>N days?". No FK to ``mitre_techniques`` (hypotheses may cite techniques
newer than the seeded corpus). No backfill, fully reversible.

Revision ID: 0043_technique_exercises
Revises: 0042_plan_runs_direct
Create Date: 2026-07-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0043_technique_exercises"
down_revision: str | None = "0042_plan_runs_direct"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "technique_exercises",
        sa.Column(
            "org_id",
            sa.String(length=64),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("technique_id", sa.String(length=20), primary_key=True),
        sa.Column("last_exercised_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_plan_id", sa.String(length=64), nullable=False),
        sa.Column("last_run_id", sa.String(length=64), nullable=False),
        sa.Column("last_outcome", sa.String(length=16), nullable=False),
        sa.Column("exercise_count", sa.Integer(), nullable=False, server_default="1"),
    )
    op.create_index(
        "idx_technique_exercises_org_at",
        "technique_exercises",
        ["org_id", "last_exercised_at"],
    )


def downgrade() -> None:
    op.drop_index("idx_technique_exercises_org_at", table_name="technique_exercises")
    op.drop_table("technique_exercises")
