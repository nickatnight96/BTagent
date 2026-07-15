"""Add ``plan_runs`` — per-run HuntPlan execution history (#120 follow-up).

Mirrors ``hunt_pack_runs`` (migration 0021): one row per
``execute_plan_and_ingest`` invocation, so repeated executions of a compiled
plan stop overwriting each other's record. The ``last_run`` summary riding
alongside the plan JSON in ``hunt_plans.plan`` is kept for backward
compatibility — no backfill (pre-table runs only ever kept their latest
summary, so there is nothing to reconstruct), fully reversible.

Revision ID: 0031_plan_runs
Revises: 0030_oauth_grants
Create Date: 2026-07-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0031_plan_runs"
down_revision: str | None = "0030_oauth_grants"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "plan_runs",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(length=64),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "plan_row_id",
            sa.String(length=64),
            sa.ForeignKey("hunt_plans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("proposal_id", sa.String(length=64), nullable=False),
        sa.Column("plan_id", sa.String(length=64), nullable=False),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("ttp_stats", JSONB, nullable=False, server_default="{}"),
        sa.Column("hit_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings_created", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="completed"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("idx_plan_runs_org_started", "plan_runs", ["org_id", "started_at"])
    op.create_index("idx_plan_runs_plan_row", "plan_runs", ["plan_row_id", "started_at"])
    op.create_index("idx_plan_runs_proposal", "plan_runs", ["org_id", "proposal_id"])


def downgrade() -> None:
    op.drop_index("idx_plan_runs_proposal", table_name="plan_runs")
    op.drop_index("idx_plan_runs_plan_row", table_name="plan_runs")
    op.drop_index("idx_plan_runs_org_started", table_name="plan_runs")
    op.drop_table("plan_runs")
