"""Relax ``plan_runs.proposal_id`` to nullable — direct-plan runs (#99).

``POST /hunts/plans/{id}/execute`` runs analyst-initiated plans that have
no pattern-hunt proposal behind them (hunt_plans.proposal_id NULL since
0041); their run-history rows carry NULL here too. Reversible; the
downgrade deletes direct-run rows first because they cannot satisfy
NOT NULL.

Revision ID: 0042_plan_runs_direct
Revises: 0041_hunt_plans_direct
Create Date: 2026-07-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0042_plan_runs_direct"
down_revision: str | None = "0041_hunt_plans_direct"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column(
        "plan_runs",
        "proposal_id",
        existing_type=sa.String(length=64),
        nullable=True,
    )


def downgrade() -> None:
    op.execute("DELETE FROM plan_runs WHERE proposal_id IS NULL")
    op.alter_column(
        "plan_runs",
        "proposal_id",
        existing_type=sa.String(length=64),
        nullable=False,
    )
