"""Relax ``hunt_plans.proposal_id`` to nullable — direct plans (#99 Phase A).

``POST /hunts/plan`` now persists analyst-initiated plans that have no
pattern-hunt proposal behind them; NULL ``proposal_id`` marks those rows.
The unique index on ``proposal_id`` is unaffected (Postgres unique indexes
admit multiple NULLs), so the one-plan-per-proposal invariant still holds
for the proposal path. Reversible; the downgrade deletes direct rows first
because they cannot satisfy NOT NULL.

Revision ID: 0041_hunt_plans_direct
Revises: 0040_hunt_package_investigation
Create Date: 2026-07-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0041_hunt_plans_direct"
down_revision: str | None = "0040_hunt_package_investigation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column(
        "hunt_plans",
        "proposal_id",
        existing_type=sa.String(length=64),
        nullable=True,
    )


def downgrade() -> None:
    op.execute("DELETE FROM hunt_plans WHERE proposal_id IS NULL")
    op.alter_column(
        "hunt_plans",
        "proposal_id",
        existing_type=sa.String(length=64),
        nullable=False,
    )
