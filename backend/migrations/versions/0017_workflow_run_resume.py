"""Add resume/checkpoint columns to workflow_runs.

Phase-4 follow-up #1 (paused-run resume). A paused run now carries enough
state to be resumed after a human approves the paused step:

* ``active_tlp`` -- the classification context the run executed under, so a
  resume reuses the same posture (drives the ConnectorPolicy TLP gate).
* ``paused_node_id`` -- the step the run is paused at (the node awaiting
  approval); cleared on a terminal transition.
* ``approved_steps`` -- step ids approved across resume cycles, whose gate
  is bypassed on subsequent executions.

All nullable / defaulted so existing rows migrate cleanly.

Revision ID: 0017_workflow_run_resume
Revises: 0016_workflow_run_inv_link
Create Date: 2026-06-09
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0017_workflow_run_resume"
down_revision: str | None = "0016_workflow_run_inv_link"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("workflow_runs", sa.Column("active_tlp", sa.String(20), nullable=True))
    op.add_column("workflow_runs", sa.Column("paused_node_id", sa.String(64), nullable=True))
    op.add_column(
        "workflow_runs",
        sa.Column("approved_steps", JSONB, nullable=False, server_default="[]"),
    )


def downgrade() -> None:
    op.drop_column("workflow_runs", "approved_steps")
    op.drop_column("workflow_runs", "paused_node_id")
    op.drop_column("workflow_runs", "active_tlp")
