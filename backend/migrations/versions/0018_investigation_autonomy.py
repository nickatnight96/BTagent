"""Investigation autonomy level + workflow run autonomy snapshot.

Phase-4 follow-up #2 (investigation ``autonomy_level`` inheritance).

* ``investigations.autonomy_level`` -- the HITL autonomy posture for agent
  work performed under this investigation (``L0``..``L4``). Defaults to
  ``L2`` (supervised), matching the previous hardcoded default.
* ``workflow_runs.agent_autonomy`` -- snapshot of the autonomy the run was
  created under (inherited from its investigation, or the L2 default), so a
  resume re-executes with the same posture instead of silently reverting.
  Mirrors how ``active_tlp`` is snapshotted (0017).

Both defaulted so existing rows migrate cleanly.

Revision ID: 0018_investigation_autonomy
Revises: 0017_workflow_run_resume
Create Date: 2026-06-10
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0018_investigation_autonomy"
down_revision: str | None = "0017_workflow_run_resume"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "investigations",
        sa.Column("autonomy_level", sa.String(8), nullable=False, server_default="L2"),
    )
    op.add_column("workflow_runs", sa.Column("agent_autonomy", sa.String(8), nullable=True))


def downgrade() -> None:
    op.drop_column("workflow_runs", "agent_autonomy")
    op.drop_column("investigations", "autonomy_level")
