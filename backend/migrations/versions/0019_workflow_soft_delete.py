"""Workflow soft-delete marker.

Phase 2 v2 — workflow CRUD follow-ups (#86, item 5).

* ``workflows.deleted_at`` — soft-delete timestamp. NULL = live. Set rows
  are filtered out of every API read path (list / get / versions / runs)
  so the workflow and its children become unreachable through the API,
  while the rows themselves stay in the DB as an audit trail.

Indexed because every workflow read now filters on ``deleted_at IS NULL``.

Revision ID: 0019_workflow_soft_delete
Revises: 0018_investigation_autonomy
Create Date: 2026-06-10
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0019_workflow_soft_delete"
down_revision: str | None = "0018_investigation_autonomy"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "workflows",
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("idx_workflows_deleted_at", "workflows", ["deleted_at"])


def downgrade() -> None:
    op.drop_index("idx_workflows_deleted_at", table_name="workflows")
    op.drop_column("workflows", "deleted_at")
