"""Add investigation_id to workflow_runs so runs can inherit an investigation's
classification context (TLP) and be traced back from run history.

The run API now accepts an optional ``investigation_id`` on the request body.
When supplied the route looks the investigation up (org-scoped), uses its
``tlp_level`` as the run's ``active_tlp`` (unless the body overrides) and
persists the link on the run row so the analyst can pivot from a run record
back to its originating investigation.

Nullable: workflow runs that don't originate from an investigation (e.g. an
ad-hoc launch from the canvas, or a future webhook trigger) still record
cleanly with this column NULL.

Revision ID: 0016_workflow_run_inv_link
Revises: 0015_workflow_run_evidence_chain
Create Date: 2026-05-30

The descriptive form ``0016_workflow_run_investigation_link`` was 36 chars
and would overrun Alembic's standard ``alembic_version.version_num
VARCHAR(32)`` column at upgrade time on Postgres -- SQLite-based tests
happen not to enforce the constraint, but a real deploy would fail.
Truncated to ``0016_workflow_run_inv_link`` (26 chars).
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0016_workflow_run_inv_link"
down_revision: str | None = "0015_workflow_run_evidence_chain"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "workflow_runs",
        sa.Column(
            "investigation_id",
            sa.String(64),
            sa.ForeignKey("investigations.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("idx_wfr_investigation_id", "workflow_runs", ["investigation_id"])


def downgrade() -> None:
    op.drop_index("idx_wfr_investigation_id", table_name="workflow_runs")
    op.drop_column("workflow_runs", "investigation_id")
