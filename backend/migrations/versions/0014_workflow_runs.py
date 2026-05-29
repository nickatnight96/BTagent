"""Add workflow_runs table (Phase 2 — workflow execution + run history).

Phase 2 made workflows first-class authorable/publishable artifacts but
left them un-runnable: there was no way to execute a version or record
what happened. This migration adds the execution-history store:

* ``workflow_runs`` — one row per execution of a specific workflow
  *version*. Captures the trigger payload, terminal status
  (``succeeded`` / ``failed`` / ``paused``), the per-step output map,
  the final leaf output, the in-order ``nodes_executed`` trail (for
  replay/audit), and an error string on failure.

Org-scoped from day one (FK → ``organizations``) like the rest of the
Phase-2 tables, so the wave-2 tenancy invariant holds without a retrofit.

Revision ID: 0014_workflow_runs
Revises: 0013_sso_identity
Create Date: 2026-05-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0014_workflow_runs"
down_revision: str | None = "0013_sso_identity"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "workflow_runs",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "workflow_id",
            sa.String(64),
            sa.ForeignKey("workflows.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "version_id",
            sa.String(64),
            sa.ForeignKey("workflow_versions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("version_number", sa.Integer, nullable=False),
        sa.Column(
            "org_id",
            sa.String(64),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "triggered_by",
            sa.String(64),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("trigger_payload", JSONB, nullable=False, server_default="{}"),
        sa.Column("outputs", JSONB, nullable=False, server_default="{}"),
        sa.Column("final_output", JSONB, nullable=True),
        sa.Column("nodes_executed", JSONB, nullable=False, server_default="[]"),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("idx_wfr_workflow_id", "workflow_runs", ["workflow_id"])
    op.create_index("idx_wfr_org_id", "workflow_runs", ["org_id"])
    op.create_index("idx_wfr_status", "workflow_runs", ["status"])
    op.create_index("idx_wfr_created_at", "workflow_runs", ["created_at"])


def downgrade() -> None:
    op.drop_index("idx_wfr_created_at", table_name="workflow_runs")
    op.drop_index("idx_wfr_status", table_name="workflow_runs")
    op.drop_index("idx_wfr_org_id", table_name="workflow_runs")
    op.drop_index("idx_wfr_workflow_id", table_name="workflow_runs")
    op.drop_table("workflow_runs")
