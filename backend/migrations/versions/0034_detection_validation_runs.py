"""Add ``detection_validation_runs`` — detection-validation run history (#118).

Persists each ``ValidationReport`` (previously a transient return value) so
analysts can diff detection coverage over time. The summary pivots
(``detected_pct`` / ``total_techniques`` / ``gaps``) are denormalised columns;
the full per-technique payload rides in ``coverage_by_technique`` JSONB. No
backfill (pre-table runs were never persisted), fully reversible. Mirrors the
``plan_runs`` history table (migration 0031).

Revision ID: 0034_detection_validation_runs
Revises: 0033_proposal_triage_rationale
Create Date: 2026-07-21
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0034_detection_validation_runs"
down_revision: str | None = "0033_proposal_triage_rationale"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "detection_validation_runs",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(length=64),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("run_id", sa.String(length=200), nullable=False),
        sa.Column("packs", JSONB, nullable=False, server_default="[]"),
        sa.Column("scenarios_run", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("total_techniques", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("detected_pct", sa.Float(), nullable=False, server_default="0"),
        sa.Column("gaps", JSONB, nullable=False, server_default="[]"),
        sa.Column("coverage_by_technique", JSONB, nullable=False, server_default="[]"),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "idx_detection_validation_runs_org_created",
        "detection_validation_runs",
        ["org_id", "created_at"],
    )
    op.create_index(
        "idx_detection_validation_runs_run_id",
        "detection_validation_runs",
        ["org_id", "run_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "idx_detection_validation_runs_run_id", table_name="detection_validation_runs"
    )
    op.drop_index(
        "idx_detection_validation_runs_org_created", table_name="detection_validation_runs"
    )
    op.drop_table("detection_validation_runs")
