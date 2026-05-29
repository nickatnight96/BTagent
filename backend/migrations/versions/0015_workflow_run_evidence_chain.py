"""Add evidence_chain column to workflow_runs.

The workflow-run path now executes through the engine middleware chain,
including ``EvidenceChainMiddleware`` which builds a hash-linked audit
trail per successful node run. This migration persists that trail on the
run row so the analyst UI / forensics tooling can replay it.

Revision ID: 0015_workflow_run_evidence_chain
Revises: 0014_workflow_runs
Create Date: 2026-05-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0015_workflow_run_evidence_chain"
down_revision: str | None = "0014_workflow_runs"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "workflow_runs",
        sa.Column("evidence_chain", JSONB, nullable=False, server_default="[]"),
    )


def downgrade() -> None:
    op.drop_column("workflow_runs", "evidence_chain")
