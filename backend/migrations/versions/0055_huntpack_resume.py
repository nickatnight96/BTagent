"""Add ``hunt_pack_runs.progress`` resume cursor + resume-lookup index (#112).

Resume-from-checkpoint for scheduled hunt-pack runs (acceptance criterion
"survives worker restart"). A run now advertises an in-flight ``running``
status and records, per rule, which rules it has already converted + ingested
under ``progress`` (``{"completed_rule_ids": [...]}``). The runner writes this
cursor incrementally — one commit per rule — so a worker that dies mid-run
resumes at the first not-yet-completed rule rather than re-doing finished work
(and re-emitting its findings).

* ``progress`` — JSONB, non-null, defaults ``{}`` (a legacy row / a run that
  never checkpointed carries an empty cursor and is treated as "nothing done
  yet"). No backfill needed: completed historical rows have a terminal status
  and are never resumed.
* ``idx_hunt_pack_runs_org_pack_status`` — serves the resume lookup (newest
  ``running`` row for an ``(org_id, pack_id)``) in one index scan.

Fully reversible.

Revision ID: 0055_huntpack_resume
Revises: 0054_report_distributions
Create Date: 2026-07-27
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0055_huntpack_resume"
down_revision: str | None = "0054_report_distributions"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "hunt_pack_runs",
        sa.Column(
            "progress",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="{}",
        ),
    )
    op.create_index(
        "idx_hunt_pack_runs_org_pack_status",
        "hunt_pack_runs",
        ["org_id", "pack_id", "status"],
    )


def downgrade() -> None:
    op.drop_index("idx_hunt_pack_runs_org_pack_status", table_name="hunt_pack_runs")
    op.drop_column("hunt_pack_runs", "progress")
