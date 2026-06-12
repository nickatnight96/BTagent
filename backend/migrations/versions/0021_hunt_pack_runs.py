"""Hunt pack-run history (#112 scheduler integration).

Adds ``hunt_pack_runs`` — one row per scheduled (or ad-hoc) hunt-pack
execution. It records *what ran and how it landed*: pack identity + version,
the backends queried, a per-rule hit/error rollup (``rule_stats`` JSON), the
number of findings the run created in the #119 store, and a terminal status.
This is the substrate the future noise baselines (#112) read to learn per-rule
hit volumes.

The engine runner's transient ``hrun_`` run id is stored on ``run_id`` so the
findings it emitted (which carry it in ``evidence.source_run_id``) correlate
back to the history row. Org-scoped from day one, matching the rest of the
hunt stores.

Revision ID: 0021_hunt_pack_runs
Revises: 0020_hunt_triage_indexes
Create Date: 2026-06-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0021_hunt_pack_runs"
down_revision: str | None = "0020_hunt_triage_indexes"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "hunt_pack_runs",
        sa.Column("id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.String(length=64), nullable=False),
        sa.Column("run_id", sa.String(length=64), nullable=False),
        sa.Column("pack_id", sa.String(length=200), nullable=False),
        sa.Column("pack_name", sa.String(length=200), nullable=False),
        sa.Column("pack_version", sa.String(length=64), nullable=False, server_default=""),
        sa.Column(
            "backends",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="[]",
        ),
        sa.Column(
            "rule_stats",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column("hit_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings_created", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="completed"),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "idx_hunt_pack_runs_org_started",
        "hunt_pack_runs",
        ["org_id", "started_at"],
    )
    op.create_index(
        "idx_hunt_pack_runs_pack_id",
        "hunt_pack_runs",
        ["pack_id"],
    )


def downgrade() -> None:
    op.drop_index("idx_hunt_pack_runs_pack_id", table_name="hunt_pack_runs")
    op.drop_index("idx_hunt_pack_runs_org_started", table_name="hunt_pack_runs")
    op.drop_table("hunt_pack_runs")
