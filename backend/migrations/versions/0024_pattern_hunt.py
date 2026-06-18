"""Add weak_signals + pattern_hunt_proposals (Cross-Investigation Pattern Hunter, #120).

The cross-investigation counterpart to the Behavioral Hunter (#114) and Hunt
Pack Runner (#112). ``weak_signals`` holds the de-duplicated faint observables
extracted from the closed-investigation corpus — one row per
``(org_id, kind, value)`` (a unique index supports the service's upsert), with
``distinct_investigation_count`` as the pinned cross-case diversity ranking
term. ``pattern_hunt_proposals`` holds ranked clusters turned into ready-to-run
``HuntInput`` payloads (JSONB) plus rationale + lifecycle state; the
``(org_id, cluster_id)`` unique index lets a weekly re-scan upsert rather than
spam duplicates.

Revision ID: 0024_pattern_hunt
Revises: 0022_hunt_pack_run_status_width
Create Date: 2026-06-18

Note: ``down_revision`` chains onto the current head (0022). If a 0023 lands
first at merge time the orchestrator re-chains this — expected; this branch is
single-head on its own.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0024_pattern_hunt"
down_revision: str | None = "0022_hunt_pack_run_status_width"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # weak_signals -----------------------------------------------------------
    op.create_table(
        "weak_signals",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(64),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("value", sa.String(2048), nullable=False),
        sa.Column(
            "first_seen", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "last_seen", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("investigation_refs", JSONB, nullable=False, server_default="[]"),
        sa.Column("distinct_investigation_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("idx_weak_signals_org_id", "weak_signals", ["org_id"])
    op.create_index(
        "idx_weak_signals_unique", "weak_signals", ["org_id", "kind", "value"], unique=True
    )
    op.create_index(
        "idx_weak_signals_diversity",
        "weak_signals",
        ["org_id", "distinct_investigation_count"],
    )

    # pattern_hunt_proposals -------------------------------------------------
    op.create_table(
        "pattern_hunt_proposals",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(64),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("cluster_id", sa.String(128), nullable=False),
        sa.Column("score", sa.Float, nullable=False, server_default="0"),
        sa.Column("hunt_input", JSONB, nullable=False, server_default="{}"),
        sa.Column("rationale", sa.Text, server_default=""),
        sa.Column("state", sa.String(16), nullable=False, server_default="proposed"),
        sa.Column("outcome", sa.String(16), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("idx_pattern_proposals_org_id", "pattern_hunt_proposals", ["org_id"])
    op.create_index(
        "idx_pattern_proposals_cluster",
        "pattern_hunt_proposals",
        ["org_id", "cluster_id"],
        unique=True,
    )
    op.create_index("idx_pattern_proposals_state", "pattern_hunt_proposals", ["org_id", "state"])
    op.create_index("idx_pattern_proposals_score", "pattern_hunt_proposals", ["org_id", "score"])


def downgrade() -> None:
    op.drop_index("idx_pattern_proposals_score", table_name="pattern_hunt_proposals")
    op.drop_index("idx_pattern_proposals_state", table_name="pattern_hunt_proposals")
    op.drop_index("idx_pattern_proposals_cluster", table_name="pattern_hunt_proposals")
    op.drop_index("idx_pattern_proposals_org_id", table_name="pattern_hunt_proposals")
    op.drop_table("pattern_hunt_proposals")

    op.drop_index("idx_weak_signals_diversity", table_name="weak_signals")
    op.drop_index("idx_weak_signals_unique", table_name="weak_signals")
    op.drop_index("idx_weak_signals_org_id", table_name="weak_signals")
    op.drop_table("weak_signals")
