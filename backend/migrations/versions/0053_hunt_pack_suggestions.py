"""Add ``hunt_pack_suggestions`` — confirmed-HIT pattern hunt → recurring #112 pack (#120 Phase C).

When a hunt launched from a cross-investigation ``PatternHuntProposal``
confirms real activity, ``execute_plan_and_ingest`` files a suggestion here
carrying a ready-to-review ``HuntPackManifest`` draft so an analyst can promote
the shape into a scheduled #112 hunt pack. Unique on ``(org_id, proposal_id)``
so repeated HIT executions upsert instead of duplicating. No backfill, fully
reversible.

Revision ID: 0053_hunt_pack_suggestions
Revises: 0052_org_autonomy
Create Date: 2026-07-27
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0053_hunt_pack_suggestions"
down_revision: str | None = "0052_org_autonomy"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "hunt_pack_suggestions",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(length=64),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "proposal_id",
            sa.String(length=64),
            sa.ForeignKey("pattern_hunt_proposals.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("plan_id", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column(
            "technique_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="[]",
        ),
        sa.Column(
            "manifest",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="{}",
        ),
        sa.Column("rationale", sa.Text(), nullable=False, server_default=""),
        sa.Column("state", sa.String(length=16), nullable=False, server_default="suggested"),
        sa.Column("hit_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "idx_hunt_pack_suggestions_org_created",
        "hunt_pack_suggestions",
        ["org_id", "created_at"],
    )
    op.create_index(
        "idx_hunt_pack_suggestions_proposal",
        "hunt_pack_suggestions",
        ["org_id", "proposal_id"],
        unique=True,
    )
    op.create_index(
        "idx_hunt_pack_suggestions_state",
        "hunt_pack_suggestions",
        ["org_id", "state"],
    )


def downgrade() -> None:
    op.drop_index("idx_hunt_pack_suggestions_state", table_name="hunt_pack_suggestions")
    op.drop_index("idx_hunt_pack_suggestions_proposal", table_name="hunt_pack_suggestions")
    op.drop_index("idx_hunt_pack_suggestions_org_created", table_name="hunt_pack_suggestions")
    op.drop_table("hunt_pack_suggestions")
