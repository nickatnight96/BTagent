"""Add ``detection_proposals`` — persisted STIX → Sigma proposals (#113 back half, slice 1).

The #213 pipeline generated proposals but returned them transiently; this
table is where they now land, carrying the analyst review lifecycle
(``proposed`` → ``accepted`` / ``rejected`` / ``modified``). Unique on
``(org_id, source_stix_id)`` so re-processing a bundle upserts instead of
duplicating; decided rows keep their decision.

Revision ID: 0027_detection_proposals
Revises: 0026_hunt_plans
Create Date: 2026-07-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0027_detection_proposals"
down_revision: str | None = "0026_hunt_plans"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "detection_proposals",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(length=64),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("proposal_id", sa.String(length=128), nullable=False),
        sa.Column("source_stix_id", sa.String(length=256), nullable=False),
        sa.Column("bundle_id", sa.String(length=256), nullable=True),
        sa.Column("title", sa.String(length=300), nullable=False),
        sa.Column("sigma_yaml", sa.Text(), nullable=False),
        sa.Column("technique_ids", JSONB, nullable=False, server_default="[]"),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="0.5"),
        sa.Column("rationale", sa.Text(), nullable=False, server_default=""),
        sa.Column("state", sa.String(length=16), nullable=False, server_default="proposed"),
        sa.Column("review_rationale", sa.Text(), nullable=False, server_default=""),
        sa.Column("reviewed_by", sa.String(length=64), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("idx_detection_proposals_org_id", "detection_proposals", ["org_id"])
    op.create_index(
        "idx_detection_proposals_source",
        "detection_proposals",
        ["org_id", "source_stix_id"],
        unique=True,
    )
    op.create_index("idx_detection_proposals_state", "detection_proposals", ["org_id", "state"])


def downgrade() -> None:
    op.drop_index("idx_detection_proposals_state", table_name="detection_proposals")
    op.drop_index("idx_detection_proposals_source", table_name="detection_proposals")
    op.drop_index("idx_detection_proposals_org_id", table_name="detection_proposals")
    op.drop_table("detection_proposals")
