"""Add ``org_custom_packs`` — org-authored hunt-pack bundles (#112 slice 2).

The row IS the pack: verbatim pack.yaml + rule files, validated through the
engine's ``load_pack_from_bundle`` at upload time and re-loaded through the
same loader by the scheduled sweep. Unique per (org_id, pack_id) so
re-uploading the same versioned pack updates in place and run history /
noise baselines keep correlating on one pack identity.

Revision ID: 0067_org_custom_packs
Revises: 0066_proposal_ds_gaps
Create Date: 2026-07-30
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0067_org_custom_packs"
down_revision: str | None = "0066_proposal_ds_gaps"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "org_custom_packs",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(64),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("pack_id", sa.String(200), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("version", sa.String(64), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("manifest_yaml", sa.Text(), nullable=False),
        sa.Column(
            "rule_files", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
        sa.Column("rule_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_by", sa.String(64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("idx_org_custom_packs_org", "org_custom_packs", ["org_id"])
    op.create_index(
        "idx_org_custom_packs_org_pack", "org_custom_packs", ["org_id", "pack_id"], unique=True
    )


def downgrade() -> None:
    op.drop_index("idx_org_custom_packs_org_pack", table_name="org_custom_packs")
    op.drop_index("idx_org_custom_packs_org", table_name="org_custom_packs")
    op.drop_table("org_custom_packs")
