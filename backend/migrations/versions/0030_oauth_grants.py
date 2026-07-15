"""Add ``oauth_grants`` — first-class grant store (#116 read-derive follow-up).

The #216 slice served the grant graph read-derive from identity findings'
evidence; this lands the promised first-class table plus the ingest-side
write path (grants upsert whenever an identity finding carrying a grant
tuple is recorded). Unique on the read-derive dedup key
``(org_id, provider, principal_id, app_id)``. No backfill — the endpoint
keeps the derive path as a fallback for orgs with no rows yet, so the
migration stays fully reversible.

Revision ID: 0030_oauth_grants
Revises: 0029_proposal_pr_url
Create Date: 2026-07-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0030_oauth_grants"
down_revision: str | None = "0029_proposal_pr_url"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "oauth_grants",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(length=64),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("provider", sa.String(length=32), nullable=False),
        sa.Column("principal_id", sa.String(length=512), nullable=False),
        sa.Column("app_id", sa.String(length=512), nullable=False),
        sa.Column("app_display_name", sa.String(length=300), nullable=False, server_default=""),
        sa.Column("scopes", JSONB, nullable=False, server_default="[]"),
        sa.Column("consent_type", sa.String(length=32), nullable=False, server_default="unknown"),
        sa.Column("granted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_used", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("source_finding_id", sa.String(length=64), nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("idx_oauth_grants_org_id", "oauth_grants", ["org_id"])
    op.create_index(
        "idx_oauth_grants_tuple",
        "oauth_grants",
        ["org_id", "provider", "principal_id", "app_id"],
        unique=True,
    )
    op.create_index("idx_oauth_grants_principal", "oauth_grants", ["org_id", "principal_id"])


def downgrade() -> None:
    op.drop_index("idx_oauth_grants_principal", table_name="oauth_grants")
    op.drop_index("idx_oauth_grants_tuple", table_name="oauth_grants")
    op.drop_index("idx_oauth_grants_org_id", table_name="oauth_grants")
    op.drop_table("oauth_grants")
