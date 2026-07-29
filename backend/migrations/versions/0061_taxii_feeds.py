"""Add ``taxii_feeds`` — org-scoped TAXII 2.1 feed subscriptions (#105 / UC-2.1).

UC-2.1 promises "STIX/TAXII feeds", but only the push half (STIX bundle import)
existed. This table is the pull half's configuration store: one row per
subscribed TAXII 2.1 collection, carrying where to poll, how often, whether it
is enabled, and the incremental poll cursor.

Security shape, enforced in the service layer and mirrored here by column
naming: ``auth_secret_ref`` stores a **reference** (``${secret:vault:...}`` /
``${secret:aws:...}`` / ``${env:VAR}``), never credential material — the raw
token stays in Vault / AWS SM / env and is resolved lazily at poll time. There
is deliberately no column that could hold an inline secret.

Org-scoped (FK to ``organizations``, cascade) so one tenant can neither read
nor be polled into another's feeds; ``(org_id, name)`` is unique.
``intake_investigation_id`` points at the case polled indicators land in
(SET NULL on delete, so removing a case never orphans the feed).

No backfill, fully reversible.

Revision ID: 0061_taxii_feeds
Revises: 0060_memory_embedding
Create Date: 2026-07-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0061_taxii_feeds"
down_revision: str | None = "0060_memory_embedding"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "taxii_feeds",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(length=64),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("server_url", sa.String(length=1000), nullable=False),
        sa.Column("collection_id", sa.String(length=200), nullable=False),
        sa.Column("auth_style", sa.String(length=16), nullable=False, server_default="none"),
        # A ${secret:...} reference only — never inline credential material.
        sa.Column("auth_secret_ref", sa.String(length=500), nullable=False, server_default=""),
        sa.Column("poll_interval_minutes", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_cursor", sa.String(length=128), nullable=True),
        sa.Column("last_polled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_status", sa.String(length=16), nullable=False, server_default=""),
        sa.Column("last_error", sa.Text(), nullable=False, server_default=""),
        sa.Column("objects_ingested", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "intake_investigation_id",
            sa.String(length=64),
            sa.ForeignKey("investigations.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_by", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("updated_by", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("idx_taxii_feeds_org_name", "taxii_feeds", ["org_id", "name"], unique=True)
    op.create_index("idx_taxii_feeds_org_enabled", "taxii_feeds", ["org_id", "enabled"])


def downgrade() -> None:
    op.drop_index("idx_taxii_feeds_org_enabled", table_name="taxii_feeds")
    op.drop_index("idx_taxii_feeds_org_name", table_name="taxii_feeds")
    op.drop_table("taxii_feeds")
