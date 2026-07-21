"""Add ``stix_bundles`` — persisted STIX 2.1 bundles for bundle-by-id reprocessing (#113).

Stores the raw bundle behind a ``POST /cti/propose-detections`` call so a later
request can re-run the pipeline via ``stix_bundle_id`` instead of re-uploading
the bundle (previously a 501 stub). Uniqueness is ``(org_id, bundle_id)``:
re-importing the same bundle upserts its stored copy. No backfill (pre-table
propose calls kept no bundle), fully reversible.

Revision ID: 0035_stix_bundles
Revises: 0034_detection_validation_runs
Create Date: 2026-07-21
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0035_stix_bundles"
down_revision: str | None = "0034_detection_validation_runs"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "stix_bundles",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(length=64),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("bundle_id", sa.String(length=256), nullable=False),
        sa.Column("bundle", JSONB, nullable=False, server_default="{}"),
        sa.Column("tlp", sa.String(length=16), nullable=False, server_default="green"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "idx_stix_bundles_org_bundle",
        "stix_bundles",
        ["org_id", "bundle_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("idx_stix_bundles_org_bundle", table_name="stix_bundles")
    op.drop_table("stix_bundles")
