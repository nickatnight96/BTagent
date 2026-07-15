"""Add validation columns to ``detection_proposals`` (#113 back half, slice 2).

Stores the historical-telemetry validation outcome (per-backend hit counts /
errors + verdict) produced by the engine rule validator, so the analyst
reviewing a proposal sees whether the rule already matches telemetry.

Revision ID: 0028_proposal_validation
Revises: 0027_detection_proposals
Create Date: 2026-07-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0028_proposal_validation"
down_revision: str | None = "0027_detection_proposals"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("detection_proposals", sa.Column("validation", JSONB, nullable=True))
    op.add_column(
        "detection_proposals",
        sa.Column("validated_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("detection_proposals", "validated_at")
    op.drop_column("detection_proposals", "validation")
