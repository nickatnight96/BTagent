"""Add ``pr_url`` to ``detection_proposals`` (#113 back half, slice 3).

Records which detection-repo pull request an accepted proposal shipped in —
the composer's back-link. Null until composed; a non-null value blocks
re-composition (a rule ships once).

Revision ID: 0029_proposal_pr_url
Revises: 0028_proposal_validation
Create Date: 2026-07-15
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0029_proposal_pr_url"
down_revision: str | None = "0028_proposal_validation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("detection_proposals", sa.Column("pr_url", sa.String(length=512), nullable=True))


def downgrade() -> None:
    op.drop_column("detection_proposals", "pr_url")
