"""Per-org feature-flag table (#418 — capability toggle home).

``org_feature_flags``: one boolean row per ``(org_id, key)``, FK'd to
``organizations`` so a tenant's flags disappear with the tenant. Fully
reversible.

Revision ID: 0051_org_feature_flags
Revises: 0050_dashboard_prefs
Create Date: 2026-07-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0051_org_feature_flags"
down_revision: str | None = "0050_dashboard_prefs"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "org_feature_flags",
        sa.Column(
            "org_id",
            sa.String(64),
            sa.ForeignKey("organizations.id"),
            primary_key=True,
        ),
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("value", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_by", sa.String(64), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("org_feature_flags")
