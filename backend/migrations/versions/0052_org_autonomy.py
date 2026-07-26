"""Per-org autonomy-override table (#418 — Autonomy & HITL gates editing).

``org_autonomy``: one JSONB overrides row per org, FK'd to ``organizations``.
Containment categories are rejected at the API layer and ignored at merge
time, so this table can never loosen the code-enforced HITL gate. Fully
reversible.

Revision ID: 0052_org_autonomy
Revises: 0051_org_feature_flags
Create Date: 2026-07-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0052_org_autonomy"
down_revision: str | None = "0051_org_feature_flags"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "org_autonomy",
        sa.Column(
            "org_id",
            sa.String(64),
            sa.ForeignKey("organizations.id"),
            primary_key=True,
        ),
        sa.Column("overrides", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_by", sa.String(64), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("org_autonomy")
