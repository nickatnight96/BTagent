"""Add ``connector_credentials`` — per-org connector credential references (#100).

Stores the ``${secret:...}`` reference that resolves a connector's credential
material — never the material itself (that lives in Vault / AWS SM / env).
Unique on ``(org_id, connector_name)`` so each connector has one binding per
org; additive + reversible.

Revision ID: 0032_connector_credentials
Revises: 0031_plan_runs
Create Date: 2026-07-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0032_connector_credentials"
down_revision: str | None = "0031_plan_runs"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "connector_credentials",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(length=64),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("connector_name", sa.String(length=100), nullable=False),
        sa.Column("secret_ref", sa.Text(), nullable=False),
        sa.Column("label", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("created_by", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("updated_by", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("idx_connector_credentials_org", "connector_credentials", ["org_id"])
    op.create_index(
        "idx_connector_credentials_unique",
        "connector_credentials",
        ["org_id", "connector_name"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("idx_connector_credentials_unique", table_name="connector_credentials")
    op.drop_index("idx_connector_credentials_org", table_name="connector_credentials")
    op.drop_table("connector_credentials")
