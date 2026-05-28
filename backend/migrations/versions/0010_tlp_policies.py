"""Add tlp_policies table (EPIC-7 UC-7.2).

Org-scoped, CISO-approved exceptions to the default-deny TLP egress gate.
Each row is a TLPPolicy (``allow`` | ``deny`` | ``downgrade_then_allow``)
with optional match conditions (``egress_kinds`` / ``applies_to_tlp``),
a downgrade target, and governance metadata (approver / rationale /
valid_until). Reads gated to senior_analyst (``policy:view``); writes to
admin / CISO (``policy:manage``).

Carries ``org_id`` (FK → organizations) so tenant scoping is present from
day one, matching the workflows / hunt-findings tables.

Revision ID: 0010_tlp_policies
Revises: 0009_behavioral
Create Date: 2026-05-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0010_tlp_policies"
down_revision: str | None = "0009_behavioral"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "tlp_policies",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(64),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("egress_kinds", JSONB, server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("applies_to_tlp", JSONB, server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column("downgrade_to", sa.String(20), nullable=True),
        sa.Column("approver_id", sa.String(200), server_default="", nullable=False),
        sa.Column("rationale", sa.Text, server_default="", nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_by",
            sa.String(64),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("idx_tlp_policies_org_id", "tlp_policies", ["org_id"])


def downgrade() -> None:
    op.drop_index("idx_tlp_policies_org_id", table_name="tlp_policies")
    op.drop_table("tlp_policies")
