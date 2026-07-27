"""Add ``response_safelist`` — org-scoped never-block safelist (EPIC-3 #106).

Replaces the hard-coded never-block allowlist that used to live inside the
bulk-mitigation engine node with an operator-managed, org-scoped table. Each row
pins one IP or domain that must never be pushed to a perimeter/EDR blocklist for
that org (a self-inflicted-outage guard). A universal baseline (public
resolvers, critical-infra domains, RFC1918/reserved IPs) stays enforced in code;
these rows extend it per tenant.

The safelist is consulted at plan time (skip) and, authoritatively, at execute
time (a safelisted target is refused before any block dispatch, with an audited
denial). Org-scoped (FK to ``organizations``, cascade) so one tenant can neither
read nor be governed by another's safelist; ``(org_id, entry_type, value)`` is
unique. No backfill, fully reversible.

Revision ID: 0056_response_safelist
Revises: 0055_huntpack_resume
Create Date: 2026-07-27
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0056_response_safelist"
down_revision: str | None = "0055_huntpack_resume"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "response_safelist",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(length=64),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("entry_type", sa.String(length=16), nullable=False),
        sa.Column("value", sa.String(length=255), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "created_by",
            sa.String(length=64),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("org_id", "entry_type", "value", name="uq_response_safelist_org_entry"),
    )
    op.create_index("idx_response_safelist_org", "response_safelist", ["org_id"])


def downgrade() -> None:
    op.drop_index("idx_response_safelist_org", table_name="response_safelist")
    op.drop_table("response_safelist")
