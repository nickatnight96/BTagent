"""Add ``report_distributions`` — org-scoped report distribution/audit ledger (EPIC-6 UC-6.2).

Records each delivery of a generated report to an audience/recipient so the
release of incident reporting is auditable: who received what, when, under
which TLP marking, and who approved the release. Reports are generated on the
fly rather than persisted, so ``report_id`` is a free-form reference with no FK
target. Org-scoped (FK to ``organizations``, cascade) so one tenant can never
read another tenant's distribution history. No backfill, fully reversible.

Revision ID: 0054_report_distributions
Revises: 0053_hunt_pack_suggestions
Create Date: 2026-07-27
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0054_report_distributions"
down_revision: str | None = "0053_hunt_pack_suggestions"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "report_distributions",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(length=64),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("report_id", sa.String(length=64), nullable=False),
        sa.Column("audience", sa.String(length=64), nullable=False),
        sa.Column("recipient", sa.String(length=500), nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tlp_applied", sa.String(length=20), nullable=False, server_default="amber"),
        sa.Column("approver_id", sa.String(length=64), nullable=True),
    )
    op.create_index(
        "idx_report_distributions_org_report",
        "report_distributions",
        ["org_id", "report_id"],
    )
    op.create_index(
        "idx_report_distributions_org_sent",
        "report_distributions",
        ["org_id", "sent_at"],
    )


def downgrade() -> None:
    op.drop_index("idx_report_distributions_org_sent", table_name="report_distributions")
    op.drop_index("idx_report_distributions_org_report", table_name="report_distributions")
    op.drop_table("report_distributions")
