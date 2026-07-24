"""Tenant-scope the audit ledger — add ``org_id`` to ``audit_logs`` (GH #385).

The SHA-256 hash-chained audit ledger had no tenant column, so the read
surfaces (/audit/entries, /audit/lineage, /audit/export) returned the *global*
cross-tenant chain — leaking other orgs' actor / action / resource. This adds a
required ``org_id`` FK (mirroring the Phase A1 org-scoping on users /
investigations / iocs / evidence) plus a composite ``(org_id, seq)`` index that
covers the org-scoped read path. Existing rows backfill to the seeded
``org_default`` org; the ``server_default`` keeps pre-existing writers working.
``org_id`` is deliberately NOT part of the chain hash — the ledger stays one
global tamper-evident sequence; the column governs read visibility only.

Fully reversible.

Revision ID: 0046_audit_org_id
Revises: 0045_ioc_annotations
Create Date: 2026-07-24
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0046_audit_org_id"
down_revision: str | None = "0045_ioc_annotations"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_DEFAULT_ORG_ID = "org_default"


def upgrade() -> None:
    # 1. add org_id nullable first so existing rows can backfill --------------
    op.add_column("audit_logs", sa.Column("org_id", sa.String(64), nullable=True))
    op.execute(sa.text("UPDATE audit_logs SET org_id = :oid").bindparams(oid=_DEFAULT_ORG_ID))

    # 2. enforce NOT NULL + FK + server_default ------------------------------
    # SQLite cannot ALTER to add NOT NULL / FK in place; batch-mode recreates
    # the table. PostgreSQL handles the operation natively.
    with op.batch_alter_table("audit_logs") as batch_op:
        batch_op.alter_column(
            "org_id",
            existing_type=sa.String(64),
            nullable=False,
            server_default=sa.text(f"'{_DEFAULT_ORG_ID}'"),
        )
        batch_op.create_foreign_key(
            "fk_audit_logs_org_id_organizations",
            "organizations",
            ["org_id"],
            ["id"],
        )

    # 3. composite index covering the org-scoped read path -------------------
    op.create_index("idx_audit_logs_org_id", "audit_logs", ["org_id", "seq"])


def downgrade() -> None:
    op.drop_index("idx_audit_logs_org_id", table_name="audit_logs")
    with op.batch_alter_table("audit_logs") as batch_op:
        batch_op.drop_constraint("fk_audit_logs_org_id_organizations", type_="foreignkey")
        batch_op.drop_column("org_id")
