"""Add org_id tenant scoping to the knowledge base tables (GH #386).

The pgvector RAG store (``knowledge_documents`` / ``knowledge_chunks``) shipped
without an ``org_id``, so every ``/knowledge`` endpoint was gated by RBAC only,
never by tenant. Org B could query/read/delete org A's knowledge docs, and
auto-indexing wrote one org's case_id/severity/TLP/IOC values into the shared
store.

This migration backfills an ``org_id`` foreign key on both tables (denormalized
onto ``knowledge_chunks`` so the hybrid-search SQL can filter by tenant without
relying solely on the join) and adds composite indexes to cover the per-tenant
filter. Mirrors ``0006_org_scoping``: add nullable, backfill the seeded default
org, then enforce NOT NULL + FK + server_default via batch mode so SQLite (which
cannot ALTER in place) rebuilds the table while PostgreSQL alters natively.

Revision ID: 0047_knowledge_org_id
Revises: 0046_audit_org_id
Create Date: 2026-07-24
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0047_knowledge_org_id"
down_revision: str | None = "0046_audit_org_id"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_DEFAULT_ORG_ID = "org_default"

# (table, composite index name, index columns)
_TABLES: tuple[tuple[str, str, list[str]], ...] = (
    ("knowledge_documents", "idx_knowledge_documents_org_id", ["org_id", "id"]),
    ("knowledge_chunks", "idx_knowledge_chunks_org_id", ["org_id", "document_id"]),
)


def upgrade() -> None:
    for table, index_name, index_cols in _TABLES:
        # 1. add org_id nullable first so existing rows can backfill.
        op.add_column(table, sa.Column("org_id", sa.String(64), nullable=True))
        op.execute(sa.text(f"UPDATE {table} SET org_id = :oid").bindparams(oid=_DEFAULT_ORG_ID))

        # 2. enforce NOT NULL + FK + server_default. The server_default lets
        #    internal callers that predate tenant scoping keep landing in the
        #    seeded default org; the API route sets org_id from the caller.
        #    SQLite cannot ALTER to add NOT NULL/FK in place — batch mode
        #    rebuilds the table; PostgreSQL handles it natively.
        with op.batch_alter_table(table) as batch_op:
            batch_op.alter_column(
                "org_id",
                existing_type=sa.String(64),
                nullable=False,
                server_default=sa.text(f"'{_DEFAULT_ORG_ID}'"),
            )
            batch_op.create_foreign_key(
                f"fk_{table}_org_id_organizations",
                "organizations",
                ["org_id"],
                ["id"],
            )

        # 3. composite index covering the per-tenant filter on every read.
        op.create_index(index_name, table, index_cols)


def downgrade() -> None:
    for table, index_name, _ in _TABLES:
        op.drop_index(index_name, table_name=table)
        with op.batch_alter_table(table) as batch_op:
            batch_op.drop_constraint(f"fk_{table}_org_id_organizations", type_="foreignkey")
            batch_op.drop_column("org_id")
