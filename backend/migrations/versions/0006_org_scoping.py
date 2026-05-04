"""Add org_id tenant scoping to core resource tables.

Introduces an ``organizations`` table and adds an ``org_id`` foreign key to the
four core resource tables: users, investigations, iocs, and evidence. A single
seed organization (``org_default``) is created so existing rows can backfill.

Also tightens the ``investigations.assigned_to`` foreign key with
``ON DELETE SET NULL`` so deleting a user no longer leaves a dangling FK.

Revision ID: 0006
Revises: 0005
Create Date: 2026-05-04
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0006_org_scoping"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


CORE_TABLES = ("users", "investigations", "iocs", "evidence")
DEFAULT_ORG_ID = "org_default"


def upgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    # 1. organizations table
    op.create_table(
        "organizations",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(200), unique=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # 2. seed default organization (so existing rows can backfill org_id)
    op.execute(
        sa.text(
            "INSERT INTO organizations (id, name, created_at) "
            "VALUES (:id, :name, CURRENT_TIMESTAMP)"
        ).bindparams(id=DEFAULT_ORG_ID, name="Default Organization")
    )

    # 3. add org_id to each core table — nullable first, backfill, then enforce.
    #    SQLite cannot ALTER constraints in place, so we use batch_alter_table
    #    which handles the recreate-and-copy dance for us.
    for table in CORE_TABLES:
        with op.batch_alter_table(table) as batch_op:
            batch_op.add_column(
                sa.Column(
                    "org_id",
                    sa.String(64),
                    nullable=True,
                    server_default=DEFAULT_ORG_ID,
                )
            )
        op.execute(
            sa.text(f"UPDATE {table} SET org_id = :oid WHERE org_id IS NULL").bindparams(
                oid=DEFAULT_ORG_ID
            )
        )
        with op.batch_alter_table(table) as batch_op:
            batch_op.alter_column("org_id", existing_type=sa.String(64), nullable=False)
            batch_op.create_foreign_key(
                f"fk_{table}_org_id",
                "organizations",
                ["org_id"],
                ["id"],
            )
            batch_op.create_index(f"idx_{table}_org_id", ["org_id", "id"])

    # 4. tighten investigations.assigned_to FK with ON DELETE SET NULL.
    #    PostgreSQL allows DROP/ADD CONSTRAINT in place. SQLite gets the
    #    batch_alter_table treatment instead.
    if dialect == "postgresql":
        op.execute("ALTER TABLE investigations DROP CONSTRAINT IF EXISTS investigations_assigned_to_fkey")
        op.create_foreign_key(
            "investigations_assigned_to_fkey",
            "investigations",
            "users",
            ["assigned_to"],
            ["id"],
            ondelete="SET NULL",
        )
    else:
        # SQLite — FKs are anonymous, so we cannot drop by name. batch_alter_table
        # rebuilds the table from scratch; declaring a new named FK with the
        # desired ON DELETE SET NULL makes the rebuild deterministic.
        with op.batch_alter_table("investigations") as batch_op:
            batch_op.create_foreign_key(
                "fk_investigations_assigned_to_users",
                "users",
                ["assigned_to"],
                ["id"],
                ondelete="SET NULL",
            )


def downgrade() -> None:
    bind = op.get_bind()
    dialect = bind.dialect.name

    # Revert assigned_to FK first (best-effort).
    if dialect == "postgresql":
        op.execute("ALTER TABLE investigations DROP CONSTRAINT IF EXISTS investigations_assigned_to_fkey")
        op.create_foreign_key(
            "investigations_assigned_to_fkey",
            "investigations",
            "users",
            ["assigned_to"],
            ["id"],
        )

    for table in CORE_TABLES:
        with op.batch_alter_table(table) as batch_op:
            batch_op.drop_index(f"idx_{table}_org_id")
            batch_op.drop_constraint(f"fk_{table}_org_id", type_="foreignkey")
            batch_op.drop_column("org_id")

    op.drop_table("organizations")
