"""Add organizations table and org_id tenant scoping to core resources.

Phase A1 of the auth-hardening milestone — adds an `organizations` table and
backfills an `org_id` column on `users`, `investigations`, `iocs`, and
`evidence` so subsequent route hardening (Phase B1) can filter by tenant.

Also tightens `investigations.assigned_to` FK to `ON DELETE SET NULL` so a
deleted user does not orphan a non-null pointer.

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


_DEFAULT_ORG_ID = "org_default"
_DEFAULT_ORG_NAME = "Default Organization"


def _is_sqlite() -> bool:
    return op.get_bind().dialect.name == "sqlite"


def upgrade() -> None:
    # 1. organizations table -------------------------------------------------
    op.create_table(
        "organizations",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False, unique=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )

    # 2. seed default org so existing rows can backfill ----------------------
    org_table = sa.table(
        "organizations",
        sa.column("id", sa.String),
        sa.column("name", sa.String),
        sa.column("created_at", sa.DateTime(timezone=True)),
    )
    op.bulk_insert(
        org_table,
        [
            {
                "id": _DEFAULT_ORG_ID,
                "name": _DEFAULT_ORG_NAME,
                # `created_at` left to server_default (now()).
            }
        ],
    )

    sqlite = _is_sqlite()

    # 3. add org_id (nullable first so existing rows can backfill) -----------
    for table in ("users", "investigations", "iocs", "evidence"):
        op.add_column(table, sa.Column("org_id", sa.String(64), nullable=True))
        op.execute(sa.text(f"UPDATE {table} SET org_id = :oid").bindparams(oid=_DEFAULT_ORG_ID))

    # 4. enforce NOT NULL + FK + indexes + server_default --------------------
    # The server_default of ``org_default`` lets Phase A1 ship before Phase B1
    # rewires routes to set org_id from the authenticated user; subsequent
    # phases will replace this fallback with explicit per-row assignment.
    # SQLite cannot ALTER to add NOT NULL or FK constraints in place; with the
    # batch-mode helper alembic recreates the table.  PostgreSQL handles the
    # operation natively.
    for table in ("users", "investigations", "iocs", "evidence"):
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

    op.create_index("idx_users_org_id", "users", ["org_id", "id"])
    op.create_index("idx_investigations_org_id", "investigations", ["org_id", "id"])
    op.create_index("idx_iocs_org_id", "iocs", ["org_id", "id"])
    op.create_index("idx_evidence_org_id", "evidence", ["org_id", "id"])

    # 5. tighten investigations.assigned_to to ON DELETE SET NULL ------------
    if not sqlite:
        # PostgreSQL: drop the existing unnamed FK, recreate with SET NULL.
        # The original migration did not name the constraint, so we look it up
        # via information_schema rather than hard-coding a name.
        op.execute(
            sa.text(
                """
                DO $$
                DECLARE
                    fk_name text;
                BEGIN
                    SELECT tc.constraint_name INTO fk_name
                    FROM information_schema.table_constraints tc
                    JOIN information_schema.key_column_usage kcu
                      ON tc.constraint_name = kcu.constraint_name
                    WHERE tc.table_name = 'investigations'
                      AND tc.constraint_type = 'FOREIGN KEY'
                      AND kcu.column_name = 'assigned_to'
                    LIMIT 1;
                    IF fk_name IS NOT NULL THEN
                        EXECUTE format(
                            'ALTER TABLE investigations DROP CONSTRAINT %I',
                            fk_name
                        );
                    END IF;
                END
                $$;
                """
            )
        )
        op.create_foreign_key(
            "fk_investigations_assigned_to_users",
            "investigations",
            "users",
            ["assigned_to"],
            ["id"],
            ondelete="SET NULL",
        )
    else:
        # SQLite: rebuild the table via batch-mode so the FK is recreated with
        # the new ON DELETE SET NULL clause.
        with op.batch_alter_table("investigations") as batch_op:
            batch_op.drop_constraint("fk_investigations_assigned_to_users", type_="foreignkey")
            batch_op.create_foreign_key(
                "fk_investigations_assigned_to_users",
                "users",
                ["assigned_to"],
                ["id"],
                ondelete="SET NULL",
            )


def downgrade() -> None:
    sqlite = _is_sqlite()

    # 1. revert assigned_to FK to no ON DELETE clause -----------------------
    if not sqlite:
        op.execute(
            sa.text(
                """
                DO $$
                DECLARE
                    fk_name text;
                BEGIN
                    SELECT tc.constraint_name INTO fk_name
                    FROM information_schema.table_constraints tc
                    JOIN information_schema.key_column_usage kcu
                      ON tc.constraint_name = kcu.constraint_name
                    WHERE tc.table_name = 'investigations'
                      AND tc.constraint_type = 'FOREIGN KEY'
                      AND kcu.column_name = 'assigned_to'
                    LIMIT 1;
                    IF fk_name IS NOT NULL THEN
                        EXECUTE format(
                            'ALTER TABLE investigations DROP CONSTRAINT %I',
                            fk_name
                        );
                    END IF;
                END
                $$;
                """
            )
        )
        op.create_foreign_key(
            None,
            "investigations",
            "users",
            ["assigned_to"],
            ["id"],
        )
    else:
        with op.batch_alter_table("investigations") as batch_op:
            batch_op.drop_constraint("fk_investigations_assigned_to_users", type_="foreignkey")
            batch_op.create_foreign_key(
                "fk_investigations_assigned_to_users",
                "users",
                ["assigned_to"],
                ["id"],
            )

    # 2. drop org_id indexes / FKs / columns --------------------------------
    op.drop_index("idx_evidence_org_id", table_name="evidence")
    op.drop_index("idx_iocs_org_id", table_name="iocs")
    op.drop_index("idx_investigations_org_id", table_name="investigations")
    op.drop_index("idx_users_org_id", table_name="users")

    for table in ("evidence", "iocs", "investigations", "users"):
        with op.batch_alter_table(table) as batch_op:
            batch_op.drop_constraint(f"fk_{table}_org_id_organizations", type_="foreignkey")
            batch_op.drop_column("org_id")

    # 3. drop organizations table -------------------------------------------
    op.drop_table("organizations")
