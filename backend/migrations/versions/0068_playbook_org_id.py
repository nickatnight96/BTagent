"""Add ``org_id`` tenant scoping to ``playbooks`` (B5, P2.3).

#394 / 0049 scoped playbook *executions* but left the *definitions* global:
``playbooks`` had no ``org_id``, and list/get/update/deactivate queried with
no org predicate — a senior_analyst in org B could read org A's SOAR YAML
(queries, hostnames), rewrite it, or deactivate it.

Same shape as 0049: backfill to the seeded ``org_default`` row, tighten to
NOT NULL + FK + server_default, and add the composite ``(org_id, id)`` index
the scoped queries ride. Definitions are stamped with the authenticated
caller's org going forward.

Revision ID: 0068_playbook_org_id
Revises: 0067_org_custom_packs
Create Date: 2026-07-31
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0068_playbook_org_id"
down_revision: str | None = "0067_org_custom_packs"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_DEFAULT_ORG_ID = "org_default"


def upgrade() -> None:
    # Add nullable first so existing rows can be backfilled without violating
    # the NOT NULL constraint, then tighten to NOT NULL + FK + server_default.
    op.add_column(
        "playbooks",
        sa.Column("org_id", sa.String(64), nullable=True),
    )
    op.execute(sa.text("UPDATE playbooks SET org_id = :oid").bindparams(oid=_DEFAULT_ORG_ID))

    # SQLite cannot ALTER to add NOT NULL / FK in place; batch-mode recreates
    # the table. PostgreSQL performs the operation natively.
    with op.batch_alter_table("playbooks") as batch_op:
        batch_op.alter_column(
            "org_id",
            existing_type=sa.String(64),
            nullable=False,
            server_default=sa.text(f"'{_DEFAULT_ORG_ID}'"),
        )
        batch_op.create_foreign_key(
            "fk_playbooks_org_id_organizations",
            "organizations",
            ["org_id"],
            ["id"],
        )

    op.create_index("idx_playbooks_org_id", "playbooks", ["org_id", "id"])


def downgrade() -> None:
    op.drop_index("idx_playbooks_org_id", table_name="playbooks")
    with op.batch_alter_table("playbooks") as batch_op:
        batch_op.drop_constraint("fk_playbooks_org_id_organizations", type_="foreignkey")
        batch_op.drop_column("org_id")
