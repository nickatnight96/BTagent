"""Add ``org_id`` tenant scoping to ``playbook_executions`` (#394).

Playbook execution rows carry sensitive per-run data (``trigger_data``,
``step_results``, and a link to an ``investigation_id``). Before this change
the list/get execution endpoints filtered only on ``playbook:view`` and not on
tenant, so an org-B analyst could read an org-A org's execution rows.

This backfills an ``org_id`` column (server-defaulted to the seeded
``org_default`` row so existing executions land in the default tenant), makes
it NOT NULL with an FK to ``organizations``, and adds the composite
``(org_id, id)`` index that the scoped list/get queries ride. Executions are
stamped with the authenticated caller's org going forward; the playbook
*definition* itself is not org-scoped.

Revision ID: 0049_playbook_exec_org_id
Revises: 0048_org_profile_per_org
Create Date: 2026-07-24
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0049_playbook_exec_org_id"
down_revision: str | None = "0048_org_profile_per_org"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_DEFAULT_ORG_ID = "org_default"


def upgrade() -> None:
    # Add nullable first so existing rows can be backfilled without violating
    # the NOT NULL constraint, then tighten to NOT NULL + FK + server_default.
    op.add_column(
        "playbook_executions",
        sa.Column("org_id", sa.String(64), nullable=True),
    )
    op.execute(
        sa.text("UPDATE playbook_executions SET org_id = :oid").bindparams(oid=_DEFAULT_ORG_ID)
    )

    # SQLite cannot ALTER to add NOT NULL / FK in place; batch-mode recreates
    # the table. PostgreSQL performs the operation natively.
    with op.batch_alter_table("playbook_executions") as batch_op:
        batch_op.alter_column(
            "org_id",
            existing_type=sa.String(64),
            nullable=False,
            server_default=sa.text(f"'{_DEFAULT_ORG_ID}'"),
        )
        batch_op.create_foreign_key(
            "fk_playbook_executions_org_id_organizations",
            "organizations",
            ["org_id"],
            ["id"],
        )

    op.create_index(
        "idx_playbook_executions_org_id",
        "playbook_executions",
        ["org_id", "id"],
    )


def downgrade() -> None:
    op.drop_index("idx_playbook_executions_org_id", table_name="playbook_executions")
    with op.batch_alter_table("playbook_executions") as batch_op:
        batch_op.drop_constraint("fk_playbook_executions_org_id_organizations", type_="foreignkey")
        batch_op.drop_column("org_id")
