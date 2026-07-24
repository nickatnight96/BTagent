"""Per-org organisation profile — replace the single global row (GH #393).

The org profile drives agent prompt context (industry, compliance, tech stack,
IR team). It was stored as ONE global row in ``org_config``
(``key='org_profile'``): any analyst read another org's profile and an admin's
update overwrote the single row, poisoning every other org's agent prompts
(cross-tenant read + destructive cross-tenant write).

This migration introduces a dedicated ``org_profiles`` table with one row per
org (unique ``org_id``), following the ``UserRow`` org-scoping convention
(``String(64)`` FK ``organizations.id``, ``server_default`` ``org_default``),
and backfills the existing single global profile into ``org_default`` so the
current tenant's data is preserved. Fully reversible.

Revision ID: 0048_org_profile_per_org
Revises: 0047_knowledge_org_id
Create Date: 2026-07-24
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0048_org_profile_per_org"
down_revision: str | None = "0047_knowledge_org_id"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Mirror ``btagent_backend.db.models.DEFAULT_ORG_ID`` — the seeded org the
# pre-existing single global profile is backfilled onto.
_DEFAULT_ORG_ID = "org_default"


def upgrade() -> None:
    op.create_table(
        "org_profiles",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(length=64),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
            server_default=sa.text(f"'{_DEFAULT_ORG_ID}'"),
        ),
        sa.Column("profile", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("updated_by", sa.String(length=64), nullable=True),
    )
    # One profile row per org — the tenant-isolation invariant.
    op.create_index("idx_org_profiles_org_id", "org_profiles", ["org_id"], unique=True)

    # Backfill: migrate the pre-existing single global profile (the
    # ``org_config`` row keyed ``org_profile``) onto ``org_default`` so the
    # current tenant's data survives the cutover. Guarded so re-runs and a
    # missing source row are both no-ops.
    op.execute(
        sa.text(
            """
            INSERT INTO org_profiles (id, org_id, profile, updated_at, updated_by)
            SELECT
                'orgprof_' || substr(md5(random()::text || clock_timestamp()::text), 1, 24),
                :oid,
                oc.value,
                COALESCE(oc.updated_at, now()),
                oc.updated_by
            FROM org_config oc
            WHERE oc.key = 'org_profile'
              AND oc.value IS NOT NULL
              AND NOT EXISTS (
                  SELECT 1 FROM org_profiles op WHERE op.org_id = :oid
              )
            """
        ).bindparams(oid=_DEFAULT_ORG_ID)
    )


def downgrade() -> None:
    op.drop_index("idx_org_profiles_org_id", table_name="org_profiles")
    op.drop_table("org_profiles")
