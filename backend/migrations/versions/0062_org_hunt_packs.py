"""Add ``org_hunt_packs`` — per-org installed/enabled hunt packs (#112).

The scheduled hunt-pack runner used to run a hardcoded builtin default
(``('windows_baseline',)``), so only a handful of the shipped builtin rules
ever ran on a schedule and an org had no way to turn a pack on or off. This
table is the per-org pack store the runner now reads:

* ``(org_id, pack_id)`` composite PK — ``pack_id`` is the **builtin pack
  name** (the ``btagent_engine/hunting/packs`` directory, e.g.
  ``windows_baseline``), i.e. the identity ``load_builtin_pack`` takes, not
  the manifest ``hpack_…`` id ``hunt_pack_runs.pack_id`` records.
* ``enabled`` — the switch the RBAC-gated API flips.
* ``installed_at`` / ``updated_at`` / ``updated_by`` — provenance for the
  audit surface ("who turned this pack off, and when").

Absence is meaningful and needs no backfill: an org with **no rows** falls
back to the builtin default set, so every existing org keeps running exactly
what it ran before this table existed.

Fully reversible.

Revision ID: 0062_org_hunt_packs
Revises: 0060_memory_embedding
Create Date: 2026-07-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0062_org_hunt_packs"
down_revision: str | None = "0060_memory_embedding"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "org_hunt_packs",
        sa.Column(
            "org_id",
            sa.String(64),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("pack_id", sa.String(200), primary_key=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "installed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("updated_by", sa.String(64), nullable=True),
    )
    op.create_index(
        "idx_org_hunt_packs_org_enabled",
        "org_hunt_packs",
        ["org_id", "enabled"],
    )


def downgrade() -> None:
    op.drop_index("idx_org_hunt_packs_org_enabled", table_name="org_hunt_packs")
    op.drop_table("org_hunt_packs")
