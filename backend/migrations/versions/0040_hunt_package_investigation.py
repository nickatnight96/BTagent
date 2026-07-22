"""Add ``hunt_packages.investigation_id`` — package → case lineage (#99).

Promoting a hunt package opens an investigation; this column records the
link so the history list can show which packages already became cases
(and block accidental double-promotion). SET NULL on case deletion keeps
the package artifact itself. Nullable + no backfill, fully reversible.

Revision ID: 0040_hunt_package_investigation
Revises: 0039_hunt_packages
Create Date: 2026-07-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0040_hunt_package_investigation"
down_revision: str | None = "0039_hunt_packages"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "hunt_packages",
        sa.Column(
            "investigation_id",
            sa.String(length=64),
            sa.ForeignKey(
                "investigations.id",
                ondelete="SET NULL",
                name="fk_hunt_packages_investigation_id",
            ),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("hunt_packages", "investigation_id")
