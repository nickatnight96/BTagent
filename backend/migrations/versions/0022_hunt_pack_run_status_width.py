"""Widen ``hunt_pack_runs.status`` to fit ``completed_with_errors`` (Codex #202 P2).

The pack-run status was originally ``VARCHAR(16)`` (``completed`` / ``failed``).
Codex #202 P2 adds a third terminal value, ``completed_with_errors`` (21 chars),
for runs where some rule×backend executions errored while others succeeded. That
no longer fits 16 chars, so the column is widened to 32. Values are otherwise
unchanged — this is a pure type-width alter, no data migration.

Revision ID: 0022_hunt_pack_run_status_width
Revises: 0021_hunt_pack_runs
Create Date: 2026-06-12
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0022_hunt_pack_run_status_width"
down_revision: str | None = "0021_hunt_pack_runs"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column(
        "hunt_pack_runs",
        "status",
        existing_type=sa.String(length=16),
        type_=sa.String(length=32),
        existing_nullable=False,
        existing_server_default="completed",
    )


def downgrade() -> None:
    op.alter_column(
        "hunt_pack_runs",
        "status",
        existing_type=sa.String(length=32),
        type_=sa.String(length=16),
        existing_nullable=False,
        existing_server_default="completed",
    )
