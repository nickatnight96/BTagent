"""Record capped/deadline-stopped hunt sweeps on ``hunt_pack_runs`` (E7).

P4.3 gave the pack runner a rules-per-sweep cap and a per-run deadline, and
``PackRunResult`` carries ``truncated`` + ``rules_not_run`` precisely so — in
the engine's own words — "the caller never mistakes a capped run for a clean
full sweep". The history table had nowhere to put either, so the signal died
at the persistence boundary: a run that examined 40 of 300 rules and a run
that examined all 300 both render as a finished sweep with N hits. An analyst
then reads "0 hits" as "nothing there" instead of "we did not look".

Both columns are NOT NULL with a server default, so existing rows backfill to
the honest reading for a pre-cap run: not truncated, nothing skipped.

Revision ID: 0069_huntpack_run_truncated
Revises: 0068_playbook_org_id
Create Date: 2026-08-02
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0069_huntpack_run_truncated"
down_revision: str | None = "0068_playbook_org_id"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "hunt_pack_runs",
        sa.Column(
            "truncated",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column(
        "hunt_pack_runs",
        sa.Column(
            "rules_not_run",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default="[]",
        ),
    )


def downgrade() -> None:
    op.drop_column("hunt_pack_runs", "rules_not_run")
    op.drop_column("hunt_pack_runs", "truncated")
