"""Add ``triage_rationale`` to ``pattern_hunt_proposals`` (#218 Phase C).

Analyst triage notes on a dismiss / snooze / accept transition previously got
concatenated onto the generated ``rationale`` (the "why this surfaced" text),
mangling it. This dedicated, nullable column holds the analyst's accumulated
notes so the generated rationale stays pristine. Null until an analyst first
provides a note.

Revision ID: 0033_proposal_triage_rationale
Revises: 0032_connector_credentials
Create Date: 2026-07-18
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0033_proposal_triage_rationale"
down_revision: str | None = "0032_connector_credentials"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "pattern_hunt_proposals",
        sa.Column("triage_rationale", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("pattern_hunt_proposals", "triage_rationale")
