"""Add ``behavioral_outliers.event_pattern_key`` (Codex #206 P2).

``feedback_benign`` raised the entity baseline's frequency map using the
outlier's ``event_id``, but ``score_outlier`` matches on the *pattern key*.
When the two differ (e.g. an event id ``evt_api`` vs a pattern key
``encoded_pwsh``) the benign pattern was never actually suppressed and kept
re-firing as an outlier. We now persist the matched pattern key on the
outlier so feedback updates the same key the scorer reads. Nullable so
pre-existing rows survive; feedback falls back to ``event_id`` for those.

Revision ID: 0025_behavioral_pattern_key
Revises: 0022_hunt_pack_run_status_width
Create Date: 2026-06-18
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0025_behavioral_pattern_key"
down_revision: str | None = "0022_hunt_pack_run_status_width"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "behavioral_outliers",
        sa.Column("event_pattern_key", sa.String(512), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("behavioral_outliers", "event_pattern_key")
