"""Add ``noise_digest_state`` — per-org memory for the newly-noisy digest (#112).

The scheduled noise-digest sweep diffs the current noise baseline against the
set of ``"pack_id:rule_id"`` keys stored here, notifying hunt seniors only
about rules that turned chronically noisy since the last run. One row per
org; no backfill (the first sweep treats everything currently noisy as new,
which is the correct cold-start behaviour). Fully reversible.

Revision ID: 0037_noise_digest_state
Revises: 0036_notification_link
Create Date: 2026-07-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0037_noise_digest_state"
down_revision: str | None = "0036_notification_link"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "noise_digest_state",
        sa.Column(
            "org_id",
            sa.String(length=64),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("noisy_keys", JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("noise_digest_state")
