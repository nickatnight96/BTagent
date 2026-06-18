"""Add harmful_flag, harmful_reason, harmful_finding_id to suppression_rules (#119 Phase C).

A suppression rule that later proves to have been hiding a confirmed threat is
flagged as ``harmful``. The three new columns track:

* ``harmful_flag`` — Boolean sentinel, default False; flipped to True by
  ``promote_to_investigation`` when a promoted finding matches this rule.
* ``harmful_reason`` — Human-readable explanation of why the rule was flagged
  (includes the promoting actor and the matched finding id).
* ``harmful_finding_id`` — The first promoted finding id that triggered the flag.

Revision ID: 0023_suppression_harmful_flag
Revises: 0022_hunt_pack_run_status_width
Create Date: 2026-06-18
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0023_suppression_harmful_flag"
down_revision: str | None = "0022_hunt_pack_run_status_width"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "suppression_rules",
        sa.Column("harmful_flag", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "suppression_rules",
        sa.Column("harmful_reason", sa.Text(), nullable=True),
    )
    op.add_column(
        "suppression_rules",
        sa.Column("harmful_finding_id", sa.String(length=64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("suppression_rules", "harmful_finding_id")
    op.drop_column("suppression_rules", "harmful_reason")
    op.drop_column("suppression_rules", "harmful_flag")
