"""Add notebook-annotation columns to ``iocs`` (#108 UC-5.2).

The IOC notebook layers analyst-owned metadata on the evidence record:
``pinned`` (surfaces the IOC at the top of the case notebook), ``tags``
(free-form labels), ``analyst_note`` (working note), and ``disposition``
(the analyst's call — under_review / confirmed_malicious / benign /
false_positive). Server-populated defaults; no backfill needed; fully
reversible.

Revision ID: 0045_ioc_annotations
Revises: 0044_shadow_agent_registry
Create Date: 2026-07-24
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0045_ioc_annotations"
down_revision: str | None = "0044_shadow_agent_registry"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "iocs",
        sa.Column("pinned", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "iocs",
        sa.Column("tags", JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
    )
    op.add_column(
        "iocs",
        sa.Column("analyst_note", sa.Text(), nullable=False, server_default=""),
    )
    op.add_column(
        "iocs",
        sa.Column("disposition", sa.String(length=30), nullable=False, server_default=""),
    )
    # The notebook's pinned view filters per investigation.
    op.create_index("idx_iocs_investigation_pinned", "iocs", ["investigation_id", "pinned"])


def downgrade() -> None:
    op.drop_index("idx_iocs_investigation_pinned", table_name="iocs")
    op.drop_column("iocs", "disposition")
    op.drop_column("iocs", "analyst_note")
    op.drop_column("iocs", "tags")
    op.drop_column("iocs", "pinned")
