"""Persist the DataSourceMatcher output on ``detection_proposals`` (#501 / #113).

The #113 ``DataSourceMatcher`` already computes, per drafted rule, which
connected connectors can supply its telemetry and which required OCSF event
classes **nothing** emits. That output had nowhere to live, so the Coverage
Console's telemetry-gaps panel *inferred* gaps from the stored validation blob
instead (``backends_errored`` vs ``never_validated``) — a strictly weaker
signal, disclosed as debt when #501 shipped. These two columns are where the
real thing lands.

Both are nullable JSON with **no backfill**, and that is deliberate: NULL means
"the matcher never ran for this row" (every row written before this migration),
which is exactly the marker the console needs to fall back to the old derived
heuristic for legacy rows. An empty list is the opposite claim — the matcher ran
and found nothing missing. Backfilling ``[]`` would turn "unknown" into
"covered", i.e. manufacture coverage, so it is not done.

Nothing here is org-scoped in its own right: the columns hang off
``detection_proposals``, which is already org-scoped + FK-cascaded, so tenancy
is unchanged.

Fully reversible (dropping the columns restores the derived-only behaviour).

Revision ID: 0066_proposal_ds_gaps
Revises: 0065_taxii_feeds
Create Date: 2026-07-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0066_proposal_ds_gaps"
down_revision: str | None = "0065_taxii_feeds"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Connector ids (manifest names) whose ocsf_emits cover the rule's telemetry.
    op.add_column(
        "detection_proposals",
        sa.Column("data_sources_required", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    # OCSF event-class values NO connected connector emits — the real gap set.
    op.add_column(
        "detection_proposals",
        sa.Column("data_source_gaps", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("detection_proposals", "data_source_gaps")
    op.drop_column("detection_proposals", "data_sources_required")
