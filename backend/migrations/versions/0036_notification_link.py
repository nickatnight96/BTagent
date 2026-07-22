"""Add ``notifications.link`` — in-app deep-link target for the bell.

Producers can now attach an app-relative route (e.g. ``/hunt`` for critical
hunt findings, ``/workflows/{id}`` for HITL pauses) so clicking a bell entry
navigates somewhere useful; the investigation deep-link remains the fallback
for rows without one. Nullable with no backfill (existing rows keep the
fallback behaviour), fully reversible.

Revision ID: 0036_notification_link
Revises: 0035_stix_bundles
Create Date: 2026-07-22
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0036_notification_link"
down_revision: str | None = "0035_stix_bundles"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("notifications", sa.Column("link", sa.String(length=512), nullable=True))


def downgrade() -> None:
    op.drop_column("notifications", "link")
