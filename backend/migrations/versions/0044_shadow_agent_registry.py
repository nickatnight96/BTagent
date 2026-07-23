"""Add ``shadow_agent_registry`` — governance decisions for shadow agents (#121/#117).

Shadow-agent/-MCP findings (evidence ``shadow_workload=True``, emitted by
both the cloud (#117) and agentic (#121) detectors) route to *governance*,
not IR. This table records the decision: ``registered`` (sanctioned, now
managed) or ``sunset`` (to be decommissioned). One row per (org, resource);
re-governing updates the decision instead of duplicating. No backfill,
fully reversible.

Revision ID: 0044_shadow_agent_registry
Revises: 0043_technique_exercises
Create Date: 2026-07-23
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0044_shadow_agent_registry"
down_revision: str | None = "0043_technique_exercises"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "shadow_agent_registry",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(length=64),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("resource_key", sa.String(length=512), nullable=False),
        sa.Column("kind", sa.String(length=64), nullable=False, server_default="unknown"),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column(
            "decided_by",
            sa.String(length=64),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("rationale", sa.Text(), nullable=False, server_default=""),
        sa.Column("source_finding_id", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(
        "idx_shadow_registry_org_resource",
        "shadow_agent_registry",
        ["org_id", "resource_key"],
        unique=True,
    )
    op.create_index("idx_shadow_registry_org_status", "shadow_agent_registry", ["org_id", "status"])


def downgrade() -> None:
    op.drop_index("idx_shadow_registry_org_status", table_name="shadow_agent_registry")
    op.drop_index("idx_shadow_registry_org_resource", table_name="shadow_agent_registry")
    op.drop_table("shadow_agent_registry")
