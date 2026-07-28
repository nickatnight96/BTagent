"""Unified long-term Agent Memory layer — ``agent_memory`` table (#482).

The FOUNDATIONAL slice of the unified memory store: a first-class, org-scoped
table of COMPACT STRUCTURED FACTS (``entity_note`` / ``decision`` / ``learning``
/ ``observation``) the agent has learned and should recall across
investigations. This complements — it does not replace — the existing scattered
stores (RAG knowledge, weak signals, behavioral baselines, org profile);
migrating those behind this interface is explicitly deferred.

One row per ``(org_id, kind, subject)`` — the uniqueness constraint is the
upsert key so re-recording a fact overwrites content/confidence and bumps
``updated_at`` rather than duplicating. TLP is stored per-row so recall can stay
clearance-aware. Fully additive + reversible; no backfill.

Revision ID: 0059_agent_memory
Revises: 0058_cti_edit_outcome
Create Date: 2026-07-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0059_agent_memory"
down_revision: str | None = "0058_cti_edit_outcome"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Mirror ``btagent_backend.db.models.DEFAULT_ORG_ID`` — the seeded org new rows
# default onto in single-tenant deployments.
_DEFAULT_ORG_ID = "org_default"


def upgrade() -> None:
    op.create_table(
        "agent_memory",
        sa.Column("id", sa.String(length=64), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(length=64),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
            server_default=sa.text(f"'{_DEFAULT_ORG_ID}'"),
        ),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("subject", sa.String(length=512), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("source", sa.String(length=256), nullable=False, server_default=""),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("tlp_level", sa.String(length=20), nullable=False, server_default="green"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    # Upsert key: one memory row per (org, kind, subject).
    op.create_unique_constraint(
        "uq_agent_memory_org_kind_subject",
        "agent_memory",
        ["org_id", "kind", "subject"],
    )
    # Primary recall filter (by org, optionally by subject).
    op.create_index("idx_agent_memory_org_subject", "agent_memory", ["org_id", "subject"])
    # Org-scoped recency ranking / kind filter.
    op.create_index("idx_agent_memory_org_updated", "agent_memory", ["org_id", "updated_at"])


def downgrade() -> None:
    op.drop_index("idx_agent_memory_org_updated", table_name="agent_memory")
    op.drop_index("idx_agent_memory_org_subject", table_name="agent_memory")
    op.drop_constraint("uq_agent_memory_org_kind_subject", "agent_memory", type_="unique")
    op.drop_table("agent_memory")
