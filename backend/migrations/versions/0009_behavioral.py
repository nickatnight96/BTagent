"""Add behavioral_entities + behavioral_profiles + behavioral_outliers (Phase 6 #114).

The Behavioral Hunter stack. ``behavioral_entities`` are the subjects
(user / host / SP / IP), with a unique key on
``(org_id, kind, canonical_id)`` so the service can upsert.
``behavioral_profiles`` carry one baseline per ``(entity, profile_type)``
window — centroid as JSONB ``list[float]`` for now (no cross-entity
nearest-neighbor lookups in Phase A; pgvector + HNSW migration is a
follow-up). ``behavioral_outliers`` are per-event anomaly records with a
nullable LLM intent label and a back-reference to the #119 ``HuntFinding``
they're promoted into.

Revision ID: 0009_behavioral
Revises: 0008_hunt_findings
Create Date: 2026-05-27
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0009_behavioral"
down_revision: str | None = "0008_hunt_findings"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # behavioral_entities ----------------------------------------------------
    op.create_table(
        "behavioral_entities",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(64),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("canonical_id", sa.String(512), nullable=False),
        sa.Column(
            "first_seen", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "last_seen", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("enrichment", JSONB, nullable=False, server_default="{}"),
    )
    op.create_index("idx_behavioral_entities_org_id", "behavioral_entities", ["org_id"])
    op.create_index(
        "idx_behavioral_entities_unique",
        "behavioral_entities",
        ["org_id", "kind", "canonical_id"],
        unique=True,
    )

    # behavioral_profiles ----------------------------------------------------
    op.create_table(
        "behavioral_profiles",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(64),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "entity_id",
            sa.String(64),
            sa.ForeignKey("behavioral_entities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("profile_type", sa.String(64), nullable=False),
        sa.Column("centroid", JSONB, nullable=True),
        sa.Column("frequency_map", JSONB, nullable=False, server_default="{}"),
        sa.Column("pattern_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("sample_size", sa.Integer, nullable=False, server_default="0"),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "computed_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("idx_behavioral_profiles_org_id", "behavioral_profiles", ["org_id"])
    op.create_index(
        "idx_behavioral_profiles_entity_type",
        "behavioral_profiles",
        ["entity_id", "profile_type"],
    )
    op.create_index("idx_behavioral_profiles_window_end", "behavioral_profiles", ["window_end"])

    # behavioral_outliers ----------------------------------------------------
    op.create_table(
        "behavioral_outliers",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(64),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "entity_id",
            sa.String(64),
            sa.ForeignKey("behavioral_entities.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("profile_type", sa.String(64), nullable=False),
        sa.Column("event_id", sa.String(200), nullable=False),
        sa.Column("cosine_distance", sa.Float, nullable=False),
        sa.Column("frequency_rank", sa.Integer, nullable=False, server_default="0"),
        sa.Column("raw_event_excerpt", sa.Text, server_default=""),
        sa.Column("intent_label", sa.String(16), nullable=True),
        sa.Column("intent_rationale", sa.Text, nullable=True),
        sa.Column(
            "promoted_to_finding_id",
            sa.String(64),
            sa.ForeignKey("hunt_findings.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("idx_behavioral_outliers_org_id", "behavioral_outliers", ["org_id"])
    op.create_index("idx_behavioral_outliers_entity_id", "behavioral_outliers", ["entity_id"])
    op.create_index("idx_behavioral_outliers_created_at", "behavioral_outliers", ["created_at"])
    op.create_index("idx_behavioral_outliers_intent_label", "behavioral_outliers", ["intent_label"])


def downgrade() -> None:
    op.drop_index("idx_behavioral_outliers_intent_label", table_name="behavioral_outliers")
    op.drop_index("idx_behavioral_outliers_created_at", table_name="behavioral_outliers")
    op.drop_index("idx_behavioral_outliers_entity_id", table_name="behavioral_outliers")
    op.drop_index("idx_behavioral_outliers_org_id", table_name="behavioral_outliers")
    op.drop_table("behavioral_outliers")

    op.drop_index("idx_behavioral_profiles_window_end", table_name="behavioral_profiles")
    op.drop_index("idx_behavioral_profiles_entity_type", table_name="behavioral_profiles")
    op.drop_index("idx_behavioral_profiles_org_id", table_name="behavioral_profiles")
    op.drop_table("behavioral_profiles")

    op.drop_index("idx_behavioral_entities_unique", table_name="behavioral_entities")
    op.drop_index("idx_behavioral_entities_org_id", table_name="behavioral_entities")
    op.drop_table("behavioral_entities")
