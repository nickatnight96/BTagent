"""Initial schema — all Phase 1 tables.

Revision ID: 0001
Revises:
Create Date: 2026-03-26
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Enable pgvector extension (for Phase 2 knowledge agent)
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")

    # Users
    op.create_table(
        "users",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("username", sa.String(100), unique=True, nullable=False),
        sa.Column("email", sa.String(255), unique=True, nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(50), nullable=False, server_default="analyst"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_login", sa.DateTime(timezone=True), nullable=True),
    )

    # Investigations
    op.create_table(
        "investigations",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("case_id", sa.String(100), nullable=True),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text, server_default=""),
        sa.Column("status", sa.String(50), nullable=False, server_default="pending"),
        sa.Column("severity", sa.String(20), nullable=False, server_default="medium"),
        sa.Column("tlp_level", sa.String(20), nullable=False, server_default="green"),
        sa.Column("assigned_to", sa.String(64), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("template", sa.String(100), nullable=True),
        sa.Column("config", JSONB, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("idx_investigations_status", "investigations", ["status"])
    op.create_index("idx_investigations_created", "investigations", ["created_at"])
    op.create_index("idx_investigations_severity", "investigations", ["severity"])

    # Evidence (before timeline_entries due to FK)
    op.create_table(
        "evidence",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "investigation_id",
            sa.String(64),
            sa.ForeignKey("investigations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("type", sa.String(50), nullable=False),
        sa.Column("content_ref", sa.String(1000), server_default=""),
        sa.Column("hash_sha256", sa.String(64), server_default=""),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("collected_by", sa.String(200), server_default=""),
    )

    # IOCs
    op.create_table(
        "iocs",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "investigation_id",
            sa.String(64),
            sa.ForeignKey("investigations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("type", sa.String(30), nullable=False),
        sa.Column("value", sa.String(1000), nullable=False),
        sa.Column("tlp_level", sa.String(20), server_default="green"),
        sa.Column("confidence", sa.Float, server_default="0.5"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("context", sa.Text, server_default=""),
        sa.Column("source", sa.String(200), server_default=""),
        sa.Column("enrichment", JSONB, server_default="{}"),
    )
    op.create_index("idx_iocs_value", "iocs", ["value"])
    op.create_index("idx_iocs_investigation", "iocs", ["investigation_id"])
    op.create_index("idx_iocs_type", "iocs", ["type"])

    # Timeline entries
    op.create_table(
        "timeline_entries",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "investigation_id",
            sa.String(64),
            sa.ForeignKey("investigations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        sa.Column("actor", sa.String(200), server_default=""),
        sa.Column("event_type", sa.String(100), server_default=""),
        sa.Column(
            "evidence_id", sa.String(64), sa.ForeignKey("evidence.id"), nullable=True
        ),
        sa.Column("technique_id", sa.String(20), nullable=True),
    )
    op.create_index(
        "idx_timeline_investigation_ts",
        "timeline_entries",
        ["investigation_id", "timestamp"],
    )

    # Containment actions
    op.create_table(
        "containment_actions",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "investigation_id",
            sa.String(64),
            sa.ForeignKey("investigations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("action_type", sa.String(100), nullable=False),
        sa.Column("target", sa.String(500), nullable=False),
        sa.Column("status", sa.String(30), server_default="proposed"),
        sa.Column("initiated_by", sa.String(200), server_default=""),
        sa.Column("approved_by", sa.String(200), nullable=True),
        sa.Column("initiated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )

    # Events
    op.create_table(
        "events",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "investigation_id",
            sa.String(64),
            sa.ForeignKey("investigations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("type", sa.String(50), nullable=False),
        sa.Column("data", JSONB, server_default="{}"),
        sa.Column("parent_id", sa.String(64), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index(
        "idx_events_investigation_ts", "events", ["investigation_id", "timestamp"]
    )
    op.create_index("idx_events_type", "events", ["type"])

    # Audit logs (SHA256 chain)
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("seq", sa.Integer, autoincrement=True, unique=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("actor", sa.String(200), nullable=False),
        sa.Column("category", sa.String(50), nullable=False),
        sa.Column("action", sa.String(200), nullable=False),
        sa.Column("resource", sa.String(500), server_default=""),
        sa.Column("outcome", sa.String(20), nullable=False, server_default="success"),
        sa.Column("details", JSONB, server_default="{}"),
        sa.Column("prev_hash", sa.String(64), server_default=""),
        sa.Column("hash", sa.String(64), server_default=""),
    )
    op.create_index("idx_audit_seq", "audit_logs", ["seq"])
    op.create_index("idx_audit_timestamp", "audit_logs", ["timestamp"])
    op.create_index("idx_audit_actor", "audit_logs", ["actor"])

    # Cost tracking
    op.create_table(
        "cost_tracking",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "investigation_id",
            sa.String(64),
            sa.ForeignKey("investigations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("model", sa.String(100), nullable=False),
        sa.Column("input_tokens", sa.Integer, server_default="0"),
        sa.Column("output_tokens", sa.Integer, server_default="0"),
        sa.Column("cache_read_tokens", sa.Integer, server_default="0"),
        sa.Column("cache_write_tokens", sa.Integer, server_default="0"),
        sa.Column("cost_usd", sa.Float, server_default="0.0"),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("idx_cost_investigation", "cost_tracking", ["investigation_id"])
    op.create_index("idx_cost_timestamp", "cost_tracking", ["timestamp"])


def downgrade() -> None:
    op.drop_table("cost_tracking")
    op.drop_table("audit_logs")
    op.drop_table("events")
    op.drop_table("containment_actions")
    op.drop_table("timeline_entries")
    op.drop_table("iocs")
    op.drop_table("evidence")
    op.drop_table("investigations")
    op.drop_table("users")
    op.execute("DROP EXTENSION IF EXISTS vector")
