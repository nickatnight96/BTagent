"""Add hunt_findings + hunt_finding_clusters + suppression_rules (Phase 6 #119).

The keystone store for proactive threat hunting. Every Phase 6 hunt source
(hunt packs, behavioral, identity, cloud, cross-investigation, agentic)
emits ``HuntFinding`` rows here; the Hunt Triage Agent clusters them,
suppresses noise, and promotes the interesting ones into investigations.

* ``hunt_finding_clusters`` — created first so ``hunt_findings.cluster_id``
  can FK to it.
* ``suppression_rules`` — created before ``hunt_findings`` so
  ``hunt_findings.suppressed_by`` can FK to it.
* ``hunt_findings`` — individual results, FK'ing to clusters, suppressions,
  and (on promotion) investigations.

All three carry ``org_id`` (FK → ``organizations``) for tenant scoping.

Revision ID: 0008_hunt_findings
Revises: 0007_workflows
Create Date: 2026-05-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0008_hunt_findings"
down_revision: str | None = "0007_workflows"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # hunt_finding_clusters --------------------------------------------------
    op.create_table(
        "hunt_finding_clusters",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(64),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("signature", sa.String(512), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("domain", sa.String(32), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False, server_default="info"),
        sa.Column("technique_ids", JSONB, nullable=False, server_default="[]"),
        sa.Column("finding_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("state", sa.String(16), nullable=False, server_default="clustered"),
        sa.Column("representative_finding_id", sa.String(64), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("idx_hunt_clusters_org_id", "hunt_finding_clusters", ["org_id"])
    op.create_index(
        "idx_hunt_clusters_org_signature",
        "hunt_finding_clusters",
        ["org_id", "signature"],
        unique=True,
    )

    # suppression_rules ------------------------------------------------------
    op.create_table(
        "suppression_rules",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(64),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("match", JSONB, nullable=False, server_default="{}"),
        sa.Column("state", sa.String(20), nullable=False, server_default="active"),
        sa.Column("match_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column(
            "created_by",
            sa.String(64),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reconfirm_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("idx_suppression_rules_org_id", "suppression_rules", ["org_id"])
    op.create_index("idx_suppression_rules_state", "suppression_rules", ["state"])
    op.create_index("idx_suppression_rules_reconfirm_at", "suppression_rules", ["reconfirm_at"])

    # hunt_findings ----------------------------------------------------------
    op.create_table(
        "hunt_findings",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(64),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("source", sa.String(32), nullable=False),
        sa.Column("domain", sa.String(32), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("description", sa.Text, server_default=""),
        sa.Column("severity", sa.String(16), nullable=False, server_default="medium"),
        sa.Column("confidence", sa.Float, nullable=False, server_default="0.5"),
        sa.Column("state", sa.String(16), nullable=False, server_default="new"),
        sa.Column("technique_ids", JSONB, nullable=False, server_default="[]"),
        sa.Column("entities", JSONB, nullable=False, server_default="[]"),
        sa.Column("observables", JSONB, nullable=False, server_default="[]"),
        sa.Column("evidence", JSONB, nullable=False, server_default="{}"),
        sa.Column("signature", sa.String(512), nullable=False, server_default=""),
        sa.Column(
            "cluster_id",
            sa.String(64),
            sa.ForeignKey("hunt_finding_clusters.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "suppressed_by",
            sa.String(64),
            sa.ForeignKey("suppression_rules.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "investigation_id",
            sa.String(64),
            sa.ForeignKey("investigations.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_index("idx_hunt_findings_org_id", "hunt_findings", ["org_id"])
    op.create_index("idx_hunt_findings_state", "hunt_findings", ["state"])
    op.create_index("idx_hunt_findings_signature", "hunt_findings", ["signature"])
    op.create_index("idx_hunt_findings_cluster_id", "hunt_findings", ["cluster_id"])
    op.create_index("idx_hunt_findings_created_at", "hunt_findings", ["created_at"])


def downgrade() -> None:
    op.drop_index("idx_hunt_findings_created_at", table_name="hunt_findings")
    op.drop_index("idx_hunt_findings_cluster_id", table_name="hunt_findings")
    op.drop_index("idx_hunt_findings_signature", table_name="hunt_findings")
    op.drop_index("idx_hunt_findings_state", table_name="hunt_findings")
    op.drop_index("idx_hunt_findings_org_id", table_name="hunt_findings")
    op.drop_table("hunt_findings")

    op.drop_index("idx_suppression_rules_reconfirm_at", table_name="suppression_rules")
    op.drop_index("idx_suppression_rules_state", table_name="suppression_rules")
    op.drop_index("idx_suppression_rules_org_id", table_name="suppression_rules")
    op.drop_table("suppression_rules")

    op.drop_index("idx_hunt_clusters_org_signature", table_name="hunt_finding_clusters")
    op.drop_index("idx_hunt_clusters_org_id", table_name="hunt_finding_clusters")
    op.drop_table("hunt_finding_clusters")
