"""SQLAlchemy ORM models for the Phase 6 hunt-finding store (#119).

This is the keystone store every Phase 6 hunt source emits into:

* ``hunt_findings`` — individual proactive-hunt results.
* ``hunt_finding_clusters`` — near-duplicate findings grouped by a stable
  clustering signature (see :mod:`btagent_shared.hunt.triage`).
* ``suppression_rules`` — analyst-authored noise suppression, with a
  TTL + re-confirmation lifecycle so suppressions don't silently rot.

All three carry ``org_id`` (FK → ``organizations``) so tenant scoping is
present from day one, matching the workflow / knowledge / playbook stores.
"""

from datetime import datetime

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from btagent_backend.db.models import Base, utcnow


class HuntFindingRow(Base):
    """A single proactive-hunt result."""

    __tablename__ = "hunt_findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    # ``HuntSource`` / ``HuntDomain`` enum values — validated at the service
    # layer, stored as strings so a new source/domain doesn't need a
    # destructive migration.
    source: Mapped[str] = mapped_column(String(32), nullable=False)
    domain: Mapped[str] = mapped_column(String(32), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    # ``HuntFindingState`` value.
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="new")
    # MITRE technique ids, entity refs, observable refs, evidence provenance.
    technique_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    entities: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    observables: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    evidence: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # Stable clustering signature (see triage.finding_signature). Denormalised
    # onto the row so the inbox can group without recomputing.
    signature: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    cluster_id: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("hunt_finding_clusters.id", ondelete="SET NULL"),
        nullable=True,
    )
    suppressed_by: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("suppression_rules.id", ondelete="SET NULL"),
        nullable=True,
    )
    investigation_id: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("investigations.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    __table_args__ = (
        # Composite hot-path indexes (migration 0020): every inbox read
        # filters on org_id and either sorts by created_at or filters by
        # state, so the composites serve filter + sort/filter in one scan
        # (same rationale as 0010_perf_indexes). The single-column org_id
        # index is gone — it's a left-prefix of both composites.
        Index("idx_hunt_findings_org_created", "org_id", "created_at"),
        Index("idx_hunt_findings_org_state", "org_id", "state"),
        Index("idx_hunt_findings_state", "state"),
        Index("idx_hunt_findings_signature", "signature"),
        Index("idx_hunt_findings_cluster_id", "cluster_id"),
        Index("idx_hunt_findings_created_at", "created_at"),
    )


class HuntFindingClusterRow(Base):
    """A group of near-duplicate findings sharing a clustering signature."""

    __tablename__ = "hunt_finding_clusters"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    signature: Mapped[str] = mapped_column(String(512), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    domain: Mapped[str] = mapped_column(String(32), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, default="info")
    technique_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="clustered")
    representative_finding_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    __table_args__ = (
        Index("idx_hunt_clusters_org_id", "org_id"),
        # One cluster per (org, signature): the service upserts on this.
        Index("idx_hunt_clusters_org_signature", "org_id", "signature", unique=True),
    )


class SuppressionRuleRow(Base):
    """An analyst-authored noise suppression rule with a TTL lifecycle."""

    __tablename__ = "suppression_rules"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    # Serialised ``SuppressionMatch``.
    match: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # ``SuppressionState`` value.
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    match_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_by: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reconfirm_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("idx_suppression_rules_org_id", "org_id"),
        Index("idx_suppression_rules_state", "state"),
        Index("idx_suppression_rules_reconfirm_at", "reconfirm_at"),
    )
