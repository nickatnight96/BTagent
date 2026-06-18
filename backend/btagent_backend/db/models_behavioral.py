"""SQLAlchemy ORM models for the Behavioral Hunter (Phase 6 #114).

The baseline-driven counterpart to the Hunt Pack Runner. Three tables:

* ``behavioral_entities`` — the subject of profiling (user / host / SP / IP),
  unique per ``(org_id, kind, canonical_id)`` so the service can upsert.
* ``behavioral_profiles`` — one per ``(entity, profile_type)`` baseline window.
  Centroid stored as JSONB ``list[float]`` rather than ``pgvector.Vector`` for
  the Phase A slice: the OutlierDetector looks up by ``entity_id`` (no
  cross-entity nearest-neighbor query), so HNSW search isn't needed yet.
  When that lookup pattern lands (Phase B's drift dashboard / Phase C's
  closed-loop retraining), we'll migrate to ``Vector(1536)`` + an HNSW
  index — a straightforward additive change.
* ``behavioral_outliers`` — per-event anomaly records with optional LLM
  intent label and a back-reference to the #119 ``HuntFinding`` they're
  promoted into.
"""

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from btagent_backend.db.models import Base, utcnow


class BehavioralEntityRow(Base):
    """A user / host / service-principal / IP being profiled."""

    __tablename__ = "behavioral_entities"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    # ``EntityKind`` value — stored as string so a new kind doesn't require a
    # destructive migration.
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    canonical_id: Mapped[str] = mapped_column(String(512), nullable=False)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    enrichment: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    __table_args__ = (
        Index("idx_behavioral_entities_org_id", "org_id"),
        # Upsert key: one row per (org, kind, canonical_id).
        Index(
            "idx_behavioral_entities_unique",
            "org_id",
            "kind",
            "canonical_id",
            unique=True,
        ),
    )


class BehavioralProfileRow(Base):
    """One behavioral baseline window for one entity × profile_type."""

    __tablename__ = "behavioral_profiles"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    entity_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("behavioral_entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    # ``ProfileType`` value (cmdline_embedding / process_tree_pattern / etc.).
    profile_type: Mapped[str] = mapped_column(String(64), nullable=False)
    # Centroid as JSONB list[float] — see module docstring on the choice.
    centroid: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    frequency_map: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    pattern_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sample_size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    __table_args__ = (
        Index("idx_behavioral_profiles_org_id", "org_id"),
        Index("idx_behavioral_profiles_entity_type", "entity_id", "profile_type"),
        Index("idx_behavioral_profiles_window_end", "window_end"),
    )


class BehavioralOutlierRow(Base):
    """One anomalous event flagged against an entity's baseline."""

    __tablename__ = "behavioral_outliers"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    entity_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("behavioral_entities.id", ondelete="CASCADE"),
        nullable=False,
    )
    profile_type: Mapped[str] = mapped_column(String(64), nullable=False)
    event_id: Mapped[str] = mapped_column(String(200), nullable=False)
    # The pattern key the scorer matched on (may differ from ``event_id``).
    # Persisted so benign feedback raises the *same* key the scorer looks up,
    # actually suppressing the pattern. Nullable for rows written before this
    # column existed; feedback falls back to ``event_id`` for those.
    event_pattern_key: Mapped[str | None] = mapped_column(String(512), nullable=True)
    cosine_distance: Mapped[float] = mapped_column(Float, nullable=False)
    frequency_rank: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    raw_event_excerpt: Mapped[str] = mapped_column(Text, default="")
    # LLM-rated intent (benign / suspicious / malicious) — populated by the
    # IntentClassifier follow-up; nullable so a row can land before the LLM
    # call completes.
    intent_label: Mapped[str | None] = mapped_column(String(16), nullable=True)
    intent_rationale: Mapped[str | None] = mapped_column(Text, nullable=True)
    promoted_to_finding_id: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey("hunt_findings.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    __table_args__ = (
        Index("idx_behavioral_outliers_org_id", "org_id"),
        Index("idx_behavioral_outliers_entity_id", "entity_id"),
        Index("idx_behavioral_outliers_created_at", "created_at"),
        Index("idx_behavioral_outliers_intent_label", "intent_label"),
    )
