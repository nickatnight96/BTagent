"""SQLAlchemy ORM models for the Behavioral Hunter (Phase 6 #114).

The baseline-driven counterpart to the Hunt Pack Runner. Three tables:

* ``behavioral_entities`` — the subject of profiling (user / host / SP / IP),
  unique per ``(org_id, kind, canonical_id)`` so the service can upsert.
* ``behavioral_profiles`` — one per ``(entity, profile_type)`` baseline window.
  The centroid is a pgvector ``Vector(1536)`` with an HNSW **cosine** index,
  mirroring ``KnowledgeChunkRow.embedding`` / ``AgentMemoryRow.embedding``
  exactly (same dimension, same index shape, same provider) so the Behavioral
  Hunter genuinely reuses the platform's pgvector substrate. That is what makes
  *cross-entity* nearest-neighbour possible (``behavioral_service.
  find_similar_profiles`` — "which other entities baseline like this one?"),
  which the original JSONB ``list[float]`` column could not express.
* ``behavioral_outliers`` — per-event anomaly records with optional LLM
  intent label and a back-reference to the #119 ``HuntFinding`` they're
  promoted into.

Entity lifecycle: ``BehavioralEntityRow.archived_at`` (NULL == active) is
stamped by the stale sweep when an entity has not been observed for the
configured window (a departed user / decommissioned host). Archived entities
are excluded from the stale sweep and from cross-entity similarity search, and
are revived automatically the moment the entity is observed again (the upsert
clears the flag). Nothing is deleted — archival is a reversible flag, not a
destructive action.
"""

from datetime import datetime

from pgvector.sqlalchemy import Vector
from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from btagent_backend.db.models import DEFAULT_ORG_ID, Base, utcnow

# Centroid dimension. Identical to ``KnowledgeChunkRow.embedding`` and
# ``AgentMemoryRow.embedding`` (OpenAI text-embedding-3-small / the mock
# embedder's deterministic 1536-dim vector) so one embedding provider and one
# index shape serve RAG, agent memory, and behavioral baselines alike.
CENTROID_DIM = 1536


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
    # Lifecycle flag. NULL == active; a timestamp == archived by the stale
    # sweep because the entity went unobserved for the configured window.
    # Archived entities are excluded from the stale sweep and from
    # cross-entity similarity search, and are revived (flag cleared) the next
    # time the entity is observed. Never deleted — the baselines stay for
    # audit/forensics.
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

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
        # Covers the "active entities only" filter the sweep + similarity
        # search apply.
        Index("idx_behavioral_entities_archived_at", "org_id", "archived_at"),
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
    # Baseline centroid as a pgvector ``Vector(1536)`` — see module docstring.
    # Nullable: a profile_type can be frequency-map-only (process lineage,
    # identity action sequences) with no meaningful embedding centroid.
    centroid = mapped_column(Vector(CENTROID_DIM), nullable=True)
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
        # ANN index for cross-entity nearest-neighbour search — cosine
        # distance, matching ``idx_knowledge_chunks_embedding_hnsw`` and
        # ``idx_agent_memory_embedding_hnsw``. PostgreSQL only; the conftest
        # strips postgresql-specific indexes before ``create_all`` builds the
        # SQLite unit-test schema.
        Index(
            "idx_behavioral_profiles_centroid_hnsw",
            "centroid",
            postgresql_using="hnsw",
            postgresql_with={"m": 16, "ef_construction": 64},
            postgresql_ops={"centroid": "vector_cosine_ops"},
        ),
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


class OrgProfileRow(Base):
    """Per-org organisation profile injected into agent prompts (GH #393).

    The org profile contextualises agent system prompts to a tenant's industry,
    compliance posture, tech stack, and IR team. It was previously stored as a
    *single global row* in ``org_config`` (``key='org_profile'``): any analyst
    read another org's profile, and an admin's update overwrote the one global
    row — poisoning every other org's agent prompts (cross-tenant read +
    destructive cross-tenant write).

    This model makes the profile **per-org**: one row per ``org_id`` (enforced
    by a unique index), following the ``UserRow`` org-scoping convention
    (``String(64)`` FK ``organizations.id``, ``nullable=False``, defaulting to
    ``DEFAULT_ORG_ID``). Reads and writes in ``api/v1/config.py`` are scoped to
    the authenticated user's ``org_id``, so cross-tenant access is structurally
    impossible.
    """

    __tablename__ = "org_profiles"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        default=DEFAULT_ORG_ID,
    )
    # The serialised ``OrgProfile`` (see ``services.org_profile.OrgProfile``).
    profile: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )
    updated_by: Mapped[str | None] = mapped_column(String(64), nullable=True)

    __table_args__ = (
        # One profile row per org — the tenant-isolation invariant.
        Index("idx_org_profiles_org_id", "org_id", unique=True),
    )
