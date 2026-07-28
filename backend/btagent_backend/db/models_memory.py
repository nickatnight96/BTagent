"""SQLAlchemy ORM model for the unified long-term Agent Memory layer (#482).

This is the FOUNDATIONAL slice of the unified memory store. Where BTagent's
existing persistent stores hold *documents* (RAG knowledge chunks), *signals*
(cross-investigation weak signals), *baselines* (behavioral profiles), or the
*org profile*, this table holds COMPACT STRUCTURED FACTS the agent has learned
and should recall across investigations:

* ``entity_note``  — a durable note about a specific entity (host / user / IOC /
  technique) e.g. "10.0.0.5 is the primary domain controller".
* ``decision``     — a decision or disposition reached e.g. an investigation's
  final verdict for a subject.
* ``learning``     — a generalised lesson e.g. "beaconing to <domain> was benign
  telemetry, not C2".
* ``observation``  — a lighter-weight recorded observation.

Every row is org-scoped (``org_id``, defaulting to the seeded ``org_default``)
following the ``UserRow`` / ``KnowledgeDocumentRow`` convention so one tenant's
memory can never surface in another tenant's recall. The ``(org_id, kind,
subject)`` uniqueness constraint is the upsert key: recording a fact about an
entity that already has one of that kind overwrites the content and bumps
``updated_at`` rather than appending a duplicate.

Slice 2 (#482) adds two columns to this row:

* ``embedding`` — a nullable pgvector ``Vector(1536)`` (same dimension and HNSW
  cosine index as ``knowledge_chunks``) so recall can be *associative* rather
  than exact-subject-only. Best-effort: a memory whose embedding could not be
  generated (no provider configured, provider outage) still records and is
  still recallable by the recency/subject path.
* ``superseded_at`` — set by consolidation when a near-duplicate row is
  collapsed into a surviving one. Superseded rows are excluded from every
  recall path but are retained for audit rather than deleted.

Deferred (see #482): a frontend surface, migrating the scattered stores behind
this interface, and cross-org/global memory.
"""

from datetime import datetime

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from btagent_backend.db.models import DEFAULT_ORG_ID, Base, utcnow

# Recognised memory kinds. Stored as a plain string on the row so adding a new
# kind never needs a destructive migration; the service validates against this
# set on write.
MEMORY_KINDS: frozenset[str] = frozenset({"entity_note", "decision", "learning", "observation"})


class AgentMemoryRow(Base):
    """One compact, structured, recallable fact in the unified memory store."""

    __tablename__ = "agent_memory"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    # Tenant scope. nullable=False + default to the seeded org, mirroring the
    # UserRow / KnowledgeDocumentRow convention; the API route sets it from the
    # authenticated user and the auto-write hook from the investigation's org.
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        default=DEFAULT_ORG_ID,
    )
    # One of ``MEMORY_KINDS``. Kept as a string (not an enum column) so a new
    # kind is additive.
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    # The entity this fact is about — a host, username, IOC value, MITRE
    # technique id, etc. This is the primary recall handle.
    subject: Mapped[str] = mapped_column(String(512), nullable=False)
    # The fact body itself.
    content: Mapped[str] = mapped_column(Text, nullable=False)
    # Where the fact came from — an investigation id, an agent name, or an
    # analyst user id.
    source: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    # Optional confidence in [0, 1]; ``None`` when the recorder had no basis.
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    # TLP classification of the fact. Defaults to green (community) — recall is
    # TLP-aware and never returns a memory more restricted than the caller's
    # clearance.
    tlp_level: Mapped[str] = mapped_column(String(20), nullable=False, default="green")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )
    # Semantic recall vector (#482 slice 2). Mirrors ``KnowledgeChunkRow.
    # embedding`` exactly — same 1536 dimension, same HNSW cosine index — so the
    # memory store reuses the RAG stack's embedding provider and index shape.
    # Nullable and best-effort: embedding generation never blocks a write.
    embedding = mapped_column(Vector(1536), nullable=True)
    # Set when consolidation collapses this row into a surviving near-duplicate.
    # NULL == live. Superseded rows are excluded from recall (all paths) but
    # kept on the table so the collapse stays auditable/reversible.
    superseded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        # Upsert key: one row per (org, kind, subject).
        UniqueConstraint("org_id", "kind", "subject", name="uq_agent_memory_org_kind_subject"),
        # Covers the primary recall filter (by org, optionally by subject).
        Index("idx_agent_memory_org_subject", "org_id", "subject"),
        # Covers the org-scoped recency ranking / kind filter.
        Index("idx_agent_memory_org_updated", "org_id", "updated_at"),
        # Covers the live-rows filter every recall path applies, and the
        # consolidation sweep's per-org scan of live rows.
        Index("idx_agent_memory_org_superseded", "org_id", "superseded_at"),
        # ANN index for semantic recall — cosine distance, matching
        # ``idx_knowledge_chunks_embedding_hnsw``. PostgreSQL only; the
        # conftest strips postgresql-specific indexes before ``create_all``
        # builds the SQLite unit-test schema.
        Index(
            "idx_agent_memory_embedding_hnsw",
            "embedding",
            postgresql_using="hnsw",
            postgresql_with={"m": 16, "ef_construction": 64},
            postgresql_ops={"embedding": "vector_cosine_ops"},
        ),
    )
