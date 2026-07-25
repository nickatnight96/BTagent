"""SQLAlchemy ORM models for the BTagent Knowledge Base (pgvector RAG)."""

from datetime import datetime

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from btagent_backend.db.models import DEFAULT_ORG_ID, Base, utcnow


class KnowledgeDocumentRow(Base):
    """A knowledge base document (investigation report, runbook, etc.)."""

    __tablename__ = "knowledge_documents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    # GH #386: tenant scoping. Without ``org_id`` the RAG store is shared
    # across every organization, so org B could query/read/delete org A's
    # knowledge docs. Follows the UserRow convention (nullable=False, FK to
    # organizations, defaulting to the seeded org so internal callers keep
    # working); the API route sets it from the authenticated user.
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
        default=DEFAULT_ORG_ID,
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    source_type: Mapped[str] = mapped_column(String(50), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    # 'metadata' is reserved in SQLAlchemy declarative; use 'doc_metadata'
    # as the Python attribute name, mapping to the 'metadata' DB column.
    doc_metadata: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)
    token_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    # Relationships
    chunks: Mapped[list["KnowledgeChunkRow"]] = relationship(
        back_populates="document",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("idx_knowledge_docs_source_type", "source_type"),
        Index("idx_knowledge_docs_created", "created_at"),
        Index(
            "idx_knowledge_docs_metadata",
            "metadata",
            postgresql_using="gin",
        ),
        # GH #386: covers the per-tenant org_id filter on every read/delete.
        Index("idx_knowledge_documents_org_id", "org_id", "id"),
    )


# Valid source types for knowledge documents
KNOWLEDGE_SOURCE_TYPES = {
    "investigation_report",
    "runbook",
    "threat_profile",
    "agency_profile",
    "enrichment_data",
    "playbook_log",
    "conversation",
}


class KnowledgeChunkRow(Base):
    """A vector-embedded chunk of a knowledge document."""

    __tablename__ = "knowledge_chunks"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    document_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("knowledge_documents.id", ondelete="CASCADE"),
        nullable=False,
    )
    # GH #386: org_id is denormalized onto the chunk so the hybrid-search
    # SQL (vector + keyword) can filter by tenant directly on the chunk row
    # without depending solely on the join to knowledge_documents.
    org_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("organizations.id"),
        nullable=False,
        index=True,
        default=DEFAULT_ORG_ID,
    )
    chunk_index: Mapped[int] = mapped_column(Integer, nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    embedding = mapped_column(Vector(1536), nullable=True)
    # 'metadata' is reserved in SQLAlchemy declarative; use 'chunk_metadata'
    chunk_metadata: Mapped[dict] = mapped_column("metadata", JSONB, default=dict)
    token_count: Mapped[int] = mapped_column(Integer, default=0)

    # Relationships
    document: Mapped["KnowledgeDocumentRow"] = relationship(
        back_populates="chunks",
    )

    __table_args__ = (
        Index(
            "idx_knowledge_chunks_embedding_hnsw",
            "embedding",
            postgresql_using="hnsw",
            postgresql_with={"m": 16, "ef_construction": 64},
            postgresql_ops={"embedding": "vector_cosine_ops"},
        ),
        Index(
            "idx_knowledge_chunks_metadata",
            "metadata",
            postgresql_using="gin",
        ),
        Index("idx_knowledge_chunks_document", "document_id"),
        Index(
            "idx_knowledge_chunks_content_ft",
            func.to_tsvector("english", "content"),
            postgresql_using="gin",
        ),
        # GH #386: covers the per-tenant org_id filter in hybrid_search.
        Index("idx_knowledge_chunks_org_id", "org_id", "document_id"),
    )
