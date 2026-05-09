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

from btagent_backend.db.models import Base, utcnow


class KnowledgeDocumentRow(Base):
    """A knowledge base document (investigation report, runbook, etc.)."""

    __tablename__ = "knowledge_documents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
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
    )
