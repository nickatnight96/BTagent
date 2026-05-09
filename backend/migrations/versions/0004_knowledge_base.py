"""Add knowledge base tables for pgvector RAG.

Revision ID: 0004
Revises: 0003
Create Date: 2026-03-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Enable pg_trgm extension for trigram search
    op.execute("CREATE EXTENSION IF NOT EXISTS pg_trgm")

    # Knowledge documents table
    op.create_table(
        "knowledge_documents",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("source_type", sa.String(50), nullable=False),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("metadata", JSONB, server_default="{}"),
        sa.Column("token_count", sa.Integer, server_default="0"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "idx_knowledge_docs_source_type",
        "knowledge_documents",
        ["source_type"],
    )
    op.create_index(
        "idx_knowledge_docs_created",
        "knowledge_documents",
        ["created_at"],
    )
    op.create_index(
        "idx_knowledge_docs_metadata",
        "knowledge_documents",
        ["metadata"],
        postgresql_using="gin",
    )

    # Knowledge chunks table — embedding column added via raw SQL below
    op.create_table(
        "knowledge_chunks",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column(
            "document_id",
            sa.String(64),
            sa.ForeignKey("knowledge_documents.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("chunk_index", sa.Integer, nullable=False),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("metadata", JSONB, server_default="{}"),
        sa.Column("token_count", sa.Integer, server_default="0"),
    )

    # Add pgvector embedding column (1536-dim for text-embedding-3-small)
    op.execute("ALTER TABLE knowledge_chunks ADD COLUMN embedding vector(1536)")

    # HNSW index on embedding for ANN search (cosine distance)
    op.execute(
        "CREATE INDEX idx_knowledge_chunks_embedding_hnsw "
        "ON knowledge_chunks USING hnsw (embedding vector_cosine_ops) "
        "WITH (m = 16, ef_construction = 64)"
    )

    # GIN index on metadata for JSONB queries
    op.create_index(
        "idx_knowledge_chunks_metadata",
        "knowledge_chunks",
        ["metadata"],
        postgresql_using="gin",
    )

    # Document FK index
    op.create_index(
        "idx_knowledge_chunks_document",
        "knowledge_chunks",
        ["document_id"],
    )

    # Full-text search GIN index on content
    op.execute(
        "CREATE INDEX idx_knowledge_chunks_content_ft "
        "ON knowledge_chunks USING gin (to_tsvector('english', content))"
    )

    # Trigram index on content for ILIKE pattern matching
    op.execute(
        "CREATE INDEX idx_knowledge_chunks_content_trgm "
        "ON knowledge_chunks USING gin (content gin_trgm_ops)"
    )


def downgrade() -> None:
    op.drop_table("knowledge_chunks")
    op.drop_table("knowledge_documents")
    op.execute("DROP EXTENSION IF EXISTS pg_trgm")
