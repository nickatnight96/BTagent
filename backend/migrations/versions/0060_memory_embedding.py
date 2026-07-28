"""Agent Memory semantic recall + consolidation columns (#482, slice 2).

Adds two nullable columns to ``agent_memory`` plus the ANN index that makes
associative recall possible:

* ``embedding`` — ``vector(1536)``, the same dimension/provider as
  ``knowledge_chunks.embedding``, with an HNSW **cosine** index mirroring
  ``idx_knowledge_chunks_embedding_hnsw``. Nullable on purpose: the write path
  generates it best-effort, so a memory recorded while the embedding provider
  is unconfigured/down still lands (and stays recallable via the existing
  recency/subject path).
* ``superseded_at`` — stamped by consolidation when a near-duplicate row is
  collapsed into a surviving one. Superseded rows are excluded from every
  recall path but retained (not deleted) so the collapse is auditable.

Fully additive + reversible; no backfill (existing rows simply have a NULL
embedding until they are next recorded/consolidated).

Revision ID: 0060_memory_embedding
Revises: 0059_agent_memory
Create Date: 2026-07-28
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0060_memory_embedding"
down_revision: str | None = "0059_agent_memory"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "agent_memory",
        sa.Column("superseded_at", sa.DateTime(timezone=True), nullable=True),
    )
    # Covers the "live rows only" filter every recall path applies and the
    # consolidation sweep's per-org scan.
    op.create_index(
        "idx_agent_memory_org_superseded",
        "agent_memory",
        ["org_id", "superseded_at"],
    )

    # pgvector column + ANN index, via raw SQL exactly as ``0004_knowledge_base``
    # does: ``vector`` is an extension type, not a core SQLAlchemy one. This
    # migration chain is PostgreSQL-only (0001 already requires the extension);
    # the SQLite unit-test schema is built from ``Base.metadata.create_all``,
    # which maps the same column and skips the PG-only index.
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")
    op.execute("ALTER TABLE agent_memory ADD COLUMN embedding vector(1536)")
    op.execute(
        "CREATE INDEX idx_agent_memory_embedding_hnsw "
        "ON agent_memory USING hnsw (embedding vector_cosine_ops) "
        "WITH (m = 16, ef_construction = 64)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_agent_memory_embedding_hnsw")
    op.drop_index("idx_agent_memory_org_superseded", table_name="agent_memory")
    op.drop_column("agent_memory", "embedding")
    op.drop_column("agent_memory", "superseded_at")
