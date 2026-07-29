"""Behavioral centroids on pgvector + entity archival lifecycle (#114).

Two changes to the Behavioral Hunter store:

1. ``behavioral_profiles.centroid`` moves from JSONB ``list[float]`` to a
   pgvector ``vector(1536)`` with an HNSW **cosine** index
   (``idx_behavioral_profiles_centroid_hnsw``), mirroring
   ``idx_knowledge_chunks_embedding_hnsw`` / ``idx_agent_memory_embedding_hnsw``
   exactly — same dimension, same ``m``/``ef_construction``, same operator
   class. This is what makes *cross-entity* nearest-neighbour search possible
   ("which other entities baseline like this one?"), which the JSONB column
   could not express.

   **Existing rows are NOT converted.** The centroid is *derived* data — the
   elementwise mean of a baseline window's embeddings — and JSONB → vector is
   not a safe in-place cast (rows written by an embedding provider with a
   different dimension, or with a NULL/garbage payload, would abort the whole
   migration). The column is therefore dropped and re-added empty: every
   profile lands with ``centroid IS NULL`` and is **rebuilt on the next
   scheduled baseline sweep** (``scheduler.jobs.behavioral_baseline_sweep``,
   default cadence ``behavioral_stale_after_days`` / every 6 h). Detection
   degrades safely in the meantime: a profile with no centroid scores every
   event at the worst-case distance ``1.0``, and the frequency-map half of the
   scorer (process lineage) is untouched, so the AND-gate in
   ``score_outlier`` keeps the detector from spraying false positives.
   ``frequency_map``, ``pattern_count`` and ``sample_size`` all survive.

2. ``behavioral_entities.archived_at`` (nullable, NULL == active) plus a
   covering ``(org_id, archived_at)`` index. The stale sweep now *acts* rather
   than only counting: entities unobserved for the configured window are
   stamped archived and excluded from subsequent sweeps and from cross-entity
   similarity search. Reversible by design — observing the entity again clears
   the flag; no row is ever deleted.

PostgreSQL-only chain (0001 already requires the ``vector`` extension). The
SQLite unit-test schema is built from ``Base.metadata.create_all``, which maps
the same column and skips the PG-only index.

Revision ID: 0063_behavioral_vector
Revises: 0060_memory_embedding
Create Date: 2026-07-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "0063_behavioral_vector"
down_revision: str | None = "0060_memory_embedding"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # --- 1. centroid: JSONB -> vector(1536) + HNSW cosine index ------------
    # Raw SQL exactly as ``0004_knowledge_base`` / ``0060_memory_embedding``
    # do: ``vector`` is an extension type, not a core SQLAlchemy one.
    op.execute("CREATE EXTENSION IF NOT EXISTS vector")
    op.drop_column("behavioral_profiles", "centroid")
    op.execute("ALTER TABLE behavioral_profiles ADD COLUMN centroid vector(1536)")
    op.execute(
        "CREATE INDEX idx_behavioral_profiles_centroid_hnsw "
        "ON behavioral_profiles USING hnsw (centroid vector_cosine_ops) "
        "WITH (m = 16, ef_construction = 64)"
    )

    # --- 2. entity archival lifecycle flag ---------------------------------
    op.add_column(
        "behavioral_entities",
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "idx_behavioral_entities_archived_at",
        "behavioral_entities",
        ["org_id", "archived_at"],
    )


def downgrade() -> None:
    op.drop_index("idx_behavioral_entities_archived_at", table_name="behavioral_entities")
    op.drop_column("behavioral_entities", "archived_at")

    op.execute("DROP INDEX IF EXISTS idx_behavioral_profiles_centroid_hnsw")
    op.drop_column("behavioral_profiles", "centroid")
    # Same rebuild-on-next-sweep contract in reverse: the JSONB column comes
    # back empty and the sweep refills it.
    op.add_column("behavioral_profiles", sa.Column("centroid", JSONB, nullable=True))
