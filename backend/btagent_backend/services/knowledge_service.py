"""Knowledge base service — document ingestion, hybrid search, auto-indexing.

Provides the core business logic for the pgvector RAG knowledge agent:
- Ingest documents (chunk, embed, store)
- Hybrid search (vector similarity + keyword ILIKE + RRF re-ranking)
- Auto-index investigations and enrichment results
- CRUD operations on knowledge documents
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import InvestigationRow, IOCRow
from btagent_backend.db.models_knowledge import (
    KNOWLEDGE_SOURCE_TYPES,
    KnowledgeChunkRow,
    KnowledgeDocumentRow,
)
from btagent_backend.services.chunking_service import (
    chunk_text,
    estimate_tokens,
)
from btagent_backend.services.embedding_service import (
    EmbeddingService,
    MockEmbeddingService,
)
from btagent_shared.utils.ids import generate_id

logger = logging.getLogger("btagent.services.knowledge")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class SearchResult:
    """A single hybrid search result with source attribution."""

    chunk_content: str
    document_title: str
    source_type: str
    relevance_score: float
    metadata: dict[str, Any]
    document_id: str = ""
    chunk_id: str = ""


# ---------------------------------------------------------------------------
# KnowledgeService
# ---------------------------------------------------------------------------


class KnowledgeService:
    """Knowledge base service for document ingestion and retrieval."""

    def __init__(
        self,
        embedding_service: EmbeddingService | None = None,
    ) -> None:
        self._embedding_service = embedding_service or MockEmbeddingService()

    # ------------------------------------------------------------------ #
    # Ingest
    # ------------------------------------------------------------------ #

    async def ingest_document(
        self,
        db: AsyncSession,
        *,
        title: str,
        content: str,
        source_type: str,
        metadata: dict[str, Any] | None = None,
    ) -> KnowledgeDocumentRow:
        """Chunk text, generate embeddings, and store document + chunks.

        Parameters
        ----------
        db : AsyncSession
            Database session.
        title : str
            Document title.
        content : str
            Full document content.
        source_type : str
            One of KNOWLEDGE_SOURCE_TYPES.
        metadata : dict | None
            Additional metadata.

        Returns
        -------
        KnowledgeDocumentRow
            The persisted document row.
        """
        if source_type not in KNOWLEDGE_SOURCE_TYPES:
            raise ValueError(
                f"Invalid source_type '{source_type}'. "
                f"Must be one of: {sorted(KNOWLEDGE_SOURCE_TYPES)}"
            )

        doc_id = generate_id("kd")
        doc_metadata = metadata or {}
        doc_token_count = estimate_tokens(content)

        # Create document row
        doc = KnowledgeDocumentRow(
            id=doc_id,
            title=title,
            source_type=source_type,
            content=content,
            doc_metadata=doc_metadata,
            token_count=doc_token_count,
        )
        db.add(doc)

        # Chunk the content
        chunks = chunk_text(content, chunk_size=512, overlap=64)

        if chunks:
            # Generate embeddings for all chunks
            chunk_texts = [c.content for c in chunks]
            embeddings = await self._embedding_service.generate_embeddings(
                chunk_texts
            )

            # Create chunk rows
            for i, (chunk, embedding) in enumerate(
                zip(chunks, embeddings, strict=False)
            ):
                chunk_row = KnowledgeChunkRow(
                    id=generate_id("kc"),
                    document_id=doc_id,
                    chunk_index=chunk.index,
                    content=chunk.content,
                    embedding=embedding,
                    chunk_metadata={
                        **chunk.metadata,
                        "document_title": title,
                        "source_type": source_type,
                    },
                    token_count=chunk.token_count,
                )
                db.add(chunk_row)

        await db.flush()

        logger.info(
            "Ingested document %s (%s): %d chunks, %d tokens",
            doc_id,
            title,
            len(chunks),
            doc_token_count,
        )
        return doc

    # ------------------------------------------------------------------ #
    # Hybrid Search
    # ------------------------------------------------------------------ #

    async def hybrid_search(
        self,
        db: AsyncSession,
        *,
        query: str,
        top_k: int = 5,
        source_type_filter: str | None = None,
    ) -> list[SearchResult]:
        """Hybrid search combining vector similarity and keyword matching.

        Uses Reciprocal Rank Fusion (RRF) to merge results from:
        1. pgvector cosine distance (semantic similarity)
        2. ILIKE keyword matching (lexical match)

        Parameters
        ----------
        db : AsyncSession
            Database session.
        query : str
            Search query text.
        top_k : int
            Number of results to return.
        source_type_filter : str | None
            Optional filter by source_type.

        Returns
        -------
        list[SearchResult]
            Ranked results with source attribution.
        """
        if not query.strip():
            return []

        # Generate query embedding
        query_embeddings = (
            await self._embedding_service.generate_embeddings([query])
        )
        query_embedding = query_embeddings[0] if query_embeddings else None

        # --- Vector search ---
        vector_results: list[tuple[str, float]] = []
        if query_embedding is not None:
            vector_sql = text("""
                SELECT kc.id, 1 - (kc.embedding <=> :embedding::vector) AS similarity
                FROM knowledge_chunks kc
                JOIN knowledge_documents kd ON kd.id = kc.document_id
                WHERE kc.embedding IS NOT NULL
                {source_filter}
                ORDER BY kc.embedding <=> :embedding::vector
                LIMIT :limit
            """.format(
                source_filter=(
                    "AND kd.source_type = :source_type"
                    if source_type_filter
                    else ""
                )
            ))

            params: dict[str, Any] = {
                "embedding": str(query_embedding),
                "limit": top_k * 3,
            }
            if source_type_filter:
                params["source_type"] = source_type_filter

            result = await db.execute(vector_sql, params)
            vector_results = [
                (row[0], float(row[1])) for row in result.fetchall()
            ]

        # --- Keyword search (ILIKE) ---
        keyword_sql = text("""
            SELECT kc.id, 1.0 AS score
            FROM knowledge_chunks kc
            JOIN knowledge_documents kd ON kd.id = kc.document_id
            WHERE kc.content ILIKE :pattern
            {source_filter}
            LIMIT :limit
        """.format(
            source_filter=(
                "AND kd.source_type = :source_type"
                if source_type_filter
                else ""
            )
        ))

        kw_params: dict[str, Any] = {
            "pattern": f"%{query}%",
            "limit": top_k * 3,
        }
        if source_type_filter:
            kw_params["source_type"] = source_type_filter

        kw_result = await db.execute(keyword_sql, kw_params)
        keyword_results: list[tuple[str, float]] = [
            (row[0], float(row[1])) for row in kw_result.fetchall()
        ]

        # --- RRF Fusion ---
        rrf_k = 60  # RRF constant
        chunk_scores: dict[str, float] = {}

        for rank, (chunk_id, _) in enumerate(vector_results):
            chunk_scores[chunk_id] = chunk_scores.get(chunk_id, 0.0) + (
                1.0 / (rrf_k + rank + 1)
            )

        for rank, (chunk_id, _) in enumerate(keyword_results):
            chunk_scores[chunk_id] = chunk_scores.get(chunk_id, 0.0) + (
                1.0 / (rrf_k + rank + 1)
            )

        # Sort by RRF score
        ranked_ids = sorted(
            chunk_scores.items(), key=lambda x: x[1], reverse=True
        )[:top_k]

        if not ranked_ids:
            return []

        # Fetch full chunk + document data for ranked results
        chunk_id_list = [cid for cid, _ in ranked_ids]
        score_map = dict(ranked_ids)

        stmt = (
            select(KnowledgeChunkRow, KnowledgeDocumentRow)
            .join(
                KnowledgeDocumentRow,
                KnowledgeChunkRow.document_id == KnowledgeDocumentRow.id,
            )
            .where(KnowledgeChunkRow.id.in_(chunk_id_list))
        )
        rows = await db.execute(stmt)
        chunk_doc_map: dict[str, tuple[KnowledgeChunkRow, KnowledgeDocumentRow]] = {}
        for chunk_row, doc_row in rows.all():
            chunk_doc_map[chunk_row.id] = (chunk_row, doc_row)

        # Build ordered results
        results: list[SearchResult] = []
        for chunk_id, score in ranked_ids:
            if chunk_id not in chunk_doc_map:
                continue
            chunk_row, doc_row = chunk_doc_map[chunk_id]
            results.append(SearchResult(
                chunk_content=chunk_row.content,
                document_title=doc_row.title,
                source_type=doc_row.source_type,
                relevance_score=round(score, 6),
                metadata=chunk_row.chunk_metadata or {},
                document_id=doc_row.id,
                chunk_id=chunk_row.id,
            ))

        logger.info(
            "Hybrid search for %r: %d vector results, %d keyword results, "
            "%d final (top_k=%d)",
            query[:50],
            len(vector_results),
            len(keyword_results),
            len(results),
            top_k,
        )
        return results

    # ------------------------------------------------------------------ #
    # Auto-indexing
    # ------------------------------------------------------------------ #

    async def auto_index_investigation(
        self,
        db: AsyncSession,
        investigation_id: str,
    ) -> KnowledgeDocumentRow | None:
        """Compile investigation findings into a knowledge document.

        Called when an investigation is closed to capture findings
        for future retrieval.

        Parameters
        ----------
        db : AsyncSession
            Database session.
        investigation_id : str
            The investigation to index.

        Returns
        -------
        KnowledgeDocumentRow | None
            The created document, or None if investigation not found.
        """
        result = await db.execute(
            select(InvestigationRow).where(
                InvestigationRow.id == investigation_id
            )
        )
        investigation = result.scalar_one_or_none()
        if investigation is None:
            logger.warning(
                "Cannot auto-index: investigation %s not found",
                investigation_id,
            )
            return None

        # Compile investigation content
        content_parts = [
            f"# Investigation: {investigation.title}",
            f"\n**Case ID:** {investigation.case_id or 'N/A'}",
            f"**Status:** {investigation.status}",
            f"**Severity:** {investigation.severity}",
            f"**TLP Level:** {investigation.tlp_level}",
            f"\n## Description\n\n{investigation.description}",
        ]

        # Add IOC summary if available
        ioc_result = await db.execute(
            select(IOCRow).where(
                IOCRow.investigation_id == investigation_id
            )
        )
        iocs = ioc_result.scalars().all()
        if iocs:
            content_parts.append("\n## Indicators of Compromise\n")
            for ioc in iocs:
                content_parts.append(
                    f"- **{ioc.type}:** `{ioc.value}` "
                    f"(confidence: {ioc.confidence})"
                )

        content = "\n".join(content_parts)

        doc = await self.ingest_document(
            db,
            title=f"Investigation Report: {investigation.title}",
            content=content,
            source_type="investigation_report",
            metadata={
                "investigation_id": investigation_id,
                "case_id": investigation.case_id,
                "severity": investigation.severity,
                "status": investigation.status,
                "auto_indexed": True,
            },
        )

        logger.info(
            "Auto-indexed investigation %s as document %s",
            investigation_id,
            doc.id,
        )
        return doc

    async def auto_index_enrichment(
        self,
        db: AsyncSession,
        investigation_id: str,
    ) -> KnowledgeDocumentRow | None:
        """Index IOC enrichment results as a knowledge document.

        Parameters
        ----------
        db : AsyncSession
            Database session.
        investigation_id : str
            The investigation whose enrichment results to index.

        Returns
        -------
        KnowledgeDocumentRow | None
            The created document, or None if no enriched IOCs found.
        """
        result = await db.execute(
            select(IOCRow).where(
                IOCRow.investigation_id == investigation_id,
                IOCRow.enrichment != {},
            )
        )
        iocs = list(result.scalars().all())
        if not iocs:
            logger.info(
                "No enriched IOCs found for investigation %s",
                investigation_id,
            )
            return None

        # Compile enrichment data
        content_parts = [
            f"# Enrichment Results for Investigation {investigation_id}",
            f"\n**IOCs Enriched:** {len(iocs)}\n",
        ]

        for ioc in iocs:
            content_parts.append(f"\n## {ioc.type}: `{ioc.value}`")
            content_parts.append(
                f"- **Confidence:** {ioc.confidence}"
            )
            content_parts.append(f"- **Source:** {ioc.source}")
            if ioc.enrichment:
                content_parts.append(
                    f"- **Enrichment data:** {len(ioc.enrichment)} fields"
                )

        content = "\n".join(content_parts)

        doc = await self.ingest_document(
            db,
            title=(
                f"Enrichment Results: Investigation {investigation_id}"
            ),
            content=content,
            source_type="enrichment_data",
            metadata={
                "investigation_id": investigation_id,
                "ioc_count": len(iocs),
                "auto_indexed": True,
            },
        )

        logger.info(
            "Auto-indexed enrichment for investigation %s as document %s",
            investigation_id,
            doc.id,
        )
        return doc

    # ------------------------------------------------------------------ #
    # CRUD
    # ------------------------------------------------------------------ #

    async def delete_document(
        self,
        db: AsyncSession,
        document_id: str,
    ) -> bool:
        """Delete a document and cascade-delete its chunks.

        Parameters
        ----------
        db : AsyncSession
            Database session.
        document_id : str
            ID of the document to delete.

        Returns
        -------
        bool
            True if document was found and deleted, False otherwise.
        """
        result = await db.execute(
            select(KnowledgeDocumentRow).where(
                KnowledgeDocumentRow.id == document_id
            )
        )
        doc = result.scalar_one_or_none()
        if doc is None:
            return False

        # Chunks are cascade-deleted via FK, but explicit delete for clarity
        await db.execute(
            delete(KnowledgeChunkRow).where(
                KnowledgeChunkRow.document_id == document_id
            )
        )
        await db.execute(
            delete(KnowledgeDocumentRow).where(
                KnowledgeDocumentRow.id == document_id
            )
        )
        await db.flush()

        logger.info("Deleted document %s and its chunks", document_id)
        return True

    async def list_documents(
        self,
        db: AsyncSession,
        *,
        source_type_filter: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[KnowledgeDocumentRow], int]:
        """List documents with optional source_type filter and pagination.

        Parameters
        ----------
        db : AsyncSession
            Database session.
        source_type_filter : str | None
            Optional filter by source_type.
        page : int
            Page number (1-based).
        page_size : int
            Items per page.

        Returns
        -------
        tuple[list[KnowledgeDocumentRow], int]
            (rows, total_count)
        """
        query = select(KnowledgeDocumentRow).order_by(
            KnowledgeDocumentRow.created_at.desc()
        )
        count_query = select(func.count(KnowledgeDocumentRow.id))

        if source_type_filter:
            query = query.where(
                KnowledgeDocumentRow.source_type == source_type_filter
            )
            count_query = count_query.where(
                KnowledgeDocumentRow.source_type == source_type_filter
            )

        total_result = await db.execute(count_query)
        total = total_result.scalar() or 0

        query = query.offset((page - 1) * page_size).limit(page_size)
        result = await db.execute(query)
        rows = list(result.scalars().all())

        return rows, total

    async def get_document(
        self,
        db: AsyncSession,
        document_id: str,
    ) -> KnowledgeDocumentRow | None:
        """Fetch a single document by ID."""
        result = await db.execute(
            select(KnowledgeDocumentRow).where(
                KnowledgeDocumentRow.id == document_id
            )
        )
        return result.scalar_one_or_none()

    async def get_document_chunk_count(
        self,
        db: AsyncSession,
        document_id: str,
    ) -> int:
        """Get the number of chunks for a document."""
        result = await db.execute(
            select(func.count(KnowledgeChunkRow.id)).where(
                KnowledgeChunkRow.document_id == document_id
            )
        )
        return result.scalar() or 0
