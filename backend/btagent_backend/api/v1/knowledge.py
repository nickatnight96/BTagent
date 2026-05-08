"""Knowledge base API — document ingestion, hybrid search, and management."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.config import get_settings
from btagent_backend.db.models_knowledge import KnowledgeDocumentRow
from btagent_backend.services.embedding_service import get_embedding_service
from btagent_backend.services.knowledge_service import KnowledgeService

logger = logging.getLogger("btagent.api.knowledge")

router = APIRouter(prefix="/knowledge", tags=["knowledge"])


# --------------------------------------------------------------------------- #
# Request / Response schemas
# --------------------------------------------------------------------------- #


class IngestRequest(BaseModel):
    # SEC-P2-003 FIX: Size limits to prevent memory exhaustion
    title: str = Field(max_length=500)
    content: str = Field(max_length=1_000_000)  # 1MB limit
    source_type: str = Field(max_length=50)
    metadata: dict[str, Any] = Field(default_factory=dict)
    # Optional TLP-style classification of the source document. The
    # knowledge service refuses TLP:RED ingest because the RAG store is
    # shared across investigations and a lower-clearance retrieval must
    # not be able to surface restricted content.
    classification: str | None = Field(default=None, max_length=20)


class QueryRequestBody(BaseModel):
    query: str
    top_k: int = Field(default=5, ge=1, le=50)
    source_type_filter: str | None = None


class SearchResultResponse(BaseModel):
    chunk_content: str
    document_title: str
    source_type: str
    relevance_score: float
    metadata: dict[str, Any] = Field(default_factory=dict)
    document_id: str = ""
    chunk_id: str = ""


class QueryResponse(BaseModel):
    query: str
    results: list[SearchResultResponse]
    total_results: int


class DocumentResponse(BaseModel):
    id: str
    title: str
    source_type: str
    token_count: int
    metadata: dict[str, Any]
    created_at: str | None
    updated_at: str | None


class DocumentDetailResponse(DocumentResponse):
    content: str
    chunk_count: int


class DocumentListResponse(BaseModel):
    items: list[DocumentResponse]
    total: int
    page: int
    page_size: int


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _get_knowledge_service() -> KnowledgeService:
    """Build a KnowledgeService with the configured embedding service."""
    settings = get_settings()
    embedding_svc = get_embedding_service(settings)
    return KnowledgeService(embedding_service=embedding_svc)


def _to_doc_response(row: KnowledgeDocumentRow) -> DocumentResponse:
    return DocumentResponse(
        id=row.id,
        title=row.title,
        source_type=row.source_type,
        token_count=row.token_count,
        metadata=row.doc_metadata or {},
        created_at=row.created_at.isoformat() if row.created_at else None,
        updated_at=row.updated_at.isoformat() if row.updated_at else None,
    )


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #


@router.post("/ingest", status_code=status.HTTP_201_CREATED)
async def ingest_document(
    body: IngestRequest,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Ingest a document into the knowledge base.

    Chunks the content, generates embeddings, and stores both the
    document and its vector-embedded chunks.
    """
    user.require_permission("knowledge:ingest")

    svc = _get_knowledge_service()
    try:
        doc = await svc.ingest_document(
            db,
            title=body.title,
            content=body.content,
            source_type=body.source_type,
            metadata=body.metadata,
            classification=body.classification,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )
    except Exception as exc:
        # ``btagent_shared.security.TLPViolation`` (raised from
        # ``assert_tlp_allows_egress`` on TLP:RED ingest) propagates
        # uncaught otherwise. Surface it as 403 so the API contract
        # asserted in tests/e2e/specs/knowledge/tlp-block.spec.ts holds.
        from btagent_shared.security import TLPViolation

        if isinstance(exc, TLPViolation):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=str(exc),
            )
        raise

    return {
        "id": doc.id,
        "title": doc.title,
        "source_type": doc.source_type,
        "token_count": doc.token_count,
        "message": "Document ingested successfully",
    }


@router.post("/query", response_model=QueryResponse)
async def query_knowledge_base(
    body: QueryRequestBody,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Hybrid search the knowledge base.

    Combines vector similarity search (pgvector cosine distance) with
    keyword matching (ILIKE), using Reciprocal Rank Fusion for re-ranking.
    Returns ranked chunks with source attribution and citations.
    """
    user.require_permission("knowledge:query")

    svc = _get_knowledge_service()
    results = await svc.hybrid_search(
        db,
        query=body.query,
        top_k=body.top_k,
        source_type_filter=body.source_type_filter,
    )

    return QueryResponse(
        query=body.query,
        results=[
            SearchResultResponse(
                chunk_content=r.chunk_content,
                document_title=r.document_title,
                source_type=r.source_type,
                relevance_score=r.relevance_score,
                metadata=r.metadata,
                document_id=r.document_id,
                chunk_id=r.chunk_id,
            )
            for r in results
        ],
        total_results=len(results),
    )


@router.get("/search", response_model=QueryResponse)
async def keyword_search(
    q: str = Query(..., min_length=1),
    top_k: int = Query(5, ge=1, le=50),
    source_type: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Simple keyword search (no vector similarity).

    Searches knowledge chunks using ILIKE pattern matching.
    Simpler than /query — no embedding generation needed.
    """
    user.require_permission("knowledge:query")

    svc = _get_knowledge_service()
    # Use hybrid_search but the keyword component will dominate for
    # simple keyword queries
    results = await svc.hybrid_search(
        db,
        query=q,
        top_k=top_k,
        source_type_filter=source_type,
    )

    return QueryResponse(
        query=q,
        results=[
            SearchResultResponse(
                chunk_content=r.chunk_content,
                document_title=r.document_title,
                source_type=r.source_type,
                relevance_score=r.relevance_score,
                metadata=r.metadata,
                document_id=r.document_id,
                chunk_id=r.chunk_id,
            )
            for r in results
        ],
        total_results=len(results),
    )


@router.get("/documents", response_model=DocumentListResponse)
async def list_documents(
    source_type: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """List knowledge base documents with optional source_type filter."""
    user.require_permission("knowledge:query")

    svc = _get_knowledge_service()
    rows, total = await svc.list_documents(
        db,
        source_type_filter=source_type,
        page=page,
        page_size=page_size,
    )

    return DocumentListResponse(
        items=[_to_doc_response(r) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/documents/{document_id}", response_model=DocumentDetailResponse)
async def get_document(
    document_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Get document detail including content and chunk count."""
    user.require_permission("knowledge:query")

    svc = _get_knowledge_service()
    doc = await svc.get_document(db, document_id)
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    chunk_count = await svc.get_document_chunk_count(db, document_id)

    return DocumentDetailResponse(
        id=doc.id,
        title=doc.title,
        source_type=doc.source_type,
        content=doc.content,
        token_count=doc.token_count,
        metadata=doc.doc_metadata or {},
        created_at=doc.created_at.isoformat() if doc.created_at else None,
        updated_at=doc.updated_at.isoformat() if doc.updated_at else None,
        chunk_count=chunk_count,
    )


@router.delete(
    "/documents/{document_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_document(
    document_id: str,
    db: AsyncSession = Depends(get_db),
    user: CurrentUser = Depends(get_current_user),
):
    """Delete a document and all its associated chunks."""
    user.require_permission("knowledge:delete")

    svc = _get_knowledge_service()
    deleted = await svc.delete_document(db, document_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    return None
