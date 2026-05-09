"""Knowledge base domain models for BTagent RAG system."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class KnowledgeSourceType(StrEnum):
    """Types of documents that can be stored in the knowledge base."""

    INVESTIGATION_REPORT = "investigation_report"
    RUNBOOK = "runbook"
    THREAT_PROFILE = "threat_profile"
    AGENCY_PROFILE = "agency_profile"
    ENRICHMENT_DATA = "enrichment_data"
    PLAYBOOK_LOG = "playbook_log"
    CONVERSATION = "conversation"


class KnowledgeDocument(BaseModel):
    """A document stored in the knowledge base."""

    id: str
    title: str
    source_type: KnowledgeSourceType
    content: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    token_count: int = 0
    created_at: datetime | None = None
    updated_at: datetime | None = None


class KnowledgeChunk(BaseModel):
    """A vector-embedded chunk of a knowledge document."""

    id: str
    document_id: str
    chunk_index: int
    content: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    token_count: int = 0


class SearchResult(BaseModel):
    """A single result from hybrid search."""

    chunk_content: str
    document_title: str
    source_type: str
    relevance_score: float
    metadata: dict[str, Any] = Field(default_factory=dict)
    document_id: str = ""
    chunk_id: str = ""


class IngestRequest(BaseModel):
    """Request to ingest a document into the knowledge base."""

    title: str
    content: str
    source_type: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class QueryRequest(BaseModel):
    """Request to query the knowledge base."""

    query: str
    top_k: int = Field(default=5, ge=1, le=50)
    source_type_filter: str | None = None


class QueryResponse(BaseModel):
    """Response from a knowledge base query."""

    query: str
    results: list[SearchResult]
    total_results: int
    answer: str | None = None
    citations: list[dict[str, Any]] = Field(default_factory=list)
