"""Phase 2 Sprint 2 UAT — Knowledge Agent (pgvector RAG).

Run with: pytest tests/uat/test_phase2_sprint2_uat.py -v

Tests cover:
- Knowledge API endpoints (ingest, query, search, documents, delete)
- Knowledge plugin loads and provides tools
- Knowledge subgraph compiles and runs
- Embedding service (mock mode)
- Chunking service (text splitting, boundary preservation)
- Hybrid search returns ranked results (mock)
- Auto-indexing service methods exist
- RBAC permissions for knowledge operations
- Event types for knowledge lifecycle
- Shared types for knowledge domain
"""

import asyncio


# ── UAT-KNOWLEDGE-API: API endpoint validation ────────────────


class TestKnowledgeAPI:
    """Validate knowledge API router and endpoint definitions."""

    def test_knowledge_router_importable(self):
        """Knowledge router can be imported."""
        from btagent_backend.api.v1.knowledge import router

        assert router is not None
        assert router.prefix == "/knowledge"

    def test_knowledge_router_mounted_in_v1(self):
        """Knowledge router is mounted in the v1 API router."""
        from fastapi import FastAPI

        from btagent_backend.api.v1.router import api_v1_router

        # FastAPI >=0.137 keeps sub-router routes inside _IncludedRouter
        # entries instead of flattening them into ``.routes``; resolve the
        # full path set via the OpenAPI schema, which walks every endpoint
        # regardless of the internal route representation.
        app = FastAPI()
        app.include_router(api_v1_router)
        route_paths = list(app.openapi()["paths"].keys())
        # Check that knowledge routes are included
        knowledge_paths = [p for p in route_paths if "knowledge" in p]
        assert len(knowledge_paths) > 0, "No knowledge routes found in api_v1_router"

    def test_ingest_endpoint_exists(self):
        """POST /knowledge/ingest endpoint is defined."""
        from btagent_backend.api.v1.knowledge import router

        routes = {
            (r.path, tuple(r.methods)) for r in router.routes if hasattr(r, "methods")
        }
        assert ("/knowledge/ingest", ("POST",)) in routes

    def test_query_endpoint_exists(self):
        """POST /knowledge/query endpoint is defined."""
        from btagent_backend.api.v1.knowledge import router

        routes = {
            (r.path, tuple(r.methods)) for r in router.routes if hasattr(r, "methods")
        }
        assert ("/knowledge/query", ("POST",)) in routes

    def test_search_endpoint_exists(self):
        """GET /knowledge/search endpoint is defined."""
        from btagent_backend.api.v1.knowledge import router

        routes = {
            (r.path, tuple(r.methods)) for r in router.routes if hasattr(r, "methods")
        }
        assert ("/knowledge/search", ("GET",)) in routes

    def test_documents_list_endpoint_exists(self):
        """GET /knowledge/documents endpoint is defined."""
        from btagent_backend.api.v1.knowledge import router

        routes = {
            (r.path, tuple(r.methods)) for r in router.routes if hasattr(r, "methods")
        }
        assert ("/knowledge/documents", ("GET",)) in routes

    def test_document_detail_endpoint_exists(self):
        """GET /knowledge/documents/{document_id} endpoint is defined."""
        from btagent_backend.api.v1.knowledge import router

        route_paths = [r.path for r in router.routes]
        assert "/knowledge/documents/{document_id}" in route_paths

    def test_delete_endpoint_exists(self):
        """DELETE /knowledge/documents/{document_id} endpoint is defined."""
        from btagent_backend.api.v1.knowledge import router

        routes = {
            (r.path, tuple(r.methods)) for r in router.routes if hasattr(r, "methods")
        }
        assert ("/knowledge/documents/{document_id}", ("DELETE",)) in routes

    def test_ingest_request_schema(self):
        """IngestRequest schema validates correctly."""
        from btagent_backend.api.v1.knowledge import IngestRequest

        req = IngestRequest(
            title="Test Doc",
            content="Test content",
            source_type="runbook",
            metadata={"key": "value"},
        )
        assert req.title == "Test Doc"
        assert req.source_type == "runbook"

    def test_query_response_schema(self):
        """QueryResponse schema has required fields."""
        from btagent_backend.api.v1.knowledge import QueryResponse

        resp = QueryResponse(
            query="test query",
            results=[],
            total_results=0,
        )
        assert resp.query == "test query"
        assert resp.total_results == 0


# ── UAT-KNOWLEDGE-PLUGIN: Plugin imports and structure ────────


class TestKnowledgePlugin:
    """Validate knowledge plugin loads and provides correct tools."""

    def test_plugin_importable(self):
        """Knowledge plugin can be imported."""
        from btagent_agents.plugins.knowledge import KnowledgePlugin

        assert KnowledgePlugin is not None

    def test_plugin_instantiates(self):
        """Knowledge plugin instantiates without errors."""
        from btagent_agents.plugins.knowledge import KnowledgePlugin

        plugin = KnowledgePlugin()
        assert plugin.name == "knowledge"
        assert plugin.version == "1.0.0"
        assert "knowledge_search" in plugin.get_metadata().capabilities
        assert "hybrid_retrieval" in plugin.get_metadata().capabilities

    def test_plugin_returns_two_tools(self):
        """Plugin provides search_knowledge_base and get_investigation_context."""
        from btagent_agents.plugins.knowledge import KnowledgePlugin

        plugin = KnowledgePlugin()
        tools = plugin.get_tools()
        assert len(tools) == 2
        tool_names = {t.name for t in tools}
        assert "search_knowledge_base" in tool_names
        assert "get_investigation_context" in tool_names

    def test_plugin_system_prompt_has_org_profile(self):
        """System prompt contains {org_profile} placeholder."""
        from btagent_agents.plugins.knowledge import KnowledgePlugin

        plugin = KnowledgePlugin()
        prompt = plugin.get_system_prompt()
        assert "{org_profile}" in prompt
        assert "knowledge" in prompt.lower()
        assert "<external-data>" in prompt

    def test_plugin_registered_in_registry(self):
        """Knowledge plugin is registered in PLUGIN_MODULES."""
        from btagent_agents.plugins import PLUGIN_MODULES

        assert "knowledge" in PLUGIN_MODULES
        assert PLUGIN_MODULES["knowledge"] == ("btagent_agents.plugins.knowledge")

    def test_plugin_loads_via_registry(self):
        """Plugin loads through the standard plugin loader."""
        from btagent_agents.plugins import load_plugin

        plugin = load_plugin("knowledge")
        assert plugin is not None
        assert plugin.name == "knowledge"


# ── UAT-KNOWLEDGE-SUBGRAPH: LangGraph subgraph compilation ───


class TestKnowledgeSubgraph:
    """Validate the knowledge subgraph compiles and runs."""

    def test_graph_compiles(self):
        """Knowledge subgraph compiles without errors."""
        from btagent_agents.knowledge.graph import (
            create_knowledge_subgraph,
        )

        graph = create_knowledge_subgraph()
        assert graph is not None

    def test_state_has_required_fields(self):
        """KnowledgeState TypedDict has all required fields."""
        from btagent_agents.knowledge.graph import KnowledgeState

        annotations = KnowledgeState.__annotations__
        required_fields = {
            "query",
            "investigation_id",
            "retrieved_chunks",
            "answer",
            "citations",
        }
        for field in required_fields:
            assert field in annotations, f"Missing field '{field}' in KnowledgeState"

    def test_graph_has_four_nodes(self):
        """Subgraph has understand_query, retrieve_context, generate_answer, cite_sources."""
        from btagent_agents.knowledge.graph import (
            create_knowledge_subgraph,
        )

        graph = create_knowledge_subgraph()
        # Get node names from the graph
        node_names = set(graph.get_graph().nodes.keys())
        # LangGraph adds __start__ and __end__ nodes
        expected = {
            "understand_query",
            "retrieve_context",
            "generate_answer",
            "cite_sources",
        }
        assert expected.issubset(node_names), f"Missing nodes: {expected - node_names}"

    def test_graph_invocation(self):
        """Subgraph runs end-to-end with test input."""
        from btagent_agents.knowledge.graph import (
            create_knowledge_subgraph,
        )

        graph = create_knowledge_subgraph()
        result = graph.invoke(
            {
                "query": "What is APT29?",
                "investigation_id": "inv_test_001",
                "retrieved_chunks": [],
                "answer": "",
                "citations": [],
                "rephrased_query": "",
                "errors": [],
                "status": "pending",
            }
        )

        assert result["status"] == "complete"
        assert result["answer"] != ""
        assert isinstance(result["citations"], list)
        assert len(result["citations"]) > 0

    def test_graph_handles_empty_query(self):
        """Subgraph handles empty query gracefully."""
        from btagent_agents.knowledge.graph import (
            create_knowledge_subgraph,
        )

        graph = create_knowledge_subgraph()
        result = graph.invoke(
            {
                "query": "",
                "investigation_id": "",
                "retrieved_chunks": [],
                "answer": "",
                "citations": [],
                "rephrased_query": "",
                "errors": [],
                "status": "pending",
            }
        )

        assert result["status"] == "failed"
        assert len(result["errors"]) > 0


# ── UAT-EMBEDDING-SERVICE: Embedding service validation ───────


class TestEmbeddingService:
    """Validate embedding service imports and mock mode."""

    def test_service_importable(self):
        """EmbeddingService and subclasses can be imported."""
        from btagent_backend.services.embedding_service import (
            EmbeddingService,
            MockEmbeddingService,
            OllamaEmbeddingService,
            OpenAIEmbeddingService,
        )

        assert EmbeddingService is not None
        assert MockEmbeddingService is not None
        assert OpenAIEmbeddingService is not None
        assert OllamaEmbeddingService is not None

    def test_mock_returns_vectors(self):
        """Mock embedding service returns deterministic vectors."""
        from btagent_backend.services.embedding_service import (
            EMBEDDING_DIM,
            MockEmbeddingService,
        )

        svc = MockEmbeddingService()
        loop = asyncio.new_event_loop()
        try:
            embeddings = loop.run_until_complete(
                svc.generate_embeddings(["hello world", "test query"])
            )
        finally:
            loop.close()

        assert len(embeddings) == 2
        assert len(embeddings[0]) == EMBEDDING_DIM
        assert len(embeddings[1]) == EMBEDDING_DIM
        # All values should be floats
        assert all(isinstance(v, float) for v in embeddings[0])

    def test_mock_deterministic(self):
        """Same input text produces same embedding."""
        from btagent_backend.services.embedding_service import (
            MockEmbeddingService,
        )

        svc = MockEmbeddingService()
        loop = asyncio.new_event_loop()
        try:
            emb1 = loop.run_until_complete(
                svc.generate_embeddings(["deterministic test"])
            )
            emb2 = loop.run_until_complete(
                svc.generate_embeddings(["deterministic test"])
            )
        finally:
            loop.close()

        assert emb1[0] == emb2[0], "Mock embeddings should be deterministic"

    def test_mock_empty_input(self):
        """Mock service handles empty input list."""
        from btagent_backend.services.embedding_service import (
            MockEmbeddingService,
        )

        svc = MockEmbeddingService()
        loop = asyncio.new_event_loop()
        try:
            embeddings = loop.run_until_complete(svc.generate_embeddings([]))
        finally:
            loop.close()

        assert embeddings == []

    def test_factory_returns_mock_in_mock_mode(self):
        """Factory returns MockEmbeddingService when mock_connectors is True."""
        from btagent_backend.services.embedding_service import (
            MockEmbeddingService,
            get_embedding_service,
        )

        class MockSettings:
            mock_connectors = True

        svc = get_embedding_service(MockSettings())
        assert isinstance(svc, MockEmbeddingService)

    def test_tlp_red_forces_local(self):
        """TLP:RED always returns local (mock or ollama) service."""
        from btagent_backend.services.embedding_service import (
            MockEmbeddingService,
            get_tlp_aware_embedding_service,
        )

        class MockSettings:
            mock_connectors = True

        svc = get_tlp_aware_embedding_service(MockSettings(), "red")
        assert isinstance(svc, MockEmbeddingService)


# ── UAT-CHUNKING-SERVICE: Text chunking validation ───────────


class TestChunkingService:
    """Validate text chunking logic."""

    def test_chunks_text_correctly(self):
        """Chunking produces non-empty chunks with correct indices."""
        from btagent_backend.services.chunking_service import chunk_text

        text = "First paragraph.\n\nSecond paragraph.\n\nThird paragraph."
        chunks = chunk_text(text, chunk_size=100, overlap=10)

        assert len(chunks) >= 1
        assert chunks[0].index == 0
        assert chunks[0].content != ""
        assert chunks[0].token_count > 0

    def test_preserves_paragraph_boundaries(self):
        """Chunks respect paragraph boundaries when possible."""
        from btagent_backend.services.chunking_service import chunk_text

        paragraphs = [f"Paragraph {i}. " * 20 for i in range(5)]
        text = "\n\n".join(paragraphs)
        chunks = chunk_text(text, chunk_size=50, overlap=10)

        assert len(chunks) > 1
        # Each chunk should have content
        for chunk in chunks:
            assert chunk.content.strip() != ""

    def test_handles_markdown_headers(self):
        """Chunking preserves markdown header context in metadata."""
        from btagent_backend.services.chunking_service import chunk_text

        text = (
            "# Introduction\n\n"
            "This is the introduction.\n\n"
            "## Background\n\n"
            "This is the background section with enough text to "
            "potentially force a chunk boundary. " * 20
        )
        chunks = chunk_text(text, chunk_size=50, overlap=10)

        assert len(chunks) >= 1
        # At least one chunk should have section_header metadata
        headers = [
            c.metadata.get("section_header")
            for c in chunks
            if c.metadata.get("section_header")
        ]
        assert len(headers) > 0

    def test_empty_text_returns_empty(self):
        """Empty text produces no chunks."""
        from btagent_backend.services.chunking_service import chunk_text

        assert chunk_text("") == []
        assert chunk_text("   ") == []

    def test_estimate_tokens(self):
        """Token estimation returns reasonable values."""
        from btagent_backend.services.chunking_service import (
            estimate_tokens,
        )

        assert estimate_tokens("hello world") >= 1
        assert estimate_tokens("a" * 100) == 25
        assert estimate_tokens("") >= 1  # minimum 1


# ── UAT-HYBRID-SEARCH: Search result validation ──────────────


class TestHybridSearch:
    """Validate hybrid search returns ranked results (via mock)."""

    def test_knowledge_service_importable(self):
        """KnowledgeService can be imported."""
        from btagent_backend.services.knowledge_service import (
            KnowledgeService,
        )

        assert KnowledgeService is not None

    def test_search_result_dataclass(self):
        """SearchResult has correct fields."""
        from btagent_backend.services.knowledge_service import SearchResult

        result = SearchResult(
            chunk_content="test content",
            document_title="Test Doc",
            source_type="runbook",
            relevance_score=0.95,
            metadata={"key": "value"},
            document_id="kd_test",
            chunk_id="kc_test",
        )
        assert result.chunk_content == "test content"
        assert result.document_title == "Test Doc"
        assert result.relevance_score == 0.95

    def test_search_tool_returns_results(self):
        """search_knowledge_base tool returns results for a query."""
        from btagent_agents.plugins.knowledge.tools.knowledge_search import (
            search_knowledge_base,
        )

        result = search_knowledge_base.invoke(
            {
                "query": "APT29 threat",
                "top_k": 3,
            }
        )

        assert "results" in result
        assert "total_results" in result
        assert result["total_results"] > 0
        assert len(result["results"]) <= 3

    def test_search_empty_query(self):
        """search_knowledge_base handles empty query."""
        from btagent_agents.plugins.knowledge.tools.knowledge_search import (
            search_knowledge_base,
        )

        result = search_knowledge_base.invoke(
            {
                "query": "",
                "top_k": 5,
            }
        )

        assert result["total_results"] == 0
        assert "error" in result


# ── UAT-AUTO-INDEXING: Auto-indexing service methods ──────────


class TestAutoIndexing:
    """Validate auto-indexing service methods exist and are callable."""

    def test_auto_index_investigation_exists(self):
        """KnowledgeService.auto_index_investigation method exists."""
        from btagent_backend.services.knowledge_service import (
            KnowledgeService,
        )

        svc = KnowledgeService()
        assert hasattr(svc, "auto_index_investigation")
        assert callable(svc.auto_index_investigation)

    def test_auto_index_enrichment_exists(self):
        """KnowledgeService.auto_index_enrichment method exists."""
        from btagent_backend.services.knowledge_service import (
            KnowledgeService,
        )

        svc = KnowledgeService()
        assert hasattr(svc, "auto_index_enrichment")
        assert callable(svc.auto_index_enrichment)

    def test_delete_document_method_exists(self):
        """KnowledgeService.delete_document method exists."""
        from btagent_backend.services.knowledge_service import (
            KnowledgeService,
        )

        svc = KnowledgeService()
        assert hasattr(svc, "delete_document")
        assert callable(svc.delete_document)

    def test_list_documents_method_exists(self):
        """KnowledgeService.list_documents method exists."""
        from btagent_backend.services.knowledge_service import (
            KnowledgeService,
        )

        svc = KnowledgeService()
        assert hasattr(svc, "list_documents")
        assert callable(svc.list_documents)


# ── UAT-RBAC: Permission verification ────────────────────────


class TestRBAC:
    """Validate RBAC permissions for knowledge operations."""

    def test_knowledge_query_analyst(self):
        """Analyst can query the knowledge base."""
        from btagent_backend.auth.rbac import has_permission

        assert has_permission("analyst", "knowledge:query") is True

    def test_knowledge_ingest_senior(self):
        """Senior analyst can ingest documents."""
        from btagent_backend.auth.rbac import has_permission

        assert has_permission("senior_analyst", "knowledge:ingest") is True

    def test_knowledge_ingest_analyst_denied(self):
        """Regular analyst cannot ingest documents."""
        from btagent_backend.auth.rbac import has_permission

        assert has_permission("analyst", "knowledge:ingest") is False

    def test_knowledge_delete_admin(self):
        """Admin can delete knowledge documents."""
        from btagent_backend.auth.rbac import has_permission

        assert has_permission("admin", "knowledge:delete") is True

    def test_knowledge_delete_senior_denied(self):
        """Senior analyst cannot delete knowledge documents."""
        from btagent_backend.auth.rbac import has_permission

        assert has_permission("senior_analyst", "knowledge:delete") is False

    def test_knowledge_permissions_in_registry(self):
        """All knowledge permissions are in the PERMISSIONS dict."""
        from btagent_backend.auth.rbac import PERMISSIONS

        assert "knowledge:query" in PERMISSIONS
        assert "knowledge:ingest" in PERMISSIONS
        assert "knowledge:delete" in PERMISSIONS


# ── UAT-EVENTS: Event type validation ────────────────────────


class TestEventTypes:
    """Validate knowledge-related event types are defined."""

    def test_knowledge_indexed_event(self):
        """KNOWLEDGE_INDEXED event type exists."""
        from btagent_shared.types.events import EventType

        assert hasattr(EventType, "KNOWLEDGE_INDEXED")
        assert EventType.KNOWLEDGE_INDEXED == "knowledge_indexed"

    def test_knowledge_queried_event(self):
        """KNOWLEDGE_QUERIED event type exists."""
        from btagent_shared.types.events import EventType

        assert hasattr(EventType, "KNOWLEDGE_QUERIED")
        assert EventType.KNOWLEDGE_QUERIED == "knowledge_queried"


# ── UAT-SHARED-TYPES: Shared Pydantic model validation ───────


class TestSharedTypes:
    """Validate shared knowledge types."""

    def test_knowledge_document_model(self):
        """KnowledgeDocument Pydantic model works correctly."""
        from btagent_shared.types.knowledge import KnowledgeDocument

        doc = KnowledgeDocument(
            id="kd_test",
            title="Test",
            source_type="runbook",
            content="Content",
        )
        assert doc.id == "kd_test"
        assert doc.token_count == 0

    def test_search_result_model(self):
        """SearchResult Pydantic model works correctly."""
        from btagent_shared.types.knowledge import SearchResult

        result = SearchResult(
            chunk_content="chunk",
            document_title="Doc",
            source_type="runbook",
            relevance_score=0.9,
        )
        assert result.relevance_score == 0.9

    def test_knowledge_source_type_enum(self):
        """KnowledgeSourceType enum has all expected values."""
        from btagent_shared.types.knowledge import KnowledgeSourceType

        expected = {
            "investigation_report",
            "runbook",
            "threat_profile",
            "agency_profile",
            "enrichment_data",
            "playbook_log",
            "conversation",
        }
        actual = {e.value for e in KnowledgeSourceType}
        assert expected == actual

    def test_ingest_request_model(self):
        """IngestRequest Pydantic model validates correctly."""
        from btagent_shared.types.knowledge import IngestRequest

        req = IngestRequest(
            title="Test",
            content="Content",
            source_type="runbook",
        )
        assert req.title == "Test"

    def test_query_request_model(self):
        """QueryRequest Pydantic model validates correctly."""
        from btagent_shared.types.knowledge import QueryRequest

        req = QueryRequest(query="test", top_k=10)
        assert req.top_k == 10
        assert req.source_type_filter is None

    def test_query_response_model(self):
        """QueryResponse Pydantic model validates correctly."""
        from btagent_shared.types.knowledge import QueryResponse

        resp = QueryResponse(
            query="test",
            results=[],
            total_results=0,
        )
        assert resp.total_results == 0
        assert resp.citations == []


# ── UAT-DB-MODELS: ORM model validation ──────────────────────


class TestDBModels:
    """Validate knowledge base ORM models."""

    def test_document_model_importable(self):
        """KnowledgeDocumentRow can be imported."""
        from btagent_backend.db.models_knowledge import (
            KnowledgeDocumentRow,
        )

        assert KnowledgeDocumentRow is not None
        assert KnowledgeDocumentRow.__tablename__ == "knowledge_documents"

    def test_chunk_model_importable(self):
        """KnowledgeChunkRow can be imported."""
        from btagent_backend.db.models_knowledge import KnowledgeChunkRow

        assert KnowledgeChunkRow is not None
        assert KnowledgeChunkRow.__tablename__ == "knowledge_chunks"

    def test_source_types_constant(self):
        """KNOWLEDGE_SOURCE_TYPES constant has expected values."""
        from btagent_backend.db.models_knowledge import (
            KNOWLEDGE_SOURCE_TYPES,
        )

        assert "investigation_report" in KNOWLEDGE_SOURCE_TYPES
        assert "runbook" in KNOWLEDGE_SOURCE_TYPES
        assert "threat_profile" in KNOWLEDGE_SOURCE_TYPES
        assert "enrichment_data" in KNOWLEDGE_SOURCE_TYPES
        assert "playbook_log" in KNOWLEDGE_SOURCE_TYPES
        assert "conversation" in KNOWLEDGE_SOURCE_TYPES

    def test_migration_file_exists(self):
        """Migration 0004_knowledge_base.py exists."""
        from pathlib import Path

        migration_path = (
            Path(__file__).resolve().parents[2]
            / "backend"
            / "migrations"
            / "versions"
            / "0004_knowledge_base.py"
        )
        assert migration_path.exists(), f"Migration not found at {migration_path}"


# ── UAT-CONFIG: Configuration settings ───────────────────────


class TestConfig:
    """Validate embedding/knowledge config settings."""

    def test_embedding_settings_exist(self):
        """Settings class has embedding-related fields."""
        from btagent_backend.config import Settings

        fields = Settings.model_fields
        assert "embedding_provider" in fields
        assert "embedding_model" in fields

    def test_default_embedding_provider(self):
        """Default embedding provider is openai."""
        from btagent_backend.config import Settings

        default = Settings.model_fields["embedding_provider"].default
        assert default == "openai"

    def test_default_embedding_model(self):
        """Default embedding model is text-embedding-3-small."""
        from btagent_backend.config import Settings

        default = Settings.model_fields["embedding_model"].default
        assert default == "text-embedding-3-small"
