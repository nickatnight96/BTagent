"""Sprint 5-foundation tests for ``run_via_engine`` + ``HttpKnowledgeClient``.

These tests verify the *wiring* of the agents-side engine bridge --
not the templates themselves (which are still partially placeholder
per Sprint 3C's report). Specifically:

* ``run_via_engine`` builds a Middleware chain in the documented order
  and invokes WorkflowExecutor end-to-end.
* The TLP-vs-provider routing fires before the LLM Node executes.
* ``HttpKnowledgeClient`` translates between the engine Protocol and
  the FastAPI ``/api/v1/knowledge/...`` JSON shapes correctly.
* ``install_as_default`` rewires the Knowledge Nodes' factory.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from btagent_engine.compiler.workflow import Workflow, WorkflowEdge, WorkflowNode
from btagent_engine.integrations import LLMCallNode  # noqa: F401 -- registers reasoning.llm.call
from btagent_engine.knowledge import (  # noqa: F401 -- registers knowledge nodes
    KnowledgeSearchNode,
    KnowledgeUpsertNode,
)
from btagent_engine.middleware import (
    ClassificationMiddleware,
    EventEmitterMiddleware,
    EvidenceChainMiddleware,
    HITLMiddleware,
    InvestigationScope,
    PromptBudgetMiddleware,
    ScopeEnforcementMiddleware,
)
from btagent_shared.security import TLPViolation
from btagent_shared.types.config import (
    TLP,
    AutonomyLevel,
    IntegrationAutonomy,
    ModelProvider,
)

from btagent_agents.middleware.llm_router import LLMRouterMiddleware
from btagent_agents.orchestrator import knowledge_client as kc_module
from btagent_agents.orchestrator.engine_runner import (
    build_middleware_chain,
    run_via_engine,
)
from btagent_agents.orchestrator.knowledge_client import (
    HttpKnowledgeClient,
    install_as_default,
)

# --------------------------------------------------------------------------- #
# Shared fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _mock_llm(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    yield


def _llm_only_workflow() -> Workflow:
    return Workflow(
        name="engine_runner_smoke",
        nodes=(
            WorkflowNode(
                step_id="llm",
                node_id="reasoning.llm.call",
                config={
                    "messages": [{"role": "user", "content": "hello"}],
                    "model": "claude-haiku",
                    "max_tokens": 32,
                },
            ),
        ),
        edges=(),
    )


class _FakeRouter:
    """Test double for TLPAwareLLMRouter -- only ``resolve`` is exercised."""

    def __init__(self, provider: str = ModelProvider.ANTHROPIC) -> None:
        self._provider = provider
        self.calls: list[tuple[Any, Any]] = []

    def resolve(self, tlp, tier, preferred_provider=None):
        self.calls.append((tlp, tier))
        return (self._provider, "stub-model-id")


# --------------------------------------------------------------------------- #
# build_middleware_chain
# --------------------------------------------------------------------------- #


def test_chain_includes_all_layers_when_fully_configured():
    chain = build_middleware_chain(
        tlp=TLP.GREEN,
        autonomy=AutonomyLevel.L2_SUPERVISED,
        integration_autonomy=IntegrationAutonomy(),
        scope=InvestigationScope(),
        budget_max_cost_usd=5.0,
        emit_callable=AsyncMock(),
        llm_router=_FakeRouter(),
        evidence_records=[],
    )
    types = [type(m).__name__ for m in chain]
    assert types == [
        "ScopeEnforcementMiddleware",
        "ClassificationMiddleware",
        "HITLMiddleware",
        "LLMRouterMiddleware",
        "PromptBudgetMiddleware",
        "EvidenceChainMiddleware",
        "EventEmitterMiddleware",
    ]


def test_chain_omits_optional_layers_when_unset():
    chain = build_middleware_chain(
        tlp=TLP.GREEN,
        autonomy=AutonomyLevel.L2_SUPERVISED,
        integration_autonomy=IntegrationAutonomy(),
        scope=None,
        budget_max_cost_usd=None,
        emit_callable=None,
        llm_router=_FakeRouter(),
        evidence_records=[],
    )
    types = [type(m).__name__ for m in chain]
    # Scope, PromptBudget, EventEmitter all dropped; classification + HITL +
    # LLMRouter + EvidenceChain remain.
    assert types == [
        "ClassificationMiddleware",
        "HITLMiddleware",
        "LLMRouterMiddleware",
        "EvidenceChainMiddleware",
    ]


# --------------------------------------------------------------------------- #
# run_via_engine end-to-end
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_run_via_engine_runs_a_template_and_returns_result(monkeypatch):
    """Patch ``load_template`` to avoid depending on the (still
    placeholder) production templates -- this test exercises the WIRING,
    not the templates."""
    workflow = _llm_only_workflow()
    monkeypatch.setattr(
        "btagent_agents.orchestrator.engine_runner.load_template",
        lambda _name: workflow,
    )

    router = _FakeRouter(provider=ModelProvider.ANTHROPIC)
    result = await run_via_engine(
        "knowledge",
        investigation_id="inv_smoke",
        user_id="usr_test",
        org_id="org_default",
        tlp=TLP.GREEN,
        autonomy=AutonomyLevel.L3_AUTONOMOUS,
        llm_router=router,
        run_id="run_smoke",
    )

    assert result.final_output is not None
    assert result.nodes_executed == ["llm"]
    # Router was invoked exactly once for the single reasoning node.
    assert len(router.calls) == 1


@pytest.mark.asyncio
async def test_run_via_engine_blocks_red_to_external_provider(monkeypatch):
    """TLP:RED + Anthropic must trip the LLMRouterMiddleware before the
    LLMCallNode runs."""
    workflow = _llm_only_workflow()
    monkeypatch.setattr(
        "btagent_agents.orchestrator.engine_runner.load_template",
        lambda _name: workflow,
    )

    router = _FakeRouter(provider=ModelProvider.ANTHROPIC)
    with pytest.raises(Exception) as exc_info:
        await run_via_engine(
            "knowledge",
            investigation_id="inv_red",
            user_id="usr_test",
            org_id="org_default",
            tlp=TLP.RED,
            autonomy=AutonomyLevel.L3_AUTONOMOUS,
            llm_router=router,
            run_id="run_red_blocked",
        )

    # The TLPViolation may be wrapped in a WorkflowExecutionError by the
    # executor -- accept either, just confirm the chain reached the gate.
    cause: Any = exc_info.value
    seen = isinstance(cause, TLPViolation)
    while cause and not seen:
        cause = getattr(cause, "__cause__", None)
        if isinstance(cause, TLPViolation):
            seen = True
    assert seen, f"expected TLPViolation in chain; got {exc_info.value!r}"


# --------------------------------------------------------------------------- #
# HttpKnowledgeClient wire format
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_http_knowledge_client_search_translates_response():
    """``/api/v1/knowledge/query`` returns ``{query, results: [...]}``;
    the client surfaces just the results list."""
    fake_response = MagicMock()
    fake_response.json.return_value = {
        "query": "ransomware",
        "results": [
            {"chunk_content": "encrypted shell observed", "relevance_score": 0.91},
            {"chunk_content": "ransom note dropped", "relevance_score": 0.85},
        ],
    }
    fake_response.raise_for_status.return_value = None

    fake_client_cls = MagicMock()
    fake_client = AsyncMock()
    fake_client.post.return_value = fake_response
    fake_client_cls.return_value.__aenter__.return_value = fake_client

    import httpx

    saved = httpx.AsyncClient
    httpx.AsyncClient = fake_client_cls  # type: ignore[misc]
    try:
        client = HttpKnowledgeClient(base_url="http://backend:8000", token="t-test")
        results = await client.search("ransomware", top_k=5)
    finally:
        httpx.AsyncClient = saved  # type: ignore[misc]

    assert len(results) == 2
    assert results[0]["relevance_score"] == 0.91
    fake_client.post.assert_awaited_once()
    call = fake_client.post.await_args
    assert call.args[0].endswith("/api/v1/knowledge/query")
    assert call.kwargs["json"] == {"query": "ransomware", "top_k": 5}
    assert call.kwargs["headers"]["Authorization"] == "Bearer t-test"


@pytest.mark.asyncio
async def test_http_knowledge_client_search_skips_empty_query():
    """Empty / whitespace-only queries don't hit the backend."""
    client = HttpKnowledgeClient(base_url="http://backend:8000", token=None)
    assert await client.search("") == []
    assert await client.search("   ") == []


@pytest.mark.asyncio
async def test_http_knowledge_client_upsert_adapts_backend_response():
    """Backend ingest returns ``{id, title, source_type, token_count, message}``;
    the client adapts to the engine's ``{document_id, chunks}`` shape."""
    fake_response = MagicMock()
    fake_response.json.return_value = {
        "id": "kd_abc123",
        "title": "Phishing playbook",
        "source_type": "playbook",
        "token_count": 1024,
        "message": "Document ingested successfully",
    }
    fake_response.raise_for_status.return_value = None

    fake_client_cls = MagicMock()
    fake_client = AsyncMock()
    fake_client.post.return_value = fake_response
    fake_client_cls.return_value.__aenter__.return_value = fake_client

    import httpx

    saved = httpx.AsyncClient
    httpx.AsyncClient = fake_client_cls  # type: ignore[misc]
    try:
        client = HttpKnowledgeClient(base_url="http://backend:8000")
        out = await client.upsert(
            title="Phishing playbook",
            content="...",
            source_type="playbook",
            metadata={"author": "soc"},
            classification="green",
        )
    finally:
        httpx.AsyncClient = saved  # type: ignore[misc]

    assert out["document_id"] == "kd_abc123"
    assert out["chunks"] >= 1


# --------------------------------------------------------------------------- #
# install_as_default
# --------------------------------------------------------------------------- #


def test_install_as_default_sets_factory_on_both_nodes(monkeypatch):
    # Capture and restore the original factories so the test doesn't
    # leak state into other tests.
    orig_search = KnowledgeSearchNode.client_factory
    orig_upsert = KnowledgeUpsertNode.client_factory
    try:
        install_as_default()
        assert KnowledgeSearchNode.client_factory is HttpKnowledgeClient
        assert KnowledgeUpsertNode.client_factory is HttpKnowledgeClient
    finally:
        KnowledgeSearchNode.client_factory = orig_search
        KnowledgeUpsertNode.client_factory = orig_upsert


def test_backend_url_resolution_honours_env(monkeypatch):
    monkeypatch.setenv("BTAGENT_BACKEND_URL", "http://prod-backend:9000/")
    assert kc_module._backend_base_url() == "http://prod-backend:9000"
    monkeypatch.delenv("BTAGENT_BACKEND_URL")
    assert kc_module._backend_base_url() == "http://backend:8000"
