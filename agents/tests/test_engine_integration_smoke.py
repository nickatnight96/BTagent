"""Sprint 3D end-to-end smoke test: WorkflowExecutor + agents-side middleware.

This is the single integration test proving Sprint 3's foundation actually
holds together. Sprint 3 deliberately does NOT cut over the live
orchestrator (the templates produced in 3C are still mostly placeholders --
see ``agents/btagent_agents/orchestrator/templates/*.yaml`` for the
``TODO(sprint3D)`` markers). Before that cutover lands, we need at least
one test that runs a workflow end-to-end with the real surface so we know
the integration is more than compile-clean.

What this test exercises:

* ``WorkflowExecutor`` (engine, sprint 2.5A) walking a graph with a
  ``ManualTriggerNode`` (engine, sprint 2.5B) -> ``LLMCallNode`` (engine,
  sprint 2.5B) sequence.
* ``LLMRouterMiddleware`` (agents, sprint 3A) firing only on the reasoning
  node, stashing the resolved provider on ``ctx.metadata``, and refusing
  the call entirely on a TLP:RED + non-local-provider mismatch.
* ``EventEmitterMiddleware`` (engine, sprint 2B + sprint 3D payload patch)
  emitting events whose ``node`` sub-dict matches what the backend WS
  adapter (sprint 3B) expects to translate into the legacy WebSocket
  ``EventType``.
* ``BudgetUsage`` written to ``ctx.metadata[USAGE_METADATA_KEY]`` by the
  reasoning node so ``PromptBudgetMiddleware`` (sprint 2B) actually has
  data to enforce against.

If this passes, Sprint 3-cautious is done. The full cutover (3D-ambitious)
needs the missing Node types (regex IOC extractor, MITRE mapper, IOC
dedup, knowledge search/upsert, decision-condition runner) before it can
replace the legacy ``orchestrator/{graph,nodes}.py`` for real.
"""

from __future__ import annotations

import os

import pytest
from btagent_engine import (
    NodeContext,
    NodeRegistry,
    WorkflowExecutor,
)
from btagent_engine.compiler.workflow import (
    Workflow,
    WorkflowEdge,
    WorkflowNode,
)
from btagent_engine.integrations import LLMCallNode  # noqa: F401 -- registers reasoning.llm.call
from btagent_engine.middleware import EventEmitterMiddleware
from btagent_engine.middleware.prompt_budget import USAGE_METADATA_KEY
from btagent_engine.triggers import ManualTriggerNode  # noqa: F401 -- registers trigger.manual
from btagent_shared.security import TLPViolation
from btagent_shared.types.config import TLP, ModelProvider

from btagent_agents.middleware.llm_router import (
    LLM_PROVIDER_METADATA_KEY,
    LLMRouterMiddleware,
)

# --------------------------------------------------------------------------- #
# Shared fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture(autouse=True)
def _mock_llm(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    yield


@pytest.fixture
def emitted_events() -> list[tuple[str, dict]]:
    return []


@pytest.fixture
def emit_callable(emitted_events):
    async def _emit(event_type, /, **payload):
        emitted_events.append((event_type, payload))

    return _emit


def _model_to_anthropic(_model: str) -> ModelProvider:
    return ModelProvider.ANTHROPIC


def _model_to_ollama(_model: str) -> ModelProvider:
    return ModelProvider.OLLAMA


def _llm_only_workflow() -> Workflow:
    """Single-node workflow: LLMCallNode as the entry, config provides
    the messages/model directly. A trigger -> LLM workflow would need a
    Transform Node (deferred to Sprint 4) to reshape the trigger's
    ``payload`` output into the LLM input -- the schemas are
    intentionally ``extra=forbid`` so the executor can't bridge them
    silently."""
    return Workflow(
        name="Sprint 3D smoke",
        nodes=(
            WorkflowNode(
                step_id="llm",
                node_id="reasoning.llm.call",
                config={
                    "messages": [{"role": "user", "content": "smoke-test prompt"}],
                    "model": "claude-haiku",
                    "max_tokens": 64,
                },
            ),
        ),
        edges=(),
    )


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_full_pipeline_runs_end_to_end(emit_callable, emitted_events):
    """Trigger -> LLM with TLP.GREEN: runs to completion, stashes provider,
    emits start/end events with the node sub-dict the WS adapter expects."""
    workflow = _llm_only_workflow()
    ctx = NodeContext(
        run_id="run_smoke_green",
        org_id="org_default",
        investigation_id="inv_smoke",
        tlp_level=TLP.GREEN.value,
    )
    executor = WorkflowExecutor(
        middlewares=[
            LLMRouterMiddleware(model_to_provider=_model_to_anthropic),
            EventEmitterMiddleware(emit_callable=emit_callable, tlp_level=TLP.GREEN),
        ]
    )

    result = await executor.execute(workflow, initial_input=None, ctx=ctx)

    # Final output is the LLM step's; mock LLM echoes the user message.
    final = result.final_output
    assert final is not None, "workflow should produce a final output"
    final_dump = final.model_dump()
    assert "[mock-llm]" in final_dump.get("text", ""), final_dump
    assert final_dump.get("model") == "claude-haiku"

    # Single-node workflow runs the LLM step.
    assert result.nodes_executed == ["llm"]

    # LLMRouter stashed the resolved provider on ctx.metadata.
    assert ctx.metadata.get(LLM_PROVIDER_METADATA_KEY) == ModelProvider.ANTHROPIC.value

    # BudgetUsage written by the LLMCallNode for PromptBudgetMiddleware.
    usage = ctx.metadata.get(USAGE_METADATA_KEY)
    assert usage is not None, "LLMCallNode must populate USAGE_METADATA_KEY"

    # Event taxonomy: the LLM node emitted start + end with the structured
    # ``node`` sub-dict that the WS adapter (sprint 3B) routes on.
    event_types = [t for t, _ in emitted_events]
    assert event_types.count("node.start") == 1
    assert event_types.count("node.end") == 1

    for event_type, payload in emitted_events:
        if event_type in ("node.start", "node.end"):
            node_descriptor = payload.get("node")
            assert isinstance(node_descriptor, dict), (
                f"{event_type} must carry a node sub-dict for the WS adapter; got {payload!r}"
            )
            assert {"id", "name", "category"}.issubset(node_descriptor.keys()), node_descriptor
            assert payload.get("investigation_id") == "inv_smoke"


@pytest.mark.asyncio
async def test_pipeline_blocks_red_to_external_provider(emit_callable, emitted_events):
    """TLP:RED + Anthropic must be refused by LLMRouterMiddleware before
    the LLMCallNode runs. The workflow aborts with TLPViolation."""
    workflow = _llm_only_workflow()
    ctx = NodeContext(
        run_id="run_smoke_red_blocked",
        org_id="org_default",
        investigation_id="inv_smoke_red",
        tlp_level=TLP.RED.value,
    )
    executor = WorkflowExecutor(
        middlewares=[
            LLMRouterMiddleware(model_to_provider=_model_to_anthropic),
            EventEmitterMiddleware(emit_callable=emit_callable, tlp_level=TLP.RED),
        ]
    )

    with pytest.raises(Exception) as exc_info:
        await executor.execute(workflow, initial_input=None, ctx=ctx)

    # Either the executor wraps the cause or re-raises it directly. Either
    # way a TLPViolation must be in the chain.
    cause = exc_info.value
    seen_tlp = isinstance(cause, TLPViolation)
    while cause and not seen_tlp:
        cause = getattr(cause, "__cause__", None) or getattr(cause, "cause", None)
        if isinstance(cause, TLPViolation):
            seen_tlp = True
            break
    assert seen_tlp, f"expected TLPViolation in chain; got {exc_info.value!r}"


@pytest.mark.asyncio
async def test_pipeline_red_to_local_provider_succeeds(emit_callable):
    """TLP:RED + OLLAMA (local) is the documented allowed combination -- the
    pipeline should run end-to-end without raising."""
    workflow = _llm_only_workflow()
    ctx = NodeContext(
        run_id="run_smoke_red_local",
        org_id="org_default",
        investigation_id="inv_smoke_red_local",
        tlp_level=TLP.RED.value,
    )
    executor = WorkflowExecutor(
        middlewares=[
            LLMRouterMiddleware(model_to_provider=_model_to_ollama),
            EventEmitterMiddleware(emit_callable=emit_callable, tlp_level=TLP.RED),
        ]
    )

    result = await executor.execute(workflow, initial_input=None, ctx=ctx)
    assert result.final_output is not None
    assert ctx.metadata.get(LLM_PROVIDER_METADATA_KEY) == ModelProvider.OLLAMA.value
