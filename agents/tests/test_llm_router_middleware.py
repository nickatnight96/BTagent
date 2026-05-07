"""Tests for :class:`btagent_agents.middleware.llm_router.LLMRouterMiddleware`.

The middleware sits between the engine's :class:`Runner` and any
reasoning :class:`Node` (notably :class:`LLMCallNode`). It resolves the
input's abstract model handle to a concrete :class:`ModelProvider` via
the injected callable, gates the resolution against ``ctx.tlp_level``
through :func:`is_provider_allowed`, and stashes the resolution on
``ctx.metadata`` for downstream consumers.

The covered cases:

1. Allowed combo (TLP.GREEN + OpenAI) flows through.
2. Disallowed combo (TLP.RED + OpenAI) raises :class:`TLPViolation`.
3. Non-reasoning nodes are skipped entirely (resolver never invoked).
4. Resolved provider is exposed under
   :data:`LLM_PROVIDER_METADATA_KEY` on the context metadata bag.
5. Custom ``model_to_provider`` callable is invoked exactly once per
   ``before_run``.
6. End-to-end via :class:`Runner` + :class:`LLMCallNode`: TLP.RED with
   OpenAI raises before the node runs; TLP.GREEN with OpenAI runs the
   mock and returns the expected text.
"""

from __future__ import annotations

from typing import ClassVar

import pytest
from btagent_engine import Node, NodeCategory, NodeContext, NodeMeta, Runner
from btagent_engine.integrations.greynoise import (
    GreyNoiseLookupIPInput,
    GreyNoiseLookupIPNode,
)
from btagent_engine.integrations.llm_call import (
    LLMCallInput,
    LLMCallNode,
)
from btagent_shared.security import TLPViolation
from btagent_shared.types.config import TLP, ModelProvider
from pydantic import BaseModel

from btagent_agents.middleware import (
    LLM_PROVIDER_METADATA_KEY,
    LLMRouterMiddleware,
)

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _ctx(tlp: str = "green") -> NodeContext:
    """Fresh per-test :class:`NodeContext` -- frozen at the field level but
    its ``metadata`` dict is mutable in place, which is how middlewares
    hand state off to nodes downstream."""
    return NodeContext(run_id="r_test", org_id="org_test", tlp_level=tlp)


class _ReasoningIn(BaseModel):
    """Minimal reasoning-node input that mirrors :class:`LLMCallInput`'s
    shape -- the middleware only reads ``input.model``."""

    model: str


class _ReasoningOut(BaseModel):
    text: str


class _ReasoningNode(Node[_ReasoningIn, _ReasoningOut]):
    """Tiny reasoning node for unit tests of the middleware in isolation."""

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="test.reasoning",
        name="Test Reasoning",
        version="0.1.0",
        category=NodeCategory.REASONING,
    )
    input_schema: ClassVar[type[BaseModel]] = _ReasoningIn
    output_schema: ClassVar[type[BaseModel]] = _ReasoningOut

    async def run(self, input: _ReasoningIn, ctx: NodeContext) -> _ReasoningOut:
        return _ReasoningOut(text=f"ran {input.model}")


# --------------------------------------------------------------------------- #
# 1. Allowed combo proceeds without raising
# --------------------------------------------------------------------------- #


async def test_allowed_combo_proceeds() -> None:
    """TLP.GREEN + OpenAI is in the allowlist; ``before_run`` returns cleanly."""

    def resolve(_: str) -> ModelProvider:
        return ModelProvider.OPENAI

    mw = LLMRouterMiddleware(model_to_provider=resolve)
    ctx = _ctx(tlp=TLP.GREEN.value)
    node = _ReasoningNode()

    # Should not raise.
    await mw.before_run(node, _ReasoningIn(model="gpt-4o"), ctx)


# --------------------------------------------------------------------------- #
# 2. Disallowed combo raises TLPViolation
# --------------------------------------------------------------------------- #


async def test_disallowed_combo_raises_tlp_violation() -> None:
    """TLP.RED only allows Ollama; routing to OpenAI must trip the gate."""

    def resolve(_: str) -> ModelProvider:
        return ModelProvider.OPENAI

    mw = LLMRouterMiddleware(model_to_provider=resolve)
    ctx = _ctx(tlp=TLP.RED.value)
    node = _ReasoningNode()

    with pytest.raises(TLPViolation) as exc:
        await mw.before_run(node, _ReasoningIn(model="gpt-4o"), ctx)
    # Carries both the offending TLP level and the provider channel name.
    assert exc.value.tlp == TLP.RED
    assert exc.value.provider == ModelProvider.OPENAI


# --------------------------------------------------------------------------- #
# 3. Non-reasoning nodes are passed through unchanged (resolver not invoked)
# --------------------------------------------------------------------------- #


async def test_non_reasoning_node_skips_resolver() -> None:
    """An integration-category node like :class:`GreyNoiseLookupIPNode`
    must not trigger a resolver lookup -- it has no model handle to
    resolve, and the router policy is meaningless for non-LLM steps."""
    calls: list[str] = []

    def resolve(model: str) -> ModelProvider:
        calls.append(model)
        return ModelProvider.OPENAI

    mw = LLMRouterMiddleware(model_to_provider=resolve)
    ctx = _ctx(tlp=TLP.RED.value)  # would block OpenAI if resolver fired
    node = GreyNoiseLookupIPNode()

    # The middleware reads input.model on reasoning nodes; integration
    # nodes do not have one. The skip must happen before the lookup.
    await mw.before_run(node, GreyNoiseLookupIPInput(ip="1.2.3.4"), ctx)

    assert calls == [], "resolver must not be invoked for non-reasoning nodes"
    assert LLM_PROVIDER_METADATA_KEY not in ctx.metadata


# --------------------------------------------------------------------------- #
# 4. Resolved provider is stashed on ctx.metadata under the documented key
# --------------------------------------------------------------------------- #


async def test_resolved_provider_stashed_on_ctx_metadata() -> None:
    def resolve(_: str) -> ModelProvider:
        return ModelProvider.ANTHROPIC

    mw = LLMRouterMiddleware(model_to_provider=resolve)
    ctx = _ctx(tlp=TLP.AMBER.value)  # AMBER permits Anthropic
    node = _ReasoningNode()

    await mw.before_run(node, _ReasoningIn(model="claude-haiku"), ctx)

    assert ctx.metadata[LLM_PROVIDER_METADATA_KEY] == ModelProvider.ANTHROPIC


# --------------------------------------------------------------------------- #
# 5. Resolver callable is invoked exactly once per before_run
# --------------------------------------------------------------------------- #


async def test_resolver_invoked_exactly_once() -> None:
    """The middleware must not double-resolve -- each ``before_run`` makes
    one resolver call and either passes or raises on that single result.

    Also asserts the *handle* the resolver receives is the one declared
    on the input, so a custom callable is correctly threaded."""
    seen: list[str] = []

    def resolve(model: str) -> ModelProvider:
        seen.append(model)
        return ModelProvider.OPENAI

    mw = LLMRouterMiddleware(model_to_provider=resolve)
    ctx = _ctx(tlp=TLP.GREEN.value)
    node = _ReasoningNode()

    await mw.before_run(node, _ReasoningIn(model="gpt-4o-mini"), ctx)

    assert seen == ["gpt-4o-mini"]


# --------------------------------------------------------------------------- #
# 6. End-to-end via Runner + LLMCallNode
# --------------------------------------------------------------------------- #


async def test_runner_blocks_red_tlp_with_openai_before_node_runs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With the router in front of :class:`LLMCallNode`, a TLP.RED context
    routing to OpenAI must raise *before* the node executes -- i.e. the
    mock-mode echo never gets a chance to run."""
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")

    def resolve(_: str) -> ModelProvider:
        return ModelProvider.OPENAI

    runner = Runner([LLMRouterMiddleware(model_to_provider=resolve)])
    ctx = _ctx(tlp=TLP.RED.value)
    payload = LLMCallInput(
        messages=[{"role": "user", "content": "hello"}],
        model="gpt-4o",
    )

    with pytest.raises(TLPViolation):
        await runner.execute(LLMCallNode(), payload, ctx)


async def test_runner_runs_node_when_tlp_permits_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The mirror case: TLP.GREEN + OpenAI is allowed, so the runner walks
    through the gate and the mock-mode :class:`LLMCallNode` produces the
    expected echo output."""
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")

    def resolve(_: str) -> ModelProvider:
        return ModelProvider.OPENAI

    runner = Runner([LLMRouterMiddleware(model_to_provider=resolve)])
    ctx = _ctx(tlp=TLP.GREEN.value)
    payload = LLMCallInput(
        messages=[{"role": "user", "content": "hello"}],
        model="gpt-4o",
    )

    out = await runner.execute(LLMCallNode(), payload, ctx)

    assert out.text == "[mock-llm] hello"
    assert out.model == "gpt-4o"
    assert out.finish_reason == "stop"
    # The middleware also stashes the resolution for downstream consumers.
    assert ctx.metadata[LLM_PROVIDER_METADATA_KEY] == ModelProvider.OPENAI
