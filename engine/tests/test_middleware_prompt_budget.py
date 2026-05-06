"""Tests for the PromptBudget middleware -- cumulative token / cost cap."""

from __future__ import annotations

import pytest
from pydantic import BaseModel

from btagent_engine import Node, NodeCategory, NodeContext, NodeMeta, Runner
from btagent_engine.middleware.prompt_budget import (
    USAGE_METADATA_KEY,
    BudgetUsage,
    PromptBudgetExceeded,
    PromptBudgetMiddleware,
)


class _In(BaseModel):
    prompt: str


class _Out(BaseModel):
    text: str


class _ReasoningNode(Node[_In, _Out]):
    """Mock reasoning node that reports a fixed usage on each run."""

    meta = NodeMeta(
        id="reason.summarise",
        name="Summarise",
        version="0.1.0",
        category=NodeCategory.REASONING,
    )
    input_schema = _In
    output_schema = _Out

    def __init__(self, usage: BudgetUsage) -> None:
        self._usage = usage

    async def run(self, input, ctx):
        # Mutate the (frozen-model, mutable-dict) metadata bag in place so
        # the middleware's after_run hook sees the report. This mirrors
        # how a real LLM-issuing node would write back its token counts.
        ctx.metadata[USAGE_METADATA_KEY] = self._usage.model_dump()
        return _Out(text=input.prompt)


class _DataNode(Node[_In, _Out]):
    meta = NodeMeta(
        id="data.passthrough",
        name="Pass",
        version="0.1.0",
        category=NodeCategory.DATA,
    )
    input_schema = _In
    output_schema = _Out

    async def run(self, input, ctx):
        return _Out(text=input.prompt)


def _ctx() -> NodeContext:
    # metadata defaults to an empty dict, which the reasoning node mutates.
    return NodeContext(run_id="r", org_id="org_test")


# --------------------------------------------------------------------------- #
# Happy: usage stays under the cap, the run completes, totals accumulate
# --------------------------------------------------------------------------- #


async def test_prompt_budget_accumulates_usage_under_cap():
    mw = PromptBudgetMiddleware(max_tokens=1_000, max_cost_usd=1.0)
    runner = Runner([mw])
    node = _ReasoningNode(BudgetUsage(input_tokens=100, output_tokens=50, cost_usd=0.01))
    await runner.execute(node, _In(prompt="x"), _ctx())
    await runner.execute(node, _In(prompt="y"), _ctx())
    assert mw.total_tokens == 300
    assert mw.total_cost_usd == pytest.approx(0.02)


# --------------------------------------------------------------------------- #
# Negative: once cumulative tokens cross the cap, the next reasoning run is
# refused with the typed exception (not a generic RuntimeError).
# --------------------------------------------------------------------------- #


async def test_prompt_budget_raises_when_token_cap_exceeded():
    mw = PromptBudgetMiddleware(max_tokens=200, max_cost_usd=10.0)
    runner = Runner([mw])
    node = _ReasoningNode(BudgetUsage(input_tokens=120, output_tokens=120, cost_usd=0.0))
    # First run accumulates 240 tokens (already past the cap of 200).
    await runner.execute(node, _In(prompt="x"), _ctx())
    # Second run is refused at before_run.
    with pytest.raises(PromptBudgetExceeded) as exc:
        await runner.execute(node, _In(prompt="y"), _ctx())
    assert exc.value.breached == "tokens"
    assert exc.value.used_tokens >= exc.value.max_tokens


# --------------------------------------------------------------------------- #
# Edge: non-reasoning nodes don't consume budget and aren't blocked even
# when the budget is already exhausted.
# --------------------------------------------------------------------------- #


async def test_prompt_budget_ignores_non_reasoning_nodes():
    mw = PromptBudgetMiddleware(max_tokens=10, max_cost_usd=0.01)
    # Pre-load to past the cap to prove integration/data nodes are unaffected.
    mw._total_tokens = 9_999_999  # type: ignore[reportPrivateUsage]
    runner = Runner([mw])
    out = await runner.execute(_DataNode(), _In(prompt="hi"), _ctx())
    assert out.text == "hi"
    # The data node didn't change the totals.
    assert mw.total_tokens == 9_999_999
