"""Tests for the LLMCallNode reasoning Node.

Covers:

* Mock-mode echo behaviour (text, model, finish_reason).
* Schema validation (empty messages, invalid roles).
* Budget-usage reporting (single call writes a BudgetUsage; sequential
  calls in the same context accumulate rather than overwrite).
* End-to-end through the Runner with the PromptBudgetMiddleware --
  exceeding the cumulative cap raises PromptBudgetExceeded.
* Production path raises NotImplementedError pointing at Sprint 3.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from btagent_engine import NodeCategory, NodeContext, NodeRegistry, Runner
from btagent_engine.integrations.llm_call import (
    LLMCallInput,
    LLMCallNode,
    LLMCallOutput,
)
from btagent_engine.middleware.prompt_budget import (
    USAGE_METADATA_KEY,
    BudgetUsage,
    PromptBudgetExceeded,
    PromptBudgetMiddleware,
)


def _ctx() -> NodeContext:
    # metadata defaults to an empty dict; the LLM Node mutates it in place
    # to record BudgetUsage. A fresh ctx per test keeps state isolated.
    return NodeContext(run_id="r_llm", org_id="org_default")


@pytest.fixture(autouse=True)
def _enable_mock(monkeypatch):
    """Default every test into mock mode; individual tests can flip back."""
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    yield


# --------------------------------------------------------------------------- #
# Mock-mode behaviour
# --------------------------------------------------------------------------- #


async def test_llm_call_mock_echoes_last_user_message():
    out = await LLMCallNode().run(
        LLMCallInput(messages=[{"role": "user", "content": "hello world"}]),
        _ctx(),
    )
    assert isinstance(out, LLMCallOutput)
    assert out.text == "[mock-llm] hello world"


async def test_llm_call_mock_echoes_model_handle_unchanged():
    """The Node never resolves the model handle -- it echoes whatever the
    caller passed so the LLM-router middleware (Sprint 3) can intercept it."""
    out = await LLMCallNode().run(
        LLMCallInput(
            messages=[{"role": "user", "content": "hi"}],
            model="claude-sonnet-4",
        ),
        _ctx(),
    )
    assert out.model == "claude-sonnet-4"


async def test_llm_call_mock_finish_reason_is_stop():
    out = await LLMCallNode().run(
        LLMCallInput(messages=[{"role": "user", "content": "hi"}]),
        _ctx(),
    )
    assert out.finish_reason == "stop"


# --------------------------------------------------------------------------- #
# Schema validation
# --------------------------------------------------------------------------- #


def test_llm_call_rejects_empty_messages_list():
    """An LLM call with no messages is meaningless; pydantic should catch it
    at construction time, not let it reach run()."""
    with pytest.raises(ValidationError):
        LLMCallInput(messages=[])


def test_llm_call_rejects_invalid_role():
    """Roles must be one of the OpenAI / Anthropic conventional set;
    'narrator' is the canonical typo to trip on."""
    with pytest.raises(ValidationError):
        LLMCallInput(messages=[{"role": "narrator", "content": "..."}])


def test_llm_call_requires_at_least_one_user_message():
    """A system-only prompt with no user message is also invalid -- the
    LLM has no question to answer."""
    with pytest.raises(ValidationError):
        LLMCallInput(messages=[{"role": "system", "content": "you are helpful"}])


# --------------------------------------------------------------------------- #
# Budget reporting
# --------------------------------------------------------------------------- #


async def test_llm_call_records_budget_usage_in_ctx_metadata():
    """Every call must write a BudgetUsage into ctx.metadata so the
    PromptBudget middleware can enforce the cumulative cap."""
    ctx = _ctx()
    await LLMCallNode().run(
        LLMCallInput(messages=[{"role": "user", "content": "hello"}]),
        ctx,
    )
    raw = ctx.metadata[USAGE_METADATA_KEY]
    usage = BudgetUsage.model_validate(raw)
    # Mock-mode token counts are len(text) // 4 -- non-zero for any non-empty
    # message; we don't assert exact counts (that would couple the test to
    # the mock estimator) only that *something* was reported.
    assert usage.input_tokens > 0
    assert usage.output_tokens > 0
    assert usage.cost_usd == 0.0


async def test_llm_call_accumulates_usage_on_sequential_calls():
    """Two sequential calls sharing one ctx must *sum* their usage -- not
    overwrite. Plugins legitimately chain multiple LLM calls inside a
    single node run; clobbering the count would silently undercount spend."""
    ctx = _ctx()
    node = LLMCallNode()
    await node.run(LLMCallInput(messages=[{"role": "user", "content": "first"}]), ctx)
    first = BudgetUsage.model_validate(ctx.metadata[USAGE_METADATA_KEY])

    await node.run(LLMCallInput(messages=[{"role": "user", "content": "second"}]), ctx)
    second = BudgetUsage.model_validate(ctx.metadata[USAGE_METADATA_KEY])

    # The accumulated total must be strictly greater than (or equal to,
    # if either call somehow produced zero tokens -- defensively allow it)
    # the first call's reading. In practice the two messages are non-empty
    # so this is strict.
    assert second.input_tokens >= first.input_tokens * 2 - 1
    assert second.output_tokens >= first.output_tokens * 2 - 1


# --------------------------------------------------------------------------- #
# End-to-end with PromptBudgetMiddleware
# --------------------------------------------------------------------------- #


async def test_llm_call_through_runner_trips_prompt_budget_cap():
    """The Node + middleware contract: after enough reasoning calls, the
    next one is refused at before_run with PromptBudgetExceeded."""
    # Cap is intentionally tiny so a single mock call exhausts it. The
    # middleware checks the cap *before* the next reasoning run -- so the
    # first call goes through (and pushes the total past the cap), the
    # second is refused.
    mw = PromptBudgetMiddleware(max_tokens=1, max_cost_usd=10.0)
    runner = Runner([mw])
    node = LLMCallNode()

    await runner.execute(
        node,
        LLMCallInput(messages=[{"role": "user", "content": "burn the budget"}]),
        _ctx(),
    )
    assert mw.total_tokens >= 1

    with pytest.raises(PromptBudgetExceeded) as exc:
        await runner.execute(
            node,
            LLMCallInput(messages=[{"role": "user", "content": "blocked"}]),
            _ctx(),
        )
    assert exc.value.breached == "tokens"


# --------------------------------------------------------------------------- #
# Production path is intentionally NotImplementedError until Sprint 3
# --------------------------------------------------------------------------- #


async def test_llm_call_production_mode_without_client_raises(monkeypatch):
    """Live LLM dispatch requires a client registered via
    btagent_engine.llm.set_llm_client. With no client AND no mock, the
    Node must fail loud so a misconfigured env doesn't silently no-op."""
    from btagent_engine.llm import clear_llm_client

    clear_llm_client()
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "false")
    with pytest.raises(NotImplementedError, match="set_llm_client"):
        await LLMCallNode().run(
            LLMCallInput(messages=[{"role": "user", "content": "hi"}]),
            _ctx(),
        )


# --------------------------------------------------------------------------- #
# Registry + metadata
# --------------------------------------------------------------------------- #


def test_llm_call_node_is_registered_with_correct_id_and_category():
    cls = NodeRegistry.get("reasoning.llm.call")
    assert cls is LLMCallNode
    assert cls.meta.category == NodeCategory.REASONING
