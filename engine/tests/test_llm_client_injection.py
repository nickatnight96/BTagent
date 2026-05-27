"""Tests for LLM client injection into LLMCallNode (real-path unlock).

Proves the seam that turns mock-only reasoning into real: with a client
registered via btagent_engine.llm.set_llm_client, LLMCallNode dispatches
through it (real path); without one, non-mock mode fails loudly; and
mock mode is unchanged either way.
"""

from __future__ import annotations

import pytest

from btagent_engine import NodeContext
from btagent_engine.integrations.llm_call import LLMCallInput, LLMCallNode
from btagent_engine.llm import clear_llm_client, get_llm_client, set_llm_client
from btagent_engine.middleware.prompt_budget import USAGE_METADATA_KEY
from btagent_shared.llm import LLMRequest, LLMResponse, LLMUsage


class _FakeClient:
    """Records the request and returns a canned response."""

    def __init__(self) -> None:
        self.last_request: LLMRequest | None = None

    async def complete(self, request: LLMRequest) -> LLMResponse:
        self.last_request = request
        return LLMResponse(
            content="FAKE-COMPLETION",
            provider="anthropic",
            model="claude-sonnet-4-6",
            usage=LLMUsage(input_tokens=11, output_tokens=7, cost_usd=0.0003),
        )


def _ctx(tlp: str = "green") -> NodeContext:
    return NodeContext(run_id="r_llm", org_id="org_test", tlp_level=tlp)


def _input(model: str = "claude-sonnet") -> LLMCallInput:
    return LLMCallInput(
        messages=[{"role": "user", "content": "summarize this alert"}],
        model=model,
    )


@pytest.fixture(autouse=True)
def _reset_client():
    clear_llm_client()
    yield
    clear_llm_client()


# --------------------------------------------------------------------------- #
# Real path via injected client
# --------------------------------------------------------------------------- #


async def test_registered_client_is_used_in_non_mock_mode(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "false")
    fake = _FakeClient()
    set_llm_client(fake)

    out = await LLMCallNode().run(_input(), _ctx())
    assert out.text == "FAKE-COMPLETION"
    assert out.model == "claude-sonnet-4-6"
    # the node mapped the "claude-sonnet" handle -> STANDARD tier
    assert fake.last_request is not None
    assert fake.last_request.tier.value == "standard"


async def test_tlp_flows_through_to_client(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "false")
    fake = _FakeClient()
    set_llm_client(fake)

    await LLMCallNode().run(_input(), _ctx(tlp="red"))
    assert fake.last_request.tlp.value == "red"


async def test_model_handle_maps_to_tier(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "false")
    fake = _FakeClient()
    set_llm_client(fake)

    await LLMCallNode().run(_input(model="claude-opus"), _ctx())
    assert fake.last_request.tier.value == "premium"


async def test_real_usage_recorded_to_budget(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "false")
    set_llm_client(_FakeClient())
    ctx = _ctx()
    await LLMCallNode().run(_input(), ctx)
    usage = ctx.metadata[USAGE_METADATA_KEY]
    assert usage["input_tokens"] == 11
    assert usage["output_tokens"] == 7
    assert usage["cost_usd"] == pytest.approx(0.0003)


# --------------------------------------------------------------------------- #
# No client registered -> fail loud in non-mock mode
# --------------------------------------------------------------------------- #


async def test_non_mock_without_client_raises(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "false")
    assert get_llm_client() is None
    with pytest.raises(NotImplementedError):
        await LLMCallNode().run(_input(), _ctx())


# --------------------------------------------------------------------------- #
# Mock mode is unchanged regardless of client registration
# --------------------------------------------------------------------------- #


async def test_mock_mode_ignores_client(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    set_llm_client(_FakeClient())  # present, but mock mode wins
    out = await LLMCallNode().run(_input(), _ctx())
    assert out.text.startswith("[mock-llm]")
    assert "summarize this alert" in out.text
