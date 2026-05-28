"""Tests for LiteLLMClient — maps LLMRequest -> router -> LLMResponse.

Does not hit a real provider: the router's get_llm is replaced with a
fake chat model so we exercise the request/response mapping + usage
extraction deterministically.
"""

from __future__ import annotations

from btagent_shared.llm import LLMMessage, LLMRequest
from btagent_shared.types.config import TLP, ModelTier

from btagent_agents.llm.client import LiteLLMClient


class _FakeAIMessage:
    def __init__(self, content: str, usage: dict | None = None) -> None:
        self.content = content
        self.usage_metadata = usage
        self.response_metadata = {}


class _FakeChatModel:
    def __init__(self, content: str, usage: dict | None = None) -> None:
        self._content = content
        self._usage = usage

    async def ainvoke(self, messages):
        return _FakeAIMessage(self._content, self._usage)


class _FakeRouter:
    """Stands in for LLMRouter: records routing, returns a fake model."""

    def __init__(self, content: str, usage: dict | None = None) -> None:
        self._content = content
        self._usage = usage
        self.resolved: tuple | None = None

    def get_llm(self, tlp, tier, *, preferred_provider=None, temperature=None, max_tokens=None):
        return _FakeChatModel(self._content, self._usage)

    def resolve(self, tlp, tier, preferred_provider=None):
        self.resolved = (tlp, tier, preferred_provider)
        return ("anthropic", "claude-sonnet-4-6")


def _req(**kw) -> LLMRequest:
    base = dict(
        messages=[
            LLMMessage(role="system", content="you are a triage analyst"),
            LLMMessage(role="user", content="classify this alert"),
        ],
        tier=ModelTier.STANDARD,
        tlp=TLP.GREEN,
    )
    base.update(kw)
    return LLMRequest(**base)


async def test_complete_maps_content_and_model():
    router = _FakeRouter("CLASSIFIED: benign", usage={"input_tokens": 20, "output_tokens": 5})
    client = LiteLLMClient(router=router)  # type: ignore[arg-type]
    resp = await client.complete(_req())
    assert resp.content == "CLASSIFIED: benign"
    assert resp.provider == "anthropic"
    assert resp.model == "claude-sonnet-4-6"
    assert resp.usage.input_tokens == 20
    assert resp.usage.output_tokens == 5


async def test_routing_uses_request_tlp_and_tier():
    router = _FakeRouter("ok")
    client = LiteLLMClient(router=router)  # type: ignore[arg-type]
    await client.complete(_req(tlp=TLP.RED, tier=ModelTier.PREMIUM))
    assert router.resolved == (TLP.RED, ModelTier.PREMIUM, None)


async def test_usage_falls_back_to_response_metadata():
    router = _FakeRouter("ok", usage=None)
    client = LiteLLMClient(router=router)  # type: ignore[arg-type]
    resp = await client.complete(_req())
    # no usage_metadata + empty response_metadata -> zeroed usage, no crash
    assert resp.usage.input_tokens == 0
    assert resp.usage.output_tokens == 0
