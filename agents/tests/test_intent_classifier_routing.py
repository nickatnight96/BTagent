"""A1 / P3.1: the intent classifier must route through ``TLPAwareLLMRouter``.

Before the fix ``_classify_intent_llm`` called ``litellm.completion`` directly
with a hard-pinned (and stale) cloud Anthropic model id — ignoring the TLP
allow-list, ``BTAGENT_LOCAL_LLM_ONLY`` and ``BTAGENT_OLLAMA_BASE_URL``. An
air-gapped operator's TLP:RED alert text with no routing keyword went straight
to api.anthropic.com. These tests pin the routed replacement.
"""

from __future__ import annotations

from typing import Any

import pytest
from btagent_shared.types.config import TLP, ModelProvider, ModelTier

from btagent_agents.llm.router import RoutingError, TLPAwareLLMRouter
from btagent_agents.orchestrator.nodes import (
    _classify_intent_llm,
    _coerce_tlp_fail_closed,
)


def test_unknown_tlp_fails_closed_to_red():
    assert _coerce_tlp_fail_closed("red") is TLP.RED
    assert _coerce_tlp_fail_closed("green") is TLP.GREEN
    assert _coerce_tlp_fail_closed(TLP.AMBER) is TLP.AMBER
    assert _coerce_tlp_fail_closed("bogus") is TLP.RED
    assert _coerce_tlp_fail_closed(None) is TLP.RED
    assert _coerce_tlp_fail_closed("") is TLP.RED


class _StubLLM:
    """Stands in for the routed chat model; returns a fixed classification."""

    def __init__(self, content: str) -> None:
        self._content = content

    def invoke(self, messages: Any) -> Any:
        class _Msg:
            content = self._content

        return _Msg()


def test_classifier_resolves_via_router_with_state_tlp(monkeypatch):
    """The router receives the investigation's TLP — not a hard-pinned model."""
    seen: dict[str, Any] = {}

    def _fake_get_llm(self, tlp, tier, **kwargs):
        seen["tlp"] = tlp
        seen["tier"] = tier
        return _StubLLM("triage")

    monkeypatch.setattr(TLPAwareLLMRouter, "get_llm", _fake_get_llm)

    assert _classify_intent_llm("what is going on here", "amber") == "triage"
    assert seen["tlp"] is TLP.AMBER
    assert seen["tier"] is ModelTier.FAST


def test_red_tlp_resolution_never_selects_a_hosted_provider():
    """At TLP:RED the router's allow-list is Ollama-only — no cloud egress."""
    provider, model_id = TLPAwareLLMRouter().resolve(TLP.RED, ModelTier.FAST)
    assert provider == ModelProvider.OLLAMA
    assert "claude" not in model_id and "gpt" not in model_id


def test_local_only_refusal_falls_back_to_general(monkeypatch):
    """local-only + a TLP with no local provider refuses; classifier degrades
    to "general" instead of routing to a hosted model."""

    def _refuse(self, tlp, tier, **kwargs):
        raise RoutingError(tlp, tier, "local-only refusal")

    monkeypatch.setattr(TLPAwareLLMRouter, "get_llm", _refuse)
    assert _classify_intent_llm("free-form question", "amber") == "general"


def test_garbage_model_output_falls_back_to_general(monkeypatch):
    monkeypatch.setattr(
        TLPAwareLLMRouter, "get_llm", lambda self, tlp, tier, **kw: _StubLLM("not-a-type")
    )
    assert _classify_intent_llm("free-form question", "green") == "general"


def test_no_direct_litellm_completion_import():
    """Drift guard: the classifier must not regrow a direct litellm call."""
    import inspect

    from btagent_agents.orchestrator import nodes

    src = inspect.getsource(nodes._classify_intent_llm)
    assert "from litellm import completion" not in src
    assert "TLPAwareLLMRouter" in src
