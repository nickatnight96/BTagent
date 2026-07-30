"""Air-gap / local-LLM configuration tests for the TLP-aware router (#506).

Two defects are pinned here, both of which undercut a fully-offline install
(the #98 Bet-4 story) without breaking anything visible in a connected one:

(A) **The configured Ollama base URL was ignored for chat completions.**
    ``LiteLLMClient`` built ``TLPAwareLLMRouter()`` with no arguments, so chat
    went to the router's hardcoded ``localhost:11434`` while embeddings
    honoured ``BTAGENT_OLLAMA_BASE_URL``. The assertions below read the
    ``api_base`` that actually reaches ``ChatLiteLLM``, not just the
    constructor argument -- the bug lived in the gap between the two.

(B) **There was no "local providers only" switch.** Offline correctness rested
    on cloud credentials merely being absent. ``local_only`` makes it explicit
    and fails closed: a TLP level authorising no local provider raises rather
    than resolving to a hosted one.

No network: ``ChatLiteLLM`` construction is inert (LiteLLM dispatches on
``ainvoke``, which these tests never call), and nothing here touches a
provider.
"""

from __future__ import annotations

import pytest
from btagent_shared.types.config import TLP, ModelProvider, ModelTier

from btagent_agents.llm.client import LiteLLMClient
from btagent_agents.llm.router import (
    DEFAULT_OLLAMA_BASE_URL,
    LOCAL_PROVIDERS,
    RoutingError,
    TLPAwareLLMRouter,
)

_ENCLAVE_URL = "http://ollama.btagent.svc.cluster.local:11434"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch):
    """Isolate from ambient config so defaults are actually the defaults."""
    monkeypatch.delenv("BTAGENT_OLLAMA_BASE_URL", raising=False)
    monkeypatch.delenv("BTAGENT_LOCAL_LLM_ONLY", raising=False)


def _chat_api_base(router: TLPAwareLLMRouter, tlp: TLP = TLP.RED) -> str | None:
    """The ``api_base`` the router hands to the chat model for an Ollama route."""
    llm = router.get_llm(tlp, ModelTier.LOCAL)
    return llm.model_kwargs.get("api_base")


# --------------------------------------------------------------------------- #
# (A) Chat completions honour the configured Ollama base URL
# --------------------------------------------------------------------------- #


def test_chat_uses_explicitly_configured_base_url():
    """An explicit base URL reaches the chat model, not just the constructor."""
    router = TLPAwareLLMRouter(ollama_base_url=_ENCLAVE_URL)
    assert router.ollama_base_url == _ENCLAVE_URL
    assert _chat_api_base(router) == _ENCLAVE_URL


def test_chat_uses_env_base_url_when_constructed_with_no_arguments(
    monkeypatch: pytest.MonkeyPatch,
):
    """The zero-argument construction sites must still honour the env var.

    ``LiteLLMClient`` and ``engine_runner.run_workflow_template`` both build
    the router with no arguments; before #506 that pinned chat to localhost.
    """
    monkeypatch.setenv("BTAGENT_OLLAMA_BASE_URL", _ENCLAVE_URL)
    assert _chat_api_base(TLPAwareLLMRouter()) == _ENCLAVE_URL


def test_chat_falls_back_to_localhost_when_unconfigured():
    """Unset means the documented loopback default, not an empty api_base."""
    assert _chat_api_base(TLPAwareLLMRouter()) == DEFAULT_OLLAMA_BASE_URL


def test_blank_env_base_url_does_not_produce_empty_api_base(
    monkeypatch: pytest.MonkeyPatch,
):
    """A commented-out/blank env value must not become an unusable ``""``."""
    monkeypatch.setenv("BTAGENT_OLLAMA_BASE_URL", "   ")
    assert _chat_api_base(TLPAwareLLMRouter()) == DEFAULT_OLLAMA_BASE_URL


def test_explicit_base_url_beats_env(monkeypatch: pytest.MonkeyPatch):
    """The caller's value wins -- the backend passes its ``Settings`` value."""
    monkeypatch.setenv("BTAGENT_OLLAMA_BASE_URL", "http://wrong:11434")
    assert _chat_api_base(TLPAwareLLMRouter(ollama_base_url=_ENCLAVE_URL)) == _ENCLAVE_URL


def test_litellm_client_threads_base_url_into_chat_route():
    """The #506 call site: the client's own router must carry the setting."""
    client = LiteLLMClient(ollama_base_url=_ENCLAVE_URL)
    assert client.router.ollama_base_url == _ENCLAVE_URL
    assert _chat_api_base(client.router) == _ENCLAVE_URL


def test_litellm_client_env_fallback(monkeypatch: pytest.MonkeyPatch):
    """A bare ``LiteLLMClient()`` still picks the env value up."""
    monkeypatch.setenv("BTAGENT_OLLAMA_BASE_URL", _ENCLAVE_URL)
    assert _chat_api_base(LiteLLMClient().router) == _ENCLAVE_URL


def test_litellm_client_respects_supplied_router():
    """A caller-owned router is used as-is (its config is not overridden)."""
    router = TLPAwareLLMRouter(ollama_base_url=_ENCLAVE_URL)
    client = LiteLLMClient(router=router, ollama_base_url="http://ignored:11434")
    assert client.router is router
    assert client.router.ollama_base_url == _ENCLAVE_URL


# --------------------------------------------------------------------------- #
# (B) local-only ON: restricted to local providers, fails closed
# --------------------------------------------------------------------------- #


def test_local_providers_covers_ollama_and_vllm():
    """The local set is the two self-hosted engines the air-gap guide names."""
    assert ModelProvider.OLLAMA in LOCAL_PROVIDERS
    assert "vllm" in LOCAL_PROVIDERS
    assert ModelProvider.ANTHROPIC not in LOCAL_PROVIDERS
    assert ModelProvider.BEDROCK not in LOCAL_PROVIDERS


@pytest.mark.parametrize("tlp", [TLP.GREEN, TLP.WHITE, TLP.AMBER_STRICT, TLP.RED])
def test_local_only_narrows_allowed_providers(tlp: TLP):
    """Every provider surviving the filter is local, and the list is non-empty."""
    allowed = TLPAwareLLMRouter(local_only=True).get_allowed_providers(tlp)
    assert allowed, f"{tlp} authorises a local provider; it must survive the filter"
    assert all(p in LOCAL_PROVIDERS for p in allowed)


@pytest.mark.parametrize(
    "tlp,tier",
    [
        (TLP.GREEN, ModelTier.STANDARD),
        (TLP.GREEN, ModelTier.PREMIUM),
        (TLP.WHITE, ModelTier.FAST),
        (TLP.AMBER_STRICT, ModelTier.STANDARD),
    ],
)
def test_local_only_resolves_to_ollama_where_cloud_would_have_won(tlp: TLP, tier: ModelTier):
    """GREEN/WHITE list Anthropic first; local-only must redirect to Ollama."""
    provider, model_id = TLPAwareLLMRouter(local_only=True).resolve(tlp, tier)
    assert provider == ModelProvider.OLLAMA
    assert model_id == "llama3.3"


def test_local_only_ignores_a_cloud_preferred_provider():
    """``preferred_provider`` cannot smuggle a hosted provider past the switch."""
    provider, _ = TLPAwareLLMRouter(local_only=True).resolve(
        TLP.GREEN, ModelTier.STANDARD, preferred_provider=ModelProvider.ANTHROPIC
    )
    assert provider == ModelProvider.OLLAMA


def test_local_only_fails_closed_when_no_local_provider_is_authorised():
    """TLP.AMBER lists no local provider: raise, never fall back to cloud."""
    router = TLPAwareLLMRouter(local_only=True)
    assert router.get_allowed_providers(TLP.AMBER) == []

    with pytest.raises(RoutingError) as exc:
        router.resolve(TLP.AMBER, ModelTier.STANDARD)

    message = str(exc.value)
    assert "BTAGENT_LOCAL_LLM_ONLY" in message
    assert "ollama" in message
    # The refusal must read as a refusal, and must not be mistaken for a route.
    assert "refused" in message


def test_local_only_fails_closed_for_every_tier_at_amber():
    """The tier-fallback branches must not become an escape hatch either."""
    router = TLPAwareLLMRouter(local_only=True)
    for tier in ModelTier:
        with pytest.raises(RoutingError):
            router.resolve(TLP.AMBER, tier)


def test_local_only_get_llm_never_builds_a_hosted_model():
    """End to end: the constructed chat model is an Ollama one, at our URL."""
    router = TLPAwareLLMRouter(local_only=True, ollama_base_url=_ENCLAVE_URL)
    llm = router.get_llm(TLP.GREEN, ModelTier.PREMIUM)
    assert llm.model.startswith("ollama/")
    assert llm.model_kwargs["api_base"] == _ENCLAVE_URL


def test_local_only_get_llm_raises_rather_than_dispatching_to_cloud():
    with pytest.raises(RoutingError):
        TLPAwareLLMRouter(local_only=True).get_llm(TLP.AMBER, ModelTier.STANDARD)


def test_local_only_validate_routing_rejects_hosted_providers():
    """The external pre-check shares the filter, so it agrees with ``resolve``."""
    router = TLPAwareLLMRouter(local_only=True)
    assert router.validate_routing(TLP.GREEN, ModelProvider.OLLAMA) is True
    assert router.validate_routing(TLP.GREEN, ModelProvider.ANTHROPIC) is False
    assert router.validate_routing(TLP.WHITE, ModelProvider.OPENAI) is False


@pytest.mark.parametrize("value", ["true", "TRUE", "1", "yes", "on"])
def test_local_only_enabled_from_env(monkeypatch: pytest.MonkeyPatch, value: str):
    monkeypatch.setenv("BTAGENT_LOCAL_LLM_ONLY", value)
    router = TLPAwareLLMRouter()
    assert router.local_only is True
    assert router.resolve(TLP.GREEN, ModelTier.STANDARD)[0] == ModelProvider.OLLAMA


def test_local_only_flows_through_the_litellm_client():
    client = LiteLLMClient(local_only=True)
    assert client.router.local_only is True
    with pytest.raises(RoutingError):
        client.router.resolve(TLP.AMBER, ModelTier.STANDARD)


# --------------------------------------------------------------------------- #
# (B) local-only OFF: today's behaviour, unchanged
# --------------------------------------------------------------------------- #


def test_default_is_off():
    """Existing (connected) deployments must see no behaviour change."""
    assert TLPAwareLLMRouter().local_only is False


@pytest.mark.parametrize("value", ["false", "FALSE", "0", "no", "", "   ", "maybe"])
def test_off_unless_explicitly_enabled(monkeypatch: pytest.MonkeyPatch, value: str):
    """Anything unparsable means OFF -- the flag only ever narrows routing."""
    monkeypatch.setenv("BTAGENT_LOCAL_LLM_ONLY", value)
    assert TLPAwareLLMRouter().local_only is False


def test_explicit_false_beats_a_true_env(monkeypatch: pytest.MonkeyPatch):
    """The backend passes ``Settings.local_llm_only``; it must be authoritative."""
    monkeypatch.setenv("BTAGENT_LOCAL_LLM_ONLY", "true")
    assert TLPAwareLLMRouter(local_only=False).local_only is False


@pytest.mark.parametrize(
    "tlp,expected",
    [
        (TLP.RED, ModelProvider.OLLAMA),
        (TLP.AMBER_STRICT, ModelProvider.OLLAMA),
        (TLP.AMBER, ModelProvider.ANTHROPIC),
        (TLP.GREEN, ModelProvider.ANTHROPIC),
        (TLP.WHITE, ModelProvider.ANTHROPIC),
    ],
)
def test_off_preserves_static_preference_resolution(tlp: TLP, expected: str):
    provider, _ = TLPAwareLLMRouter().resolve(tlp, ModelTier.STANDARD)
    assert provider == expected


@pytest.mark.parametrize("tlp", list(TLP))
def test_off_preserves_the_full_allow_lists(tlp: TLP):
    router = TLPAwareLLMRouter()
    assert router.get_allowed_providers(tlp) == list(TLPAwareLLMRouter.TLP_ROUTING.get(tlp, []))


def test_off_still_honours_a_preferred_provider():
    provider, _ = TLPAwareLLMRouter().resolve(
        TLP.GREEN, ModelTier.STANDARD, preferred_provider=ModelProvider.OLLAMA
    )
    assert provider == ModelProvider.OLLAMA


def test_tlp_red_remains_ollama_only_under_both_settings():
    """The TLP invariant is independent of the new switch, in both directions."""
    for local_only in (False, True):
        router = TLPAwareLLMRouter(local_only=local_only)
        assert router.get_allowed_providers(TLP.RED) == [ModelProvider.OLLAMA]
        assert router.validate_routing(TLP.RED, ModelProvider.ANTHROPIC) is False
