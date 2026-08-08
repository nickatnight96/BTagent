"""TLP-aware multi-provider LLM router.

Routes LLM requests to the appropriate provider and model based on:
1. TLP classification — restricts which providers may see the data
2. Model tier — selects capability level (fast/standard/premium/local)
3. Provider preference — honors user's preferred provider when compatible
4. Fallback — automatically falls back to the next allowed provider

Uses LiteLLM via LangChain's ChatLiteLLM wrapper for a unified interface.
``ChatLiteLLM`` ships in the standalone ``langchain-litellm`` package; the
old ``langchain_community.chat_models`` home was removed in
langchain-community 0.4.2 (that package is being sunset).

Air-gap knobs (#506). Two constructor arguments decide whether an offline
install actually stays offline, and both fall back to the ``BTAGENT_``
environment when the caller passes nothing:

* ``ollama_base_url`` -- where chat completions are sent when the resolved
  provider is Ollama. Defaults from ``BTAGENT_OLLAMA_BASE_URL`` so the
  zero-argument construction sites (``LiteLLMClient``,
  ``engine_runner.run_workflow_template``) honour an operator's setting
  instead of silently targeting ``localhost``. The backend passes the value
  from its ``Settings`` object explicitly, which also picks up ``.env``.
* ``local_only`` -- restricts resolution to :data:`LOCAL_PROVIDERS` and
  **fails closed**: when no local provider is allowed at the requested TLP
  level, :meth:`TLPAwareLLMRouter.resolve` raises :class:`RoutingError`
  rather than falling through to a hosted provider. Defaults from
  ``BTAGENT_LOCAL_LLM_ONLY`` and is OFF unless explicitly set, so the
  connected-deployment behaviour is unchanged.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from btagent_shared.types.config import TLP, ModelProvider, ModelTier
from langchain_core.language_models import BaseChatModel
from langchain_litellm import ChatLiteLLM

logger = logging.getLogger("btagent.llm.router")

#: Fallback when neither the caller nor ``BTAGENT_OLLAMA_BASE_URL`` says where
#: the local model server lives.
DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"

#: Providers that serve models from inside the deployment boundary. ``"vllm"``
#: is deliberately a bare string: it is not a :class:`ModelProvider` member
#: yet, and naming it here means the local allow-list is already correct the
#: day one is added rather than quietly excluding it. Membership tests work
#: either way because ``ModelProvider`` is a ``StrEnum``.
LOCAL_PROVIDERS: frozenset[str] = frozenset({ModelProvider.OLLAMA, "vllm"})

_TRUTHY = frozenset({"1", "true", "yes", "on"})
_FALSEY = frozenset({"", "0", "false", "no", "off"})


def _env_ollama_base_url() -> str:
    """Resolve the Ollama base URL from the environment."""
    return os.getenv("BTAGENT_OLLAMA_BASE_URL", "").strip() or DEFAULT_OLLAMA_BASE_URL


def _env_local_only() -> bool:
    """Read ``BTAGENT_LOCAL_LLM_ONLY``; anything unset/unparsable means OFF.

    Defaulting to OFF keeps existing (connected) deployments on today's
    behaviour, and the restriction only ever *narrows* routing -- so a value
    this function cannot parse leaves a working, permissive system rather than
    a half-configured one. That is quiet, though, which is the failure mode an
    enclave operator can least afford, so an unrecognised value is logged as a
    warning. (The backend does not rely on this path at all: it passes
    ``Settings.local_llm_only``, and pydantic rejects a malformed boolean at
    startup.)
    """
    raw = os.getenv("BTAGENT_LOCAL_LLM_ONLY", "").strip().lower()
    if raw in _TRUTHY:
        return True
    if raw not in _FALSEY:
        logger.warning(
            "BTAGENT_LOCAL_LLM_ONLY=%r is not a recognised boolean; treating local-LLM-only "
            "mode as DISABLED. Set it to 'true' to restrict routing to local providers.",
            raw,
        )
    return False


class RoutingError(Exception):
    """Raised when no compatible provider/model can be found."""

    def __init__(self, tlp: TLP, tier: ModelTier, reason: str) -> None:
        self.tlp = tlp
        self.tier = tier
        super().__init__(f"Cannot route LLM request (TLP={tlp}, tier={tier}): {reason}")


class TLPAwareLLMRouter:
    """Routes LLM requests respecting TLP classification and model tier requirements.

    The router enforces that data classified at a given TLP level is only sent to
    providers authorized for that level. Within the set of allowed providers, it
    selects the model matching the requested capability tier.

    With ``local_only=True`` the allowed set is additionally intersected with
    :data:`LOCAL_PROVIDERS`, which turns "no cloud egress" from a property of
    *not having credentials* into an explicit, testable setting.
    """

    # Which providers are allowed at each TLP level (ordered by preference).
    #
    # This table must agree with the classification boundary's ladder
    # (``classification_hook.TLP_ALLOWED_PROVIDERS``) — same policy, two
    # consumers: the hook *validates* a provider, this table *picks* one.
    # ``test_router_hook_tlp_drift.py`` pins the agreement. The AMBER rung
    # previously omitted Ollama (the hook's ladder had the same hole, fixed
    # first): local inference is admissible at every level — data never
    # leaves the deployment — so under ``local_only`` the omission refused
    # AMBER work outright, and a ``ModelTier.LOCAL`` request at AMBER
    # fell back to a *cloud* STANDARD model. Ollama sits last so connected
    # deployments still prefer the hosted providers.
    TLP_ROUTING: dict[TLP, list[str]] = {
        TLP.RED: [ModelProvider.OLLAMA],
        TLP.AMBER_STRICT: [ModelProvider.OLLAMA, ModelProvider.BEDROCK],
        TLP.AMBER: [
            ModelProvider.ANTHROPIC,
            ModelProvider.BEDROCK,
            ModelProvider.VERTEX_AI,
            ModelProvider.OLLAMA,
        ],
        TLP.GREEN: [
            ModelProvider.ANTHROPIC,
            ModelProvider.OPENAI,
            ModelProvider.BEDROCK,
            ModelProvider.VERTEX_AI,
            ModelProvider.OLLAMA,
        ],
        TLP.WHITE: [
            ModelProvider.ANTHROPIC,
            ModelProvider.OPENAI,
            ModelProvider.BEDROCK,
            ModelProvider.VERTEX_AI,
            ModelProvider.AZURE,
            ModelProvider.OLLAMA,
        ],
    }

    # Model IDs per tier per provider
    MODEL_TIERS: dict[ModelTier, dict[str, str]] = {
        ModelTier.FAST: {
            ModelProvider.ANTHROPIC: "claude-haiku-4-5-20251001",
            ModelProvider.OPENAI: "gpt-4o-mini",
            ModelProvider.BEDROCK: "bedrock/claude-haiku-4-5-20251001",
            ModelProvider.VERTEX_AI: "gemini-2.0-flash",
            ModelProvider.AZURE: "azure/gpt-4o-mini",
            ModelProvider.OLLAMA: "llama3.3",
        },
        ModelTier.STANDARD: {
            ModelProvider.ANTHROPIC: "claude-sonnet-4-6",
            ModelProvider.OPENAI: "gpt-4o",
            ModelProvider.BEDROCK: "bedrock/claude-sonnet-4-6",
            ModelProvider.VERTEX_AI: "gemini-2.5-pro",
            ModelProvider.AZURE: "azure/gpt-4o",
            ModelProvider.OLLAMA: "llama3.3",
        },
        ModelTier.PREMIUM: {
            ModelProvider.ANTHROPIC: "claude-opus-4-7",
            ModelProvider.OPENAI: "gpt-5",
            ModelProvider.BEDROCK: "bedrock/claude-opus-4-7",
            ModelProvider.VERTEX_AI: "gemini-2.5-pro",
            ModelProvider.AZURE: "azure/gpt-4o",
            ModelProvider.OLLAMA: "llama3.3",
        },
        ModelTier.LOCAL: {
            ModelProvider.OLLAMA: "llama3.3",
        },
    }

    def __init__(
        self,
        *,
        default_temperature: float = 0.1,
        default_max_tokens: int = 4096,
        ollama_base_url: str | None = None,
        local_only: bool | None = None,
        litellm_kwargs: dict[str, Any] | None = None,
    ) -> None:
        self._default_temperature = default_temperature
        self._default_max_tokens = default_max_tokens
        # ``None`` (not a hardcoded localhost default) so an unset argument
        # means "ask the environment" rather than "override the operator".
        self._ollama_base_url = ollama_base_url or _env_ollama_base_url()
        self._local_only = _env_local_only() if local_only is None else local_only
        self._litellm_kwargs = litellm_kwargs or {}

    @property
    def ollama_base_url(self) -> str:
        """Base URL chat completions use when the resolved provider is Ollama."""
        return self._ollama_base_url

    @property
    def local_only(self) -> bool:
        """Whether resolution is restricted to :data:`LOCAL_PROVIDERS`."""
        return self._local_only

    def get_allowed_providers(self, tlp: TLP) -> list[str]:
        """Return the ordered list of providers allowed for a TLP level.

        Under ``local_only`` the TLP allow-list is intersected with
        :data:`LOCAL_PROVIDERS`. Filtering here rather than inside
        :meth:`resolve` keeps one source of truth, so
        :meth:`validate_routing` (used by external callers to pre-check a
        provider) rejects hosted providers under local-only too.
        """
        allowed = list(self.TLP_ROUTING.get(tlp, []))
        if self._local_only:
            allowed = [p for p in allowed if p in LOCAL_PROVIDERS]
        return allowed

    def get_model_id(self, tier: ModelTier, provider: str) -> str | None:
        """Look up the model ID for a given tier and provider.

        Returns None if the provider does not have a model for that tier.
        """
        tier_models = self.MODEL_TIERS.get(tier, {})
        return tier_models.get(provider)

    def _local_only_refusal(self, unrestricted: list[str]) -> str:
        """Explain a local-only refusal in terms an operator can act on."""
        return (
            "local-LLM-only mode is enabled (BTAGENT_LOCAL_LLM_ONLY=true) and no local "
            f"provider ({', '.join(sorted(LOCAL_PROVIDERS))}) is authorised at this TLP "
            "level, so the request is refused rather than routed to a hosted provider. "
            f"Providers allowed at this level without the restriction: "
            f"{', '.join(sorted(unrestricted))}. Classify this work at a TLP level that "
            "permits a local provider, or turn the restriction off."
        )

    def resolve(
        self,
        tlp: TLP,
        tier: ModelTier,
        preferred_provider: str | None = None,
    ) -> tuple[str, str]:
        """Resolve the provider and model ID for a request.

        Args:
            tlp: TLP classification level.
            tier: Desired model capability tier.
            preferred_provider: Optional preferred provider (used if compatible).

        Returns:
            Tuple of (provider, model_id).

        Raises:
            RoutingError: If no compatible provider/model can be found. Under
                ``local_only`` this is the fail-closed path: a TLP level whose
                allow-list contains no local provider raises here instead of
                resolving to a hosted one.
        """
        unrestricted = list(self.TLP_ROUTING.get(tlp, []))
        allowed = self.get_allowed_providers(tlp)
        if not allowed:
            if self._local_only and unrestricted:
                raise RoutingError(tlp, tier, self._local_only_refusal(unrestricted))
            raise RoutingError(tlp, tier, "No providers allowed for this TLP level")

        # Try preferred provider first if it's in the allowed list
        if preferred_provider and preferred_provider in allowed:
            model_id = self.get_model_id(tier, preferred_provider)
            if model_id:
                return preferred_provider, model_id

        # Fall back through allowed providers in preference order
        for provider in allowed:
            model_id = self.get_model_id(tier, provider)
            if model_id:
                return provider, model_id

        # If LOCAL tier is requested but no match, try STANDARD as fallback
        if tier == ModelTier.LOCAL:
            for provider in allowed:
                model_id = self.get_model_id(ModelTier.STANDARD, provider)
                if model_id:
                    logger.warning(
                        "No LOCAL tier model for TLP=%s; falling back to STANDARD on %s",
                        tlp,
                        provider,
                    )
                    return provider, model_id

        detail = f"No model found for tier={tier} among allowed providers: {allowed}"
        if self._local_only:
            detail += " (local-LLM-only mode is enabled; hosted providers were excluded)"
        raise RoutingError(tlp, tier, detail)

    def get_llm(
        self,
        tlp: TLP,
        tier: ModelTier,
        *,
        preferred_provider: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        streaming: bool = False,
        **kwargs: Any,
    ) -> BaseChatModel:
        """Create a LangChain chat model routed by TLP and tier.

        Args:
            tlp: TLP classification level.
            tier: Desired model capability tier.
            preferred_provider: Optional preferred provider.
            temperature: Override default temperature.
            max_tokens: Override default max output tokens.
            streaming: Enable streaming token output.
            **kwargs: Additional kwargs passed to ChatLiteLLM.

        Returns:
            A LangChain BaseChatModel ready for use in LangGraph.

        Raises:
            RoutingError: If no compatible provider/model can be found.
        """
        provider, model_id = self.resolve(tlp, tier, preferred_provider)

        # Build LiteLLM kwargs
        litellm_params: dict[str, Any] = {
            **self._litellm_kwargs,
            **kwargs,
        }

        # Provider-specific configuration
        if provider == ModelProvider.OLLAMA:
            litellm_params.setdefault("api_base", self._ollama_base_url)
            # LiteLLM expects "ollama/" prefix for Ollama models
            if not model_id.startswith("ollama/"):
                model_id = f"ollama/{model_id}"

        llm = ChatLiteLLM(
            model=model_id,
            temperature=temperature if temperature is not None else self._default_temperature,
            max_tokens=max_tokens or self._default_max_tokens,
            streaming=streaming,
            model_kwargs=litellm_params,
        )

        logger.info(
            "Routed LLM: TLP=%s tier=%s -> provider=%s model=%s (local_only=%s)",
            tlp.value,
            tier.value,
            provider,
            model_id,
            self._local_only,
        )

        return llm

    def validate_routing(self, tlp: TLP, provider: str) -> bool:
        """Check if a provider is allowed for a TLP level (for external validation)."""
        return provider in self.get_allowed_providers(tlp)
