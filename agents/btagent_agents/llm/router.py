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
"""

from __future__ import annotations

import logging
from typing import Any

from btagent_shared.types.config import TLP, ModelProvider, ModelTier
from langchain_core.language_models import BaseChatModel
from langchain_litellm import ChatLiteLLM

logger = logging.getLogger("btagent.llm.router")


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
    """

    # Which providers are allowed at each TLP level (ordered by preference)
    TLP_ROUTING: dict[TLP, list[str]] = {
        TLP.RED: [ModelProvider.OLLAMA],
        TLP.AMBER_STRICT: [ModelProvider.OLLAMA, ModelProvider.BEDROCK],
        TLP.AMBER: [
            ModelProvider.ANTHROPIC,
            ModelProvider.BEDROCK,
            ModelProvider.VERTEX_AI,
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
            ModelProvider.ANTHROPIC: "claude-sonnet-4-20250514",
            ModelProvider.OPENAI: "gpt-4o",
            ModelProvider.BEDROCK: "bedrock/claude-sonnet-4-20250514",
            ModelProvider.VERTEX_AI: "gemini-2.5-pro",
            ModelProvider.AZURE: "azure/gpt-4o",
            ModelProvider.OLLAMA: "llama3.3",
        },
        ModelTier.PREMIUM: {
            ModelProvider.ANTHROPIC: "claude-opus-4-20250415",
            ModelProvider.OPENAI: "o3",
            ModelProvider.BEDROCK: "bedrock/claude-opus-4-20250415",
            ModelProvider.VERTEX_AI: "gemini-ultra",
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
        ollama_base_url: str = "http://localhost:11434",
        litellm_kwargs: dict[str, Any] | None = None,
    ) -> None:
        self._default_temperature = default_temperature
        self._default_max_tokens = default_max_tokens
        self._ollama_base_url = ollama_base_url
        self._litellm_kwargs = litellm_kwargs or {}

    def get_allowed_providers(self, tlp: TLP) -> list[str]:
        """Return the ordered list of providers allowed for a TLP level."""
        return list(self.TLP_ROUTING.get(tlp, []))

    def get_model_id(self, tier: ModelTier, provider: str) -> str | None:
        """Look up the model ID for a given tier and provider.

        Returns None if the provider does not have a model for that tier.
        """
        tier_models = self.MODEL_TIERS.get(tier, {})
        return tier_models.get(provider)

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
            RoutingError: If no compatible provider/model can be found.
        """
        allowed = self.get_allowed_providers(tlp)
        if not allowed:
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

        raise RoutingError(
            tlp,
            tier,
            f"No model found for tier={tier} among allowed providers: {allowed}",
        )

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
            "Routed LLM: TLP=%s tier=%s -> provider=%s model=%s",
            tlp.value,
            tier.value,
            provider,
            model_id,
        )

        return llm

    def validate_routing(self, tlp: TLP, provider: str) -> bool:
        """Check if a provider is allowed for a TLP level (for external validation)."""
        return provider in self.get_allowed_providers(tlp)
