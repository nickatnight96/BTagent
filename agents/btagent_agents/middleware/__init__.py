"""Agents-layer middleware that supplements the engine's middleware chain.

The engine in ``btagent_engine.middleware`` deliberately stops short of
provider-aware concerns -- the engine has no notion of "OpenAI" vs
"Ollama" because those live in the LiteLLM-driven router that sits in
``btagent_agents.llm``. Cross-cutting middlewares whose policy *does*
depend on a concrete provider (e.g. TLP-vs-provider routing for LLM
calls) therefore live here, where the agents package has both the
engine ABC and the router available.

Sprint 3A ships :class:`LLMRouterMiddleware`. It reuses the
``TLP_ALLOWED_PROVIDERS`` policy table and ``is_provider_allowed`` helper
from :mod:`btagent_agents.hooks.classification_hook` so there is exactly
one source of truth for the TLP -> allowed-provider matrix; the legacy
LangChain callback in ``classification_hook`` and the new engine-level
middleware enforce the same rules.
"""

from btagent_agents.middleware.llm_router import (
    LLM_PROVIDER_METADATA_KEY,
    LLMRouterMiddleware,
)

__all__ = [
    "LLM_PROVIDER_METADATA_KEY",
    "LLMRouterMiddleware",
]
