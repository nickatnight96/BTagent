"""LLM client protocol + transport-neutral request/response types.

The contract between the engine's reasoning nodes and whatever actually
talks to a model provider. Lives in shared/ (pydantic + typing only, no
LiteLLM) so the engine can depend on the *protocol* without pulling a
provider SDK — the concrete LiteLLM-backed client lives in agents/ and
is injected at runtime via ``btagent_engine.llm.set_llm_client``.

This is the seam that turns the mock-only reasoning nodes into real
ones: when a client is registered, nodes call it; otherwise they fall
back to their deterministic mock path (so demos + tests run with no
keys).
"""

from __future__ import annotations

from typing import Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from btagent_shared.types.config import TLP, ModelTier

Role = Literal["system", "user", "assistant"]


class LLMMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Role
    content: str


class LLMRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    messages: list[LLMMessage]
    tier: ModelTier = Field(
        default=ModelTier.STANDARD,
        description="Capability tier; the router maps this to a concrete model per provider.",
    )
    tlp: TLP = Field(
        default=TLP.GREEN,
        description="Classification of the data in the prompt; the router uses it to "
        "restrict which providers may see it (TLP:RED -> on-prem only).",
    )
    temperature: float = Field(default=0.1, ge=0.0, le=2.0)
    max_tokens: int = Field(default=4096, ge=1, le=200_000)
    preferred_provider: str | None = None
    json_mode: bool = Field(
        default=False, description="Request structured/JSON output where the provider supports it."
    )


class LLMUsage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0


class LLMResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    content: str
    provider: str = ""
    model: str = ""
    usage: LLMUsage = Field(default_factory=LLMUsage)


@runtime_checkable
class LLMClient(Protocol):
    """What a model client must implement for the engine to use it.

    Implementations own provider selection, credential resolution, TLP-
    aware routing, and cost accounting. The engine only sees this method.
    """

    async def complete(self, request: LLMRequest) -> LLMResponse: ...


__all__ = [
    "LLMClient",
    "LLMMessage",
    "LLMRequest",
    "LLMResponse",
    "LLMUsage",
    "Role",
]
