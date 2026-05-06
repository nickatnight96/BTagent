"""LLM-call reasoning Node.

The ``LLMCallNode`` is the canonical reasoning step in a BTagent
workflow. Every prompt-driven node (triage summariser, query planner,
hypothesis generator) ultimately ends up making an LLM call, and the
intent is that the canvas UI exposes *this* node as the building block
for that work rather than asking authors to subclass anything.

Design notes worth recording so the Sprint 3 LLM-router work doesn't
drift:

1. **The Node does NOT pick providers.** Provider selection (Claude vs
   GPT-4 vs the on-prem llama for TLP:RED), credential resolution, and
   per-tenant rate limiting are all the responsibility of the
   LLM-router middleware that will sit between the Runner and this
   Node in production. Keeping that out of the Node means the Node
   stays trivially testable and the routing policy can be swapped
   without touching workflow files.

2. **Mock mode is the default.** ``BTAGENT_MOCK_LLM`` defaults to
   ``true``; the production path raises ``NotImplementedError`` until
   Sprint 3 wires LiteLLM. This intentionally matches the integration-
   node convention (``BTAGENT_MOCK_CONNECTORS``) so tests, CI, and
   local dev never accidentally hit a real LLM.

3. **Budget reporting is mandatory.** Every call writes a
   :class:`btagent_engine.middleware.prompt_budget.BudgetUsage` blob
   into ``ctx.metadata[USAGE_METADATA_KEY]`` so the
   :class:`PromptBudgetMiddleware` can enforce the per-workflow cap.
   When the same key already holds a usage report (because the same
   ctx was reused across multiple LLM calls -- which the runner does,
   one ctx per node-execution but plugin code may chain calls within
   a single ``run``), the new usage is *summed* into the existing one
   rather than overwriting it. Overwriting would silently undercount
   spend across chained calls inside one node.
"""

from __future__ import annotations

import os
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

from btagent_engine.middleware.prompt_budget import USAGE_METADATA_KEY, BudgetUsage
from btagent_engine.node import (
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Roles the OpenAI / Anthropic / LiteLLM message-list convention recognises.
# Tool-call roles ("tool", "function") are deferred -- those land with the
# tool-calling Node in Sprint 3 alongside the router.
_ALLOWED_ROLES: frozenset[str] = frozenset({"system", "user", "assistant"})

# Mock-mode token estimator divisor. Real tokenisation belongs to the router
# (which knows the model's tokenizer); the engine's mock just needs a
# deterministic number that scales with text length.
_MOCK_TOKEN_DIVISOR: int = 4

# Mock-mode prefix on the echoed text. Tests rely on this exact string.
_MOCK_PREFIX: str = "[mock-llm]"


def _mock_mode_enabled() -> bool:
    """Resolve the mock-mode flag at call time so tests can flip it."""
    return os.getenv("BTAGENT_MOCK_LLM", "true").lower() == "true"


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class _Message(BaseModel):
    """Single chat-style message. Internal -- the public input is a list of
    plain dicts to keep the workflow JSON / YAML representation simple."""

    model_config = ConfigDict(extra="forbid")

    role: str = Field(..., description="One of 'system' / 'user' / 'assistant'.")
    content: str = Field(..., description="Message body.")

    @field_validator("role")
    @classmethod
    def _role_allowed(cls, v: str) -> str:
        if v not in _ALLOWED_ROLES:
            raise ValueError(
                f"role must be one of {sorted(_ALLOWED_ROLES)}, got {v!r}"
            )
        return v


class LLMCallInput(BaseModel):
    """Input to the LLM-call Node."""

    model_config = ConfigDict(extra="forbid")

    messages: list[dict[str, str]] = Field(
        ...,
        min_length=1,
        description="OpenAI-style chat message list. Each item must have "
        "'role' (one of 'system' / 'user' / 'assistant') and 'content'. "
        "Must contain at least one user message.",
    )
    model: str = Field(
        default="claude-haiku",
        description="Abstract model handle the LLM-router middleware will "
        "resolve to a concrete provider + model name. Engine never resolves "
        "this itself -- that's deliberately the router's job per Sprint 2B.",
    )
    max_tokens: int = Field(
        default=1024,
        ge=1,
        description="Per-call cap on completion tokens. The middleware-level "
        "PromptBudget enforces the *cumulative* cap across calls.",
    )
    temperature: float = Field(
        default=0.7,
        ge=0.0,
        le=2.0,
        description="Sampling temperature passed through to the provider.",
    )

    @field_validator("messages")
    @classmethod
    def _validate_messages(cls, v: list[dict[str, str]]) -> list[dict[str, str]]:
        # Validate each message via the inner _Message model so role + content
        # are checked. We re-emit the dicts unchanged so the public surface
        # stays plain JSON.
        has_user = False
        for i, msg in enumerate(v):
            try:
                parsed = _Message.model_validate(msg)
            except Exception as exc:  # ValidationError or TypeError
                raise ValueError(
                    f"messages[{i}] is not a valid chat message: {exc}"
                ) from exc
            if parsed.role == "user":
                has_user = True
        if not has_user:
            raise ValueError("messages must include at least one 'user' message.")
        return v


class LLMCallOutput(BaseModel):
    """Output of the LLM-call Node."""

    model_config = ConfigDict(extra="forbid")

    text: str = Field(..., description="Model response text.")
    model: str = Field(..., description="Echo of the model handle that was used.")
    finish_reason: str = Field(
        ...,
        description="One of 'stop' / 'length' / 'content_filter' / etc; "
        "matches the upstream provider's vocabulary.",
    )


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


@NodeRegistry.register
class LLMCallNode(Node[LLMCallInput, LLMCallOutput]):
    """Make a single LLM call. Provider selection is the router's job.

    See module docstring for the full contract (mock mode, budget reporting,
    why provider routing lives in middleware).
    """

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="reasoning.llm.call",
        name="LLM: Call",
        version="0.1.0",
        category=NodeCategory.REASONING,
        description="Single chat-completion call. Honours BTAGENT_MOCK_LLM "
        "(default true). Writes a BudgetUsage to ctx.metadata so the "
        "PromptBudget middleware can enforce the cumulative cap.",
    )
    input_schema: ClassVar[type[BaseModel]] = LLMCallInput
    output_schema: ClassVar[type[BaseModel]] = LLMCallOutput

    async def run(
        self,
        input: LLMCallInput,
        ctx: NodeContext,
    ) -> LLMCallOutput:
        if _mock_mode_enabled():
            output = self._mock_call(input)
        else:
            # The engine deliberately does not call LiteLLM directly. The
            # LLM-router middleware (Sprint 3) wraps this Node and intercepts
            # the call to apply provider selection, TLP gating, and credential
            # resolution. Until that lands, fail loudly so a misconfigured
            # prod env doesn't silently no-op.
            raise NotImplementedError(
                "Live LLM dispatch ships in Sprint 3 LLM-router milestone; "
                "set BTAGENT_MOCK_LLM=true to use the deterministic stub."
            )

        # Always report usage to the budget middleware. We compute the report
        # from the mock output; in production the router middleware will
        # overwrite this with the real provider-reported counts.
        usage = self._estimate_usage(input, output)
        self._record_usage(ctx, usage)
        return output

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _last_user_content(input: LLMCallInput) -> str:
        """Pull the most recent user message's content. The mock echoes this
        so test assertions stay readable."""
        for msg in reversed(input.messages):
            if msg.get("role") == "user":
                return msg.get("content", "")
        # Schema validation guarantees at least one user message; the
        # fallback is defensive.
        return ""

    def _mock_call(self, input: LLMCallInput) -> LLMCallOutput:
        last_user = self._last_user_content(input)
        text = f"{_MOCK_PREFIX} {last_user}".strip()
        return LLMCallOutput(
            text=text,
            model=input.model,
            finish_reason="stop",
        )

    @staticmethod
    def _estimate_usage(input: LLMCallInput, output: LLMCallOutput) -> BudgetUsage:
        """Rough token-count estimate for mock-mode usage reporting.

        Uses ``len(text) // 4`` as a stand-in for real tokenisation -- the
        router knows the right tokenizer per provider; the Node does not.
        Cost is 0.0 in mock mode (we're not billing for fake calls).
        """
        prompt_chars = sum(len(msg.get("content", "")) for msg in input.messages)
        completion_chars = len(output.text)
        return BudgetUsage(
            input_tokens=prompt_chars // _MOCK_TOKEN_DIVISOR,
            output_tokens=completion_chars // _MOCK_TOKEN_DIVISOR,
            cost_usd=0.0,
        )

    @staticmethod
    def _record_usage(ctx: NodeContext, usage: BudgetUsage) -> None:
        """Write *usage* into ``ctx.metadata[USAGE_METADATA_KEY]``.

        If the key already holds a usage report from an earlier call within
        the same context (e.g. a plugin that chains two LLM calls inside one
        node ``run``), the tokens and cost are *summed* rather than the
        existing value being clobbered. This keeps the budget middleware's
        cumulative count accurate.

        Malformed pre-existing values (anything that isn't a dict or a
        ``BudgetUsage``) are overwritten -- the previous content was already
        unreadable, so preserving it would only mask the corruption.
        """
        existing_raw = ctx.metadata.get(USAGE_METADATA_KEY)
        existing: BudgetUsage | None
        if isinstance(existing_raw, BudgetUsage):
            existing = existing_raw
        elif isinstance(existing_raw, dict):
            try:
                existing = BudgetUsage.model_validate(existing_raw)
            except Exception:
                existing = None
        else:
            existing = None

        merged = (
            usage
            if existing is None
            else BudgetUsage(
                input_tokens=existing.input_tokens + usage.input_tokens,
                output_tokens=existing.output_tokens + usage.output_tokens,
                cost_usd=existing.cost_usd + usage.cost_usd,
            )
        )
        # Persist as a dict so JSON-serialised contexts round-trip without
        # needing to know about BudgetUsage on the consumer side.
        ctx.metadata[USAGE_METADATA_KEY] = merged.model_dump()


__all__ = [
    "LLMCallInput",
    "LLMCallNode",
    "LLMCallOutput",
]
