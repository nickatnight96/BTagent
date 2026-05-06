"""Prompt-budget middleware -- caps token + dollar spend on reasoning nodes.

Engine-side port of ``agents/btagent_agents/hooks/prompt_budget_hook.py``.

Scope difference from the legacy hook: that one wired into the LangChain
LLM-call event and pulled token counts directly out of the LLM response
metadata. The engine model has no LLM-call event, so the middleware
reads token + cost figures off a small ``BudgetUsage`` shape that
reasoning nodes attach to their output via ``ctx.metadata`` (or, when
the orchestrator provides one, a ``BudgetReporter`` callable).

If the cumulative usage across all reasoning-category node runs exceeds
the configured cap, the middleware raises :class:`PromptBudgetExceeded`
from ``before_run`` of the *next* node -- giving a deterministic stop
point that doesn't depend on which node tipped the scale.

Edge case worth flagging: the middleware does not retroactively cancel
the run that exceeded the cap. The expected pattern is that reasoning
nodes hold their own per-call cap (so a single LLM call can't consume
the whole budget), and this middleware enforces the cumulative cap
across calls.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel as _BaseModel
from pydantic import ConfigDict, Field

from btagent_engine.middleware.base import Middleware
from btagent_engine.node import NodeCategory

if TYPE_CHECKING:
    from pydantic import BaseModel

    from btagent_engine.node import Node, NodeContext


# Key under which a reasoning node may stash its post-run usage in
# ``ctx.metadata``. Stable; renaming this is a breaking change for plugins.
USAGE_METADATA_KEY: str = "btagent.budget.usage"


class BudgetUsage(_BaseModel):
    """Token + cost report for a single reasoning step."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    cost_usd: float = Field(default=0.0, ge=0.0)


class PromptBudgetExceeded(Exception):
    """Raised when cumulative token or dollar spend has hit the configured cap."""

    def __init__(
        self,
        used_tokens: int,
        max_tokens: int,
        used_cost_usd: float,
        max_cost_usd: float,
        breached: str,
    ) -> None:
        self.used_tokens = used_tokens
        self.max_tokens = max_tokens
        self.used_cost_usd = used_cost_usd
        self.max_cost_usd = max_cost_usd
        # Which cap tripped: ``"tokens"`` or ``"cost"``. Useful for the
        # orchestrator's escalation message.
        self.breached = breached
        super().__init__(
            f"Prompt budget exceeded ({breached}): "
            f"tokens {used_tokens:,}/{max_tokens:,}, "
            f"cost ${used_cost_usd:.4f}/${max_cost_usd:.4f}"
        )


class PromptBudgetMiddleware(Middleware):
    """Tracks reasoning-node spend; refuses further reasoning past the cap.

    State is kept on the instance (``_total_tokens``, ``_total_cost_usd``)
    so the orchestrator should construct one per workflow-run, not once
    per process.
    """

    name = "prompt_budget"

    def __init__(self, max_tokens: int = 80_000, max_cost_usd: float = 5.0) -> None:
        self._max_tokens = max_tokens
        self._max_cost_usd = max_cost_usd
        self._total_tokens: int = 0
        self._total_cost_usd: float = 0.0

    @property
    def total_tokens(self) -> int:
        return self._total_tokens

    @property
    def total_cost_usd(self) -> float:
        return self._total_cost_usd

    async def before_run(
        self,
        node: Node,
        input: BaseModel,
        ctx: NodeContext,
    ) -> None:
        # The cap only applies to reasoning-category nodes -- triggers,
        # data transforms, and integrations don't burn LLM tokens.
        if node.meta.category != NodeCategory.REASONING:
            return
        if self._total_tokens >= self._max_tokens:
            raise PromptBudgetExceeded(
                used_tokens=self._total_tokens,
                max_tokens=self._max_tokens,
                used_cost_usd=self._total_cost_usd,
                max_cost_usd=self._max_cost_usd,
                breached="tokens",
            )
        if self._total_cost_usd >= self._max_cost_usd:
            raise PromptBudgetExceeded(
                used_tokens=self._total_tokens,
                max_tokens=self._max_tokens,
                used_cost_usd=self._total_cost_usd,
                max_cost_usd=self._max_cost_usd,
                breached="cost",
            )

    async def after_run(
        self,
        node: Node,
        input: BaseModel,
        output: BaseModel,
        ctx: NodeContext,
    ) -> None:
        if node.meta.category != NodeCategory.REASONING:
            return
        usage = self._extract_usage(ctx)
        if usage is None:
            return
        self._total_tokens += usage.input_tokens + usage.output_tokens
        self._total_cost_usd += usage.cost_usd

    @staticmethod
    def _extract_usage(ctx: NodeContext) -> BudgetUsage | None:
        """Pull a :class:`BudgetUsage` out of ``ctx.metadata`` if present.

        Accepts either an already-typed instance or a plain dict (which is
        the more common shape coming off a JSON-deserialised context).
        Returns ``None`` if the key is absent or the value is malformed --
        a missing usage report should not trip the cap, only a real one.
        """
        raw = ctx.metadata.get(USAGE_METADATA_KEY)
        if raw is None:
            return None
        if isinstance(raw, BudgetUsage):
            return raw
        if isinstance(raw, dict):
            try:
                return BudgetUsage.model_validate(raw)
            except Exception:
                return None
        return None


__all__ = [
    "BudgetUsage",
    "PromptBudgetExceeded",
    "PromptBudgetMiddleware",
    "USAGE_METADATA_KEY",
]
