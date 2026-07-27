"""Per-entity cost gate for the Behavioral Hunter intent classifier (#114 Phase A).

The IntentClassifier (:mod:`behavioral_intent_service`) spends real model
tokens per outlier — a cheap Haiku screen plus, for non-benign screens, a
Sonnet confirming pass. Without a guard, a noisy entity that produces a burst
of outliers could quietly run up unbounded per-entity LLM cost. This module is
the PromptBudget/TokenBudget hook that caps it: a per-entity dollar ceiling
(default **<$0.10/entity**) enforced by wrapping the injected ``LLMCallable``.

Mirrors the engine's :class:`PromptBudgetMiddleware` in spirit — accumulate
token→cost per unit of work and refuse further spend past the cap — but the
unit here is the *entity*, not a workflow run, and the seam is the classifier's
injectable ``llm`` callable (which returns raw text, so cost is estimated from a
char→token heuristic + a per-tier price table rather than read off a response).

The gate refuses to START a new model call once the entity has reached its cap.
Each classification pass is itself bounded (the intent service caps
``max_tokens`` per call and makes at most two calls), so a per-entity pass costs
well under a cent — the cap exists to stop *runaway repetition*, not to shave a
single pass. Refused calls raise :class:`BehavioralCostBudgetExceeded`, which
the classifier's own screen/promote error-handling degrades to "skip / keep
screen verdict" — so an over-budget entity simply stops being (re)classified
rather than crashing the ingest loop.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

from btagent_backend.services import behavioral_intent_service as intent_svc
from btagent_backend.services.behavioral_intent_service import LLMCallable

if TYPE_CHECKING:
    from btagent_backend.db.models_behavioral import BehavioralOutlierRow

logger = logging.getLogger("btagent.services.behavioral_cost_gate")

# Default per-entity ceiling. The acceptance target is < $0.10 / entity.
DEFAULT_MAX_COST_USD = 0.10

# char→token heuristic (Anthropic English average ~3.7 chars/token), matching
# ``agents.context.budget``. Approximate on purpose — good enough for a budget
# decision without pulling a tokenizer into the backend.
_CHARS_PER_TOKEN = 3.7


@dataclass(frozen=True)
class _TierPrice:
    """USD-per-million-token input/output pricing for one capability tier."""

    input_per_m: float
    output_per_m: float


# The classifier maps its FAST screen → Haiku and STANDARD promote → Sonnet
# (see ``behavioral_intent_service._TIER_SCREEN`` / ``_TIER_PROMOTE``). Prices
# per 1M tokens, aligned with ``agents.llm.cost_calculator.PRICING``.
_PRICE_BY_TIER: dict[str, _TierPrice] = {
    intent_svc._TIER_SCREEN: _TierPrice(input_per_m=0.80, output_per_m=4.00),  # Haiku
    intent_svc._TIER_PROMOTE: _TierPrice(input_per_m=3.00, output_per_m=15.00),  # Sonnet
}
_DEFAULT_PRICE = _PRICE_BY_TIER[intent_svc._TIER_PROMOTE]


def _estimate_tokens(text: str) -> int:
    if not text:
        return 0
    return max(1, int(len(text) / _CHARS_PER_TOKEN))


def _price_for(tier: str) -> _TierPrice:
    return _PRICE_BY_TIER.get(tier, _DEFAULT_PRICE)


def estimate_call_cost(tier: str, system: str, user: str, output: str) -> float:
    """Estimate the USD cost of one screen/promote model call.

    Input side is ``system + user``; output side is the raw completion. Uses the
    per-tier price table + char→token heuristic. Exposed so callers/tests can
    reason about the cap without reaching into the gate's internals.
    """
    price = _price_for(tier)
    input_tokens = _estimate_tokens(system) + _estimate_tokens(user)
    output_tokens = _estimate_tokens(output)
    return (
        input_tokens / 1_000_000 * price.input_per_m
        + output_tokens / 1_000_000 * price.output_per_m
    )


class BehavioralCostBudgetExceeded(Exception):
    """Raised when an entity has reached its per-entity classification cost cap."""

    def __init__(self, entity_key: str, spent_usd: float, max_cost_usd: float) -> None:
        self.entity_key = entity_key
        self.spent_usd = spent_usd
        self.max_cost_usd = max_cost_usd
        super().__init__(
            f"Behavioral classification budget exceeded for {entity_key!r}: "
            f"spent ${spent_usd:.4f} / cap ${max_cost_usd:.4f}"
        )


class EntityClassificationBudget:
    """Tracks per-entity classification spend and refuses calls past the cap.

    One instance can span a whole ingest sweep (spend accumulates across every
    entity it sees). Keep it per-sweep, not per-process, so an entity's ceiling
    resets between sweeps. State is a plain dict — single-threaded async, no
    locking needed.
    """

    def __init__(self, max_cost_usd: float = DEFAULT_MAX_COST_USD) -> None:
        self._max_cost_usd = max_cost_usd
        self._spent: dict[str, float] = {}

    @property
    def max_cost_usd(self) -> float:
        return self._max_cost_usd

    def spent(self, entity_key: str) -> float:
        """USD spent classifying ``entity_key`` so far this sweep."""
        return self._spent.get(entity_key, 0.0)

    def remaining(self, entity_key: str) -> float:
        return max(0.0, self._max_cost_usd - self.spent(entity_key))

    def over_budget(self, entity_key: str) -> bool:
        return self.spent(entity_key) >= self._max_cost_usd

    def charge(self, entity_key: str, cost_usd: float) -> float:
        """Attribute ``cost_usd`` to ``entity_key`` and return the new total.

        Public so callers can seed the ledger from persisted per-entity spend
        (rehydrating across sweeps) — the guard uses it internally too.
        """
        total = self._spent.get(entity_key, 0.0) + max(0.0, cost_usd)
        self._spent[entity_key] = total
        return total

    def guard(self, entity_key: str, inner: LLMCallable) -> LLMCallable:
        """Wrap an ``LLMCallable`` so every call is metered against ``entity_key``.

        Before each call, if the entity has already reached its cap, raise
        :class:`BehavioralCostBudgetExceeded` (no model call is made). Otherwise
        run the inner call, estimate its cost, and add it to the entity's tally.
        """

        async def _guarded(system: str, user: str, tier: str) -> str:
            if self.over_budget(entity_key):
                raise BehavioralCostBudgetExceeded(
                    entity_key, self.spent(entity_key), self._max_cost_usd
                )
            raw = await inner(system, user, tier)
            cost = estimate_call_cost(tier, system, user, raw or "")
            self.charge(entity_key, cost)
            logger.debug(
                "classification spend for %s: +$%.5f (total $%.5f / cap $%.4f)",
                entity_key,
                cost,
                self.spent(entity_key),
                self._max_cost_usd,
            )
            return raw

        return _guarded


def entity_key_for(kind: str, canonical_id: str) -> str:
    """Stable per-entity budget key (``kind:canonical_id``)."""
    return f"{kind}:{canonical_id}"


async def classify_outlier_within_budget(
    db,
    *,
    outlier_id: str,
    budget: EntityClassificationBudget,
    llm: LLMCallable | None = None,
    entity_key: str | None = None,
) -> BehavioralOutlierRow | None:
    """Classify an outlier under the per-entity cost gate.

    Resolves the outlier's entity to a budget key, wraps the LLM callable with
    :meth:`EntityClassificationBudget.guard`, and delegates to
    :func:`behavioral_intent_service.classify_outlier`. When the entity is over
    budget, the guarded call raises inside the classifier's own error-handling,
    which degrades to skipping the (further) classification — so this returns
    ``None`` (or, if only the promote pass was blocked, the screen verdict).
    Does NOT commit.
    """
    from btagent_backend.db.models_behavioral import (
        BehavioralEntityRow,
        BehavioralOutlierRow,
    )

    outlier = await db.get(BehavioralOutlierRow, outlier_id)
    if outlier is None:
        raise ValueError(f"Behavioral outlier not found: {outlier_id}")

    if entity_key is None:
        entity = await db.get(BehavioralEntityRow, outlier.entity_id)
        entity_key = (
            entity_key_for(entity.kind, entity.canonical_id)
            if entity is not None
            else outlier.entity_id
        )

    inner = llm if llm is not None else intent_svc._engine_llm_callable()
    if inner is None:
        # No model available — nothing to meter; let the classifier no-op.
        return await intent_svc.classify_outlier(db, outlier_id=outlier_id, llm=None)

    guarded = budget.guard(entity_key, inner)
    return await intent_svc.classify_outlier(db, outlier_id=outlier_id, llm=guarded)


__all__ = [
    "DEFAULT_MAX_COST_USD",
    "BehavioralCostBudgetExceeded",
    "EntityClassificationBudget",
    "classify_outlier_within_budget",
    "entity_key_for",
    "estimate_call_cost",
]
