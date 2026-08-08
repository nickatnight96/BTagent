"""The router's TLP table and pricing table must not drift from their peers.

Two drift bugs are pinned here, both instances of the same failure shape — a
policy or catalog duplicated in two places, one copy updated, the other left
behind:

1. **Router vs classification hook.** ``TLPAwareLLMRouter.TLP_ROUTING`` (which
   provider gets *picked*) and ``classification_hook.TLP_ALLOWED_PROVIDERS``
   (which provider is *permitted*) encode the same TLP policy. The hook's
   AMBER rung was fixed to include Ollama (``test_tlp_provider_ladder.py``);
   the router's copy still omitted it. Consequences of the divergence:
   under ``local_only`` every TLP:AMBER request was refused while stricter
   RED/AMBER_STRICT routed fine, and — without ``local_only`` — a
   ``ModelTier.LOCAL`` request at AMBER fell through the tier-fallback branch
   to a *cloud* STANDARD model.

2. **Router vs pricing table.** ``MODEL_TIERS`` routes ``claude-sonnet-4-6``,
   ``claude-opus-4-7`` and ``gpt-5``; ``cost_calculator.PRICING`` only knew
   the older IDs, and the partial matcher does not bridge them ("claude-opus-
   4-7" neither contains nor is contained in "claude-opus-4-20250415"). Every
   premium call silently billed at the 3/15 default — Opus-class output cost
   under-reported ~5x in the analyst-facing cost events.
"""

from __future__ import annotations

import pytest
from btagent_shared.types.config import TLP, ModelTier

from btagent_agents.hooks.classification_hook import TLP_ALLOWED_PROVIDERS
from btagent_agents.llm.cost_calculator import (
    _DEFAULT_PRICING,
    PRICING,
    calculate_cost,
    get_pricing,
)
from btagent_agents.llm.router import TLPAwareLLMRouter

# Strictest first — mirrors _LADDER in test_tlp_provider_ladder.py.
_LADDER: tuple[TLP, ...] = (TLP.RED, TLP.AMBER_STRICT, TLP.AMBER, TLP.GREEN, TLP.WHITE)


# --------------------------------------------------------------------------- #
# Router table vs classification-hook ladder
# --------------------------------------------------------------------------- #


def test_router_and_hook_agree_on_the_tlp_policy():
    """One policy, two consumers — the copies must be identical.

    The hook validates a provider, the router picks one. If the router
    permits a provider the hook forbids, a call is dispatched and then
    refused at the boundary; if the hook permits one the router omits, the
    capability exists and cannot be reached (the AMBER/Ollama hole). Either
    direction of drift is a bug, so this is equality, not subset.
    """
    for level in TLP:
        router_set = set(TLPAwareLLMRouter.TLP_ROUTING.get(level, []))
        hook_set = set(TLP_ALLOWED_PROVIDERS.get(level, frozenset()))
        assert router_set == hook_set, (
            f"TLP:{level.value}: router routes {sorted(router_set)} but the "
            f"classification hook permits {sorted(hook_set)}. These are two "
            "copies of one policy — change them together."
        )


@pytest.mark.parametrize(
    ("stricter", "looser"),
    list(zip(_LADDER, _LADDER[1:], strict=False)),
    ids=lambda level: level.value if isinstance(level, TLP) else str(level),
)
def test_router_ladder_only_widens_as_classification_relaxes(stricter: TLP, looser: TLP):
    """A provider trusted with more-sensitive data stays trusted with less."""
    lost = sorted(
        set(TLPAwareLLMRouter.TLP_ROUTING[stricter]) - set(TLPAwareLLMRouter.TLP_ROUTING[looser])
    )
    assert not lost, (
        f"{looser.value} forbids providers the stricter {stricter.value} allows: {lost}"
    )


def test_local_only_has_no_dead_zone():
    """Every TLP level x tier resolves under local_only.

    This is the operator-visible consequence the AMBER hole produced: an
    air-gapped deployment could run TLP:RED work but had TLP:AMBER refused.
    Local inference is admissible at every level, so no (level, tier) may
    raise.
    """
    router = TLPAwareLLMRouter(local_only=True)
    for level in TLP:
        for tier in ModelTier:
            provider, model_id = router.resolve(level, tier)
            assert provider == "ollama", (provider, level, tier)
            assert model_id


def test_local_tier_never_falls_back_to_a_hosted_model():
    """The tier-fallback branch must stay inside the local set for LOCAL.

    Before the AMBER fix, ``resolve(TLP.AMBER, ModelTier.LOCAL)`` (no
    local_only) found no LOCAL-tier model among [anthropic, bedrock,
    vertex_ai] and fell back to STANDARD on Anthropic — a request that named
    the local tier was silently dispatched to the cloud.
    """
    for level in TLP:
        provider, _ = TLPAwareLLMRouter().resolve(level, ModelTier.LOCAL)
        assert provider == "ollama", (
            f"TLP:{level.value}: ModelTier.LOCAL resolved to {provider!r} — a "
            "local-tier request must never dispatch to a hosted provider"
        )


# --------------------------------------------------------------------------- #
# Router model catalog vs pricing table
# --------------------------------------------------------------------------- #


def test_every_routed_model_has_an_exact_pricing_entry():
    """No routed model may bill via partial match or the silent default.

    Partial matching is a heuristic for models *outside* the router's
    catalog; everything the router can actually pick must be priced
    deliberately. The default fallback (3/15) under-reports Opus-class
    output ~5x, which corrupts the per-investigation cost events analysts
    see.
    """
    missing = sorted(
        {
            model_id
            for tier_models in TLPAwareLLMRouter.MODEL_TIERS.values()
            for model_id in tier_models.values()
            if model_id not in PRICING
        }
    )
    assert not missing, (
        f"Models the router routes but PRICING has no exact entry for: {missing}. "
        "Add entries to cost_calculator.PRICING — get_pricing's partial match / "
        "default fallback silently misprices them."
    )


def test_premium_models_do_not_price_at_the_default():
    """The canary for the exact bug: opus-class output is not 15/M."""
    assert get_pricing("claude-opus-4-7") is not _DEFAULT_PRICING
    assert calculate_cost("claude-opus-4-7", 0, 1_000_000) == 25.0
    assert calculate_cost("bedrock/claude-opus-4-7", 0, 1_000_000) == 25.0
    # gpt-5 happens to share the default's output rate; pin it via identity,
    # not value, so a deliberate entry is still distinguishable.
    assert get_pricing("gpt-5") is not _DEFAULT_PRICING


def test_local_models_stay_free():
    """Guard the guard: the pricing sweep must not invent cost for Ollama."""
    for model_id in TLPAwareLLMRouter.MODEL_TIERS[ModelTier.LOCAL].values():
        pricing = get_pricing(model_id)
        assert pricing.input_per_m == 0.0 and pricing.output_per_m == 0.0
