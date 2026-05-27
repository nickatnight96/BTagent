"""Pure hunt-pack logic: manifest loading + noise-baseline classification (#112).

Dependency-free (no pysigma, no DB, no network) so it's trivially testable and
reusable as an engine node body. The Sigma transpile (which *does* need
pysigma) lives in the agents package; everything here operates on already-
loaded :mod:`btagent_shared.types.huntpack` models.
"""

from __future__ import annotations

from typing import Any

from btagent_shared.types.huntpack import (
    HuntPackManifest,
    HuntRule,
    HuntRuleState,
    NoiseProfile,
)

# A rule is "over-firing" when this run's hit count exceeds the rolling mean by
# more than this multiplicative factor (and the mean is meaningfully above
# zero). Kept conservative so a single noisy run doesn't cry wolf.
_OVER_FIRING_FACTOR = 3.0
# Consecutive zero-hit runs before a rule is flagged as a possible stale /
# coverage-gap rule. At a 4-hourly cadence this is ~10 days.
_UNDER_FIRING_RUNS = 60
# EWMA smoothing factor for the rolling mean.
_EWMA_ALPHA = 0.3


def load_pack(data: dict[str, Any]) -> HuntPackManifest:
    """Parse + validate a hunt-pack manifest dict (e.g. from YAML).

    Raises :class:`pydantic.ValidationError` on a malformed manifest — callers
    surface that as a load error. Rule ids must be unique within a pack.
    """
    pack = HuntPackManifest.model_validate(data)
    ids = [r.id for r in pack.rules]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f"Duplicate rule ids in pack {pack.id!r}: {sorted(dupes)}")
    return pack


def update_baseline(profile: NoiseProfile, hit_count: int) -> NoiseProfile:
    """Fold a new hit count into the rolling baseline (returns a new profile).

    First observation seeds the mean directly; subsequent ones use an EWMA so
    the baseline tracks drift without a single spike dominating it.
    """
    if profile.sample_count == 0:
        new_mean = float(hit_count)
    else:
        new_mean = _EWMA_ALPHA * hit_count + (1 - _EWMA_ALPHA) * profile.mean_hits

    return NoiseProfile(
        mean_hits=new_mean,
        sample_count=profile.sample_count + 1,
        last_count=hit_count,
        consecutive_zero_runs=(profile.consecutive_zero_runs + 1 if hit_count == 0 else 0),
    )


def classify_rule_state(profile: NoiseProfile, hit_count: int) -> HuntRuleState:
    """Classify a rule's health from this run's hit count vs. its baseline.

    ``profile`` is the baseline *before* folding in ``hit_count``. With no
    prior samples we can't judge over/under-firing, so any hits are reported
    as firing-as-expected and zero hits as clean.
    """
    if hit_count == 0:
        # Long stretch of silence -> flag as a possible stale / coverage gap.
        if profile.consecutive_zero_runs + 1 >= _UNDER_FIRING_RUNS:
            return HuntRuleState.UNDER_FIRING
        return HuntRuleState.CLEAN

    if profile.sample_count == 0 or profile.mean_hits <= 0:
        return HuntRuleState.FIRING_AS_EXPECTED

    if hit_count > profile.mean_hits * _OVER_FIRING_FACTOR:
        return HuntRuleState.OVER_FIRING

    return HuntRuleState.FIRING_AS_EXPECTED


def select_runnable_rules(
    pack: HuntPackManifest,
) -> list[HuntRule]:
    """Rules with at least one compiled backend query — i.e. runnable.

    Rules that failed to transpile to any backend (empty ``backend_queries``)
    are excluded; the runner marks those ``ERRORED`` separately.
    """
    return [r for r in pack.rules if r.backend_queries]
