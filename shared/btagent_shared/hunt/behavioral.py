"""Pure outlier-scoring logic for the Behavioral Hunter (#114).

Dependency-free (no DB, no embedding service, no LLM) so the scoring is
trivially unit-testable and reusable as an engine node body. Operates on
:mod:`btagent_shared.types.behavioral` models plus raw vectors / pattern
keys; persistence + telemetry ingestion live in
``backend/btagent_backend/services/behavioral_service.py``.
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from datetime import datetime, timedelta

from btagent_shared.types.behavioral import BehavioralProfile

# Defaults — tunable per-call but chosen for the common cmdline-embedding
# profile where cosine distances cluster low among Living-off-the-Land
# benign noise.
_DEFAULT_DISTANCE_THRESHOLD = 0.35
_DEFAULT_FREQUENCY_FLOOR = 1
# Top-K frequency-map cap — keeps the JSONB column bounded as entities rack
# up patterns over months.
_DEFAULT_FREQUENCY_MAP_MAX = 256


def cosine_distance(a: list[float], b: list[float]) -> float:
    """Cosine distance (1 − cosine similarity), in ``[0, 2]``.

    Defensive: a zero-magnitude input returns the worst-case distance ``1.0``
    so a malformed embedding can't masquerade as "perfectly similar."
    """
    if len(a) != len(b):
        raise ValueError(f"vector length mismatch: {len(a)} vs {len(b)}")
    if not a:
        return 1.0
    dot = 0.0
    na = 0.0
    nb = 0.0
    for x, y in zip(a, b, strict=True):
        dot += x * y
        na += x * x
        nb += y * y
    if na == 0.0 or nb == 0.0:
        return 1.0
    return 1.0 - dot / (math.sqrt(na) * math.sqrt(nb))


def frequency_rank(freq_map: dict[str, int], pattern_key: str) -> int:
    """1-indexed rank of ``pattern_key`` in ``freq_map`` (0 if absent).

    Ties broken by lexicographic key order — deterministic. Used by the
    outlier scorer to compare against a "frequency floor" (i.e. is this
    pattern in the top-N most common for the entity?).
    """
    if pattern_key not in freq_map:
        return 0
    ranked = sorted(freq_map.items(), key=lambda kv: (-kv[1], kv[0]))
    for i, (k, _v) in enumerate(ranked, start=1):
        if k == pattern_key:
            return i
    return 0


def score_outlier(
    profile: BehavioralProfile,
    event_vector: list[float] | None,
    event_pattern_key: str | None,
    *,
    distance_threshold: float = _DEFAULT_DISTANCE_THRESHOLD,
    frequency_floor: int = _DEFAULT_FREQUENCY_FLOOR,
) -> tuple[bool, float, int]:
    """Score a single event against an entity's baseline profile.

    Returns ``(is_outlier, distance, rank)``:

    * ``distance`` — cosine distance vs. the profile's centroid, or ``1.0``
      if no centroid is set / no event vector given (treated as "far").
    * ``rank`` — 1-indexed position of ``event_pattern_key`` in the
      frequency map (``0`` = absent).
    * ``is_outlier`` — true when the event is **both** far from the centroid
      *and* not in the top ``frequency_floor`` most-common patterns. The
      "and" is deliberate: a high-distance event that's nonetheless a common
      pattern for this entity isn't anomalous (e.g. a power user's diverse
      but-normal toolkit), and a rare-pattern event that lies near the
      centroid is similarly within behavioral bounds.

    A new entity with no samples / no centroid is treated as having no
    baseline — every event is an outlier until enough samples accumulate
    (callers can gate this via ``profile.sample_size``).
    """
    if profile.centroid and event_vector:
        distance = cosine_distance(event_vector, profile.centroid)
    else:
        distance = 1.0

    rank = frequency_rank(profile.frequency_map, event_pattern_key or "")

    is_distant = distance >= distance_threshold
    is_rare = rank == 0 or rank > frequency_floor

    return (is_distant and is_rare), distance, rank


def update_centroid(
    centroid: list[float] | None,
    new_vector: list[float],
    *,
    sample_size: int,
) -> list[float]:
    """Fold a new vector into the rolling centroid.

    First sample seeds the centroid directly; subsequent samples use a
    cumulative running-mean update (numerically stable, no EWMA drift):
    ``new_centroid = old + (new − old) / (n + 1)``.
    """
    if centroid is None or sample_size <= 0:
        return list(new_vector)
    if len(new_vector) != len(centroid):
        raise ValueError(f"vector length mismatch: {len(new_vector)} vs centroid {len(centroid)}")
    n = sample_size
    return [old + (new - old) / (n + 1) for old, new in zip(centroid, new_vector, strict=True)]


def update_frequency_map(
    freq_map: dict[str, int],
    pattern_key: str,
    *,
    increment: int = 1,
    max_entries: int = _DEFAULT_FREQUENCY_MAP_MAX,
) -> dict[str, int]:
    """Increment a pattern's count, keeping the map bounded at ``max_entries``.

    When the cap is reached and we're adding a *new* key, the least-frequent
    entry is evicted (ties broken by lexicographic order — deterministic).
    Returns a new dict; doesn't mutate the input.
    """
    new = dict(freq_map)
    if pattern_key in new:
        new[pattern_key] += increment
        return new

    if len(new) >= max_entries:
        # Evict the least-frequent (tie: lex-last).
        victim = min(new.items(), key=lambda kv: (kv[1], kv[0]))[0]
        del new[victim]

    new[pattern_key] = increment
    return new


def topk_patterns(freq_map: dict[str, int], k: int = 10) -> list[tuple[str, int]]:
    """Top-K most common patterns in the map (for UI / debugging)."""
    return sorted(freq_map.items(), key=lambda kv: (-kv[1], kv[0]))[:k]


def is_baseline_stale(
    profile: BehavioralProfile,
    *,
    now: datetime,
    stale_after: timedelta = timedelta(days=30),
) -> bool:
    """Has the entity not been observed long enough to flag for archival?

    Per the design: entities unseen for ≥ ``stale_after`` are candidates
    for archival so the active baseline pool doesn't accumulate noise from
    departed users / decommissioned hosts.
    """
    return now - profile.window_end >= stale_after


def aggregate_pattern_keys(keys: Iterable[str]) -> dict[str, int]:
    """Count occurrences of each pattern key in a batch — used by baseline build."""
    counts: dict[str, int] = {}
    for k in keys:
        counts[k] = counts.get(k, 0) + 1
    return counts
