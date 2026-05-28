"""Unit tests for the dependency-free Behavioral Hunter logic (#114).

Pins the cosine + frequency-floor outlier-scoring rules and the rolling
centroid / bounded-frequency-map updates — all without a DB, embedding
service, or LLM.
"""

from datetime import UTC, datetime, timedelta

import pytest
from btagent_shared.hunt import behavioral
from btagent_shared.types.behavioral import (
    BehavioralProfile,
    ProfileType,
)


def _profile(
    *,
    centroid: list[float] | None = None,
    freq_map: dict[str, int] | None = None,
    sample_size: int = 0,
    window_end: datetime | None = None,
) -> BehavioralProfile:
    now = window_end or datetime.now(UTC)
    return BehavioralProfile(
        id="bprof_t",
        org_id="org_default",
        entity_id="bent_t",
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        centroid=centroid,
        frequency_map=freq_map or {},
        pattern_count=len(freq_map or {}),
        sample_size=sample_size,
        window_start=now - timedelta(days=30),
        window_end=now,
        computed_at=now,
        updated_at=now,
    )


# --- cosine_distance ---


def test_cosine_distance_identical_is_zero():
    assert behavioral.cosine_distance([1.0, 0.0], [1.0, 0.0]) == pytest.approx(0.0)


def test_cosine_distance_orthogonal_is_one():
    assert behavioral.cosine_distance([1.0, 0.0], [0.0, 1.0]) == pytest.approx(1.0)


def test_cosine_distance_opposite_is_two():
    assert behavioral.cosine_distance([1.0, 0.0], [-1.0, 0.0]) == pytest.approx(2.0)


def test_cosine_distance_zero_vector_returns_worst_case():
    # Defensive guard: zero-magnitude input doesn't fake "perfect similarity".
    assert behavioral.cosine_distance([0.0, 0.0], [1.0, 0.0]) == pytest.approx(1.0)


def test_cosine_distance_length_mismatch_raises():
    with pytest.raises(ValueError, match="length mismatch"):
        behavioral.cosine_distance([1.0, 0.0], [1.0, 0.0, 0.0])


# --- frequency_rank ---


def test_frequency_rank_orders_by_count_then_key():
    fm = {"a": 5, "b": 5, "c": 1}
    # tie between a/b broken lexicographically -> a is rank 1, b is rank 2
    assert behavioral.frequency_rank(fm, "a") == 1
    assert behavioral.frequency_rank(fm, "b") == 2
    assert behavioral.frequency_rank(fm, "c") == 3
    assert behavioral.frequency_rank(fm, "missing") == 0


# --- score_outlier ---


def test_score_outlier_flags_distant_and_rare():
    p = _profile(centroid=[1.0, 0.0], freq_map={"common": 10})
    is_outlier, distance, rank = behavioral.score_outlier(p, [0.0, 1.0], "rare_pattern")
    assert is_outlier is True
    assert distance == pytest.approx(1.0)
    assert rank == 0


def test_score_outlier_not_flagged_when_near_centroid():
    p = _profile(centroid=[1.0, 0.0], freq_map={"common": 10})
    # near-identical vector, even with a rare pattern, isn't anomalous
    is_outlier, distance, rank = behavioral.score_outlier(p, [0.99, 0.01], "rare_pattern")
    assert is_outlier is False
    assert distance < 0.05


def test_score_outlier_not_flagged_when_pattern_is_common():
    p = _profile(centroid=[1.0, 0.0], freq_map={"common_pwsh": 100})
    # distance is high, but the pattern is the most-common for this entity
    # -> within behavioral bounds (e.g. power user)
    is_outlier, distance, rank = behavioral.score_outlier(
        p, [0.0, 1.0], "common_pwsh", frequency_floor=1
    )
    assert is_outlier is False
    assert distance == pytest.approx(1.0)
    assert rank == 1


def test_score_outlier_no_centroid_treats_as_far():
    p = _profile(centroid=None, freq_map={})
    is_outlier, distance, rank = behavioral.score_outlier(p, [1.0, 0.0], "x")
    assert distance == pytest.approx(1.0)
    assert is_outlier is True


def test_score_outlier_no_event_vector_treats_as_far():
    p = _profile(centroid=[1.0, 0.0], freq_map={})
    is_outlier, distance, _ = behavioral.score_outlier(p, None, "x")
    assert distance == pytest.approx(1.0)
    assert is_outlier is True


# --- update_centroid ---


def test_update_centroid_seeds_on_first_sample():
    c = behavioral.update_centroid(None, [1.0, 2.0, 3.0], sample_size=0)
    assert c == [1.0, 2.0, 3.0]


def test_update_centroid_running_mean():
    # Start with sample of 1 at [0,0]; add [10,10] as 2nd sample -> mean [5,5]
    c = behavioral.update_centroid([0.0, 0.0], [10.0, 10.0], sample_size=1)
    assert c == pytest.approx([5.0, 5.0])


def test_update_centroid_length_mismatch_raises():
    with pytest.raises(ValueError, match="length mismatch"):
        behavioral.update_centroid([0.0, 0.0], [1.0], sample_size=1)


# --- update_frequency_map ---


def test_update_frequency_map_increments_existing():
    fm = behavioral.update_frequency_map({"a": 3}, "a")
    assert fm == {"a": 4}


def test_update_frequency_map_adds_new_key():
    fm = behavioral.update_frequency_map({"a": 3}, "b")
    assert fm == {"a": 3, "b": 1}


def test_update_frequency_map_evicts_least_frequent_when_capped():
    capped = behavioral.update_frequency_map(
        {"hot": 100, "warm": 5, "cold": 1}, "new", max_entries=3
    )
    # "cold" (count 1) is evicted to make room
    assert "cold" not in capped
    assert capped == {"hot": 100, "warm": 5, "new": 1}


def test_update_frequency_map_does_not_mutate_input():
    original = {"a": 1}
    behavioral.update_frequency_map(original, "b")
    assert original == {"a": 1}


# --- aggregate_pattern_keys ---


def test_aggregate_pattern_keys():
    counts = behavioral.aggregate_pattern_keys(["a", "b", "a", "a", "c"])
    assert counts == {"a": 3, "b": 1, "c": 1}


# --- is_baseline_stale ---


def test_is_baseline_stale_when_window_end_is_old():
    now = datetime.now(UTC)
    p = _profile(window_end=now - timedelta(days=45))
    assert behavioral.is_baseline_stale(p, now=now, stale_after=timedelta(days=30))


def test_is_baseline_stale_false_when_recent():
    now = datetime.now(UTC)
    p = _profile(window_end=now - timedelta(days=5))
    assert not behavioral.is_baseline_stale(p, now=now, stale_after=timedelta(days=30))


# --- topk_patterns ---


def test_topk_patterns_orders_correctly():
    top = behavioral.topk_patterns({"a": 5, "b": 5, "c": 10, "d": 1}, k=3)
    assert top == [("c", 10), ("a", 5), ("b", 5)]
