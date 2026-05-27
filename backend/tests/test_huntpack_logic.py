"""Unit tests for the dependency-free hunt-pack logic (#112).

Covers manifest loading/validation and the noise-baseline classification that
the Hunt Pack Runner uses to mark rules clean / firing / over- / under-firing.
"""

import pytest
from btagent_shared.hunt import huntpack
from btagent_shared.types.huntpack import (
    HuntPackManifest,
    HuntRuleState,
    NoiseProfile,
    SiemBackend,
)
from pydantic import ValidationError

_MIN_RULE = {
    "id": "rule_1",
    "title": "Encoded PowerShell",
    "sigma_yaml": "title: x\ndetection:\n  sel: {Image: powershell.exe}\n  condition: sel",
    "mitre_techniques": ["T1059.001"],
    "severity": "high",
}


def _pack(**overrides) -> dict:
    data = {
        "id": "sigmahq-windows",
        "version": "1.0.0",
        "source": "sigmahq",
        "rules": [dict(_MIN_RULE)],
    }
    data.update(overrides)
    return data


def test_load_pack_ok():
    pack = huntpack.load_pack(_pack())
    assert isinstance(pack, HuntPackManifest)
    assert pack.rules[0].mitre_techniques == ["T1059.001"]


def test_load_pack_rejects_duplicate_rule_ids():
    two = _pack(rules=[dict(_MIN_RULE), dict(_MIN_RULE)])
    with pytest.raises(ValueError, match="Duplicate rule ids"):
        huntpack.load_pack(two)


def test_load_pack_rejects_bad_source():
    with pytest.raises(ValidationError):
        huntpack.load_pack(_pack(source="not-a-source"))


def test_update_baseline_seeds_then_ewmas():
    p0 = NoiseProfile()
    p1 = huntpack.update_baseline(p0, 10)
    assert p1.sample_count == 1
    assert p1.mean_hits == 10.0
    assert p1.last_count == 10

    p2 = huntpack.update_baseline(p1, 20)
    # EWMA: 0.3*20 + 0.7*10 = 13.0
    assert p2.mean_hits == pytest.approx(13.0)
    assert p2.consecutive_zero_runs == 0


def test_update_baseline_counts_consecutive_zeros():
    p = NoiseProfile(mean_hits=5.0, sample_count=3)
    p = huntpack.update_baseline(p, 0)
    assert p.consecutive_zero_runs == 1
    p = huntpack.update_baseline(p, 0)
    assert p.consecutive_zero_runs == 2
    p = huntpack.update_baseline(p, 4)
    assert p.consecutive_zero_runs == 0


def test_classify_clean_when_zero_and_not_stale():
    assert (
        huntpack.classify_rule_state(NoiseProfile(sample_count=5, mean_hits=2.0), 0)
        == HuntRuleState.CLEAN
    )


def test_classify_under_firing_after_long_silence():
    p = NoiseProfile(sample_count=100, mean_hits=1.0, consecutive_zero_runs=59)
    assert huntpack.classify_rule_state(p, 0) == HuntRuleState.UNDER_FIRING


def test_classify_first_hits_are_expected():
    assert huntpack.classify_rule_state(NoiseProfile(), 7) == HuntRuleState.FIRING_AS_EXPECTED


def test_classify_over_firing_above_threshold():
    p = NoiseProfile(sample_count=10, mean_hits=5.0)
    # 5 * 3 = 15 threshold; 20 > 15 -> over firing
    assert huntpack.classify_rule_state(p, 20) == HuntRuleState.OVER_FIRING
    # 12 < 15 -> still expected
    assert huntpack.classify_rule_state(p, 12) == HuntRuleState.FIRING_AS_EXPECTED


def test_select_runnable_rules_filters_uncompiled():
    pack = huntpack.load_pack(_pack())
    # no backend_queries populated yet -> not runnable
    assert huntpack.select_runnable_rules(pack) == []

    pack.rules[0].backend_queries = {SiemBackend.SPLUNK: "index=* powershell.exe"}
    runnable = huntpack.select_runnable_rules(pack)
    assert len(runnable) == 1
