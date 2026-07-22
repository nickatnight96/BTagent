"""Unit tests for the dependency-free hunt triage logic (#119).

These exercise :mod:`btagent_shared.hunt.triage` in isolation — no DB, no
client — so the clustering + suppression decisions are pinned independently
of the service/API shell.
"""

from datetime import UTC, datetime

import pytest
from btagent_shared.hunt import triage
from btagent_shared.types.enums import Severity
from btagent_shared.types.hunt import HuntDomain, HuntSource
from btagent_shared.types.hunt_finding import (
    HuntEntity,
    HuntFinding,
    HuntObservable,
    SuppressionMatch,
)


def _finding(
    *,
    fid: str = "hfnd_x",
    domain: HuntDomain = HuntDomain.SIGMA,
    source: HuntSource = HuntSource.HUNT_PACK,
    severity: Severity = Severity.MEDIUM,
    technique_ids: list[str] | None = None,
    entities: list[HuntEntity] | None = None,
    observables: list[HuntObservable] | None = None,
    evidence: dict | None = None,
) -> HuntFinding:
    now = datetime.now(UTC)
    return HuntFinding(
        id=fid,
        org_id="org_default",
        source=source,
        domain=domain,
        title="t",
        severity=severity,
        technique_ids=technique_ids or [],
        entities=entities or [],
        observables=observables or [],
        evidence=evidence or {},
        created_at=now,
        updated_at=now,
    )


def test_signature_collapses_same_shape_different_host():
    a = _finding(
        fid="a",
        technique_ids=["T1059.001"],
        entities=[HuntEntity(kind="host", value="host-1")],
    )
    b = _finding(
        fid="b",
        technique_ids=["T1059.001"],
        entities=[HuntEntity(kind="host", value="host-2")],
    )
    assert triage.finding_signature(a) == triage.finding_signature(b)


def test_signature_splits_on_different_technique():
    a = _finding(fid="a", technique_ids=["T1059.001"])
    b = _finding(fid="b", technique_ids=["T1078"])
    assert triage.finding_signature(a) != triage.finding_signature(b)


def test_signature_is_order_independent():
    a = _finding(fid="a", technique_ids=["T1", "T2", "T3"])
    b = _finding(fid="b", technique_ids=["T3", "T1", "T2"])
    # technique list order shouldn't matter
    assert triage.finding_signature(a) == triage.finding_signature(b)


def test_group_and_reduction():
    findings = [
        _finding(fid="a", technique_ids=["T1059.001"]),
        _finding(fid="b", technique_ids=["T1059.001"]),
        _finding(fid="c", technique_ids=["T1078"]),
        _finding(fid="d", technique_ids=["T1078"]),
    ]
    clusters = triage.group_into_clusters(findings)
    assert len(clusters) == 2
    # 4 findings -> 2 clusters == 50% reduction
    assert triage.cluster_reduction(findings) == pytest.approx(0.5)


def test_reduction_empty_is_zero():
    assert triage.cluster_reduction([]) == 0.0


def test_max_severity_and_union():
    findings = [
        _finding(fid="a", severity=Severity.LOW, technique_ids=["T1"]),
        _finding(fid="b", severity=Severity.CRITICAL, technique_ids=["T2"]),
    ]
    assert triage.max_severity(findings) == Severity.CRITICAL
    assert triage.union_techniques(findings) == ["T1", "T2"]


def test_suppression_matches_source_and_technique():
    f = _finding(source=HuntSource.HUNT_PACK, technique_ids=["T1059.001"])
    assert triage.suppression_matches(
        SuppressionMatch(source=HuntSource.HUNT_PACK, technique_ids=["T1059.001"]), f
    )
    # wrong source -> no match even though technique overlaps
    assert not triage.suppression_matches(
        SuppressionMatch(source=HuntSource.BEHAVIORAL, technique_ids=["T1059.001"]), f
    )
    # technique with no overlap -> no match
    assert not triage.suppression_matches(SuppressionMatch(technique_ids=["T9999"]), f)


def test_suppression_matches_entity_and_observable_values():
    f = _finding(
        entities=[HuntEntity(kind="user", value="svc_backup")],
        observables=[HuntObservable(type="ip", value="10.0.0.5")],
    )
    assert triage.suppression_matches(SuppressionMatch(entity_values=["svc_backup"]), f)
    assert triage.suppression_matches(SuppressionMatch(observable_values=["10.0.0.5"]), f)
    assert not triage.suppression_matches(SuppressionMatch(entity_values=["administrator"]), f)


def test_suppression_matches_rule_ids_via_evidence_provenance():
    match = SuppressionMatch(rule_ids=["rule_noisy"])
    hit = _finding(fid="a", evidence={"rule_id": "rule_noisy", "pack_id": "p"})
    other_rule = _finding(fid="b", evidence={"rule_id": "rule_other"})
    no_provenance = _finding(fid="c", evidence={})
    assert triage.suppression_matches(match, hit)
    assert not triage.suppression_matches(match, other_rule)
    # A finding with no rule provenance can never match a rule_ids rule.
    assert not triage.suppression_matches(match, no_provenance)


def test_rule_ids_and_other_criteria_are_conjunctive():
    match = SuppressionMatch(domain=HuntDomain.SIGMA, rule_ids=["rule_noisy"])
    wrong_domain = _finding(fid="a", domain=HuntDomain.EMAIL, evidence={"rule_id": "rule_noisy"})
    assert not triage.suppression_matches(match, wrong_domain)


def test_rule_ids_only_match_is_not_criterionless_overbroad():
    match = SuppressionMatch(rule_ids=["rule_noisy"])
    # A sample where the rule matches nothing — narrow by every measure.
    sample = [_finding(fid=f"s{i}", evidence={"rule_id": "other"}) for i in range(4)]
    overbroad, _reason = triage.is_overbroad(match, sample)
    assert not overbroad


def test_overbroad_empty_match():
    overbroad, why = triage.is_overbroad(SuppressionMatch(), [])
    assert overbroad
    assert "no criteria" in why


def test_overbroad_high_match_fraction():
    sample = [_finding(fid=str(i), source=HuntSource.HUNT_PACK) for i in range(10)]
    # matches all 10 -> 100% > 50% threshold
    overbroad, why = triage.is_overbroad(SuppressionMatch(source=HuntSource.HUNT_PACK), sample)
    assert overbroad
    assert "%" in why


def test_overbroad_too_many_techniques():
    # a rule keyed on a shared entity that spans 6 distinct techniques
    sample = [
        _finding(
            fid=str(i),
            technique_ids=[f"T{i}"],
            entities=[HuntEntity(kind="host", value="shared")],
        )
        for i in range(6)
    ]
    overbroad, why = triage.is_overbroad(
        SuppressionMatch(entity_values=["shared"]), sample, max_match_fraction=1.0
    )
    assert overbroad
    assert "distinct techniques" in why


def test_narrow_suppression_not_overbroad():
    sample = [_finding(fid=str(i), technique_ids=[f"T{i}"]) for i in range(20)]
    # a single-technique rule against a diverse sample matches just 1/20
    overbroad, _ = triage.is_overbroad(SuppressionMatch(technique_ids=["T1"]), sample)
    assert not overbroad
