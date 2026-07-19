"""Golden tests for the deception hunt-finding mapper (deception vertical, slice 1).

All tests are deterministic, pure-logic (no network / LLM / DB): they exercise
``btagent_shared.hunt.deception`` over the dict shape the deception-triage
correlator returns, and verify the end-to-end flow correlator → findings by
feeding the real ``correlate_deception_events`` output straight into the mapper.

Matrix:
  T1  priority → severity + confidence (high-fidelity rungs).
  T2  technique set by kill-chain stage; multi-decoy adds lateral movement.
  T3  entities: attacker IP + decoy become clustering keys.
  T4  observables: attacker IP becomes the pivot.
  T5  source/domain stamped DECEPTION; evidence carries the raw incident.
  T6  ordering preserved (critical-first) and empty input → no findings.
  T7  end-to-end: correlate_deception_events output maps cleanly to findings.
"""

from __future__ import annotations

from btagent_shared.hunt.deception import (
    deception_incident_to_finding,
    deception_incidents_to_findings,
)
from btagent_shared.types.enums import Severity
from btagent_shared.types.hunt import HuntDomain, HuntSource

from btagent_agents.plugins.triage.tools.deception_correlator import correlate_deception_events


def _incident(**overrides) -> dict:
    base = {
        "priority": "high",
        "src_host": "198.51.100.23",
        "target": "aws-key-finance",
        "incident_type": "canarytoken triggered",
        "stage": "credential_use",
        "acknowledged": False,
        "multi_decoy": False,
        "id": "inc-1",
        "rationale": "why",
    }
    base.update(overrides)
    return base


# --------------------------------------------------------------------------- #
# T1 — severity + confidence
# --------------------------------------------------------------------------- #


class TestSeverityConfidence:
    def test_all_priority_rungs(self) -> None:
        expected = {
            "critical": (Severity.CRITICAL, 0.98),
            "high": (Severity.HIGH, 0.9),
            "medium": (Severity.MEDIUM, 0.8),
            "low": (Severity.LOW, 0.6),
        }
        for priority, (sev, conf) in expected.items():
            f = deception_incident_to_finding(_incident(priority=priority))
            assert f.severity == sev
            assert f.confidence == conf

    def test_confidence_floor_is_high(self) -> None:
        # Even a low-priority (acknowledged) deception trip carries real weight.
        f = deception_incident_to_finding(_incident(priority="low"))
        assert f.confidence >= 0.6


# --------------------------------------------------------------------------- #
# T2 — techniques by stage
# --------------------------------------------------------------------------- #


class TestTechniques:
    def test_credential_use_stage(self) -> None:
        f = deception_incident_to_finding(_incident(stage="credential_use"))
        assert "T1078" in f.technique_ids

    def test_interaction_stage(self) -> None:
        f = deception_incident_to_finding(_incident(stage="interaction"))
        assert "T1021" in f.technique_ids

    def test_recon_stage(self) -> None:
        f = deception_incident_to_finding(_incident(stage="recon"))
        assert "T1046" in f.technique_ids

    def test_multi_decoy_adds_lateral_movement(self) -> None:
        f = deception_incident_to_finding(_incident(stage="interaction", multi_decoy=True))
        assert "T1210" in f.technique_ids

    def test_unknown_stage_no_technique(self) -> None:
        f = deception_incident_to_finding(_incident(stage="", multi_decoy=False))
        assert f.technique_ids == []


# --------------------------------------------------------------------------- #
# T3 / T4 — entities + observables
# --------------------------------------------------------------------------- #


class TestEntitiesObservables:
    def test_attacker_and_decoy_entities(self) -> None:
        f = deception_incident_to_finding(_incident())
        kinds = {(e.kind, e.value) for e in f.entities}
        assert ("attacker_ip", "198.51.100.23") in kinds
        assert ("decoy", "aws-key-finance") in kinds

    def test_attacker_ip_observable(self) -> None:
        f = deception_incident_to_finding(_incident())
        assert any(o.type == "ip" and o.value == "198.51.100.23" for o in f.observables)

    def test_missing_src_host_omits_observable(self) -> None:
        f = deception_incident_to_finding(_incident(src_host=""))
        assert f.observables == []
        assert all(e.kind != "attacker_ip" for e in f.entities)


# --------------------------------------------------------------------------- #
# T5 — provenance
# --------------------------------------------------------------------------- #


class TestProvenance:
    def test_source_and_domain_stamped(self) -> None:
        f = deception_incident_to_finding(_incident())
        assert f.source == HuntSource.DECEPTION
        assert f.domain == HuntDomain.DECEPTION

    def test_evidence_carries_raw_incident(self) -> None:
        inc = _incident()
        f = deception_incident_to_finding(inc)
        assert f.evidence["deception_incident"] == inc
        assert f.description == "why"


# --------------------------------------------------------------------------- #
# T6 — batch ordering + empty
# --------------------------------------------------------------------------- #


class TestBatch:
    def test_ordering_preserved(self) -> None:
        correlation = {
            "incidents": [
                _incident(priority="critical", id="a"),
                _incident(priority="low", id="b"),
            ]
        }
        findings = deception_incidents_to_findings(correlation)
        assert [f.severity for f in findings] == [Severity.CRITICAL, Severity.LOW]

    def test_empty_correlation_no_findings(self) -> None:
        assert deception_incidents_to_findings({}) == []
        assert deception_incidents_to_findings({"incidents": []}) == []


# --------------------------------------------------------------------------- #
# T7 — end-to-end from the real correlator
# --------------------------------------------------------------------------- #


class TestEndToEndFromCorrelator:
    def test_correlator_output_maps_cleanly(self) -> None:
        # One attacker IP trips a canarytoken then a canary → the correlator's
        # critical multi-decoy incidents; the mapper turns them into CRITICAL
        # deception findings carrying the lateral-movement technique.
        incidents = [
            {
                "id": "i1",
                "src_host": "198.51.100.23",
                "incident_type": "canarytoken triggered",
                "target": "aws-key-finance",
                "acknowledged": False,
            },
            {
                "id": "i2",
                "src_host": "198.51.100.23",
                "incident_type": "SMB file open",
                "target": "fileserver-decoy",
                "acknowledged": False,
            },
        ]
        correlation = correlate_deception_events(incidents)
        findings = deception_incidents_to_findings(correlation)
        assert findings
        assert all(f.source == HuntSource.DECEPTION for f in findings)
        top = findings[0]
        assert top.severity == Severity.CRITICAL
        assert "T1210" in top.technique_ids  # multi-decoy lateral movement
        assert any(o.type == "ip" for o in top.observables)
