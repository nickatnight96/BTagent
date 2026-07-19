"""Golden tests for the NDR hunt-finding mapper (NDR vertical, slice 1).

All tests are deterministic, pure-logic (no network / LLM / DB): they exercise
``btagent_shared.hunt.ndr`` over the dict shape the NDR-triage correlator
returns, and verify the end-to-end flow correlator → findings by feeding the
real ``correlate_ndr_detections`` output straight into the mapper.

Matrix:
  T1  priority → severity; confidence blends certainty with a per-priority floor.
  T2  technique set: one per active kill-chain stage.
  T3  entities: host + IP become clustering keys.
  T4  observables: host IP becomes the pivot.
  T5  source/domain stamped NDR; evidence carries the raw host rollup.
  T6  ordering preserved (critical-first) and empty input → no findings.
  T7  end-to-end: correlate_ndr_detections output maps cleanly to findings.
"""

from __future__ import annotations

from btagent_shared.hunt.ndr import ndr_host_to_finding, ndr_hosts_to_findings
from btagent_shared.types.enums import Severity
from btagent_shared.types.hunt import HuntDomain, HuntSource

from btagent_agents.plugins.triage.tools.ndr_correlator import correlate_ndr_detections


def _host(**overrides) -> dict:
    base = {
        "host": "WIN10-FIN-07",
        "ip": "10.12.4.71",
        "priority": "high",
        "kill_chain_stages": ["command-and-control"],
        "deepest_stage": "command-and-control",
        "campaign": False,
        "max_threat": 82,
        "max_certainty": 76,
        "detection_count": 1,
        "rationale": "why",
    }
    base.update(overrides)
    return base


# --------------------------------------------------------------------------- #
# T1 — severity + confidence
# --------------------------------------------------------------------------- #


class TestSeverityConfidence:
    def test_priority_maps_to_severity(self) -> None:
        expected = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }
        for priority, sev in expected.items():
            f = ndr_host_to_finding(_host(priority=priority, max_certainty=0))
            assert f.severity == sev

    def test_confidence_uses_certainty_when_above_floor(self) -> None:
        f = ndr_host_to_finding(_host(priority="high", max_certainty=90))
        assert f.confidence == 0.9

    def test_confidence_uses_floor_when_certainty_low(self) -> None:
        # high floor is 0.7; certainty 10 → floor wins.
        f = ndr_host_to_finding(_host(priority="high", max_certainty=10))
        assert f.confidence == 0.7


# --------------------------------------------------------------------------- #
# T2 — techniques per stage
# --------------------------------------------------------------------------- #


class TestTechniques:
    def test_one_technique_per_stage(self) -> None:
        f = ndr_host_to_finding(
            _host(
                kill_chain_stages=[
                    "reconnaissance",
                    "command-and-control",
                    "lateral-movement",
                    "exfiltration",
                ]
            )
        )
        assert set(f.technique_ids) == {"T1046", "T1071", "T1021", "T1041"}

    def test_unknown_stage_ignored(self) -> None:
        f = ndr_host_to_finding(_host(kill_chain_stages=["command-and-control", "bogus"]))
        assert f.technique_ids == ["T1071"]

    def test_no_stages_no_techniques(self) -> None:
        f = ndr_host_to_finding(_host(kill_chain_stages=[]))
        assert f.technique_ids == []


# --------------------------------------------------------------------------- #
# T3 / T4 — entities + observables
# --------------------------------------------------------------------------- #


class TestEntitiesObservables:
    def test_host_and_ip_entities(self) -> None:
        f = ndr_host_to_finding(_host())
        kinds = {(e.kind, e.value) for e in f.entities}
        assert ("host", "WIN10-FIN-07") in kinds
        assert ("ip", "10.12.4.71") in kinds

    def test_ip_observable(self) -> None:
        f = ndr_host_to_finding(_host())
        assert any(o.type == "ip" and o.value == "10.12.4.71" for o in f.observables)

    def test_missing_ip_omits_observable(self) -> None:
        f = ndr_host_to_finding(_host(ip=""))
        assert f.observables == []
        assert all(e.kind != "ip" for e in f.entities)


# --------------------------------------------------------------------------- #
# T5 — provenance
# --------------------------------------------------------------------------- #


class TestProvenance:
    def test_source_and_domain_stamped(self) -> None:
        f = ndr_host_to_finding(_host())
        assert f.source == HuntSource.NDR
        assert f.domain == HuntDomain.NDR

    def test_evidence_carries_raw_host(self) -> None:
        h = _host()
        f = ndr_host_to_finding(h)
        assert f.evidence["ndr_host"] == h
        assert f.description == "why"


# --------------------------------------------------------------------------- #
# T6 — batch ordering + empty
# --------------------------------------------------------------------------- #


class TestBatch:
    def test_ordering_preserved(self) -> None:
        correlation = {
            "hosts": [
                _host(host="a", priority="critical"),
                _host(host="b", priority="low"),
            ]
        }
        findings = ndr_hosts_to_findings(correlation)
        assert [f.severity for f in findings] == [Severity.CRITICAL, Severity.LOW]

    def test_empty_correlation_no_findings(self) -> None:
        assert ndr_hosts_to_findings({}) == []
        assert ndr_hosts_to_findings({"hosts": []}) == []


# --------------------------------------------------------------------------- #
# T7 — end-to-end from the real correlator
# --------------------------------------------------------------------------- #


class TestEndToEndFromCorrelator:
    def test_correlator_output_maps_cleanly(self) -> None:
        # One host walks C2 → exfiltration → the correlator's critical campaign;
        # the mapper turns it into a CRITICAL NDR finding with both techniques.
        detections = [
            {
                "src_host": {"name": "HOST-1", "ip": "10.0.0.5"},
                "category": "command-and-control",
                "threat": 82,
                "certainty": 76,
                "state": "active",
            },
            {
                "src_host": {"name": "HOST-1", "ip": "10.0.0.5"},
                "category": "exfiltration",
                "threat": 91,
                "certainty": 84,
                "state": "active",
            },
        ]
        correlation = correlate_ndr_detections(detections)
        findings = ndr_hosts_to_findings(correlation)
        assert findings
        top = findings[0]
        assert top.source == HuntSource.NDR
        assert top.severity == Severity.CRITICAL
        assert "T1041" in top.technique_ids  # exfiltration
        assert "T1071" in top.technique_ids  # command-and-control
        assert any(o.type == "ip" for o in top.observables)
