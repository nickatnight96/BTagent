"""Tests for the cloud control-plane hunt runner (cloud vertical, #117).

Exercises the pure composition ``run_cloud_hunt`` over a caller-supplied
observation bundle and the mock-first ``run_cloud_hunt_mock`` over the built-in
deterministic demo bundle. Like agentic, the cloud domain has no live connector
yet — the demo bundle is the mock stand-in.

Coverage:
- The mock bundle trips a representative set of detectors (cross-account trust,
  shadow workload, overprivileged identity); every finding is cloud/cloud.
- The severity rollup reconciles with the finding count.
- An empty bundle yields no findings; the input-size summary is reported.
- Determinism: two mock runs produce identical finding titles.
"""

from __future__ import annotations

from btagent_agents.plugins.triage.cloud_hunt import (
    CloudHuntRunResult,
    run_cloud_hunt,
    run_cloud_hunt_mock,
)


class TestMockBundle:
    def test_trips_representative_detectors(self) -> None:
        result = run_cloud_hunt_mock()
        assert isinstance(result, CloudHuntRunResult)
        assert len(result.findings) >= 3
        detections = {f.evidence.get("detection") for f in result.findings}
        assert "cross_account_trust_abuse" in detections
        assert "shadow_workload" in detections
        assert "overprivileged_workload_identity" in detections

    def test_findings_all_cloud(self) -> None:
        result = run_cloud_hunt_mock()
        assert result.findings
        assert all(f.source.value == "cloud" for f in result.findings)
        assert all(f.domain.value == "cloud" for f in result.findings)

    def test_severity_rollup_reconciles(self) -> None:
        result = run_cloud_hunt_mock()
        assert sum(result.counts_by_severity.values()) == len(result.findings)

    def test_input_summary_reported(self) -> None:
        result = run_cloud_hunt_mock()
        assert result.total_identities >= 1
        assert result.total_workloads >= 1

    def test_deterministic(self) -> None:
        a = [f.title for f in run_cloud_hunt_mock().findings]
        b = [f.title for f in run_cloud_hunt_mock().findings]
        assert a == b

    def test_governed_workload_not_flagged(self) -> None:
        # The demo has one shadow + one governed workload; only the shadow one
        # should surface a shadow-workload finding.
        result = run_cloud_hunt_mock()
        shadow = [f for f in result.findings if f.evidence.get("detection") == "shadow_workload"]
        assert len(shadow) == 1


class TestEmptyBundle:
    def test_no_inputs_no_findings(self) -> None:
        result = run_cloud_hunt()
        assert isinstance(result, CloudHuntRunResult)
        assert result.findings == []
        assert result.total_identities == 0
        assert result.total_workloads == 0
        assert sum(result.counts_by_severity.values()) == 0
