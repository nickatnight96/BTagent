"""Tests for the agentic-misuse hunt runner (agentic vertical, #121).

Exercises the pure composition ``run_agentic_hunt`` over a caller-supplied
observation bundle and the mock-first ``run_agentic_hunt_mock`` over the
built-in deterministic demo bundle. Unlike the connector-backed verticals, the
agentic domain has no live connector yet — the demo bundle is the mock stand-in.

Coverage:
- The mock bundle trips one of each detector (A1 prompt-injection, A2 shadow
  agent/workload, A3 identity abuse); every finding is agentic/agentic.
- The severity rollup reconciles with the finding count.
- An empty bundle yields no findings; the input-size summary is reported.
- Determinism: two mock runs produce identical finding titles.
"""

from __future__ import annotations

from btagent_agents.plugins.triage.agentic_hunt import (
    AgenticHuntRunResult,
    run_agentic_hunt,
    run_agentic_hunt_mock,
)


class TestMockBundle:
    def test_trips_every_detector(self) -> None:
        result = run_agentic_hunt_mock()
        assert isinstance(result, AgenticHuntRunResult)
        # A1 (prompt injection), A2 (shadow workload + shadow registration),
        # A3 (identity abuse) → at least 4 findings.
        assert len(result.findings) >= 4
        titles = " || ".join(f.title.lower() for f in result.findings)
        assert "prompt injection" in titles
        assert "shadow" in titles
        assert "identity abuse" in titles

    def test_findings_all_agentic(self) -> None:
        result = run_agentic_hunt_mock()
        assert result.findings
        assert all(f.source.value == "agentic" for f in result.findings)
        assert all(f.domain.value == "agentic" for f in result.findings)

    def test_severity_rollup_reconciles(self) -> None:
        result = run_agentic_hunt_mock()
        assert sum(result.counts_by_severity.values()) == len(result.findings)

    def test_input_summary_reported(self) -> None:
        result = run_agentic_hunt_mock()
        assert result.total_events >= 1
        assert result.total_identities >= 1
        assert result.total_workloads >= 1

    def test_deterministic(self) -> None:
        a = [f.title for f in run_agentic_hunt_mock().findings]
        b = [f.title for f in run_agentic_hunt_mock().findings]
        assert a == b


class TestEmptyBundle:
    def test_no_inputs_no_findings(self) -> None:
        result = run_agentic_hunt()
        assert isinstance(result, AgenticHuntRunResult)
        assert result.findings == []
        assert result.total_events == 0
        assert result.total_identities == 0
        assert result.total_workloads == 0
        assert sum(result.counts_by_severity.values()) == 0
