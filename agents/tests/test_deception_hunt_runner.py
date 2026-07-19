"""Tests for the deception-hunt runner (deception vertical, slice 2).

Exercises the pure composition ``run_deception_hunt`` /
``run_deception_hunt_from_envelope`` that chains the deception correlator →
deception finding mapper, and the async connector gather over the mock Canary
connector.

Coverage:
- The run summary: severity counts, active-intruder headline, attacker rollup.
- Envelope extraction + garbage tolerance; empty input → no findings.
- Async gather over the real mock Canary connector; connector-failure and
  bad-envelope tolerance.
"""

from __future__ import annotations

from btagent_agents.mcp.servers.canary_mcp import CanaryMCPServer
from btagent_agents.plugins.triage.deception_hunt import (
    DeceptionHuntRunResult,
    run_deception_hunt,
    run_deception_hunt_from_envelope,
    run_deception_hunt_over_connector,
)


def _inc(src_host: str, incident_type: str, target: str, acknowledged: bool = False) -> dict:
    return {
        "id": f"{src_host}-{target}",
        "src_host": src_host,
        "incident_type": incident_type,
        "target": target,
        "acknowledged": acknowledged,
    }


class TestRunSummary:
    def test_severity_counts_and_headline(self) -> None:
        incidents = [
            _inc("1.1.1.1", "canarytoken triggered", "decoy-a"),
            _inc("1.1.1.1", "SMB file open", "decoy-b"),  # multi-decoy → critical
            _inc("2.2.2.2", "port scan", "decoy-c"),  # recon-only → medium
        ]
        result = run_deception_hunt(incidents)
        assert result.total_incidents == 3
        assert result.active_intruder_count == 1  # 1.1.1.1 moved across 2 decoys
        assert result.counts_by_severity["critical"] == 2
        assert result.counts_by_severity["medium"] == 1
        assert sum(result.counts_by_severity.values()) == len(result.findings)

    def test_attacker_rollup_carried(self) -> None:
        result = run_deception_hunt(
            [
                _inc("9.9.9.9", "canarytoken triggered", "d1"),
                _inc("9.9.9.9", "SSH login attempt", "d2"),
            ]
        )
        hosts = {a["src_host"] for a in result.attackers}
        assert "9.9.9.9" in hosts

    def test_findings_carry_source_domain(self) -> None:
        result = run_deception_hunt([_inc("3.3.3.3", "port scan", "d")])
        assert result.findings
        f = result.findings[0]
        assert f.source.value == "deception"
        assert f.domain.value == "deception"


class TestEnvelopeAndEmpty:
    def test_from_envelope(self) -> None:
        env = {"incidents": [_inc("4.4.4.4", "canarytoken triggered", "d")]}
        result = run_deception_hunt_from_envelope(env)
        assert result.total_incidents == 1
        assert result.findings

    def test_garbage_envelope_tolerated(self) -> None:
        for bad in ({}, {"unrelated": 1}, {"incidents": "nope"}, "nonsense"):
            result = run_deception_hunt_from_envelope(bad)  # type: ignore[arg-type]
            assert isinstance(result, DeceptionHuntRunResult)
            assert result.total_incidents == 0

    def test_empty_incidents(self) -> None:
        assert run_deception_hunt([]).findings == []
        assert run_deception_hunt(None).findings == []


class _BrokenServer:
    async def canary_list_incidents(self, *a, **k):
        raise RuntimeError("canary console unavailable")


class _JunkServer:
    async def canary_list_incidents(self, *a, **k):
        return "not a dict"


class TestOverConnector:
    async def test_end_to_end_over_mock_canary(self) -> None:
        server = CanaryMCPServer(mock_mode=True)
        result = await run_deception_hunt_over_connector(server)
        assert isinstance(result, DeceptionHuntRunResult)
        assert result.findings
        assert all(f.domain.value == "deception" for f in result.findings)
        # The fixture attacker (198.51.100.23) trips a token then a canary →
        # multi-decoy movement → an active intruder + critical findings.
        assert result.active_intruder_count == 1
        assert result.counts_by_severity["critical"] >= 2

    async def test_connector_failure_is_empty_hunt(self) -> None:
        result = await run_deception_hunt_over_connector(_BrokenServer())
        assert result.total_incidents == 0
        assert result.findings == []

    async def test_bad_envelope_is_empty_hunt(self) -> None:
        result = await run_deception_hunt_over_connector(_JunkServer())
        assert result.total_incidents == 0
        assert result.findings == []
