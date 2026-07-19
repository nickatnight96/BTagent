"""Tests for the NDR-hunt runner (NDR vertical, slice 2).

Exercises the pure composition ``run_ndr_hunt`` / ``run_ndr_hunt_from_envelope``
that chains the NDR correlator → NDR finding mapper, and the async connector
gather over the mock Vectra connector.

Coverage:
- The run summary: severity counts, campaign headline.
- Envelope extraction + garbage tolerance; empty input → no findings.
- Async gather over the real mock Vectra connector; connector-failure and
  bad-envelope tolerance.
"""

from __future__ import annotations

from btagent_agents.mcp.servers.vectra_mcp import VectraMCPServer
from btagent_agents.plugins.triage.ndr_hunt import (
    NdrHuntRunResult,
    run_ndr_hunt,
    run_ndr_hunt_from_envelope,
    run_ndr_hunt_over_connector,
)


def _det(host: str, category: str, threat: int, certainty: int = 60, state: str = "active") -> dict:
    return {
        "src_host": {"name": host, "ip": "10.0.0.9"},
        "category": category,
        "threat": threat,
        "certainty": certainty,
        "state": state,
    }


class TestRunSummary:
    def test_severity_counts_and_campaign_headline(self) -> None:
        detections = [
            _det("camp-host", "command-and-control", 82),
            _det("camp-host", "exfiltration", 91),  # 2 stages + exfil → critical
            _det("recon-host", "reconnaissance", 15),  # recon-only → low
        ]
        result = run_ndr_hunt(detections)
        assert result.total_hosts == 2
        assert result.campaign_count == 1  # camp-host spans 2 stages
        assert result.counts_by_severity["critical"] == 1
        assert result.counts_by_severity["low"] == 1
        assert sum(result.counts_by_severity.values()) == len(result.findings)

    def test_findings_carry_source_domain(self) -> None:
        result = run_ndr_hunt([_det("h", "command-and-control", 80)])
        assert result.findings
        f = result.findings[0]
        assert f.source.value == "ndr"
        assert f.domain.value == "ndr"


class TestEnvelopeAndEmpty:
    def test_from_envelope(self) -> None:
        env = {"detections": [_det("h", "exfiltration", 90)]}
        result = run_ndr_hunt_from_envelope(env)
        assert result.total_hosts == 1
        assert result.findings

    def test_garbage_envelope_tolerated(self) -> None:
        for bad in ({}, {"unrelated": 1}, {"detections": "nope"}, "nonsense"):
            result = run_ndr_hunt_from_envelope(bad)  # type: ignore[arg-type]
            assert isinstance(result, NdrHuntRunResult)
            assert result.total_hosts == 0

    def test_empty_detections(self) -> None:
        assert run_ndr_hunt([]).findings == []
        assert run_ndr_hunt(None).findings == []


class _BrokenServer:
    async def vectra_list_detections(self, *a, **k):
        raise RuntimeError("vectra brain unavailable")


class _JunkServer:
    async def vectra_list_detections(self, *a, **k):
        return "not a dict"


class TestOverConnector:
    async def test_end_to_end_over_mock_vectra(self) -> None:
        server = VectraMCPServer(mock_mode=True)
        result = await run_ndr_hunt_over_connector(server)
        assert isinstance(result, NdrHuntRunResult)
        assert result.findings
        assert all(f.domain.value == "ndr" for f in result.findings)
        # The fixture host WIN10-FIN-07 walks the full kill chain → a critical
        # campaign finding.
        assert result.campaign_count >= 1
        assert result.counts_by_severity["critical"] >= 1

    async def test_connector_failure_is_empty_hunt(self) -> None:
        result = await run_ndr_hunt_over_connector(_BrokenServer())
        assert result.total_hosts == 0
        assert result.findings == []

    async def test_bad_envelope_is_empty_hunt(self) -> None:
        result = await run_ndr_hunt_over_connector(_JunkServer())
        assert result.total_hosts == 0
        assert result.findings == []
