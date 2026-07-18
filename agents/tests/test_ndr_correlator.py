"""Unit tests for the NDR-triage correlation tool.

Exercises the pure ``correlate_ndr_detections`` correlator over the Vectra
connector's detection-envelope dict shape and the ``ndr_triage`` JSON tool
wrapper.

Coverage:
- Priority model: active exfiltration → critical; ≥3 kill-chain stages →
  critical; C2 / lateral-movement → high; single elevated-threat → medium;
  recon-only → low.
- The campaign headline (multi-stage progression) + per-host stage rollup and
  ranking.
- Fixed / triaged detections do not count toward the live footprint.
- The tool wrapper: JSON parsing, bad-JSON and non-array guards, and that the
  Vectra connector's real envelope output feeds straight in.
"""

from __future__ import annotations

import json

from btagent_agents.mcp.servers.vectra_mcp import VectraMCPServer
from btagent_agents.plugins.triage.tools.ndr_correlator import (
    correlate_ndr_detections,
    ndr_triage,
)


def _det(
    host: str,
    category: str,
    threat: int,
    certainty: int = 50,
    state: str = "active",
    triaged: bool = False,
    ip: str = "10.0.0.1",
) -> dict:
    return {
        "detection_id": f"d-{host}-{category}",
        "category": category,
        "threat": threat,
        "certainty": certainty,
        "state": state,
        "triaged": triaged,
        "src_host": {"name": host, "ip": ip},
    }


# ---------------------------------------------------------------------------
# Priority model
# ---------------------------------------------------------------------------


class TestPriorityModel:
    def test_exfiltration_is_critical(self) -> None:
        out = correlate_ndr_detections([_det("h1", "exfiltration", 60)])
        assert out["hosts"][0]["priority"] == "critical"

    def test_three_stages_is_critical(self) -> None:
        out = correlate_ndr_detections(
            [
                _det("h1", "reconnaissance", 30),
                _det("h1", "command-and-control", 40),
                _det("h1", "lateral-movement", 45),
            ]
        )
        host = out["hosts"][0]
        assert host["priority"] == "critical"
        assert host["campaign"] is True
        assert len(host["kill_chain_stages"]) == 3

    def test_c2_alone_is_high(self) -> None:
        out = correlate_ndr_detections([_det("h1", "command-and-control", 40)])
        assert out["hosts"][0]["priority"] == "high"

    def test_lateral_movement_alone_is_high(self) -> None:
        out = correlate_ndr_detections([_det("h1", "lateral-movement", 20)])
        assert out["hosts"][0]["priority"] == "high"

    def test_single_elevated_recon_is_medium(self) -> None:
        out = correlate_ndr_detections([_det("h1", "reconnaissance", 55)])
        assert out["hosts"][0]["priority"] == "medium"

    def test_low_threat_recon_is_low(self) -> None:
        out = correlate_ndr_detections([_det("h1", "reconnaissance", 10)])
        assert out["hosts"][0]["priority"] == "low"


# ---------------------------------------------------------------------------
# Fixed / triaged detections excluded from the live footprint
# ---------------------------------------------------------------------------


class TestExcludesHandledDetections:
    def test_fixed_detection_ignored(self) -> None:
        out = correlate_ndr_detections([_det("h1", "exfiltration", 90, state="fixed")])
        assert out["total_hosts"] == 0

    def test_triaged_detection_ignored(self) -> None:
        out = correlate_ndr_detections([_det("h1", "command-and-control", 80, triaged=True)])
        assert out["total_hosts"] == 0

    def test_handled_stage_does_not_inflate_campaign(self) -> None:
        # A live C2 plus a triaged exfil: live footprint is C2-only (high), not
        # critical — the exfil is already handled.
        out = correlate_ndr_detections(
            [
                _det("h1", "command-and-control", 80),
                _det("h1", "exfiltration", 90, triaged=True),
            ]
        )
        host = out["hosts"][0]
        assert host["priority"] == "high"
        assert "exfiltration" not in host["kill_chain_stages"]


# ---------------------------------------------------------------------------
# Rollups + ranking
# ---------------------------------------------------------------------------


class TestRollupsAndRanking:
    def test_campaign_count_and_ranking(self) -> None:
        out = correlate_ndr_detections(
            [
                _det("campaign-host", "command-and-control", 80),
                _det("campaign-host", "exfiltration", 90),
                _det("recon-host", "reconnaissance", 15),
            ]
        )
        assert out["campaign_count"] == 1
        assert out["hosts"][0]["host"] == "campaign-host"  # critical ranks first
        assert out["hosts"][0]["deepest_stage"] == "exfiltration"
        assert out["counts_by_priority"]["critical"] == 1
        assert out["counts_by_priority"]["low"] == 1


# ---------------------------------------------------------------------------
# Tool wrapper
# ---------------------------------------------------------------------------


class TestToolWrapper:
    def test_bad_json_guard(self) -> None:
        out = ndr_triage.invoke({"detections_json": "{not json"})
        assert "error" in out
        assert out["total_hosts"] == 0

    def test_non_array_guard(self) -> None:
        out = ndr_triage.invoke({"detections_json": '{"host": "x"}'})
        assert "error" in out
        assert out["total_hosts"] == 0

    def test_empty_string_is_empty_result(self) -> None:
        out = ndr_triage.invoke({"detections_json": ""})
        assert out["total_hosts"] == 0
        assert out["hosts"] == []


# ---------------------------------------------------------------------------
# End-to-end from the real connector envelope
# ---------------------------------------------------------------------------


class TestFromConnectorEnvelope:
    async def test_correlates_vectra_connector_output(self) -> None:
        server = VectraMCPServer(mock_mode=True)
        env = await server.vectra_list_detections()
        out = ndr_triage.invoke({"detections_json": json.dumps(env["detections"])})
        # WIN10-FIN-07 walks the full kill chain (recon → C2 → lateral → exfil)
        # → a critical, confirmed campaign ranked first. SRV-DB-11's recon is
        # fixed+triaged → excluded entirely.
        assert out["campaign_count"] == 1
        top = out["hosts"][0]
        assert top["host"] == "WIN10-FIN-07"
        assert top["priority"] == "critical"
        assert top["deepest_stage"] == "exfiltration"
        assert set(top["kill_chain_stages"]) == {
            "reconnaissance",
            "command-and-control",
            "lateral-movement",
            "exfiltration",
        }
        assert {h["host"] for h in out["hosts"]} == {"WIN10-FIN-07"}
