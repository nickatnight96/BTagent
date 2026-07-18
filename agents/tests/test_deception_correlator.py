"""Unit tests for the deception-triage correlation tool.

Exercises the pure ``correlate_deception_events`` correlator over the Canary
connector's incident-envelope dict shape and the ``deception_triage`` JSON tool
wrapper.

Coverage:
- Priority model: unacknowledged multi-decoy → critical; single-decoy
  credential-use / interaction → high; recon-only → medium; acknowledged → low.
- The headline active-intruder count and the per-attacker decoy rollup.
- Acknowledged trips do not inflate an active intruder's movement score.
- The tool wrapper: JSON parsing, bad-JSON and non-array guards, and that the
  Canary connector's real envelope output feeds straight in.
"""

from __future__ import annotations

import json

from btagent_agents.mcp.servers.canary_mcp import CanaryMCPServer
from btagent_agents.plugins.triage.tools.deception_correlator import (
    correlate_deception_events,
    deception_triage,
)


def _inc(
    src_host: str,
    incident_type: str,
    target: str,
    acknowledged: bool = False,
    inc_id: str = "i",
) -> dict:
    return {
        "id": inc_id,
        "src_host": src_host,
        "incident_type": incident_type,
        "target": target,
        "acknowledged": acknowledged,
    }


# ---------------------------------------------------------------------------
# Priority model
# ---------------------------------------------------------------------------


class TestPriorityModel:
    def test_multi_decoy_unacked_is_critical(self) -> None:
        out = correlate_deception_events(
            [
                _inc("1.1.1.1", "port scan", "decoy-a", inc_id="a"),
                _inc("1.1.1.1", "SMB file open", "decoy-b", inc_id="b"),
            ]
        )
        assert all(i["priority"] == "critical" for i in out["incidents"])
        assert all(i["multi_decoy"] is True for i in out["incidents"])

    def test_single_credential_use_is_high(self) -> None:
        out = correlate_deception_events(
            [_inc("2.2.2.2", "canarytoken triggered", "aws-key", inc_id="c")]
        )
        assert out["incidents"][0]["priority"] == "high"
        assert out["incidents"][0]["stage"] == "credential_use"

    def test_single_interaction_is_high(self) -> None:
        out = correlate_deception_events(
            [_inc("3.3.3.3", "SSH login attempt", "decoy-a", inc_id="d")]
        )
        assert out["incidents"][0]["priority"] == "high"
        assert out["incidents"][0]["stage"] == "interaction"

    def test_single_recon_is_medium(self) -> None:
        out = correlate_deception_events([_inc("4.4.4.4", "port scan", "decoy-a", inc_id="e")])
        assert out["incidents"][0]["priority"] == "medium"
        assert out["incidents"][0]["stage"] == "recon"

    def test_acknowledged_is_low(self) -> None:
        out = correlate_deception_events(
            [_inc("5.5.5.5", "HTTP login attempt", "decoy-a", acknowledged=True, inc_id="f")]
        )
        assert out["incidents"][0]["priority"] == "low"
        assert out["incidents"][0]["multi_decoy"] is False


# ---------------------------------------------------------------------------
# Acknowledged trips must not inflate movement
# ---------------------------------------------------------------------------


class TestAcknowledgedDoesNotInflateMovement:
    def test_ack_second_decoy_does_not_make_critical(self) -> None:
        # Same IP touched two decoys but one trip is already acknowledged, so
        # the live footprint is a single decoy → not lateral movement.
        out = correlate_deception_events(
            [
                _inc("6.6.6.6", "canarytoken triggered", "decoy-a", inc_id="g"),
                _inc("6.6.6.6", "port scan", "decoy-b", acknowledged=True, inc_id="h"),
            ]
        )
        by_id = {i["id"]: i for i in out["incidents"]}
        assert by_id["g"]["priority"] == "high"  # not escalated to critical
        assert by_id["g"]["multi_decoy"] is False
        assert by_id["h"]["priority"] == "low"
        assert out["active_intruder_count"] == 0


# ---------------------------------------------------------------------------
# Rollups and ranking
# ---------------------------------------------------------------------------


class TestRollups:
    def test_active_intruder_count_and_attacker_rollup(self) -> None:
        out = correlate_deception_events(
            [
                _inc("7.7.7.7", "canarytoken triggered", "decoy-a", inc_id="a"),
                _inc("7.7.7.7", "SMB file open", "decoy-b", inc_id="b"),
                _inc("8.8.8.8", "port scan", "decoy-c", inc_id="c"),
            ]
        )
        assert out["active_intruder_count"] == 1
        # Mover ranked first.
        assert out["attackers"][0]["src_host"] == "7.7.7.7"
        assert out["attackers"][0]["distinct_decoys"] == 2
        assert out["attackers"][0]["moving"] is True
        assert set(out["attackers"][0]["decoys_tripped"]) == {"decoy-a", "decoy-b"}

    def test_incidents_ranked_critical_first(self) -> None:
        out = correlate_deception_events(
            [
                _inc("9.9.9.9", "port scan", "decoy-x", inc_id="lonely"),
                _inc("1.1.1.1", "canarytoken triggered", "decoy-a", inc_id="a"),
                _inc("1.1.1.1", "SMB file open", "decoy-b", inc_id="b"),
            ]
        )
        assert out["incidents"][0]["priority"] == "critical"
        assert out["counts_by_priority"]["critical"] == 2
        assert out["counts_by_priority"]["medium"] == 1


# ---------------------------------------------------------------------------
# Tool wrapper
# ---------------------------------------------------------------------------


class TestToolWrapper:
    def test_bad_json_guard(self) -> None:
        out = deception_triage.invoke({"incidents_json": "{not json"})
        assert "error" in out
        assert out["total_incidents"] == 0

    def test_non_array_guard(self) -> None:
        out = deception_triage.invoke({"incidents_json": '{"src_host": "x"}'})
        assert "error" in out
        assert out["total_incidents"] == 0

    def test_empty_string_is_empty_result(self) -> None:
        out = deception_triage.invoke({"incidents_json": ""})
        assert out["total_incidents"] == 0
        assert out["incidents"] == []


# ---------------------------------------------------------------------------
# End-to-end from the real connector envelope
# ---------------------------------------------------------------------------


class TestFromConnectorEnvelope:
    async def test_correlates_canary_connector_output(self) -> None:
        server = CanaryMCPServer(mock_mode=True)
        env = await server.canary_list_incidents()
        out = deception_triage.invoke({"incidents_json": json.dumps(env["incidents"])})
        # The fixture attacker (198.51.100.23) trips a token then a canary =
        # lateral movement across the grid → an active intruder.
        assert out["active_intruder_count"] == 1
        mover = next(a for a in out["attackers"] if a["moving"])
        assert mover["src_host"] == "198.51.100.23"
        assert set(mover["decoys_tripped"]) == {"aws-key-finance", "fileserver-decoy"}
        # Those trips rank critical; the acknowledged benign scanner ranks low.
        assert out["counts_by_priority"]["critical"] >= 2
        assert out["counts_by_priority"]["low"] == 1
