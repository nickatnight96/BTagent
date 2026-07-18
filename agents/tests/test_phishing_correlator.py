"""Unit tests for the phishing-triage correlation tool.

Exercises the pure ``correlate_email_threats`` correlator over the normalised
email_hunt dict shape (what the email connectors return via
``model_dump(mode="json")``) and the ``phishing_triage`` JSON tool wrapper.

Coverage:
- Priority model: delivered+clicked malicious → critical; severe delivered →
  high; phish delivered → medium; blocked/quarantined → low; clean omitted.
- The headline active-incident count and most-targeted ranking.
- Standalone permitted click (no matching message) → high.
- Held malicious message needing review → medium.
- The tool wrapper: JSON parsing, bad-JSON and non-array guards, and that the
  connectors' real envelope output feeds straight in.
"""

from __future__ import annotations

import json

from btagent_agents.mcp.servers.proofpoint_mcp import ProofpointMCPServer
from btagent_agents.plugins.triage.tools.phishing_correlator import (
    correlate_email_threats,
    phishing_triage,
)


def _msg(recipient: str, verdict: str, delivery: str, mid: str, subject: str = "s") -> dict:
    return {
        "internet_message_id": mid,
        "recipient": recipient,
        "sender": "attacker@bad.example",
        "subject": subject,
        "verdict": verdict,
        "delivery_action": delivery,
    }


def _click(recipient: str, verdict: str, disposition: str, mid: str) -> dict:
    return {
        "internet_message_id": mid,
        "recipient": recipient,
        "verdict": verdict,
        "disposition": disposition,
        "url": "https://bad.example/pay",
    }


# ---------------------------------------------------------------------------
# Priority model
# ---------------------------------------------------------------------------


class TestPriorityModel:
    def test_delivered_and_clicked_is_critical(self) -> None:
        out = correlate_email_threats(
            [_msg("a@x.com", "phish", "delivered", "m1")],
            [_click("a@x.com", "phish", "permitted", "m1")],
        )
        assert out["incidents"][0]["priority"] == "critical"
        assert out["incidents"][0]["clicked"] is True
        assert out["active_incident_count"] == 1

    def test_severe_delivered_not_clicked_is_high(self) -> None:
        out = correlate_email_threats([_msg("a@x.com", "malware", "delivered", "m2")])
        assert out["incidents"][0]["priority"] == "high"

    def test_phish_delivered_not_clicked_is_medium(self) -> None:
        out = correlate_email_threats([_msg("a@x.com", "phish", "delivered", "m3")])
        assert out["incidents"][0]["priority"] == "medium"

    def test_blocked_malicious_is_low(self) -> None:
        out = correlate_email_threats([_msg("a@x.com", "malware", "blocked", "m4")])
        assert out["incidents"][0]["priority"] == "low"

    def test_clean_message_is_not_an_incident(self) -> None:
        out = correlate_email_threats([_msg("a@x.com", "none", "delivered", "m5")])
        assert out["total_incidents"] == 0

    def test_blocked_click_not_counted_as_active(self) -> None:
        # A blocked click on a delivered phish must not upgrade it to critical.
        out = correlate_email_threats(
            [_msg("a@x.com", "phish", "delivered", "m6")],
            [_click("a@x.com", "phish", "blocked", "m6")],
        )
        assert out["incidents"][0]["priority"] == "medium"
        assert out["active_incident_count"] == 0


# ---------------------------------------------------------------------------
# Standalone clicks + quarantine
# ---------------------------------------------------------------------------


class TestOtherSurfaces:
    def test_standalone_permitted_click_is_high(self) -> None:
        out = correlate_email_threats([], [_click("a@x.com", "malware", "permitted", "orphan")])
        assert out["total_incidents"] == 1
        inc = out["incidents"][0]
        assert inc["kind"] == "click"
        assert inc["priority"] == "high"

    def test_held_malicious_needs_review_is_medium(self) -> None:
        quarantine = [
            {
                "recipient": "a@x.com",
                "subject": "wire request",
                "verdict": "suspicious",
                "release_status": "needs_review",
            }
        ]
        out = correlate_email_threats([], [], quarantine)
        assert out["incidents"][0]["kind"] == "quarantine"
        assert out["incidents"][0]["priority"] == "medium"

    def test_released_quarantine_not_an_incident(self) -> None:
        quarantine = [{"recipient": "a@x.com", "verdict": "spam", "release_status": "released"}]
        out = correlate_email_threats([], [], quarantine)
        assert out["total_incidents"] == 0


# ---------------------------------------------------------------------------
# Ranking + summary
# ---------------------------------------------------------------------------


class TestRankingAndSummary:
    def test_incidents_ranked_most_urgent_first(self) -> None:
        out = correlate_email_threats(
            [
                _msg("a@x.com", "phish", "delivered", "m1"),  # medium
                _msg("b@x.com", "malware", "delivered", "m2"),  # high
                _msg("c@x.com", "phish", "delivered", "m3"),  # critical (clicked)
            ],
            [_click("c@x.com", "phish", "permitted", "m3")],
        )
        priorities = [i["priority"] for i in out["incidents"]]
        assert priorities == ["critical", "high", "medium"]

    def test_most_targeted_recipients(self) -> None:
        out = correlate_email_threats(
            [
                _msg("victim@x.com", "phish", "delivered", "m1"),
                _msg("victim@x.com", "malware", "delivered", "m2"),
                _msg("other@x.com", "phish", "delivered", "m3"),
            ]
        )
        top = out["most_targeted_recipients"][0]
        assert top["recipient"] == "victim@x.com"
        assert top["incidents"] == 2

    def test_counts_by_priority(self) -> None:
        out = correlate_email_threats(
            [
                _msg("a@x.com", "malware", "delivered", "m1"),  # high
                _msg("b@x.com", "malware", "blocked", "m2"),  # low
            ]
        )
        assert out["counts_by_priority"]["high"] == 1
        assert out["counts_by_priority"]["low"] == 1


# ---------------------------------------------------------------------------
# The @tool JSON wrapper
# ---------------------------------------------------------------------------


class TestPhishingTriageTool:
    def test_tool_parses_json(self) -> None:
        msgs = json.dumps([_msg("a@x.com", "phish", "delivered", "m1")])
        clicks = json.dumps([_click("a@x.com", "phish", "permitted", "m1")])
        out = phishing_triage.invoke({"message_events_json": msgs, "click_events_json": clicks})
        assert out["active_incident_count"] == 1

    def test_tool_bad_json_returns_error(self) -> None:
        out = phishing_triage.invoke({"message_events_json": "{not json"})
        assert "error" in out and out["total_incidents"] == 0

    def test_tool_non_array_returns_error(self) -> None:
        out = phishing_triage.invoke({"message_events_json": '{"a": 1}'})
        assert "error" in out

    def test_tool_defaults_empty(self) -> None:
        out = phishing_triage.invoke({"message_events_json": "[]"})
        assert out["total_incidents"] == 0


# ---------------------------------------------------------------------------
# End-to-end: a connector's real envelope feeds straight in
# ---------------------------------------------------------------------------


class TestConnectorEnvelopeIntegration:
    async def test_proofpoint_envelope_feeds_correlator(self) -> None:
        server = ProofpointMCPServer(mock_mode=True)
        msgs = await server.pfpt_message_events_search(
            "2026-07-08T00:00:00Z", "2026-07-09T00:00:00Z"
        )
        clicks = await server.pfpt_click_events_search(
            "2026-07-08T00:00:00Z", "2026-07-09T00:00:00Z"
        )
        out = correlate_email_threats(msgs["events"], clicks["clicks"])
        # The Proofpoint fixture: a delivered phish to dkim that gets a
        # permitted click — exactly one active (critical) incident.
        assert out["active_incident_count"] == 1
        crit = next(i for i in out["incidents"] if i["priority"] == "critical")
        assert crit["recipient"] == "dkim@example.com"
