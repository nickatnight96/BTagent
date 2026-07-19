"""Tests for the email-hunt runner (email vertical, slice 2).

Exercises the pure composition ``run_email_hunt`` / ``run_email_hunt_from_envelopes``
that chains the phishing correlator → email finding mapper, and the
connector-envelope partitioning that feeds it.

Coverage:
- Envelope partitioning: events → messages, clicks → clicks, messages →
  quarantine; mixed/garbage envelopes tolerated.
- The run summary: severity counts, active-incident headline, most-targeted.
- End-to-end from the real Defender O365 / Proofpoint / Mimecast mock
  connectors — the runner turns their envelopes into hunt findings.
"""

from __future__ import annotations

import pytest

from btagent_agents.mcp.servers.defender_o365_mcp import DefenderO365MCPServer
from btagent_agents.mcp.servers.mimecast_mcp import MimecastMCPServer
from btagent_agents.mcp.servers.proofpoint_mcp import ProofpointMCPServer
from btagent_agents.plugins.triage.email_hunt import (
    EmailHuntRunResult,
    gather_email_envelopes,
    run_email_hunt,
    run_email_hunt_from_envelopes,
    run_email_hunt_over_connectors,
)

# Wide window so every connector's fixtures (dated mid-2026) fall inside it.
_WINDOW = ("2026-01-01T00:00:00Z", "2026-12-31T00:00:00Z")


def _msg(recipient: str, verdict: str, delivery: str, mid: str) -> dict:
    return {
        "internet_message_id": mid,
        "recipient": recipient,
        "sender": "attacker@bad.example",
        "subject": "s",
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


# --------------------------------------------------------------------------- #
# Envelope partitioning
# --------------------------------------------------------------------------- #


class TestEnvelopePartitioning:
    def test_events_clicks_and_quarantine_split(self) -> None:
        envelopes = [
            {"events": [_msg("a@x.com", "phish", "delivered", "m1")]},
            {"clicks": [_click("a@x.com", "phish", "permitted", "m1")]},
            {
                "messages": [
                    {"recipient": "a@x.com", "verdict": "phish", "release_status": "needs_review"}
                ]
            },
        ]
        result = run_email_hunt_from_envelopes(envelopes)
        # Delivered + clicked → a critical active incident.
        assert result.active_incident_count == 1
        assert result.counts_by_severity["critical"] == 1

    def test_garbage_envelopes_tolerated(self) -> None:
        result = run_email_hunt_from_envelopes([{}, {"unrelated": 1}, "nonsense", None])  # type: ignore[list-item]
        assert isinstance(result, EmailHuntRunResult)
        assert result.total_incidents == 0
        assert result.findings == []

    def test_empty_input(self) -> None:
        assert run_email_hunt_from_envelopes([]).findings == []
        assert run_email_hunt().findings == []


# --------------------------------------------------------------------------- #
# Run summary
# --------------------------------------------------------------------------- #


class TestRunSummary:
    def test_severity_counts_and_headline(self) -> None:
        messages = [
            _msg("cfo@x.com", "high_confidence_phish", "delivered", "m1"),
            _msg("ceo@x.com", "phish", "delivered", "m2"),
            _msg("staff@x.com", "phish", "blocked", "m3"),
        ]
        clicks = [_click("cfo@x.com", "high_confidence_phish", "permitted", "m1")]
        result = run_email_hunt(messages, clicks)
        # m1 delivered+clicked → critical; m2 delivered phish → medium; m3
        # blocked → low.
        assert result.counts_by_severity["critical"] == 1
        assert result.counts_by_severity["medium"] == 1
        assert result.counts_by_severity["low"] == 1
        assert result.active_incident_count == 1
        assert result.total_incidents == 3

    def test_most_targeted_recipients_carried(self) -> None:
        messages = [
            _msg("victim@x.com", "phish", "delivered", "m1"),
            _msg("victim@x.com", "malware", "delivered", "m2"),
        ]
        result = run_email_hunt(messages)
        recips = {r["recipient"] for r in result.most_targeted_recipients}
        assert "victim@x.com" in recips

    def test_findings_carry_source_and_technique(self) -> None:
        result = run_email_hunt([_msg("a@x.com", "malware", "delivered", "m1")])
        assert result.findings
        f = result.findings[0]
        assert f.source.value == "email_security"
        assert f.domain.value == "email"
        assert "T1566" in f.technique_ids


# --------------------------------------------------------------------------- #
# End-to-end from the real mock connectors
# --------------------------------------------------------------------------- #


class TestEndToEndFromConnectors:
    async def test_runner_over_o365_envelopes(self) -> None:
        o365 = DefenderO365MCPServer(mock_mode=True)
        events_env = await o365.o365_email_events_search(*_WINDOW)
        quar_env = await o365.o365_list_quarantine(*_WINDOW)
        result = run_email_hunt_from_envelopes([events_env, quar_env])
        assert isinstance(result, EmailHuntRunResult)
        # Every finding produced is an email-domain finding.
        assert all(f.domain.value == "email" for f in result.findings)
        # The connector's fixtures include malicious mail → at least one finding.
        assert result.total_incidents >= 1
        assert result.findings

    async def test_runner_over_proofpoint_and_mimecast(self) -> None:
        pfpt = ProofpointMCPServer(mock_mode=True)
        mmc = MimecastMCPServer(mock_mode=True)
        envelopes = [
            await pfpt.pfpt_message_events_search(*_WINDOW),
            await pfpt.pfpt_click_events_search(*_WINDOW),
            await mmc.mimecast_message_events_search(*_WINDOW),
            await mmc.mimecast_list_held_messages(*_WINDOW),
            await mmc.mimecast_click_logs_search(*_WINDOW),
        ]
        result = run_email_hunt_from_envelopes(envelopes)
        assert isinstance(result, EmailHuntRunResult)
        assert all(f.domain.value == "email" for f in result.findings)
        # Severity counts sum to the number of findings.
        assert sum(result.counts_by_severity.values()) == len(result.findings)


@pytest.mark.parametrize("bad", [None, 123, "x"])
def test_run_email_hunt_none_args_are_safe(bad: object) -> None:
    # Defensive: the low-level entry tolerates None for any stream.
    result = run_email_hunt(None, None, None)
    assert result.total_incidents == 0


# --------------------------------------------------------------------------- #
# Live connector gathering
# --------------------------------------------------------------------------- #


class _BrokenServer:
    """A stand-in email connector whose message search always raises."""

    server_id = "defender_o365"

    async def o365_email_events_search(self, *a, **k):
        raise RuntimeError("connector unavailable")

    async def o365_list_quarantine(self, *a, **k):
        return {"messages": []}


class _UnknownServer:
    server_id = "totally_unknown_connector"


class TestGatherEmailEnvelopes:
    async def test_gathers_streams_across_connectors(self) -> None:
        servers = [
            DefenderO365MCPServer(mock_mode=True),
            ProofpointMCPServer(mock_mode=True),
            MimecastMCPServer(mock_mode=True),
        ]
        envelopes = await gather_email_envelopes(servers, start=_WINDOW[0], end=_WINDOW[1])
        # o365: messages+quarantine (2); pfpt: messages+clicks (2); mimecast:
        # messages+clicks+quarantine (3) = 7 envelopes.
        assert len(envelopes) == 7
        # Each envelope carries exactly one recognised payload key.
        keyed = [e for e in envelopes if {"events", "clicks", "messages"} & set(e)]
        assert len(keyed) == 7

    async def test_unknown_connector_skipped(self) -> None:
        envelopes = await gather_email_envelopes(
            [_UnknownServer()], start=_WINDOW[0], end=_WINDOW[1]
        )
        assert envelopes == []

    async def test_failing_tool_call_is_tolerated(self) -> None:
        # The broken message search is skipped; the working quarantine call still
        # contributes its (empty) envelope.
        envelopes = await gather_email_envelopes(
            [_BrokenServer()], start=_WINDOW[0], end=_WINDOW[1]
        )
        assert all("events" not in e for e in envelopes)
        assert any("messages" in e for e in envelopes)


class TestRunOverConnectors:
    async def test_end_to_end_over_all_connectors(self) -> None:
        servers = [
            DefenderO365MCPServer(mock_mode=True),
            ProofpointMCPServer(mock_mode=True),
            MimecastMCPServer(mock_mode=True),
        ]
        result = await run_email_hunt_over_connectors(servers, start=_WINDOW[0], end=_WINDOW[1])
        assert isinstance(result, EmailHuntRunResult)
        assert result.findings
        assert all(f.domain.value == "email" for f in result.findings)
        assert sum(result.counts_by_severity.values()) == len(result.findings)

    async def test_no_servers_is_empty(self) -> None:
        result = await run_email_hunt_over_connectors([], start=_WINDOW[0], end=_WINDOW[1])
        assert result.findings == []
        assert result.total_incidents == 0
