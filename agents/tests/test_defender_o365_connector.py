"""Unit tests for the Defender for Office 365 MCP connector (#100 Tier-1 slice).

First email-security connector — mirrors the Okta / Entra / GWS test suites so
the Tier-1 connectors stay exercised symmetrically.

Coverage:
- EmailEvents JSON → :class:`EmailMessageEvent` normalisation across the
  verdict matrix (none / spam / phish / high-confidence phish / malware) and
  the delivery-action map.
- Quarantine JSON → :class:`QuarantinedMessage` including the release
  lifecycle and the HighConfPhish quarantine reason.
- Submission JSON → :class:`EmailThreatSubmission` including post-analysis
  verdicts and unknown-category drops.
- Cross-surface joins: events ↔ submissions on ``internet_message_id``,
  events ↔ quarantine on ``network_message_id``.
- Mock envelopes: time window, sender/recipient/subject/category filters,
  limits.
- Live mode refuses without a client secret; secret redaction; lazy secret
  resolution at construction; circuit breaker; discovery registration.
"""

from __future__ import annotations

import logging
from typing import Any

import pytest
from btagent_shared.types.email_hunt import (
    EmailDeliveryAction,
    EmailSecurityProvider,
    EmailThreatVerdict,
    QuarantineReleaseStatus,
    ThreatSubmissionCategory,
    ThreatSubmissionStatus,
)
from btagent_shared.types.mcp import MCPServerConfig

from btagent_agents.mcp.registry import (
    CircuitOpenError,
    CircuitState,
    MCPConnectionRegistry,
)
from btagent_agents.mcp.servers._defender_o365_fixtures import (
    O365_FIXTURE_EMAIL_EVENTS,
    O365_FIXTURE_QUARANTINE,
    O365_FIXTURE_SUBMISSIONS,
)
from btagent_agents.mcp.servers.defender_o365_mcp import (
    DefenderO365MCPServer,
    _redact_secret,
    classify_verdict,
    normalise_email_event,
    normalise_quarantine_message,
    normalise_threat_submission,
)

ORG = "org_test"

# Fixture window covering every recorded EmailEvents row / submission.
WINDOW_START = "2026-06-01T00:00:00Z"
WINDOW_END = "2026-06-02T00:00:00Z"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_event(network_id_suffix: str) -> dict[str, Any]:
    for evt in O365_FIXTURE_EMAIL_EVENTS:
        if str(evt.get("NetworkMessageId", "")).endswith(network_id_suffix):
            return evt
    raise AssertionError(f"email-event fixture …{network_id_suffix} not found")


def _find_submission(category: str) -> dict[str, Any]:
    for sub in O365_FIXTURE_SUBMISSIONS:
        if sub.get("category") == category:
            return sub
    raise AssertionError(f"submission fixture {category} not found")


# ---------------------------------------------------------------------------
# Verdict classification (pure)
# ---------------------------------------------------------------------------


class TestVerdictClassification:
    def test_empty_types_is_none(self) -> None:
        assert classify_verdict("") is EmailThreatVerdict.NONE

    def test_spam(self) -> None:
        assert classify_verdict("Spam") is EmailThreatVerdict.SPAM

    def test_phish_normal_confidence(self) -> None:
        assert classify_verdict("Phish", "Normal") is EmailThreatVerdict.PHISH

    def test_phish_high_confidence_upgrades(self) -> None:
        assert classify_verdict("Phish", "High") is EmailThreatVerdict.HIGH_CONFIDENCE_PHISH

    def test_malware_beats_phish(self) -> None:
        assert classify_verdict("Phish, Malware", "High") is EmailThreatVerdict.MALWARE

    def test_phish_beats_spam(self) -> None:
        assert classify_verdict("Spam, Phish") is EmailThreatVerdict.PHISH


# ---------------------------------------------------------------------------
# EmailEvents normalisation
# ---------------------------------------------------------------------------


class TestEmailEventNormalisation:
    def test_delivered_phish_normalises(self) -> None:
        ev = normalise_email_event(_find_event("0001"), org_id=ORG)
        assert ev.provider is EmailSecurityProvider.DEFENDER_O365
        assert ev.verdict is EmailThreatVerdict.PHISH
        assert ev.delivery_action is EmailDeliveryAction.DELIVERED
        assert ev.sender == "billing@invoice-alerts.example.net"
        assert ev.recipient == "alice@example.com"
        assert ev.sender_ip == "203.0.113.66"
        assert ev.url_count == 2
        assert ev.org_id == ORG

    def test_high_confidence_phish_quarantined(self) -> None:
        ev = normalise_email_event(_find_event("0003"), org_id=ORG)
        assert ev.verdict is EmailThreatVerdict.HIGH_CONFIDENCE_PHISH
        assert ev.delivery_action is EmailDeliveryAction.QUARANTINED

    def test_malware_blocked_with_threat_name(self) -> None:
        ev = normalise_email_event(_find_event("0004"), org_id=ORG)
        assert ev.verdict is EmailThreatVerdict.MALWARE
        assert ev.delivery_action is EmailDeliveryAction.BLOCKED
        assert ev.threat_names == ["Trojan:JS/Phonk.A"]
        assert ev.attachment_count == 1

    def test_clean_mail_is_none_verdict(self) -> None:
        ev = normalise_email_event(_find_event("0005"), org_id=ORG)
        assert ev.verdict is EmailThreatVerdict.NONE
        assert ev.threat_names == []

    def test_junked_spam(self) -> None:
        ev = normalise_email_event(_find_event("0006"), org_id=ORG)
        assert ev.verdict is EmailThreatVerdict.SPAM
        assert ev.delivery_action is EmailDeliveryAction.DELIVERED_TO_JUNK

    def test_unknown_delivery_action_maps_to_unknown(self) -> None:
        raw = dict(_find_event("0001"), DeliveryAction="TeleportedElsewhere")
        ev = normalise_email_event(raw, org_id=ORG)
        assert ev.delivery_action is EmailDeliveryAction.UNKNOWN

    def test_normaliser_preserves_raw_payload(self) -> None:
        raw = _find_event("0001")
        ev = normalise_email_event(raw, org_id=ORG)
        assert ev.raw == raw


# ---------------------------------------------------------------------------
# Quarantine normalisation
# ---------------------------------------------------------------------------


class TestQuarantineNormalisation:
    def test_high_conf_phish_needs_review(self) -> None:
        msg = normalise_quarantine_message(O365_FIXTURE_QUARANTINE[0], org_id=ORG)
        assert msg.verdict is EmailThreatVerdict.HIGH_CONFIDENCE_PHISH
        assert msg.release_status is QuarantineReleaseStatus.NEEDS_REVIEW
        assert msg.recipient == "carol@example.com"
        assert msg.expires_at is not None

    def test_released_spam(self) -> None:
        msg = normalise_quarantine_message(O365_FIXTURE_QUARANTINE[1], org_id=ORG)
        assert msg.verdict is EmailThreatVerdict.SPAM
        assert msg.release_status is QuarantineReleaseStatus.RELEASED

    def test_unknown_release_status_maps_to_unknown(self) -> None:
        raw = dict(O365_FIXTURE_QUARANTINE[0], releaseStatus="vanished")
        msg = normalise_quarantine_message(raw, org_id=ORG)
        assert msg.release_status is QuarantineReleaseStatus.UNKNOWN


# ---------------------------------------------------------------------------
# Submission normalisation
# ---------------------------------------------------------------------------


class TestSubmissionNormalisation:
    def test_user_phish_report_completed(self) -> None:
        sub = normalise_threat_submission(_find_submission("phishing"), org_id=ORG)
        assert sub is not None
        assert sub.category is ThreatSubmissionCategory.PHISHING
        assert sub.status is ThreatSubmissionStatus.COMPLETED
        assert sub.result_verdict is EmailThreatVerdict.PHISH
        assert sub.submitted_by == "alice@example.com"

    def test_admin_malware_submission_running(self) -> None:
        sub = normalise_threat_submission(_find_submission("malware"), org_id=ORG)
        assert sub is not None
        assert sub.status is ThreatSubmissionStatus.RUNNING
        assert sub.result_verdict is EmailThreatVerdict.NONE

    def test_not_junk_report_clean_result(self) -> None:
        sub = normalise_threat_submission(_find_submission("notJunk"), org_id=ORG)
        assert sub is not None
        assert sub.category is ThreatSubmissionCategory.NOT_JUNK
        assert sub.result_verdict is EmailThreatVerdict.NONE

    def test_unknown_category_returns_none(self) -> None:
        raw = dict(_find_submission("phishing"), category="somethingElse")
        assert normalise_threat_submission(raw, org_id=ORG) is None


# ---------------------------------------------------------------------------
# Cross-surface joins — the module-docstring join discipline
# ---------------------------------------------------------------------------


class TestJoinDiscipline:
    def test_submission_joins_event_on_internet_message_id(self) -> None:
        """alice's report resolves to the delivered-phish event."""
        sub = normalise_threat_submission(_find_submission("phishing"), org_id=ORG)
        assert sub is not None
        events = [normalise_email_event(e, org_id=ORG) for e in O365_FIXTURE_EMAIL_EVENTS]
        matched = [e for e in events if e.internet_message_id == sub.internet_message_id]
        assert len(matched) == 1
        assert matched[0].verdict is EmailThreatVerdict.PHISH
        assert matched[0].delivery_action is EmailDeliveryAction.DELIVERED

    def test_quarantine_joins_event_on_network_message_id(self) -> None:
        """carol's quarantine entry resolves to her campaign event."""
        quar = normalise_quarantine_message(O365_FIXTURE_QUARANTINE[0], org_id=ORG)
        events = [normalise_email_event(e, org_id=ORG) for e in O365_FIXTURE_EMAIL_EVENTS]
        matched = [e for e in events if e.network_message_id == quar.network_message_id]
        assert len(matched) == 1
        assert matched[0].recipient == quar.recipient

    def test_campaign_groups_by_sender_and_subject(self) -> None:
        """The invoice campaign is one sender × subject × three recipients."""
        events = [normalise_email_event(e, org_id=ORG) for e in O365_FIXTURE_EMAIL_EVENTS]
        campaign = [e for e in events if e.sender == "billing@invoice-alerts.example.net"]
        assert len(campaign) == 3
        assert len({e.subject for e in campaign}) == 1
        assert len({e.recipient for e in campaign}) == 3


# ---------------------------------------------------------------------------
# Mock envelopes
# ---------------------------------------------------------------------------


class TestMockEnvelopes:
    async def test_events_search_returns_normalised_events(self) -> None:
        server = DefenderO365MCPServer(mock_mode=True)
        out = await server.o365_email_events_search(WINDOW_START, WINDOW_END)
        assert out["status"] == "success" and out["is_mock"] is True
        assert out["total"] == len(O365_FIXTURE_EMAIL_EVENTS)
        assert len(out["events"]) == out["total"]
        assert all(e["provider"] == "defender_o365" for e in out["events"])

    async def test_events_search_respects_time_window(self) -> None:
        server = DefenderO365MCPServer(mock_mode=True)
        out = await server.o365_email_events_search("2026-06-01T11:00:00Z", "2026-06-01T12:00:00Z")
        assert out["total"] == 1
        assert out["events"][0]["verdict"] == "malware"

    async def test_events_sender_filter(self) -> None:
        server = DefenderO365MCPServer(mock_mode=True)
        out = await server.o365_email_events_search(
            WINDOW_START, WINDOW_END, sender="invoice-alerts"
        )
        assert out["total"] == 3

    async def test_events_recipient_and_subject_filters(self) -> None:
        server = DefenderO365MCPServer(mock_mode=True)
        out = await server.o365_email_events_search(
            WINDOW_START, WINDOW_END, recipient="alice@", subject_contains="invoice"
        )
        assert out["total"] == 1
        assert out["events"][0]["recipient"] == "alice@example.com"

    async def test_events_limit_caps_count(self) -> None:
        server = DefenderO365MCPServer(mock_mode=True)
        out = await server.o365_email_events_search(WINDOW_START, WINDOW_END, limit=2)
        assert out["total"] == 2

    async def test_quarantine_lists_all_without_window(self) -> None:
        server = DefenderO365MCPServer(mock_mode=True)
        out = await server.o365_list_quarantine()
        assert out["total"] == len(O365_FIXTURE_QUARANTINE)
        assert all(m["provider"] == "defender_o365" for m in out["messages"])

    async def test_quarantine_recipient_filter(self) -> None:
        server = DefenderO365MCPServer(mock_mode=True)
        out = await server.o365_list_quarantine(recipient="carol@")
        assert out["total"] == 1
        assert out["messages"][0]["release_status"] == "needs_review"

    async def test_quarantine_window_excludes_older_entry(self) -> None:
        server = DefenderO365MCPServer(mock_mode=True)
        out = await server.o365_list_quarantine(start=WINDOW_START, end=WINDOW_END)
        assert out["total"] == 1

    async def test_submissions_category_filter(self) -> None:
        server = DefenderO365MCPServer(mock_mode=True)
        out = await server.o365_list_threat_submissions(
            WINDOW_START, WINDOW_END, category="phishing"
        )
        assert out["total"] == 1
        assert out["submissions"][0]["submitted_by"] == "alice@example.com"

    async def test_submissions_returns_all_in_window(self) -> None:
        server = DefenderO365MCPServer(mock_mode=True)
        out = await server.o365_list_threat_submissions(WINDOW_START, WINDOW_END)
        assert out["total"] == len(O365_FIXTURE_SUBMISSIONS)
        assert len(out["submissions"]) == out["total"]


# ---------------------------------------------------------------------------
# Live mode refuses without a client secret
# ---------------------------------------------------------------------------


class TestLiveModeRefusesWithoutSecret:
    async def test_live_mode_without_secret_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("BTAGENT_O365_CLIENT_SECRET", raising=False)
        server = DefenderO365MCPServer(
            mock_mode=False, client_secret_ref="${env:BTAGENT_O365_CLIENT_SECRET}"
        )
        with pytest.raises(NotImplementedError):
            await server.o365_email_events_search(WINDOW_START, WINDOW_END)
        with pytest.raises(NotImplementedError):
            await server.o365_list_quarantine()
        with pytest.raises(NotImplementedError):
            await server.o365_list_threat_submissions(WINDOW_START, WINDOW_END)

    async def test_live_mode_real_path_not_yet_implemented(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BTAGENT_O365_CLIENT_SECRET", "graph-secret-0123456789abcdef")
        server = DefenderO365MCPServer(
            mock_mode=False, client_secret_ref="${env:BTAGENT_O365_CLIENT_SECRET}"
        )
        with pytest.raises(NotImplementedError):
            await server.o365_email_events_search(WINDOW_START, WINDOW_END)


# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------


class TestSecretRedaction:
    def test_repr_omits_secret(self) -> None:
        server = DefenderO365MCPServer(
            mock_mode=False, client_secret_ref="${env:BTAGENT_O365_CLIENT_SECRET}"
        )
        assert "graph-secret" not in repr(server)

    def test_redact_secret_short_returns_placeholder(self) -> None:
        assert _redact_secret("short") == "[redacted]"
        assert _redact_secret("") == "[redacted]"

    def test_redact_secret_long_returns_fingerprint(self) -> None:
        out = _redact_secret("graph-secret-0123456789abcdef")
        assert out.startswith("[redacted:o365-client-secret:")
        assert "graph-secret" not in out

    async def test_live_mode_log_lines_redact_secret(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setenv("BTAGENT_O365_CLIENT_SECRET", "graph-secret-0123456789abcdef")
        server = DefenderO365MCPServer(
            mock_mode=False, client_secret_ref="${env:BTAGENT_O365_CLIENT_SECRET}"
        )
        with caplog.at_level(logging.WARNING, logger="btagent.mcp.servers.defender_o365"):
            with pytest.raises(NotImplementedError):
                await server.o365_email_events_search(WINDOW_START, WINDOW_END)
        for record in caplog.records:
            assert "graph-secret-0123456789abcdef" not in record.getMessage()


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------


class TestCircuitBreaker:
    def setup_method(self) -> None:
        MCPConnectionRegistry.reset_instance()

    def teardown_method(self) -> None:
        MCPConnectionRegistry.reset_instance()

    async def test_breaker_opens_after_failures_and_blocks(self) -> None:
        registry = MCPConnectionRegistry.get_instance()
        cfg = MCPServerConfig(
            name="defender_o365",
            description="defender_o365 test",
            circuit_breaker_threshold=3,
            circuit_breaker_recovery=60,
        )
        conn = await registry.get_connection("defender_o365", config=cfg, consumer_id="inv_test")
        assert conn.circuit_breaker.state is CircuitState.CLOSED

        for _ in range(3):
            registry.record_failure("defender_o365", RuntimeError("simulated 503"))
        assert conn.circuit_breaker.state is CircuitState.OPEN
        with pytest.raises(CircuitOpenError):
            conn.circuit_breaker.check_state()


# ---------------------------------------------------------------------------
# Discovery registration + construction hygiene
# ---------------------------------------------------------------------------


class TestDiscoveryRegistration:
    def test_o365_server_registered_in_discovery(self) -> None:
        from btagent_agents.mcp import discovery

        discovery._ensure_servers_loaded()
        assert "defender_o365" in discovery._SERVER_CLASSES
        assert discovery._SERVER_CLASSES["defender_o365"] is DefenderO365MCPServer

    def test_tool_metadata_marks_o365_server(self) -> None:
        server = DefenderO365MCPServer(mock_mode=True)
        meta = server.get_tool_metadata()
        assert {m["name"] for m in meta} == {
            "o365_email_events_search",
            "o365_list_quarantine",
            "o365_list_threat_submissions",
        }
        assert all(m["server_id"] == "defender_o365" for m in meta)


def test_construction_does_not_resolve_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Constructing the server must never read the secret ref (lazy resolution)."""
    calls: list[str] = []

    def _spy(ref: str) -> str:
        calls.append(ref)
        return ""

    monkeypatch.setattr("btagent_agents.mcp.servers.defender_o365_mcp.resolve_secret", _spy)
    DefenderO365MCPServer(mock_mode=False)
    assert calls == []
