"""Unit tests for the Mimecast MCP connector (#100 Tier-2 slice).

Second email-gateway connector — the first to exercise all three email_hunt
units under one provider (message events, held/quarantine queue, URL clicks).

Coverage:
- Verdict classifier: malware/phishing/impersonation→suspicious/spam/none.
- Message normalisation: verdict + delivery action from status, raw preserved.
- Held (quarantine) normalisation: reason→verdict, status→release lifecycle.
- Click normalisation: action→disposition, category→verdict, message-id join.
- Mock envelopes: window / sender / recipient / subject / action filters, limits.
- The BEC-plus-phish story: the delivered phish is the same messageId as the
  permitted click; the impersonation email is held for review.
- Live mode refuses without a secret key; secret redaction; lazy secret
  resolution at construction; circuit breaker; discovery registration.
"""

from __future__ import annotations

import logging

import pytest
from btagent_shared.types.email_hunt import (
    ClickDisposition,
    EmailDeliveryAction,
    EmailSecurityProvider,
    EmailThreatVerdict,
    QuarantineReleaseStatus,
)
from btagent_shared.types.mcp import MCPServerConfig

from btagent_agents.mcp.registry import (
    CircuitOpenError,
    CircuitState,
    MCPConnectionRegistry,
)
from btagent_agents.mcp.servers._mimecast_fixtures import (
    MIMECAST_FIXTURE_CLICKS,
    MIMECAST_FIXTURE_HELD,
    MIMECAST_FIXTURE_MESSAGES,
)
from btagent_agents.mcp.servers.mimecast_mcp import (
    MimecastMCPServer,
    _redact_secret,
    classify_verdict,
    normalise_click_event,
    normalise_held_message,
    normalise_message_event,
)

ORG = "org_test"
WINDOW_START = "2026-07-11T00:00:00Z"
WINDOW_END = "2026-07-12T00:00:00Z"


def _server() -> MimecastMCPServer:
    return MimecastMCPServer(mock_mode=True)


def _msg(status: str, detection: str) -> dict:
    for m in MIMECAST_FIXTURE_MESSAGES:
        if m["status"] == status and m["detectionLevel"] == detection:
            return m
    raise AssertionError(f"message fixture status={status} detection={detection} missing")


# ---------------------------------------------------------------------------
# Verdict classifier (pure)
# ---------------------------------------------------------------------------


class TestClassifyVerdict:
    def test_malware(self) -> None:
        assert classify_verdict("malware") is EmailThreatVerdict.MALWARE
        assert classify_verdict("malicious") is EmailThreatVerdict.MALWARE

    def test_phishing(self) -> None:
        assert classify_verdict("phishing") is EmailThreatVerdict.PHISH

    def test_impersonation_is_suspicious(self) -> None:
        assert classify_verdict("impersonation") is EmailThreatVerdict.SUSPICIOUS

    def test_spam_and_none(self) -> None:
        assert classify_verdict("spam") is EmailThreatVerdict.SPAM
        assert classify_verdict("none") is EmailThreatVerdict.NONE
        assert classify_verdict("") is EmailThreatVerdict.NONE


# ---------------------------------------------------------------------------
# Normalisers
# ---------------------------------------------------------------------------


class TestMessageNormalisation:
    def test_delivered_phish(self) -> None:
        ev = normalise_message_event(_msg("delivered", "phishing"), org_id=ORG)
        assert ev.provider is EmailSecurityProvider.MIMECAST
        assert ev.verdict is EmailThreatVerdict.PHISH
        assert ev.delivery_action is EmailDeliveryAction.DELIVERED
        assert ev.recipient == "dkim@example.com"

    def test_blocked_malware(self) -> None:
        ev = normalise_message_event(_msg("blocked", "malware"), org_id=ORG)
        assert ev.verdict is EmailThreatVerdict.MALWARE
        assert ev.delivery_action is EmailDeliveryAction.BLOCKED

    def test_raw_preserved(self) -> None:
        raw = _msg("delivered", "phishing")
        assert normalise_message_event(raw, org_id=ORG).raw == raw


class TestHeldNormalisation:
    def test_impersonation_held_needs_review(self) -> None:
        raw = next(h for h in MIMECAST_FIXTURE_HELD if h["reason"] == "impersonation")
        m = normalise_held_message(raw, org_id=ORG)
        assert m.provider is EmailSecurityProvider.MIMECAST
        assert m.verdict is EmailThreatVerdict.SUSPICIOUS
        assert m.release_status is QuarantineReleaseStatus.NEEDS_REVIEW
        assert m.recipient == "dkim@example.com"

    def test_released_spam(self) -> None:
        raw = next(h for h in MIMECAST_FIXTURE_HELD if h["status"] == "released")
        m = normalise_held_message(raw, org_id=ORG)
        assert m.verdict is EmailThreatVerdict.SPAM
        assert m.release_status is QuarantineReleaseStatus.RELEASED


class TestClickNormalisation:
    def test_permitted_phish_click(self) -> None:
        raw = next(c for c in MIMECAST_FIXTURE_CLICKS if c["action"] == "permit")
        ev = normalise_click_event(raw, org_id=ORG)
        assert ev.disposition is ClickDisposition.PERMITTED
        assert ev.verdict is EmailThreatVerdict.PHISH
        assert ev.recipient == "dkim@example.com"

    def test_blocked_malicious_click(self) -> None:
        raw = next(c for c in MIMECAST_FIXTURE_CLICKS if c["action"] == "block")
        ev = normalise_click_event(raw, org_id=ORG)
        assert ev.disposition is ClickDisposition.BLOCKED
        assert ev.verdict is EmailThreatVerdict.MALWARE

    def test_click_joins_message_on_message_id(self) -> None:
        message_ids = {m["messageId"] for m in MIMECAST_FIXTURE_MESSAGES}
        for c in MIMECAST_FIXTURE_CLICKS:
            assert c["messageId"] in message_ids


# ---------------------------------------------------------------------------
# Mock envelopes
# ---------------------------------------------------------------------------


class TestMockEnvelopes:
    async def test_messages_all_in_window(self) -> None:
        out = await _server().mimecast_message_events_search(WINDOW_START, WINDOW_END)
        assert out["status"] == "success" and out["is_mock"] is True
        assert out["total"] == len(MIMECAST_FIXTURE_MESSAGES)
        assert all(e["provider"] == "mimecast" for e in out["events"])

    async def test_messages_recipient_filter(self) -> None:
        out = await _server().mimecast_message_events_search(
            WINDOW_START, WINDOW_END, recipient="bwallace@example.com"
        )
        assert out["total"] == 1
        assert out["events"][0]["verdict"] == "malware"

    async def test_messages_window_excludes(self) -> None:
        # 09:02 and 09:20 in-window; 15:00 clean one out.
        out = await _server().mimecast_message_events_search(
            "2026-07-11T09:00:00Z", "2026-07-11T10:00:00Z"
        )
        assert out["total"] == 2

    async def test_held_all_and_filter(self) -> None:
        out = await _server().mimecast_list_held_messages()
        assert out["total"] == len(MIMECAST_FIXTURE_HELD)
        one = await _server().mimecast_list_held_messages(recipient="dkim@example.com")
        assert one["total"] == 1
        assert one["messages"][0]["release_status"] == "needs_review"

    async def test_clicks_all_and_action_filter(self) -> None:
        out = await _server().mimecast_click_logs_search(WINDOW_START, WINDOW_END)
        assert out["total"] == len(MIMECAST_FIXTURE_CLICKS)
        permitted = await _server().mimecast_click_logs_search(
            WINDOW_START, WINDOW_END, action="permit"
        )
        assert permitted["total"] == 1
        assert permitted["clicks"][0]["recipient"] == "dkim@example.com"

    async def test_clicks_limit(self) -> None:
        out = await _server().mimecast_click_logs_search(WINDOW_START, WINDOW_END, limit=1)
        assert out["total"] == 1


# ---------------------------------------------------------------------------
# The BEC-plus-phish story coheres
# ---------------------------------------------------------------------------


class TestStoryCoherence:
    async def test_delivered_phish_is_the_clicked_message(self) -> None:
        msgs = await _server().mimecast_message_events_search(
            WINDOW_START, WINDOW_END, recipient="dkim@example.com"
        )
        clicks = await _server().mimecast_click_logs_search(
            WINDOW_START, WINDOW_END, action="permit"
        )
        phish_msg = next(e for e in msgs["events"] if e["verdict"] == "phish")
        permitted_click = clicks["clicks"][0]
        assert permitted_click["internet_message_id"] == phish_msg["internet_message_id"]
        assert phish_msg["delivery_action"] == "delivered"

    async def test_impersonation_is_held(self) -> None:
        held = await _server().mimecast_list_held_messages()
        imp = next(m for m in held["messages"] if m["verdict"] == "suspicious")
        assert imp["release_status"] == "needs_review"


# ---------------------------------------------------------------------------
# Live mode refuses without a secret key
# ---------------------------------------------------------------------------


class TestLiveModeRefusesWithoutSecret:
    async def test_live_mode_without_secret_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("BTAGENT_MIMECAST_SECRET_KEY", raising=False)
        server = MimecastMCPServer(
            mock_mode=False, secret_key_ref="${env:BTAGENT_MIMECAST_SECRET_KEY}"
        )
        with pytest.raises(NotImplementedError):
            await server.mimecast_message_events_search(WINDOW_START, WINDOW_END)
        with pytest.raises(NotImplementedError):
            await server.mimecast_list_held_messages()
        with pytest.raises(NotImplementedError):
            await server.mimecast_click_logs_search(WINDOW_START, WINDOW_END)

    async def test_live_mode_real_path_not_yet_implemented(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BTAGENT_MIMECAST_SECRET_KEY", "mc-secret-0123456789abcdef")
        server = MimecastMCPServer(
            mock_mode=False, secret_key_ref="${env:BTAGENT_MIMECAST_SECRET_KEY}"
        )
        with pytest.raises(NotImplementedError):
            await server.mimecast_message_events_search(WINDOW_START, WINDOW_END)


# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------


class TestSecretRedaction:
    def test_repr_omits_secret(self) -> None:
        server = MimecastMCPServer(
            mock_mode=False, secret_key_ref="${env:BTAGENT_MIMECAST_SECRET_KEY}"
        )
        assert "mc-secret" not in repr(server)

    def test_redact_secret_short_returns_placeholder(self) -> None:
        assert _redact_secret("short") == "[redacted]"
        assert _redact_secret("") == "[redacted]"

    def test_redact_secret_long_returns_fingerprint(self) -> None:
        out = _redact_secret("mc-secret-0123456789abcdef")
        assert out.startswith("[redacted:mimecast-secret-key:")
        assert "mc-secret-0123456789" not in out

    async def test_live_mode_log_lines_redact_secret(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setenv("BTAGENT_MIMECAST_SECRET_KEY", "mc-secret-0123456789abcdef")
        server = MimecastMCPServer(
            mock_mode=False, secret_key_ref="${env:BTAGENT_MIMECAST_SECRET_KEY}"
        )
        with caplog.at_level(logging.WARNING, logger="btagent.mcp.servers.mimecast"):
            with pytest.raises(NotImplementedError):
                await server.mimecast_message_events_search(WINDOW_START, WINDOW_END)
        for record in caplog.records:
            assert "mc-secret-0123456789abcdef" not in record.getMessage()


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
            name="mimecast",
            description="mimecast test",
            circuit_breaker_threshold=3,
            circuit_breaker_recovery=60,
        )
        conn = await registry.get_connection("mimecast", config=cfg, consumer_id="inv_test")
        assert conn.circuit_breaker.state is CircuitState.CLOSED

        for _ in range(3):
            registry.record_failure("mimecast", RuntimeError("simulated 503"))
        assert conn.circuit_breaker.state is CircuitState.OPEN
        with pytest.raises(CircuitOpenError):
            conn.circuit_breaker.check_state()


# ---------------------------------------------------------------------------
# Discovery registration + construction hygiene
# ---------------------------------------------------------------------------


class TestDiscoveryRegistration:
    def test_mimecast_server_registered_in_discovery(self) -> None:
        from btagent_agents.mcp import discovery

        discovery._ensure_servers_loaded()
        assert "mimecast" in discovery._SERVER_CLASSES
        assert discovery._SERVER_CLASSES["mimecast"] is MimecastMCPServer

    def test_tool_metadata_marks_mimecast_server(self) -> None:
        meta = _server().get_tool_metadata()
        assert {m["name"] for m in meta} == {
            "mimecast_message_events_search",
            "mimecast_list_held_messages",
            "mimecast_click_logs_search",
        }
        assert all(m["server_id"] == "mimecast" for m in meta)


def test_construction_does_not_resolve_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Constructing the server must never read the secret ref (lazy resolution)."""
    calls: list[str] = []

    def _spy(ref: str) -> str:
        calls.append(ref)
        return ""

    monkeypatch.setattr("btagent_agents.mcp.servers.mimecast_mcp.resolve_secret", _spy)
    MimecastMCPServer(mock_mode=False)
    assert calls == []
