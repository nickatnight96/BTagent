"""Unit tests for the Proofpoint TAP MCP connector (#100 Tier-2 slice).

Fifth Tier-2 connector and the first email-gateway connector — introduces the
:class:`EmailClickEvent` schema unit, so the suite exercises both normalisers
(message + click) plus the VAP rollup, mirroring the Defender O365 suite's
hygiene coverage.

Coverage:
- Message normalisation: verdict precedence (malware/phish/suspicious/spam/
  none), delivery action from disposition, recipient list flattening, raw
  preservation.
- Click normalisation: disposition + verdict mapping, message-id join key.
- Mock envelopes: window / sender / recipient / subject / disposition filters,
  limits, raw + normalised parity.
- VAP summary: per-recipient verdict counts, permitted-click accounting,
  campaign set, most-attacked ordering.
- The campaign story: the delivered phish is the same messageID as the
  permitted click on dkim@example.com.
- Live mode refuses without a service secret; secret redaction; lazy secret
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
)
from btagent_shared.types.mcp import MCPServerConfig

from btagent_agents.mcp.registry import (
    CircuitOpenError,
    CircuitState,
    MCPConnectionRegistry,
)
from btagent_agents.mcp.servers._proofpoint_fixtures import (
    CAMPAIGN_ID,
    PFPT_FIXTURE_CLICKS,
    PFPT_FIXTURE_MESSAGES,
)
from btagent_agents.mcp.servers.proofpoint_mcp import (
    ProofpointMCPServer,
    _redact_secret,
    classify_verdict,
    normalise_click_event,
    normalise_message_event,
)

ORG = "org_test"
WINDOW_START = "2026-07-08T00:00:00Z"
WINDOW_END = "2026-07-09T00:00:00Z"


def _server() -> ProofpointMCPServer:
    return ProofpointMCPServer(mock_mode=True)


def _msg(disposition: str, classification: str | None) -> dict:
    for m in PFPT_FIXTURE_MESSAGES:
        types = [t.get("classification") for t in m.get("threatsInfoMap") or []]
        match_class = (classification in types) if classification is not None else not types
        if m["_disposition"] == disposition and match_class:
            return m
    raise AssertionError(
        f"message fixture disposition={disposition} class={classification} missing"
    )


# ---------------------------------------------------------------------------
# Verdict classifier (pure)
# ---------------------------------------------------------------------------


class TestClassifyVerdict:
    def test_precedence_malware_over_phish(self) -> None:
        assert classify_verdict(["phish", "malware"]) is EmailThreatVerdict.MALWARE

    def test_phish(self) -> None:
        assert classify_verdict(["phish"]) is EmailThreatVerdict.PHISH

    def test_impostor_is_suspicious(self) -> None:
        assert classify_verdict(["impostor"]) is EmailThreatVerdict.SUSPICIOUS

    def test_empty_is_none(self) -> None:
        assert classify_verdict([]) is EmailThreatVerdict.NONE
        assert classify_verdict([""]) is EmailThreatVerdict.NONE


# ---------------------------------------------------------------------------
# Message normalisation
# ---------------------------------------------------------------------------


class TestMessageNormalisation:
    def test_delivered_phish_maps(self) -> None:
        ev = normalise_message_event(_msg("delivered", "phish"), org_id=ORG)
        assert ev.provider is EmailSecurityProvider.PROOFPOINT
        assert ev.verdict is EmailThreatVerdict.PHISH
        assert ev.delivery_action is EmailDeliveryAction.DELIVERED
        assert ev.recipient == "dkim@example.com"  # recipient list flattened
        assert ev.url_count == 1

    def test_blocked_malware_maps(self) -> None:
        ev = normalise_message_event(_msg("blocked", "malware"), org_id=ORG)
        assert ev.verdict is EmailThreatVerdict.MALWARE
        assert ev.delivery_action is EmailDeliveryAction.BLOCKED

    def test_clean_message_is_none_verdict(self) -> None:
        ev = normalise_message_event(_msg("delivered", None), org_id=ORG)
        assert ev.verdict is EmailThreatVerdict.NONE

    def test_raw_preserved(self) -> None:
        raw = _msg("delivered", "phish")
        assert normalise_message_event(raw, org_id=ORG).raw == raw


# ---------------------------------------------------------------------------
# Click normalisation
# ---------------------------------------------------------------------------


class TestClickNormalisation:
    def test_permitted_phish_click(self) -> None:
        raw = next(c for c in PFPT_FIXTURE_CLICKS if c["_disposition"] == "permitted")
        ev = normalise_click_event(raw, org_id=ORG)
        assert ev.disposition is ClickDisposition.PERMITTED
        assert ev.verdict is EmailThreatVerdict.PHISH
        assert ev.recipient == "dkim@example.com"
        assert ev.campaign_id == CAMPAIGN_ID

    def test_blocked_click(self) -> None:
        raw = next(c for c in PFPT_FIXTURE_CLICKS if c["_disposition"] == "blocked")
        ev = normalise_click_event(raw, org_id=ORG)
        assert ev.disposition is ClickDisposition.BLOCKED
        assert ev.verdict is EmailThreatVerdict.MALWARE

    def test_click_joins_message_on_message_id(self) -> None:
        message_ids = {m["messageID"] for m in PFPT_FIXTURE_MESSAGES}
        for c in PFPT_FIXTURE_CLICKS:
            assert c["messageID"] in message_ids


# ---------------------------------------------------------------------------
# Mock envelopes
# ---------------------------------------------------------------------------


class TestMockEnvelopes:
    async def test_messages_all_in_window(self) -> None:
        out = await _server().pfpt_message_events_search(WINDOW_START, WINDOW_END)
        assert out["status"] == "success" and out["is_mock"] is True
        assert out["total"] == len(PFPT_FIXTURE_MESSAGES)
        assert all(e["provider"] == "proofpoint" for e in out["events"])

    async def test_messages_recipient_filter(self) -> None:
        out = await _server().pfpt_message_events_search(
            WINDOW_START, WINDOW_END, recipient="bwallace@example.com"
        )
        assert out["total"] == 1
        assert out["events"][0]["verdict"] == "malware"

    async def test_messages_subject_filter(self) -> None:
        out = await _server().pfpt_message_events_search(
            WINDOW_START, WINDOW_END, subject_contains="Invoice"
        )
        assert out["total"] == 1

    async def test_messages_limit(self) -> None:
        out = await _server().pfpt_message_events_search(WINDOW_START, WINDOW_END, limit=1)
        assert out["total"] == 1

    async def test_clicks_all_in_window(self) -> None:
        out = await _server().pfpt_click_events_search(WINDOW_START, WINDOW_END)
        assert out["total"] == len(PFPT_FIXTURE_CLICKS)

    async def test_clicks_disposition_filter(self) -> None:
        out = await _server().pfpt_click_events_search(
            WINDOW_START, WINDOW_END, disposition="permitted"
        )
        assert out["total"] == 1
        assert out["clicks"][0]["recipient"] == "dkim@example.com"

    async def test_window_excludes(self) -> None:
        # 13:02 and 13:20 messages in-window; 15:00 clean one out.
        out = await _server().pfpt_message_events_search(
            "2026-07-08T13:00:00Z", "2026-07-08T14:00:00Z"
        )
        assert out["total"] == 2


# ---------------------------------------------------------------------------
# VAP summary
# ---------------------------------------------------------------------------


class TestVapSummary:
    async def test_summary_orders_most_attacked_first(self) -> None:
        out = await _server().pfpt_vap_summary(WINDOW_START, WINDOW_END)
        assert out["status"] == "success"
        vap = out["vap"]
        # dkim clicked a phish (permitted) → ranks first.
        assert vap[0]["recipient"] == "dkim@example.com"
        assert vap[0]["permitted_clicks"] == 1
        assert vap[0]["campaigns"] == [CAMPAIGN_ID]

    async def test_summary_counts_verdicts(self) -> None:
        out = await _server().pfpt_vap_summary(WINDOW_START, WINDOW_END)
        by_recipient = {r["recipient"]: r for r in out["vap"]}
        # dkim: one phish + one clean message.
        assert by_recipient["dkim@example.com"]["verdict_counts"]["phish"] == 1
        assert by_recipient["dkim@example.com"]["verdict_counts"]["none"] == 1
        # bwallace: one blocked malware, no permitted clicks.
        assert by_recipient["bwallace@example.com"]["verdict_counts"]["malware"] == 1
        assert by_recipient["bwallace@example.com"]["permitted_clicks"] == 0


# ---------------------------------------------------------------------------
# The campaign story coheres
# ---------------------------------------------------------------------------


class TestStoryCoherence:
    async def test_delivered_phish_is_the_clicked_message(self) -> None:
        msgs = await _server().pfpt_message_events_search(
            WINDOW_START, WINDOW_END, recipient="dkim@example.com"
        )
        clicks = await _server().pfpt_click_events_search(
            WINDOW_START, WINDOW_END, disposition="permitted"
        )
        phish_msg = next(e for e in msgs["events"] if e["verdict"] == "phish")
        permitted_click = clicks["clicks"][0]
        assert permitted_click["internet_message_id"] == phish_msg["internet_message_id"]
        assert phish_msg["delivery_action"] == "delivered"


# ---------------------------------------------------------------------------
# Live mode refuses without a service secret
# ---------------------------------------------------------------------------


class TestLiveModeRefusesWithoutSecret:
    async def test_live_mode_without_secret_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("BTAGENT_PROOFPOINT_SERVICE_SECRET", raising=False)
        server = ProofpointMCPServer(
            mock_mode=False, service_secret_ref="${env:BTAGENT_PROOFPOINT_SERVICE_SECRET}"
        )
        with pytest.raises(NotImplementedError):
            await server.pfpt_message_events_search(WINDOW_START, WINDOW_END)
        with pytest.raises(NotImplementedError):
            await server.pfpt_click_events_search(WINDOW_START, WINDOW_END)
        with pytest.raises(NotImplementedError):
            await server.pfpt_vap_summary(WINDOW_START, WINDOW_END)

    async def test_live_mode_real_path_not_yet_implemented(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BTAGENT_PROOFPOINT_SERVICE_SECRET", "pfpt-secret-0123456789abcdef")
        server = ProofpointMCPServer(
            mock_mode=False, service_secret_ref="${env:BTAGENT_PROOFPOINT_SERVICE_SECRET}"
        )
        with pytest.raises(NotImplementedError):
            await server.pfpt_message_events_search(WINDOW_START, WINDOW_END)


# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------


class TestSecretRedaction:
    def test_repr_omits_secret(self) -> None:
        server = ProofpointMCPServer(
            mock_mode=False, service_secret_ref="${env:BTAGENT_PROOFPOINT_SERVICE_SECRET}"
        )
        assert "pfpt-secret" not in repr(server)

    def test_redact_secret_short_returns_placeholder(self) -> None:
        assert _redact_secret("short") == "[redacted]"
        assert _redact_secret("") == "[redacted]"

    def test_redact_secret_long_returns_fingerprint(self) -> None:
        out = _redact_secret("pfpt-secret-0123456789abcdef")
        assert out.startswith("[redacted:proofpoint-service-secret:")
        assert "pfpt-secret-0123456789" not in out

    async def test_live_mode_log_lines_redact_secret(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setenv("BTAGENT_PROOFPOINT_SERVICE_SECRET", "pfpt-secret-0123456789abcdef")
        server = ProofpointMCPServer(
            mock_mode=False, service_secret_ref="${env:BTAGENT_PROOFPOINT_SERVICE_SECRET}"
        )
        with caplog.at_level(logging.WARNING, logger="btagent.mcp.servers.proofpoint"):
            with pytest.raises(NotImplementedError):
                await server.pfpt_message_events_search(WINDOW_START, WINDOW_END)
        for record in caplog.records:
            assert "pfpt-secret-0123456789abcdef" not in record.getMessage()


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
            name="proofpoint",
            description="proofpoint test",
            circuit_breaker_threshold=3,
            circuit_breaker_recovery=60,
        )
        conn = await registry.get_connection("proofpoint", config=cfg, consumer_id="inv_test")
        assert conn.circuit_breaker.state is CircuitState.CLOSED

        for _ in range(3):
            registry.record_failure("proofpoint", RuntimeError("simulated 503"))
        assert conn.circuit_breaker.state is CircuitState.OPEN
        with pytest.raises(CircuitOpenError):
            conn.circuit_breaker.check_state()


# ---------------------------------------------------------------------------
# Discovery registration + construction hygiene
# ---------------------------------------------------------------------------


class TestDiscoveryRegistration:
    def test_proofpoint_server_registered_in_discovery(self) -> None:
        from btagent_agents.mcp import discovery

        discovery._ensure_servers_loaded()
        assert "proofpoint" in discovery._SERVER_CLASSES
        assert discovery._SERVER_CLASSES["proofpoint"] is ProofpointMCPServer

    def test_tool_metadata_marks_proofpoint_server(self) -> None:
        meta = _server().get_tool_metadata()
        assert {m["name"] for m in meta} == {
            "pfpt_message_events_search",
            "pfpt_click_events_search",
            "pfpt_vap_summary",
        }
        assert all(m["server_id"] == "proofpoint" for m in meta)


def test_construction_does_not_resolve_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Constructing the server must never read the secret ref (lazy resolution)."""
    calls: list[str] = []

    def _spy(ref: str) -> str:
        calls.append(ref)
        return ""

    monkeypatch.setattr("btagent_agents.mcp.servers.proofpoint_mcp.resolve_secret", _spy)
    ProofpointMCPServer(mock_mode=False)
    assert calls == []
