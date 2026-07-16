"""Unit tests for the Slack MCP connector (#100 Tier-1 slice — completes Tier-1).

First comms connector — a stateful write surface like Jira, so the suite
exercises the mock ledger lifecycle end-to-end (create channel → post →
thread → pin → history) plus the seeded fixture channel.

Coverage:
- Channel-name normalisation: lowering, collapsing, inc- prefixing,
  80-char truncation, blank rejection.
- Channel create: field capture, name_taken on duplicates, severity
  validation.
- Post: ts allocation, thread replies, blank-text validation, unknown
  channel / unknown thread_ts envelopes, leading-# tolerance.
- Pin: status-of-record flag, unknown ts.
- History: newest-first ordering, limit, seeded fixture read-back.
- Live mode refuses without a bot token; secret redaction; lazy secret
  resolution at construction; circuit breaker; discovery registration.
"""

from __future__ import annotations

import logging

import pytest
from btagent_shared.types.mcp import MCPServerConfig

from btagent_agents.mcp.registry import (
    CircuitOpenError,
    CircuitState,
    MCPConnectionRegistry,
)
from btagent_agents.mcp.servers.slack_mcp import (
    MOCK_SLACK_LEDGER,
    SlackMCPServer,
    _redact_secret,
    normalise_channel_name,
    reset_mock_ledger,
)

SEED_CHANNEL = "inc-seed-phish-4471"
SEED_PINNED_TS = "1786000000.000001"


@pytest.fixture(autouse=True)
def _fresh_ledger() -> None:
    """Every test starts from the seeded one-channel fixture state."""
    reset_mock_ledger()


def _server() -> SlackMCPServer:
    return SlackMCPServer(mock_mode=True)


# ---------------------------------------------------------------------------
# Channel-name normalisation (pure)
# ---------------------------------------------------------------------------


class TestChannelNameNormalisation:
    def test_lowercases_and_collapses(self) -> None:
        assert normalise_channel_name("Invoice #4471 Phish!!") == "inc-invoice-4471-phish"

    def test_existing_inc_prefix_kept(self) -> None:
        assert normalise_channel_name("inc-already-prefixed") == "inc-already-prefixed"

    def test_truncates_to_slack_limit(self) -> None:
        name = normalise_channel_name("x" * 200)
        assert len(name) <= 80
        assert name.startswith("inc-")

    def test_blank_slug_normalises_empty(self) -> None:
        assert normalise_channel_name("!!!") == ""
        assert normalise_channel_name("") == ""


# ---------------------------------------------------------------------------
# Channel create
# ---------------------------------------------------------------------------


class TestCreateChannel:
    async def test_create_captures_fields(self) -> None:
        out = await _server().slack_create_incident_channel(
            "Ransomware LAPTOP-DESIGN-03",
            topic="IC bridge: pennysvc ransomware",
            severity="critical",
            investigation_id="inv_test_001",
        )
        assert out["status"] == "success" and out["is_mock"] is True
        assert out["channel"] == "inc-ransomware-laptop-design-03"
        chan = MOCK_SLACK_LEDGER[out["channel"]]
        assert chan["severity"] == "critical"
        assert chan["investigation_id"] == "inv_test_001"
        assert chan["messages"] == []

    async def test_duplicate_is_name_taken(self) -> None:
        out = await _server().slack_create_incident_channel("seed phish 4471")
        assert out["status"] == "name_taken"
        assert out["channel"] == SEED_CHANNEL

    async def test_blank_slug_rejected(self) -> None:
        out = await _server().slack_create_incident_channel("!!!")
        assert out["status"] == "error"

    async def test_invalid_severity_rejected(self) -> None:
        out = await _server().slack_create_incident_channel("x", severity="apocalyptic")
        assert out["status"] == "error"


# ---------------------------------------------------------------------------
# Post + threads
# ---------------------------------------------------------------------------


class TestPostMessage:
    async def test_post_allocates_ts(self) -> None:
        out = await _server().slack_post_message(SEED_CHANNEL, "Containment complete.")
        assert out["status"] == "success"
        assert out["ts"].startswith("1786000000.")
        assert MOCK_SLACK_LEDGER[SEED_CHANNEL]["messages"][-1]["text"] == "Containment complete."

    async def test_leading_hash_tolerated(self) -> None:
        out = await _server().slack_post_message(f"#{SEED_CHANNEL}", "hash-prefixed")
        assert out["status"] == "success"

    async def test_thread_reply_records_parent(self) -> None:
        out = await _server().slack_post_message(
            SEED_CHANNEL, "Threaded update", thread_ts=SEED_PINNED_TS
        )
        assert out["status"] == "success"
        assert MOCK_SLACK_LEDGER[SEED_CHANNEL]["messages"][-1]["thread_ts"] == SEED_PINNED_TS

    async def test_unknown_thread_ts_not_found(self) -> None:
        out = await _server().slack_post_message(SEED_CHANNEL, "x", thread_ts="999.0")
        assert out["status"] == "not_found"

    async def test_blank_text_rejected(self) -> None:
        out = await _server().slack_post_message(SEED_CHANNEL, "   ")
        assert out["status"] == "error"

    async def test_unknown_channel_not_found(self) -> None:
        out = await _server().slack_post_message("inc-ghost", "x")
        assert out["status"] == "not_found"


# ---------------------------------------------------------------------------
# Pins
# ---------------------------------------------------------------------------


class TestPinMessage:
    async def test_pin_sets_flag(self) -> None:
        server = _server()
        posted = await server.slack_post_message(SEED_CHANNEL, "New status of record.")
        out = await server.slack_pin_message(SEED_CHANNEL, posted["ts"])
        assert out["status"] == "success"
        pinned = [m for m in MOCK_SLACK_LEDGER[SEED_CHANNEL]["messages"] if m["pinned"]]
        assert {m["ts"] for m in pinned} == {SEED_PINNED_TS, posted["ts"]}

    async def test_unknown_ts_not_found(self) -> None:
        out = await _server().slack_pin_message(SEED_CHANNEL, "999.0")
        assert out["status"] == "not_found"

    async def test_unknown_channel_not_found(self) -> None:
        out = await _server().slack_pin_message("inc-ghost", SEED_PINNED_TS)
        assert out["status"] == "not_found"


# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------


class TestChannelHistory:
    async def test_seeded_history_newest_first(self) -> None:
        out = await _server().slack_get_channel_history(SEED_CHANNEL)
        assert out["status"] == "success"
        assert out["total"] == 2
        ts_list = [m["ts"] for m in out["messages"]]
        assert ts_list == sorted(ts_list, reverse=True)
        assert out["messages"][-1]["pinned"] is True  # the oldest seeded message

    async def test_new_posts_appear_first(self) -> None:
        server = _server()
        posted = await server.slack_post_message(SEED_CHANNEL, "Latest update")
        out = await server.slack_get_channel_history(SEED_CHANNEL)
        assert out["messages"][0]["ts"] == posted["ts"]

    async def test_limit_caps_messages(self) -> None:
        out = await _server().slack_get_channel_history(SEED_CHANNEL, limit=1)
        assert out["total"] == 1

    async def test_unknown_channel_not_found(self) -> None:
        out = await _server().slack_get_channel_history("inc-ghost")
        assert out["status"] == "not_found"


# ---------------------------------------------------------------------------
# Live mode refuses without a bot token
# ---------------------------------------------------------------------------


class TestLiveModeRefusesWithoutToken:
    async def test_live_mode_without_token_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("BTAGENT_SLACK_BOT_TOKEN", raising=False)
        server = SlackMCPServer(mock_mode=False, bot_token_ref="${env:BTAGENT_SLACK_BOT_TOKEN}")
        with pytest.raises(NotImplementedError):
            await server.slack_create_incident_channel("x")
        with pytest.raises(NotImplementedError):
            await server.slack_post_message(SEED_CHANNEL, "x")
        with pytest.raises(NotImplementedError):
            await server.slack_pin_message(SEED_CHANNEL, SEED_PINNED_TS)
        with pytest.raises(NotImplementedError):
            await server.slack_get_channel_history(SEED_CHANNEL)

    async def test_live_mode_real_path_not_yet_implemented(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("BTAGENT_SLACK_BOT_TOKEN", "xobb-fake-0123456789abcdef")
        server = SlackMCPServer(mock_mode=False, bot_token_ref="${env:BTAGENT_SLACK_BOT_TOKEN}")
        with pytest.raises(NotImplementedError):
            await server.slack_post_message(SEED_CHANNEL, "x")


# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------


class TestSecretRedaction:
    def test_repr_omits_secret(self) -> None:
        server = SlackMCPServer(mock_mode=False, bot_token_ref="${env:BTAGENT_SLACK_BOT_TOKEN}")
        assert "xobb-fake" not in repr(server)

    def test_redact_secret_short_returns_placeholder(self) -> None:
        assert _redact_secret("short") == "[redacted]"
        assert _redact_secret("") == "[redacted]"

    def test_redact_secret_long_returns_fingerprint(self) -> None:
        out = _redact_secret("xobb-fake-0123456789abcdef")
        assert out.startswith("[redacted:slack-bot-token:")
        assert "xobb-fake-0123456789" not in out

    async def test_live_mode_log_lines_redact_secret(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setenv("BTAGENT_SLACK_BOT_TOKEN", "xobb-fake-0123456789abcdef")
        server = SlackMCPServer(mock_mode=False, bot_token_ref="${env:BTAGENT_SLACK_BOT_TOKEN}")
        with caplog.at_level(logging.WARNING, logger="btagent.mcp.servers.slack"):
            with pytest.raises(NotImplementedError):
                await server.slack_create_incident_channel("x")
        for record in caplog.records:
            assert "xobb-fake-0123456789abcdef" not in record.getMessage()


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
            name="slack",
            description="slack test",
            circuit_breaker_threshold=3,
            circuit_breaker_recovery=60,
        )
        conn = await registry.get_connection("slack", config=cfg, consumer_id="inv_test")
        assert conn.circuit_breaker.state is CircuitState.CLOSED

        for _ in range(3):
            registry.record_failure("slack", RuntimeError("simulated 503"))
        assert conn.circuit_breaker.state is CircuitState.OPEN
        with pytest.raises(CircuitOpenError):
            conn.circuit_breaker.check_state()


# ---------------------------------------------------------------------------
# Discovery registration + construction hygiene
# ---------------------------------------------------------------------------


class TestDiscoveryRegistration:
    def test_slack_server_registered_in_discovery(self) -> None:
        from btagent_agents.mcp import discovery

        discovery._ensure_servers_loaded()
        assert "slack" in discovery._SERVER_CLASSES
        assert discovery._SERVER_CLASSES["slack"] is SlackMCPServer

    def test_tool_metadata_marks_slack_server(self) -> None:
        meta = _server().get_tool_metadata()
        assert {m["name"] for m in meta} == {
            "slack_create_incident_channel",
            "slack_post_message",
            "slack_pin_message",
            "slack_get_channel_history",
        }
        assert all(m["server_id"] == "slack" for m in meta)


def test_construction_does_not_resolve_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Constructing the server must never read the secret ref (lazy resolution)."""
    calls: list[str] = []

    def _spy(ref: str) -> str:
        calls.append(ref)
        return ""

    monkeypatch.setattr("btagent_agents.mcp.servers.slack_mcp.resolve_secret", _spy)
    SlackMCPServer(mock_mode=False)
    assert calls == []
