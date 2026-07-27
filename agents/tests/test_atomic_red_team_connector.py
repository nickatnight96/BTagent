"""Unit tests for the Atomic Red Team MCP connector (#118).

Mock-first, sandbox-only adversary-emulation trigger. These tests prove the
mock path fires NOTHING (``executed=False``), records runs + synthetic
telemetry in inspectable ledgers, cleans up, and that live mode is a
fail-closed ``NotImplementedError``. The connector registers with lazy
discovery and its tool metadata matches its manifest (drift lock lives in
``test_mcp_server_manifests.py``).
"""

from __future__ import annotations

import pytest

from btagent_agents.mcp.servers.atomic_red_team_mcp import (
    MOCK_ATOMIC_LEDGER,
    MOCK_DETECTION_LEDGER,
    AtomicRedTeamMCPServer,
    _redact_secret,
)


@pytest.fixture(autouse=True)
def _clean_ledgers() -> None:
    MOCK_ATOMIC_LEDGER.clear()
    MOCK_DETECTION_LEDGER.clear()


class TestMockPath:
    async def test_list_atomics_returns_catalog(self) -> None:
        server = AtomicRedTeamMCPServer(mock_mode=True)
        out = await server.list_atomics()
        assert out["status"] == "success" and out["is_mock"] is True
        assert out["total"] >= 4
        techniques = {a["technique_id"] for a in out["atomics"]}
        assert "T1059.001" in techniques

    async def test_list_atomics_filters_by_technique(self) -> None:
        server = AtomicRedTeamMCPServer(mock_mode=True)
        out = await server.list_atomics(technique_id="T1059.001")
        assert out["total"] == 1
        assert out["atomics"][0]["technique_id"] == "T1059.001"

    async def test_run_atomic_fires_nothing_and_seeds_telemetry(self) -> None:
        server = AtomicRedTeamMCPServer(mock_mode=True)
        out = await server.run_atomic("T1059.001")
        assert out["status"] == "success" and out["is_mock"] is True
        # The single most important assertion: the mock NEVER executes.
        assert out["executed"] is False
        assert out["run_id"].startswith("art_")
        assert out["expected_rule_id"] == "encoded_powershell"
        # A run recorded + synthetic telemetry seeded for the observe phase.
        assert len(MOCK_ATOMIC_LEDGER) == 1
        assert len(MOCK_DETECTION_LEDGER) == 1
        assert MOCK_DETECTION_LEDGER[0]["technique_id"] == "T1059.001"

    async def test_unknown_technique_seeds_no_telemetry(self) -> None:
        server = AtomicRedTeamMCPServer(mock_mode=True)
        out = await server.run_atomic("T9999")
        assert out["executed"] is False
        assert out["expected_rule_id"] is None
        # An uncatalogued technique produces no detectable firing → silent gap.
        assert MOCK_DETECTION_LEDGER == []

    async def test_run_atomic_requires_technique(self) -> None:
        server = AtomicRedTeamMCPServer(mock_mode=True)
        with pytest.raises(ValueError, match="non-empty technique_id"):
            await server.run_atomic("  ")

    async def test_cleanup_removes_run_telemetry(self) -> None:
        server = AtomicRedTeamMCPServer(mock_mode=True)
        ran = await server.run_atomic("T1059.001")
        assert len(MOCK_DETECTION_LEDGER) == 1
        out = await server.cleanup_atomic(ran["run_id"])
        assert out["status"] == "success"
        assert out["telemetry_removed"] == 1
        assert MOCK_DETECTION_LEDGER == []

    async def test_cleanup_requires_run_id(self) -> None:
        server = AtomicRedTeamMCPServer(mock_mode=True)
        with pytest.raises(ValueError, match="non-empty run_id"):
            await server.cleanup_atomic("")


class TestLiveModeIsFailClosed:
    async def test_live_run_atomic_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("BTAGENT_ART_TOKEN", raising=False)
        server = AtomicRedTeamMCPServer(mock_mode=False, token_ref="${env:BTAGENT_ART_TOKEN}")
        with pytest.raises(NotImplementedError):
            await server.run_atomic("T1059.001")
        # Live refusal must not have recorded a run or any telemetry.
        assert MOCK_ATOMIC_LEDGER == []
        assert MOCK_DETECTION_LEDGER == []

    async def test_live_list_atomics_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("BTAGENT_ART_TOKEN", raising=False)
        server = AtomicRedTeamMCPServer(mock_mode=False, token_ref="${env:BTAGENT_ART_TOKEN}")
        with pytest.raises(NotImplementedError):
            await server.list_atomics()

    def test_repr_omits_token(self) -> None:
        server = AtomicRedTeamMCPServer(mock_mode=False)
        assert "token" not in repr(server).lower() or "ref" in repr(server).lower()

    def test_redact_secret(self) -> None:
        assert _redact_secret("short") == "[redacted]"
        out = _redact_secret("art_0123456789abcdef")
        assert out.startswith("[redacted:art-token:")
        assert "art_0123456789" not in out

    def test_construction_does_not_resolve_secret(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls: list[str] = []
        monkeypatch.setattr(
            "btagent_agents.mcp.servers.atomic_red_team_mcp.resolve_secret",
            lambda ref: calls.append(ref) or "",
        )
        AtomicRedTeamMCPServer(mock_mode=False)
        assert calls == []


def test_registered_in_discovery() -> None:
    from btagent_agents.mcp import discovery

    discovery._ensure_servers_loaded()
    assert "atomic_red_team" in discovery._SERVER_CLASSES
    meta = AtomicRedTeamMCPServer(mock_mode=True).get_tool_metadata()
    names = [m["name"] for m in meta]
    assert names == ["list_atomics", "run_atomic", "cleanup_atomic"]
    assert all(m["server_id"] == "atomic_red_team" for m in meta)
