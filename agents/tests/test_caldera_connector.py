"""Unit tests for the MITRE Caldera MCP connector (#118).

Mock-first, sandbox-only adversary-operation driver. Same discipline as the
Atomic Red Team connector: the mock path fires NOTHING, records operations and
seeds synthetic detection telemetry (shared with the atomic connector's ledger),
and live mode is fail-closed.
"""

from __future__ import annotations

import pytest

from btagent_agents.mcp.servers.atomic_red_team_mcp import MOCK_DETECTION_LEDGER
from btagent_agents.mcp.servers.caldera_mcp import (
    MOCK_OPERATION_LEDGER,
    CalderaMCPServer,
)


@pytest.fixture(autouse=True)
def _clean_ledgers() -> None:
    MOCK_OPERATION_LEDGER.clear()
    MOCK_DETECTION_LEDGER.clear()


class TestMockPath:
    async def test_list_abilities_returns_catalog(self) -> None:
        server = CalderaMCPServer(mock_mode=True)
        out = await server.list_abilities()
        assert out["status"] == "success" and out["is_mock"] is True
        assert out["total"] >= 3

    async def test_list_abilities_filters_by_tactic(self) -> None:
        server = CalderaMCPServer(mock_mode=True)
        out = await server.list_abilities(tactic="execution")
        assert out["total"] == 1
        assert out["abilities"][0]["tactic"] == "execution"

    async def test_run_operation_fires_nothing_and_seeds_chain_telemetry(self) -> None:
        server = CalderaMCPServer(mock_mode=True)
        out = await server.run_operation("ingress_chain")
        assert out["status"] == "success" and out["is_mock"] is True
        assert out["executed"] is False
        assert out["operation_id"].startswith("calop_")
        assert out["technique_chain"] == ["T1059.001", "T1105"]
        # One synthetic detection per catalogued technique in the chain.
        assert len(MOCK_OPERATION_LEDGER) == 1
        seeded = {d["technique_id"] for d in MOCK_DETECTION_LEDGER}
        assert seeded == {"T1059.001", "T1105"}
        assert all(d["executed"] is False for d in out.get("ability_results", []))

    async def test_run_operation_requires_profile(self) -> None:
        server = CalderaMCPServer(mock_mode=True)
        with pytest.raises(ValueError, match="non-empty adversary_profile"):
            await server.run_operation("")

    async def test_get_operation_results_roundtrip(self) -> None:
        server = CalderaMCPServer(mock_mode=True)
        ran = await server.run_operation("discovery_chain")
        out = await server.get_operation_results(ran["operation_id"])
        assert out["status"] == "success"
        assert out["operation_id"] == ran["operation_id"]
        assert out["adversary_profile"] == "discovery_chain"

    async def test_get_operation_results_not_found(self) -> None:
        server = CalderaMCPServer(mock_mode=True)
        out = await server.get_operation_results("calop_missing")
        assert out["status"] == "not_found"


class TestLiveModeIsFailClosed:
    async def test_live_run_operation_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("BTAGENT_CALDERA_TOKEN", raising=False)
        server = CalderaMCPServer(mock_mode=False, token_ref="${env:BTAGENT_CALDERA_TOKEN}")
        with pytest.raises(NotImplementedError):
            await server.run_operation("ingress_chain")
        assert MOCK_OPERATION_LEDGER == []
        assert MOCK_DETECTION_LEDGER == []

    async def test_live_list_abilities_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("BTAGENT_CALDERA_TOKEN", raising=False)
        server = CalderaMCPServer(mock_mode=False, token_ref="${env:BTAGENT_CALDERA_TOKEN}")
        with pytest.raises(NotImplementedError):
            await server.list_abilities()

    def test_repr_omits_token(self) -> None:
        server = CalderaMCPServer(mock_mode=False)
        assert "token" not in repr(server).lower() or "ref" in repr(server).lower()


def test_registered_in_discovery() -> None:
    from btagent_agents.mcp import discovery

    discovery._ensure_servers_loaded()
    assert "caldera" in discovery._SERVER_CLASSES
    meta = CalderaMCPServer(mock_mode=True).get_tool_metadata()
    names = [m["name"] for m in meta]
    assert names == ["list_abilities", "run_operation", "get_operation_results"]
    assert all(m["server_id"] == "caldera" for m in meta)
