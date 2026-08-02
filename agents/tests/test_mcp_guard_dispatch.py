"""A3 / P3.2: the manifest policy gate must run on the REAL dispatch path.

``evaluate_tool_call``'s only caller used to be ``mcp_router_tool``, which no
plugin returns — production dispatch imports MCP server classes directly, so
the TLP-egress / HITL declarations in ``manifests.py`` were documentation.
:func:`guard_dispatch` is the enforcement now invoked at every direct dispatch
site; these tests pin the gate itself and its wiring into the hunt verticals.
"""

from __future__ import annotations

from typing import Any

import pytest
from btagent_shared.types.config import TLP

from btagent_agents.mcp.policy import (
    MCPPolicyRefused,
    active_tlp_scope,
    guard_dispatch,
)
from btagent_agents.plugins.triage.deception_hunt import run_deception_hunt_over_connector
from btagent_agents.plugins.triage.email_hunt import gather_email_envelopes
from btagent_agents.plugins.triage.ndr_hunt import run_ndr_hunt_over_connector

# --------------------------------------------------------------------------- #
# The gate itself
# --------------------------------------------------------------------------- #


def test_declared_query_capability_is_allowed():
    verdict = guard_dispatch("canary_list_incidents")
    assert verdict.allowed


def test_undeclared_tool_is_refused_fail_closed():
    with pytest.raises(MCPPolicyRefused) as exc:
        guard_dispatch("totally_made_up_tool")
    assert exc.value.verdict.status == "undeclared"


def test_hitl_gated_action_refused_without_server_side_approval():
    with pytest.raises(MCPPolicyRefused) as exc:
        guard_dispatch("cs_isolate_host")
    assert exc.value.verdict.status == "hitl_required"


def test_hitl_gated_action_allowed_with_server_side_approval():
    assert guard_dispatch("cs_isolate_host", hitl_approved=True).allowed


def test_tlp_blocked_capability_is_refused():
    """An AMBER_STRICT-egress capability may not run in a RED context."""
    with pytest.raises(MCPPolicyRefused) as exc:
        guard_dispatch("o365_email_events_search", active_tlp=TLP.RED)
    assert exc.value.verdict.status == "tlp_blocked"


# --------------------------------------------------------------------------- #
# Wiring: the hunt verticals refuse fail-closed under a blocking TLP context
# --------------------------------------------------------------------------- #


class _Recorder:
    """Connector stand-in that records whether its tool was ever called."""

    def __init__(self, server_id: str, method_name: str, envelope: dict[str, Any]) -> None:
        self.server_id = server_id
        self.calls = 0
        self._envelope = envelope

        async def _tool(*args: Any, **kwargs: Any) -> dict[str, Any]:
            self.calls += 1
            return self._envelope

        setattr(self, method_name, _tool)


@pytest.mark.asyncio
async def test_email_hunt_skips_streams_refused_by_policy():
    """Under an active RED classification every AMBER_STRICT email stream is
    refused BEFORE the connector is invoked — the tool never runs."""
    server = _Recorder("defender_o365", "o365_email_events_search", {"messages": []})

    with active_tlp_scope(TLP.RED):
        envelopes = await gather_email_envelopes([server], start="a", end="b")
    assert envelopes == []
    assert server.calls == 0

    # Without the restriction the same stream flows.
    envelopes = await gather_email_envelopes([server], start="a", end="b")
    assert server.calls >= 1


@pytest.mark.asyncio
async def test_deception_hunt_degrades_to_empty_under_blocking_tlp():
    server = _Recorder("canary", "canary_list_incidents", {"incidents": []})
    with active_tlp_scope(TLP.RED):
        result = await run_deception_hunt_over_connector(server)
    assert result.findings == []
    assert server.calls == 0


@pytest.mark.asyncio
async def test_ndr_hunt_degrades_to_empty_under_blocking_tlp():
    server = _Recorder("vectra", "vectra_list_detections", {"detections": []})
    with active_tlp_scope(TLP.RED):
        result = await run_ndr_hunt_over_connector(server)
    assert result.findings == []
    assert server.calls == 0
