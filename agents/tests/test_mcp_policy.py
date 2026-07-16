"""Manifest policy enforcement in the MCP router (#100 Layer 3).

The engine's suite pins ConnectorPolicyMiddleware for integration nodes;
this suite is the same contract for the agents-side router:

- TLP ordering + the allowed/blocked matrix (a capability's declared
  egress is the highest context classification it may run at)
- HITL gate: containment actions refused without approval, allowed with
  the resume-path flag; queries never gated
- fail-closed on undeclared tool names
- router integration: the envelopes actually come back from
  ``mcp_router_tool`` and approved calls dispatch through to the mock
"""

from __future__ import annotations

import pytest
from btagent_shared.types.config import TLP

from btagent_agents.mcp.discovery import mcp_router_tool
from btagent_agents.mcp.policy import (
    TLP_RANK,
    evaluate_tool_call,
    get_active_tlp,
    is_tlp_allowed,
    reset_active_tlp,
    set_active_tlp,
)


@pytest.fixture(autouse=True)
def _unrestricted_tlp():
    """Every test starts (and ends) with no active classification."""
    reset_active_tlp()
    yield
    reset_active_tlp()


# --------------------------------------------------------------------------- #
# TLP ordering
# --------------------------------------------------------------------------- #


class TestTlpOrdering:
    def test_rank_is_strictly_increasing_with_restrictiveness(self) -> None:
        assert (
            TLP_RANK[TLP.WHITE]
            < TLP_RANK[TLP.GREEN]
            < TLP_RANK[TLP.AMBER]
            < TLP_RANK[TLP.AMBER_STRICT]
            < TLP_RANK[TLP.RED]
        )

    def test_no_active_classification_allows_everything(self) -> None:
        for cap_tlp in TLP:
            assert is_tlp_allowed(cap_tlp, None)

    def test_red_capability_allowed_at_any_context(self) -> None:
        for active in TLP:
            assert is_tlp_allowed(TLP.RED, active)

    def test_amber_strict_capability_blocked_at_red_only(self) -> None:
        assert not is_tlp_allowed(TLP.AMBER_STRICT, TLP.RED)
        for active in (TLP.AMBER_STRICT, TLP.AMBER, TLP.GREEN, TLP.WHITE):
            assert is_tlp_allowed(TLP.AMBER_STRICT, active)


# --------------------------------------------------------------------------- #
# Verdicts
# --------------------------------------------------------------------------- #


class TestVerdicts:
    def test_query_allowed_unrestricted(self) -> None:
        verdict = evaluate_tool_call("splunk_search")
        assert verdict.allowed and verdict.server_id == "splunk"

    def test_containment_action_requires_hitl(self) -> None:
        verdict = evaluate_tool_call("mde_isolate_machine")
        assert verdict.status == "hitl_required"
        assert verdict.detail["requires_hitl"] is True
        assert "single_host" in verdict.reason

    def test_containment_action_allowed_with_approval(self) -> None:
        verdict = evaluate_tool_call("mde_isolate_machine", hitl_approved=True)
        assert verdict.allowed

    def test_sink_action_needs_no_approval(self) -> None:
        assert evaluate_tool_call("jira_create_incident").allowed
        assert evaluate_tool_call("slack_post_message").allowed

    def test_git_pr_composer_requires_hitl(self) -> None:
        assert evaluate_tool_call("git_open_detection_pr").status == "hitl_required"

    def test_org_tenant_query_blocked_at_red(self) -> None:
        verdict = evaluate_tool_call("okta_system_log_search", active_tlp=TLP.RED)
        assert verdict.status == "tlp_blocked"
        assert verdict.detail == {"capability_tlp": "amber_strict", "active_tlp": "red"}

    def test_on_prem_query_allowed_at_red(self) -> None:
        assert evaluate_tool_call("zeek_log_search", active_tlp=TLP.RED).allowed

    def test_tlp_check_precedes_hitl(self) -> None:
        """A gated org-tenant action at RED is refused for TLP, not HITL."""
        verdict = evaluate_tool_call("mde_isolate_machine", active_tlp=TLP.RED)
        assert verdict.status == "tlp_blocked"

    def test_undeclared_tool_fails_closed(self) -> None:
        verdict = evaluate_tool_call("totally_new_tool")
        assert verdict.status == "undeclared"
        assert not verdict.allowed
        assert "fail-closed" in verdict.reason

    def test_global_active_tlp_is_used_by_default(self) -> None:
        set_active_tlp(TLP.RED)
        assert get_active_tlp() is TLP.RED
        assert evaluate_tool_call("okta_system_log_search").status == "tlp_blocked"
        reset_active_tlp()
        assert evaluate_tool_call("okta_system_log_search").allowed

    def test_envelope_shape(self) -> None:
        env = evaluate_tool_call("mde_isolate_machine").to_envelope()
        assert env["status"] == "hitl_required"
        assert env["tool_name"] == "mde_isolate_machine"
        assert env["server_id"] == "defender_endpoint"
        assert env["requires_hitl"] is True


# --------------------------------------------------------------------------- #
# Router integration — the envelopes come back from actual dispatch
# --------------------------------------------------------------------------- #


class TestRouterIntegration:
    async def test_query_dispatches_to_mock(self) -> None:
        out = await mcp_router_tool.ainvoke({"tool_name": "s1_list_threats", "arguments": "{}"})
        assert out["status"] == "success" and out["is_mock"] is True

    async def test_containment_refused_without_approval(self) -> None:
        out = await mcp_router_tool.ainvoke(
            {"tool_name": "mde_isolate_machine", "arguments": '{"hostname": "WS-FINANCE-07"}'}
        )
        assert out["status"] == "hitl_required"
        assert out["requires_hitl"] is True

    async def test_containment_dispatches_with_approval(self) -> None:
        out = await mcp_router_tool.ainvoke(
            {
                "tool_name": "mde_isolate_machine",
                "arguments": '{"hostname": "WS-FINANCE-07"}',
                "hitl_approved": True,
            }
        )
        assert out["status"] == "success"
        assert out["isolation_state"] == "Isolated"

    async def test_tlp_blocked_at_red_context(self) -> None:
        set_active_tlp(TLP.RED)
        out = await mcp_router_tool.ainvoke(
            {"tool_name": "okta_list_oauth_grants", "arguments": "{}"}
        )
        assert out["status"] == "tlp_blocked"

    async def test_unknown_tool_refused_before_dispatch(self) -> None:
        out = await mcp_router_tool.ainvoke({"tool_name": "totally_new_tool"})
        assert out["status"] == "undeclared"
