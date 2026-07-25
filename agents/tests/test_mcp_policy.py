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
    hitl_approval,
    is_tlp_allowed,
    reset_active_tlp,
    reset_hitl_approved,
    set_active_tlp,
    set_hitl_approved,
)


@pytest.fixture(autouse=True)
def _unrestricted_tlp():
    """Every test starts (and ends) with no active classification and no
    server-set HITL approval."""
    reset_active_tlp()
    reset_hitl_approved()
    yield
    reset_active_tlp()
    reset_hitl_approved()


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
        # Approval comes from the server-controlled resume path (a run-scoped
        # contextvar), NOT a model-supplied tool argument (#374).
        with hitl_approval():
            out = await mcp_router_tool.ainvoke(
                {"tool_name": "mde_isolate_machine", "arguments": '{"hostname": "WS-FINANCE-07"}'}
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


# --------------------------------------------------------------------------- #
# #374 — HITL approval is server-controlled, never a model-settable tool arg
# --------------------------------------------------------------------------- #


class TestHitlApprovalIsServerControlled:
    def test_hitl_approved_absent_from_model_facing_schema(self) -> None:
        """The router must not expose ``hitl_approved`` to the model at all —
        the LLM has no parameter to fill in to self-approve containment."""
        assert "hitl_approved" not in mcp_router_tool.args

    async def test_model_supplied_hitl_approved_cannot_bypass_gate(self) -> None:
        """A prompt-injected/misaligned agent that tries to pass
        ``hitl_approved`` as an argument is ignored — the HITL gate still
        refuses the containment action (#374)."""
        out = await mcp_router_tool.ainvoke(
            {
                "tool_name": "cs_isolate_host",
                "arguments": '{"hostname": "WS-JSMITH-PC"}',
                "hitl_approved": True,  # model-supplied — must be ignored
            }
        )
        assert out["status"] == "hitl_required"
        assert out["requires_hitl"] is True

    async def test_server_set_approval_passes_gate(self) -> None:
        """The server-controlled resume path (contextvar) CAN approve a gated
        action — this is the only path that works."""
        set_hitl_approved(True)
        try:
            out = await mcp_router_tool.ainvoke(
                {"tool_name": "cs_isolate_host", "arguments": '{"hostname": "WS-JSMITH-PC"}'}
            )
        finally:
            reset_hitl_approved()
        assert out["status"] == "success"

    async def test_approval_does_not_leak_past_resume_scope(self) -> None:
        """Once the resume scope exits, the approval is cleared — a later
        model-issued call is gated again (no sticky self-approval)."""
        with hitl_approval():
            approved = await mcp_router_tool.ainvoke(
                {"tool_name": "cs_isolate_host", "arguments": '{"hostname": "WS-JSMITH-PC"}'}
            )
        after = await mcp_router_tool.ainvoke(
            {"tool_name": "cs_isolate_host", "arguments": '{"hostname": "WS-JSMITH-PC"}'}
        )
        assert approved["status"] == "success"
        assert after["status"] == "hitl_required"


# --------------------------------------------------------------------------- #
# #397 — the TLP-egress gate actually engages on the production dispatch path,
# wired per-run by the classification hook, with contextvar isolation.
# --------------------------------------------------------------------------- #


class TestTlpGateEngagesOnDispatchPath:
    @staticmethod
    def _make_classification_hook(tlp: TLP):
        """Construct the per-run ClassificationHook exactly as production does
        (it binds the investigation's TLP into the MCP dispatch path)."""
        from unittest.mock import AsyncMock

        from btagent_shared.types.config import ModelProvider

        from btagent_agents.hooks.classification_hook import ClassificationHook

        return ClassificationHook(
            emitter=AsyncMock(),
            tlp_level=tlp,
            provider=ModelProvider.OLLAMA,
            investigation_id=f"inv_{tlp.value}",
        )

    async def test_red_investigation_blocks_amber_strict_tool_via_router(self) -> None:
        """Constructing the RED classification hook makes the router refuse an
        AMBER_STRICT-egress tool with ``tlp_blocked`` (#397). Previously
        ``set_active_tlp`` was never called in prod, so the gate never fired."""
        self._make_classification_hook(TLP.RED)
        out = await mcp_router_tool.ainvoke(
            {"tool_name": "okta_list_oauth_grants", "arguments": "{}"}
        )
        assert out["status"] == "tlp_blocked"

    async def test_concurrent_investigations_do_not_clobber_tlp(self) -> None:
        """Two investigations running concurrently keep independent active-TLP
        state (ContextVar per task, not a shared process-global). A leaked
        global would let the second run's classification overwrite the first."""
        import asyncio

        async def run_investigation(tlp: TLP) -> str:
            self._make_classification_hook(tlp)
            # Force interleaving: if the state were a process-global, the other
            # task's set would clobber ours before we dispatch.
            await asyncio.sleep(0)
            out = await mcp_router_tool.ainvoke(
                {"tool_name": "okta_list_oauth_grants", "arguments": "{}"}
            )
            return out["status"]

        red_status, white_status = await asyncio.gather(
            asyncio.create_task(run_investigation(TLP.RED)),
            asyncio.create_task(run_investigation(TLP.WHITE)),
        )
        # RED context blocks the AMBER_STRICT tool; the WHITE context running
        # alongside it dispatches successfully — no cross-contamination.
        assert red_status == "tlp_blocked"
        assert white_status == "success"
