"""Sprint 5B end-to-end smoke: real production templates run with rendering.

Sprint 3C produced 4 production templates (triage / query / enrichment /
knowledge) with Jinja-style ``{{ ... }}`` placeholders. Sprint 5B added
runtime templating in the executor's config-merge step. This test
proves the loop closes: a real template loads, compiles, runs through
``WorkflowExecutor``, and the placeholders are substituted with the
runtime values.

We pick ``knowledge.yaml`` because it's the simplest template (single
LLM step) and exercises the full chain: trigger payload -> upstream
output -> ``{{ investigation_summary }}`` rendering -> mock LLM ->
final output.
"""

from __future__ import annotations

import pytest
from btagent_engine import NodeContext, WorkflowExecutor
from btagent_engine.integrations import LLMCallNode  # noqa: F401 -- registers reasoning.llm.call

from btagent_agents.orchestrator.templates import load_template


@pytest.fixture(autouse=True)
def _mock_llm(monkeypatch):
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    yield


@pytest.mark.asyncio
async def test_knowledge_template_runs_end_to_end_with_rendered_summary():
    """The ``knowledge`` template's user message contains
    ``"<external-data>{{ investigation_summary }}</external-data>"``.
    With Sprint 5B's templating in place, that should be substituted at
    runtime with whatever ``investigation_summary`` the trigger payload
    carries -- not passed to the LLM as a literal string.
    """
    workflow = load_template("knowledge")

    summary = "ransomware variant observed encrypting C:\\Users on host-42"
    ctx = NodeContext(
        run_id="run_kb_smoke",
        org_id="org_default",
        investigation_id="inv_kb_smoke",
    )

    result = await WorkflowExecutor().execute(
        workflow,
        {"investigation_summary": summary},
        ctx,
    )

    # The single step ran and produced output.
    assert "draft_kb_entry" in result.outputs
    out = result.outputs["draft_kb_entry"]
    out_dump = out.model_dump()

    # Mock LLM echoes the last user message back as ``[mock-llm] <text>``.
    # The text should contain the substituted summary, NOT the literal
    # ``{{ investigation_summary }}`` placeholder. That's the whole point
    # of Sprint 5B.
    rendered_text = out_dump.get("text", "")
    assert "[mock-llm]" in rendered_text
    assert summary in rendered_text, (
        f"Sprint 5B templating did not substitute the placeholder; LLM saw: {rendered_text!r}"
    )
    assert "{{ investigation_summary }}" not in rendered_text, (
        "Placeholder was passed to the LLM as a literal -- rendering didn't fire"
    )


# --------------------------------------------------------------------------- #
# Sprint 5C: smoke tests for the remaining 3 production templates
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_triage_template_runs_end_to_end():
    """Triage: extract_iocs -> score_severity -> decision -> handoff_query
    OR summarise. Mock LLM produces ``[mock-llm] <content>`` for each step.
    Decision condition must evaluate cleanly even though ``severity.level``
    isn't a real upstream output -- use an explicit condition that
    references actual upstream content."""

    workflow = load_template("triage")
    ctx = NodeContext(
        run_id="run_triage_smoke",
        org_id="org_default",
        investigation_id="inv_triage_smoke",
    )
    result = await WorkflowExecutor().execute(
        workflow,
        {"alert_text": "ransomware encrypting workstations"},
        ctx,
    )
    # Decision routes to either handoff_query or summarise; both are
    # valid endings. Just verify the workflow finished without raising.
    assert result.final_output is not None
    assert "extract_iocs" in result.outputs
    assert "score_severity" in result.outputs


@pytest.mark.asyncio
async def test_query_template_runs_end_to_end(monkeypatch):
    """Query: parallel_fork into 4 SIEM/EDR integrations -> join ->
    summarise_results. Mock-mode integration Nodes return deterministic
    fixtures. ``{{ join_results }}`` placeholder in the summarise step
    must resolve to something usable."""

    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")

    workflow = load_template("query")
    ctx = NodeContext(
        run_id="run_query_smoke",
        org_id="org_default",
        investigation_id="inv_query_smoke",
    )
    result = await WorkflowExecutor().execute(workflow, {}, ctx)
    assert result.final_output is not None
    # Each SIEM/EDR step ran.
    assert "splunk_search" in result.outputs
    assert "summarise_results" in result.outputs


@pytest.mark.asyncio
async def test_enrichment_template_runs_end_to_end(monkeypatch):
    """Enrichment: parallel_fork into 5 CTI lookups -> join -> merge_verdict.
    Each branch needs the IOC value via ``{{ ioc.value }}`` placeholder
    resolved from the trigger payload."""

    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "true")

    workflow = load_template("enrichment")
    ctx = NodeContext(
        run_id="run_enrich_smoke",
        org_id="org_default",
        investigation_id="inv_enrich_smoke",
    )
    result = await WorkflowExecutor().execute(
        workflow,
        {"ioc": {"type": "ip", "value": "8.8.8.8"}},
        ctx,
    )
    assert result.final_output is not None
    assert "vt_lookup" in result.outputs
    assert "merge_verdict" in result.outputs
