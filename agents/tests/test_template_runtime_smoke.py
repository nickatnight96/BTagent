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
