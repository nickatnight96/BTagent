"""Tests for per-audience cover-communication drafting (EPIC-6 UC-6.2 part B).

The ``draft_cover_communications`` tool builds DRAFT-ONLY cover notes from an
existing investigation summary:

* an email to a CISA liaison, and
* a Slack post to leadership.

The load-bearing invariant is that nothing is ever sent: every draft routes
through the HITL-gated MCP *draft* path, carries ``send: false`` /
``requires_approval: true``, and the top-level ``auto_send`` is ``False``.
"""

from __future__ import annotations

import json

from btagent_agents.plugins.coordination.tools.summarizer import (
    draft_cover_communications,
    summarize_investigation,
    summarize_multiple,
)

_INV = "inv_mock_001"


def _summary(inv: str = _INV) -> dict:
    return summarize_investigation.invoke({"investigation_id": inv})


def test_drafts_both_audiences_and_never_sends() -> None:
    """Both audiences get a draft and nothing is flagged for auto-send."""
    result = draft_cover_communications.invoke(
        {"summary_json": json.dumps(_summary()), "incident_ref": "INC-2025-0421"}
    )
    assert result["status"] == "success"
    # Hard guardrail: cover comms are never auto-sent.
    assert result["auto_send"] is False

    drafts = result["drafts"]
    assert result["draft_count"] == len(drafts) == 2
    assert {d["audience"] for d in drafts} == {"cisa_liaison", "leadership"}

    for draft in drafts:
        assert draft["send"] is False
        assert draft["requires_approval"] is True
        # Routed through the MCP *draft* path — not a direct send.
        assert "draft" in draft["mcp_draft_path"].lower()


def test_cisa_email_draft_is_built_from_summary() -> None:
    """The CISA email draft is an email carrying the exec + technical summary."""
    summary = _summary()
    result = draft_cover_communications.invoke(
        {"summary_json": json.dumps(summary), "incident_ref": "INC-2025-0421"}
    )
    email = next(d for d in result["drafts"] if d["audience"] == "cisa_liaison")

    assert email["channel"] == "email"
    assert email["mcp_draft_path"] == "email.create_draft"
    assert email["subject"].strip()
    # Cites the incident reference and is built from the summaries.
    assert "INC-2025-0421" in email["subject"] or "INC-2025-0421" in email["body"]
    assert summary["executive_summary"] in email["body"]
    assert summary["technical_summary"] in email["body"]


def test_leadership_slack_draft_is_built_from_summary() -> None:
    """The leadership draft is a Slack post carrying the executive summary."""
    summary = _summary()
    result = draft_cover_communications.invoke({"summary_json": json.dumps(summary)})
    slack = next(d for d in result["drafts"] if d["audience"] == "leadership")

    assert slack["channel"] == "slack"
    assert slack["mcp_draft_path"] == "slack.send_message_draft"
    assert "text" in slack
    assert summary["executive_summary"] in slack["text"]
    # Draft framing is explicit so an approver can't mistake it for a sent post.
    assert "DRAFT" in slack["text"]


def test_drafts_work_from_multi_investigation_summary() -> None:
    """A reduce-phase (multi) summary with no technical_summary still drafts."""
    multi = summarize_multiple.invoke({"investigation_ids": "inv_mock_001,inv_mock_002"})
    result = draft_cover_communications.invoke({"summary_json": json.dumps(multi)})
    assert result["status"] == "success"
    assert result["auto_send"] is False
    email = next(d for d in result["drafts"] if d["audience"] == "cisa_liaison")
    # Synthesized technical detail references the aggregated technique count.
    assert "MITRE ATT&CK" in email["body"]
    assert email["send"] is False


def test_invalid_summary_json_fails_cleanly() -> None:
    """Malformed JSON is rejected without raising."""
    result = draft_cover_communications.invoke({"summary_json": "{not json"})
    assert result["status"] == "failed"
    assert "drafts" not in result
