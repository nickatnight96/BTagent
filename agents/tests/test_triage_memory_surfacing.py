"""The recalled ``<agent-memory>`` block must reach the analyst, once.

#611: investigation create recalls org memory, renders it to a fenced
``<agent-memory>`` block, and carries it into graph state as
``agent_memory`` — where, before this, nothing read it. The recall pipeline
(store → consolidate → recall → render → carry) was complete and its output
was dead state.

The first triage response is the block's live consumer. These tests pin the
contract of that surfacing:

- it appears in the FIRST triage response, fence intact (the block was already
  fence-neutralised and size-capped at render time, and the persisted
  transcript may be replayed into LLM context where the fence marks it as
  data, not instructions);
- it appears ONLY in the first response — any prior ``AIMessage`` in the
  transcript means it has already been shown;
- absent/blank memory renders nothing, not an empty header;
- surfacing is purely additive: with the section removed, the response is
  byte-identical to the no-memory response.
"""

from __future__ import annotations

from typing import Any

from langchain_core.messages import AIMessage, HumanMessage

from btagent_agents.orchestrator.nodes import triage_node

MEMORY_BLOCK = (
    "<agent-memory>\n"
    "- [entity_note] host web-01: AdminToolX flags EDR weekly; documented false positive\n"
    "</agent-memory>"
)

ALERT = "Suspicious PowerShell on host web-01 contacting 203.0.113.7"


def _state(agent_memory: Any = "", messages: list | None = None) -> dict[str, Any]:
    return {
        "investigation_id": "inv_memory_surfacing",
        "iocs": [],
        "timeline": [],
        "messages": messages if messages is not None else [HumanMessage(content=ALERT)],
        "agent_memory": agent_memory,
    }


def test_first_triage_response_surfaces_the_block_verbatim():
    result = triage_node(_state(agent_memory=MEMORY_BLOCK))

    text = result["messages"][0].content
    assert "Relevant agency memory (recalled from prior investigations):" in text
    # Verbatim, fence intact: the transcript persists and may be replayed into
    # LLM context, where the fence is what marks the content as data.
    assert MEMORY_BLOCK in text


def test_later_turns_do_not_repeat_the_block():
    # A prior AIMessage means the block was already surfaced on the first
    # response; repeating it on every follow-up would bury the new content.
    messages = [
        HumanMessage(content=ALERT),
        AIMessage(content="**Triage Analysis** (earlier turn)"),
        HumanMessage(content="also check host db-02"),
    ]
    result = triage_node(_state(agent_memory=MEMORY_BLOCK, messages=messages))

    text = result["messages"][0].content
    assert "Relevant agency memory" not in text
    assert "<agent-memory>" not in text


def test_absent_or_blank_memory_renders_nothing():
    for empty in (None, "", "   \n  "):
        result = triage_node(_state(agent_memory=empty))
        text = result["messages"][0].content
        assert "Relevant agency memory" not in text, f"leaked header for {empty!r}"
        assert "<agent-memory>" not in text


def test_surfacing_is_purely_additive():
    """Guard the guard: with the section cut out, the responses are identical.

    This is what stops the feature from quietly rewriting other parts of the
    triage output — severity, IOC summary, MITRE section — under cover of
    "adding" the memory block. Timestamps differ between the two calls, so the
    comparison stops at the timeline line.
    """
    with_memory = triage_node(_state(agent_memory=MEMORY_BLOCK))["messages"][0].content
    without_memory = triage_node(_state(agent_memory=""))["messages"][0].content

    section = f"Relevant agency memory (recalled from prior investigations):\n{MEMORY_BLOCK}\n\n"
    assert section in with_memory

    marker = "Timeline entry added at"
    stripped = with_memory.replace(section, "", 1)
    assert stripped.split(marker)[0] == without_memory.split(marker)[0]
