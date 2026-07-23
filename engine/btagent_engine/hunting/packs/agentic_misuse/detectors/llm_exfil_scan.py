"""Code-based detector: LLM-exfil scan (agentic hunt pack #121, Phase A4).

Pack entry point for the LLM-exfil detector.  The logic lives in
:mod:`btagent_shared.hunt.agentic` so it is dependency-free and
unit-testable.

Where the prompt-injection detector flags exfil *requests* (an input asking
the agent to reveal secrets), this one flags exfil *material*: actual secret
patterns (cloud keys, tokens, private keys) present in either direction of
an agent call, plus abnormally large outbound prompts — the bulk-exfil
channel called out in issue #121.

Live-wiring TODO (deferred):
  Same telemetry tap as ``prompt_injection_scan`` — stream ``AgentCallEvent``
  records (with ``output_text`` populated from response capture) into this
  detector at ingest rate.  The detection logic itself requires no changes.
"""

from __future__ import annotations

from btagent_shared.hunt.agentic import detect_llm_exfil
from btagent_shared.types.agentic_hunt import AgentCallEvent
from btagent_shared.types.hunt_finding import RecordFindingRequest


def run(events: list[AgentCallEvent]) -> list[RecordFindingRequest]:
    """Run the LLM-exfil scan over a batch of agent-call events.

    Parameters
    ----------
    events:
        Per-invocation agent-call telemetry.  Loaded from a fixture (tests) or
        future LLM-call telemetry connector output (production).

    Returns
    -------
    list[RecordFindingRequest]
        One finding per event carrying secret material or an oversized
        outbound prompt.  Matched secrets are masked before entering evidence.
    """
    return detect_llm_exfil(events)
