"""Code-based detector: prompt-injection input scan (agentic hunt pack #121).

This module is the *pack entry point* for the prompt-injection detector.  The
actual logic lives in :mod:`btagent_shared.hunt.agentic` so it is dependency-
free and unit-testable.

The pack runner calls :func:`run` with a batch of agent-call events (from a
fixture or future LLM-call telemetry connector) and receives a list of
:class:`~btagent_shared.types.hunt_finding.RecordFindingRequest` objects.

Live-wiring TODO (deferred):
  Replace ``events`` parameter with a call to the LLM-call telemetry MCP
  connector (Bedrock invocation logs, Vertex request/response capture, or an
  inference-gateway tap) and stream ``AgentCallEvent`` records into this
  detector at ingest rate.  The detection logic itself requires no changes.
"""

from __future__ import annotations

from btagent_shared.hunt.agentic import detect_prompt_injection
from btagent_shared.types.agentic_hunt import AgentCallEvent
from btagent_shared.types.hunt_finding import RecordFindingRequest


def run(events: list[AgentCallEvent]) -> list[RecordFindingRequest]:
    """Run the prompt-injection scan over a batch of agent-call events.

    Parameters
    ----------
    events:
        Per-invocation agent-call telemetry.  Loaded from a fixture (tests) or
        future LLM-call telemetry connector output (production).

    Returns
    -------
    list[RecordFindingRequest]
        One finding per event that matched at least one prompt-injection
        signature, aggregated across all signal categories.
    """
    return detect_prompt_injection(events)
