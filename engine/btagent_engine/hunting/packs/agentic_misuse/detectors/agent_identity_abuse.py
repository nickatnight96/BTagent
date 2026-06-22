"""Code-based detector: agent identity abuse (agentic hunt pack #121).

Compares each :class:`AgentCallEvent` against the registered
:class:`AgentIdentity` to flag out-of-toolset invocations, role-escalation
mismatches, and unregistered-agent activity.

Live-wiring TODO (deferred):
  - Replace fixture-supplied event batch with live telemetry stream.
  - Replace fixture-supplied identity registry with a live pull from the
    agent-platform inventory MCP connector.
  - Hook the detector into the engine pack runner as a streaming node so
    findings emit at event-arrival rate rather than batch.
"""

from __future__ import annotations

from btagent_shared.hunt.agentic import detect_agent_identity_abuse
from btagent_shared.types.agentic_hunt import AgentCallEvent, AgentIdentity
from btagent_shared.types.hunt_finding import RecordFindingRequest


def run(
    events: list[AgentCallEvent],
    identities: list[AgentIdentity],
    *,
    privileged_role_keywords: set[str] | None = None,
) -> list[RecordFindingRequest]:
    """Run the agent-identity-abuse detector.

    Parameters
    ----------
    events:
        Per-invocation agent-call telemetry.
    identities:
        Known agent registrations.
    privileged_role_keywords:
        Lowercase keyword set used to escalate role-mismatch findings to HIGH
        severity (default ``{"admin", "root", "billing", "orgadmin", "poweruser"}``).

    Returns
    -------
    list[RecordFindingRequest]
        One finding per divergent or unregistered call.
    """
    return detect_agent_identity_abuse(
        events,
        identities,
        privileged_role_keywords=privileged_role_keywords,
    )
