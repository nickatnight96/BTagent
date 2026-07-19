"""Deception-hunt runner — composition + connector gather (deception vertical, slice 2).

Ties the Thinkst Canary connector to the Phase 6 hunt-findings pipeline by
composing the two pure pieces already in place:

1. the deception-triage **correlator**
   (:func:`btagent_agents.plugins.triage.tools.deception_correlator.correlate_deception_events`),
   which ranks canary telemetry into deception incidents;
2. the deception **finding mapper**
   (:func:`btagent_shared.hunt.deception.deception_incidents_to_findings`),
   which turns those incidents into
   :class:`~btagent_shared.types.hunt_finding.RecordFindingRequest` objects.

Mirrors :mod:`btagent_agents.plugins.triage.email_hunt` but simpler: deception
telemetry comes from a **single** connector (Thinkst Canary) with no time
window, so the gather is one tool call. The pure entry points do no I/O; the
async :func:`run_deception_hunt_over_connector` is the only I/O boundary and
tolerates a connector failure so a hunt never crashes the caller. Persisting
the findings is a later (backend) slice.
"""

from __future__ import annotations

import logging
from typing import Any

from btagent_shared.hunt.deception import deception_incidents_to_findings
from btagent_shared.types.enums import Severity
from btagent_shared.types.hunt_finding import RecordFindingRequest
from pydantic import BaseModel, ConfigDict, Field

from btagent_agents.plugins.triage.tools.deception_correlator import correlate_deception_events

logger = logging.getLogger("btagent.hunt.deception")


class DeceptionHuntRunResult(BaseModel):
    """Outcome of one deception-hunt run — findings plus a triage summary."""

    model_config = ConfigDict(extra="forbid")

    findings: list[RecordFindingRequest] = Field(default_factory=list)
    total_incidents: int = 0
    # Attackers moving across more than one decoy — the correlator's headline.
    active_intruder_count: int = 0
    counts_by_severity: dict[str, int] = Field(default_factory=dict)
    attackers: list[dict[str, Any]] = Field(default_factory=list)


def run_deception_hunt(incidents: list[dict[str, Any]] | None = None) -> DeceptionHuntRunResult:
    """Correlate raw Canary incidents and map them into findings.

    Pure: no I/O. The lower-level entry point when the caller has already
    pulled the incident list (the ``incidents`` field of a
    ``canary_list_incidents`` envelope).
    """
    correlation = correlate_deception_events(incidents or [])
    findings = deception_incidents_to_findings(correlation)

    counts_by_severity: dict[str, int] = {s.value: 0 for s in Severity}
    for f in findings:
        counts_by_severity[f.severity.value] = counts_by_severity.get(f.severity.value, 0) + 1

    return DeceptionHuntRunResult(
        findings=findings,
        total_incidents=int(correlation.get("total_incidents", 0)),
        active_intruder_count=int(correlation.get("active_intruder_count", 0)),
        counts_by_severity=counts_by_severity,
        attackers=list(correlation.get("attackers", [])),
    )


def run_deception_hunt_from_envelope(envelope: dict[str, Any]) -> DeceptionHuntRunResult:
    """Correlate + map the incidents of a ``canary_list_incidents`` envelope.

    Pure: no I/O. Accepts the tool-result envelope and extracts its
    ``incidents`` list before delegating to :func:`run_deception_hunt`.
    """
    incidents = (envelope or {}).get("incidents") if isinstance(envelope, dict) else None
    return run_deception_hunt(incidents if isinstance(incidents, list) else [])


async def run_deception_hunt_over_connector(
    server: Any,
    *,
    limit: int = 200,
) -> DeceptionHuntRunResult:
    """Gather incidents from the Canary connector and run the hunt end-to-end.

    The single entry point a runner / scheduled job calls. A connector failure
    is logged and treated as an empty hunt (no findings) so one outage can't
    crash the caller. The connector is mock-first, so this is safe in CI.
    """
    try:
        envelope = await server.canary_list_incidents(limit=limit)
    except Exception as exc:  # noqa: BLE001 - a connector outage must not crash the hunt
        logger.warning("deception hunt: canary_list_incidents failed (%s) — empty hunt", exc)
        return DeceptionHuntRunResult()
    if not isinstance(envelope, dict):
        return DeceptionHuntRunResult()
    return run_deception_hunt_from_envelope(envelope)
