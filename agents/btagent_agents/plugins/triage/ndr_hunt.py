"""NDR-hunt runner — composition + connector gather (NDR vertical, slice 2).

Ties the Vectra AI NDR connector to the Phase 6 hunt-findings pipeline by
composing the two pure pieces already in place:

1. the NDR-triage **correlator**
   (:func:`btagent_agents.plugins.triage.tools.ndr_correlator.correlate_ndr_detections`),
   which rolls Vectra detections up per host and scores kill-chain progression;
2. the NDR **finding mapper**
   (:func:`btagent_shared.hunt.ndr.ndr_hosts_to_findings`), which turns those
   per-host rollups into
   :class:`~btagent_shared.types.hunt_finding.RecordFindingRequest` objects.

Mirrors :mod:`btagent_agents.plugins.triage.deception_hunt`: NDR telemetry comes
from a **single** connector (Vectra) with no time window, so the gather is one
tool call. The pure entry points do no I/O; the async
:func:`run_ndr_hunt_over_connector` is the only I/O boundary and tolerates a
connector failure so a hunt never crashes the caller. Persisting the findings is
a later (backend) slice.
"""

from __future__ import annotations

import logging
from typing import Any

from btagent_shared.hunt.ndr import ndr_hosts_to_findings
from btagent_shared.types.enums import Severity
from btagent_shared.types.hunt_finding import RecordFindingRequest
from pydantic import BaseModel, ConfigDict, Field

from btagent_agents.plugins.triage.tools.ndr_correlator import correlate_ndr_detections

logger = logging.getLogger("btagent.hunt.ndr")


class NdrHuntRunResult(BaseModel):
    """Outcome of one NDR-hunt run — findings plus a triage summary."""

    model_config = ConfigDict(extra="forbid")

    findings: list[RecordFindingRequest] = Field(default_factory=list)
    total_hosts: int = 0
    # Hosts showing kill-chain progression (≥2 stages) — the correlator's
    # headline campaign signal.
    campaign_count: int = 0
    counts_by_severity: dict[str, int] = Field(default_factory=dict)


def run_ndr_hunt(detections: list[dict[str, Any]] | None = None) -> NdrHuntRunResult:
    """Correlate raw Vectra detections and map them into findings.

    Pure: no I/O. The lower-level entry point when the caller has already
    pulled the detection list (the ``detections`` field of a
    ``vectra_list_detections`` envelope).
    """
    correlation = correlate_ndr_detections(detections or [])
    findings = ndr_hosts_to_findings(correlation)

    counts_by_severity: dict[str, int] = {s.value: 0 for s in Severity}
    for f in findings:
        counts_by_severity[f.severity.value] = counts_by_severity.get(f.severity.value, 0) + 1

    return NdrHuntRunResult(
        findings=findings,
        total_hosts=int(correlation.get("total_hosts", 0)),
        campaign_count=int(correlation.get("campaign_count", 0)),
        counts_by_severity=counts_by_severity,
    )


def run_ndr_hunt_from_envelope(envelope: dict[str, Any]) -> NdrHuntRunResult:
    """Correlate + map the detections of a ``vectra_list_detections`` envelope.

    Pure: no I/O. Accepts the tool-result envelope and extracts its
    ``detections`` list before delegating to :func:`run_ndr_hunt`.
    """
    detections = (envelope or {}).get("detections") if isinstance(envelope, dict) else None
    return run_ndr_hunt(detections if isinstance(detections, list) else [])


async def run_ndr_hunt_over_connector(server: Any, *, limit: int = 200) -> NdrHuntRunResult:
    """Gather detections from the Vectra connector and run the hunt end-to-end.

    The single entry point a runner / scheduled job calls. A connector failure
    is logged and treated as an empty hunt (no findings) so one outage can't
    crash the caller. The connector is mock-first, so this is safe in CI.
    """
    try:
        envelope = await server.vectra_list_detections(limit=limit)
    except Exception as exc:  # noqa: BLE001 - a connector outage must not crash the hunt
        logger.warning("ndr hunt: vectra_list_detections failed (%s) — empty hunt", exc)
        return NdrHuntRunResult()
    if not isinstance(envelope, dict):
        return NdrHuntRunResult()
    return run_ndr_hunt_from_envelope(envelope)
