"""Email-hunt runner — composition layer (email vertical, slice 2).

Ties the email-security connectors to the Phase 6 hunt-findings pipeline by
composing the two pure pieces already in place:

1. the phishing-triage **correlator**
   (:func:`btagent_agents.plugins.triage.tools.phishing_correlator.correlate_email_threats`),
   which ranks message / click / quarantine telemetry into phishing incidents;
2. the email **finding mapper**
   (:func:`btagent_shared.hunt.email.phishing_incidents_to_findings`),
   which turns those incidents into
   :class:`~btagent_shared.types.hunt_finding.RecordFindingRequest` objects.

This slice is the **pure orchestration** shell (mirroring
``hunt_pack_run_service``'s split of pure conversion vs. side-effectful
persistence): it accepts the *envelopes* the email connectors return — from
Defender for O365, Proofpoint, or Mimecast — extracts the normalised telemetry,
and produces findings plus a run summary. It does **no I/O**: the caller pulls
the connector envelopes and (in a later slice) persists the findings via
``POST /hunt/findings``.

Connector-agnostic extraction
-----------------------------
Every email connector returns the same envelope keys regardless of vendor, so
the runner keys off the payload, not the source:

* a **message-search** envelope carries normalised ``EmailMessageEvent`` dicts
  under ``events``;
* a **click-search** envelope carries ``EmailClickEvent`` dicts under
  ``clicks``;
* a **quarantine / held** envelope carries ``QuarantinedMessage`` dicts under
  ``messages``.
"""

from __future__ import annotations

from typing import Any

from btagent_shared.hunt.email import phishing_incidents_to_findings
from btagent_shared.types.enums import Severity
from btagent_shared.types.hunt_finding import RecordFindingRequest
from pydantic import BaseModel, ConfigDict, Field

from btagent_agents.plugins.triage.tools.phishing_correlator import correlate_email_threats


class EmailHuntRunResult(BaseModel):
    """Outcome of one email-hunt run — findings plus a triage summary."""

    model_config = ConfigDict(extra="forbid")

    findings: list[RecordFindingRequest] = Field(default_factory=list)
    total_incidents: int = 0
    # Delivered-and-clicked malicious mail — the correlator's headline signal.
    active_incident_count: int = 0
    counts_by_severity: dict[str, int] = Field(default_factory=dict)
    most_targeted_recipients: list[dict[str, Any]] = Field(default_factory=list)


def _partition_envelopes(
    envelopes: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Split connector envelopes into (messages, clicks, quarantine) telemetry.

    Keys off the payload shape, so it works for any email connector. A single
    envelope only ever carries one of the three payload keys.
    """
    messages: list[dict[str, Any]] = []
    clicks: list[dict[str, Any]] = []
    quarantine: list[dict[str, Any]] = []
    for env in envelopes or []:
        if not isinstance(env, dict):
            continue
        if isinstance(env.get("events"), list):
            messages.extend(env["events"])
        if isinstance(env.get("clicks"), list):
            clicks.extend(env["clicks"])
        if isinstance(env.get("messages"), list):
            quarantine.extend(env["messages"])
    return messages, clicks, quarantine


def run_email_hunt_from_envelopes(envelopes: list[dict[str, Any]]) -> EmailHuntRunResult:
    """Correlate + map a batch of email-connector envelopes into findings.

    Pure: no I/O. Accepts the tool-result envelopes returned by the email
    connectors (message-search, click-search, quarantine/held) in any mix and
    from any vendor, and returns the ranked findings plus a run summary.
    """
    messages, clicks, quarantine = _partition_envelopes(envelopes)
    return run_email_hunt(messages, clicks, quarantine)


def run_email_hunt(
    messages: list[dict[str, Any]] | None = None,
    clicks: list[dict[str, Any]] | None = None,
    quarantine: list[dict[str, Any]] | None = None,
) -> EmailHuntRunResult:
    """Correlate pre-extracted email telemetry and map it into findings.

    Pure: no I/O. The lower-level entry point when the caller has already
    pulled the normalised message / click / quarantine lists.
    """
    correlation = correlate_email_threats(messages or [], clicks or [], quarantine or [])
    findings = phishing_incidents_to_findings(correlation)

    counts_by_severity: dict[str, int] = {s.value: 0 for s in Severity}
    for f in findings:
        counts_by_severity[f.severity.value] = counts_by_severity.get(f.severity.value, 0) + 1

    return EmailHuntRunResult(
        findings=findings,
        total_incidents=int(correlation.get("total_incidents", 0)),
        active_incident_count=int(correlation.get("active_incident_count", 0)),
        counts_by_severity=counts_by_severity,
        most_targeted_recipients=list(correlation.get("most_targeted_recipients", [])),
    )
