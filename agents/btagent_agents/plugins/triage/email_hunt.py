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

import logging
from typing import Any

from btagent_shared.hunt.email import phishing_incidents_to_findings
from btagent_shared.types.enums import Severity
from btagent_shared.types.hunt_finding import RecordFindingRequest
from pydantic import BaseModel, ConfigDict, Field

from btagent_agents.plugins.triage.tools.phishing_correlator import correlate_email_threats

logger = logging.getLogger("btagent.hunt.email")

# Which tool on each email connector yields which telemetry stream. Keyed by
# ``server_id`` so a new email connector only has to add an entry here. A
# ``None`` slot means the connector does not expose that stream (e.g. Defender
# for O365 has no post-delivery URL-click feed).
_EMAIL_CONNECTOR_METHODS: dict[str, dict[str, str | None]] = {
    "defender_o365": {
        "messages": "o365_email_events_search",
        "clicks": None,
        "quarantine": "o365_list_quarantine",
    },
    "proofpoint": {
        "messages": "pfpt_message_events_search",
        "clicks": "pfpt_click_events_search",
        "quarantine": None,
    },
    "mimecast": {
        "messages": "mimecast_message_events_search",
        "clicks": "mimecast_click_logs_search",
        "quarantine": "mimecast_list_held_messages",
    },
}


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


# --------------------------------------------------------------------------- #
# Live connector gathering (async, mock-first via the connectors themselves)
# --------------------------------------------------------------------------- #


async def gather_email_envelopes(
    servers: list[Any],
    *,
    start: str,
    end: str,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """Pull message / click / quarantine envelopes from email connectors.

    For each server, calls whichever of its message-search, click-search, and
    quarantine/held tools exist (per :data:`_EMAIL_CONNECTOR_METHODS`, keyed by
    ``server_id``) over the ``[start, end]`` window. A connector whose
    ``server_id`` is unknown, or a single tool call that raises, is logged and
    skipped so one flaky provider never sinks the whole hunt.

    The connectors are themselves mock-first, so this is safe to run in CI; it
    is the only I/O boundary in the email vertical.
    """
    envelopes: list[dict[str, Any]] = []
    for server in servers or []:
        server_id = getattr(server, "server_id", "")
        method_map = _EMAIL_CONNECTOR_METHODS.get(server_id)
        if method_map is None:
            logger.warning("email hunt: no method map for connector %r — skipping", server_id)
            continue
        for stream, method_name in method_map.items():
            if not method_name:
                continue
            method = getattr(server, method_name, None)
            if method is None:
                logger.warning(
                    "email hunt: connector %r missing expected tool %r", server_id, method_name
                )
                continue
            try:
                envelope = await method(start, end, limit=limit)
            except Exception as exc:  # noqa: BLE001 - one provider must not sink the hunt
                logger.warning(
                    "email hunt: %s.%s failed (%s) — skipping that stream",
                    server_id,
                    method_name,
                    exc,
                )
                continue
            if isinstance(envelope, dict):
                envelopes.append(envelope)
    return envelopes


async def run_email_hunt_over_connectors(
    servers: list[Any],
    *,
    start: str,
    end: str,
    limit: int = 200,
) -> EmailHuntRunResult:
    """Gather from the email connectors and run the hunt end-to-end.

    The single entry point a runner / scheduled job calls: pulls every
    connector's telemetry over the window, then correlates + maps it into
    findings. Persisting the findings is the caller's job (a later slice wires
    ``POST /hunt/findings``).
    """
    envelopes = await gather_email_envelopes(servers, start=start, end=end, limit=limit)
    return run_email_hunt_from_envelopes(envelopes)
