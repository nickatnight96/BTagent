"""Summarization tools for the Coordination plugin.

Provides investigation summarization, multi-investigation aggregation via
map-reduce, and agency-specific report formatting.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from langchain_core.tools import tool

# --------------------------------------------------------------------------- #
# Mock investigation data store (used when no DB is available)
# --------------------------------------------------------------------------- #

_MOCK_INVESTIGATIONS: dict[str, dict[str, Any]] = {
    "inv_mock_001": {
        "id": "inv_mock_001",
        "title": "Phishing Campaign Targeting Finance Department",
        "severity": "high",
        "status": "contained",
        "iocs": [
            {"type": "email", "value": "attacker@malicious-domain.com"},
            {"type": "domain", "value": "malicious-domain.com"},
            {"type": "ip", "value": "198.51.100.23"},
            {"type": "url", "value": "https://malicious-domain.com/harvest"},
            {"type": "hash_sha256", "value": "a" * 64},
        ],
        "timeline": [
            {
                "timestamp": "2025-03-20T08:30:00Z",
                "description": "First phishing email received by finance team",
            },
            {
                "timestamp": "2025-03-20T09:15:00Z",
                "description": "User clicked malicious link, credentials harvested",
            },
            {
                "timestamp": "2025-03-20T10:00:00Z",
                "description": "Anomalous login detected from external IP",
            },
            {
                "timestamp": "2025-03-20T11:30:00Z",
                "description": "Incident reported to SOC, investigation initiated",
            },
            {
                "timestamp": "2025-03-20T12:00:00Z",
                "description": "Account disabled, email quarantined",
            },
        ],
        "mitre_techniques": ["T1566.002", "T1078", "T1114.002"],
        "containment_actions": [
            {"action_type": "disable_account", "target": "jdoe@corp.com"},
            {"action_type": "block_domain", "target": "malicious-domain.com"},
            {"action_type": "block_ip", "target": "198.51.100.23"},
        ],
        "enrichment": {
            "198.51.100.23": {"reputation": "malicious", "country": "RU", "asn": "AS12345"},
            "malicious-domain.com": {
                "reputation": "malicious",
                "registrar": "NameCheap",
                "age_days": 7,
            },
        },
    },
    "inv_mock_002": {
        "id": "inv_mock_002",
        "title": "Lateral Movement via Compromised Service Account",
        "severity": "critical",
        "status": "investigating",
        "iocs": [
            {"type": "ip", "value": "10.0.5.42"},
            {"type": "ip", "value": "198.51.100.23"},
            {"type": "hash_sha256", "value": "b" * 64},
            {"type": "domain", "value": "c2-server.xyz"},
        ],
        "timeline": [
            {
                "timestamp": "2025-03-20T14:00:00Z",
                "description": "Anomalous service account activity detected on DC01",
            },
            {
                "timestamp": "2025-03-20T14:30:00Z",
                "description": "PsExec execution from compromised workstation",
            },
            {
                "timestamp": "2025-03-20T15:00:00Z",
                "description": "C2 beacon detected to c2-server.xyz",
            },
        ],
        "mitre_techniques": ["T1021.002", "T1078.002", "T1071.001"],
        "containment_actions": [
            {"action_type": "isolate_host", "target": "WKSTN-042"},
            {"action_type": "disable_account", "target": "svc_backup"},
        ],
        "enrichment": {
            "c2-server.xyz": {
                "reputation": "malicious",
                "registrar": "Unknown",
                "age_days": 3,
            },
        },
    },
}


# --------------------------------------------------------------------------- #
# Helper functions
# --------------------------------------------------------------------------- #


def _get_investigation(investigation_id: str) -> dict[str, Any] | None:
    """Retrieve investigation data from mock store."""
    return _MOCK_INVESTIGATIONS.get(investigation_id)


def _build_executive_summary(inv: dict[str, Any]) -> str:
    """Build an executive summary from investigation data."""
    ioc_count = len(inv.get("iocs", []))
    timeline = inv.get("timeline", [])
    containment = inv.get("containment_actions", [])
    severity = inv.get("severity", "medium")

    first_event = timeline[0]["timestamp"] if timeline else "Unknown"
    last_event = timeline[-1]["timestamp"] if timeline else "Unknown"

    return (
        f"Investigation '{inv['title']}' identified a {severity}-severity security "
        f"incident spanning {first_event} to {last_event}. "
        f"The investigation uncovered {ioc_count} indicators of compromise and "
        f"{len(containment)} containment actions were executed. "
        f"Current status: {inv.get('status', 'unknown')}."
    )


def _build_technical_summary(inv: dict[str, Any]) -> str:
    """Build a technical summary from investigation data."""
    techniques = inv.get("mitre_techniques", [])
    iocs = inv.get("iocs", [])
    timeline = inv.get("timeline", [])

    parts = [
        "## Technical Analysis\n",
        f"MITRE ATT&CK techniques observed: {', '.join(techniques) if techniques else 'None'}",
        f"\nIndicators of compromise ({len(iocs)}):",
    ]
    for ioc in iocs:
        parts.append(f"  - [{ioc['type']}] {ioc['value']}")

    if timeline:
        parts.append(f"\nTimeline ({len(timeline)} events):")
        for event in timeline:
            parts.append(f"  - {event['timestamp']}: {event['description']}")

    return "\n".join(parts)


def _aggregate_iocs(investigations: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Aggregate and deduplicate IOCs across multiple investigations."""
    seen: set[str] = set()
    aggregated: list[dict[str, str]] = []

    for inv in investigations:
        for ioc in inv.get("iocs", []):
            key = f"{ioc['type']}:{ioc['value']}"
            if key not in seen:
                seen.add(key)
                aggregated.append(ioc)

    return aggregated


def _aggregate_techniques(investigations: list[dict[str, Any]]) -> list[str]:
    """Aggregate and deduplicate MITRE techniques across investigations."""
    techniques: set[str] = set()
    for inv in investigations:
        techniques.update(inv.get("mitre_techniques", []))
    return sorted(techniques)


def _merge_timelines(investigations: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Merge and sort timelines from multiple investigations."""
    all_events: list[dict[str, str]] = []
    for inv in investigations:
        for event in inv.get("timeline", []):
            event_copy = dict(event)
            event_copy["source_investigation"] = inv.get("id", "unknown")
            all_events.append(event_copy)

    return sorted(all_events, key=lambda e: e.get("timestamp", ""))


# --------------------------------------------------------------------------- #
# Tool implementations
# --------------------------------------------------------------------------- #


def build_summary(investigation: dict[str, Any]) -> dict[str, Any]:
    """Summarize investigation *data* rather than an id (#557).

    Same seam as ``report_generator.build_report``: the id-taking tool can only
    see :data:`_MOCK_INVESTIGATIONS`, so ``POST /reports/summarize`` failed for
    every case that actually existed. Everything below is a pure function over
    the dict — it only ever needed to be handed the real one.
    """
    inv = investigation
    iocs = inv.get("iocs", [])
    techniques = inv.get("mitre_techniques", [])
    containment = inv.get("containment_actions", [])

    recommendations = []
    if inv.get("severity") in ("high", "critical"):
        recommendations.append("Conduct full forensic analysis of affected systems")
        recommendations.append("Review and reset all potentially compromised credentials")
    if any(t.startswith("T1566") for t in techniques):
        recommendations.append("Deploy additional email security controls")
        recommendations.append("Conduct phishing awareness training for affected department")
    if any(t.startswith("T1021") for t in techniques):
        recommendations.append("Review and restrict lateral movement paths")
        recommendations.append("Implement network segmentation improvements")
    if containment:
        recommendations.append("Verify containment actions remain effective")
        recommendations.append("Plan eradication and recovery procedures")
    if not recommendations:
        recommendations.append("Continue monitoring for related activity")

    return {
        "investigation_id": inv.get("id", ""),
        "executive_summary": _build_executive_summary(inv),
        "technical_summary": _build_technical_summary(inv),
        "ioc_list": iocs,
        "ioc_count": len(iocs),
        "mitre_techniques": techniques,
        "timeline_events": len(inv.get("timeline", [])),
        "containment_actions": containment,
        "recommendations": recommendations,
        "status": "success",
    }


@tool
def summarize_investigation(investigation_id: str) -> dict[str, Any]:
    """Compile investigation data into a structured summary.

    Gathers IOCs, timeline, containment actions, and enrichment data from
    a single investigation and produces executive and technical summaries,
    IOC lists, MITRE mappings, and recommendations.

    Args:
        investigation_id: The investigation ID to summarize (e.g. inv_mock_001).
    """
    inv = _get_investigation(investigation_id)
    if inv is None:
        return {
            "error": f"Investigation {investigation_id} not found",
            "status": "failed",
        }

    return build_summary(inv)


def build_multi_summary(
    investigations: list[dict[str, Any]],
    *,
    errors: list[str] | None = None,
) -> dict[str, Any]:
    """Map-reduce a set of investigations from data rather than ids (#557)."""
    errors = list(errors or [])

    if not investigations:
        return {
            "error": "No valid investigations found",
            "errors": errors,
            "status": "failed",
        }

    # --- Map phase: summarize each investigation individually ---
    individual_summaries = [build_summary(inv) for inv in investigations]

    # --- Reduce phase: merge into unified synthesis ---
    aggregated_iocs = _aggregate_iocs(investigations)
    aggregated_techniques = _aggregate_techniques(investigations)
    merged_timeline = _merge_timelines(investigations)

    # Determine overall severity (highest wins)
    severity_order = ["info", "low", "medium", "high", "critical"]
    severities = [inv.get("severity", "medium") for inv in investigations]
    overall_severity = max(severities, key=lambda s: severity_order.index(s))

    # Merge recommendations (deduplicate)
    all_recommendations: list[str] = []
    seen_recs: set[str] = set()
    for summary in individual_summaries:
        for rec in summary.get("recommendations", []):
            if rec not in seen_recs:
                seen_recs.add(rec)
                all_recommendations.append(rec)

    executive_summary = (
        f"Cross-investigation analysis of {len(investigations)} related incident(s). "
        f"Overall severity: {overall_severity}. "
        f"Aggregated {len(aggregated_iocs)} unique IOCs and "
        f"{len(aggregated_techniques)} MITRE ATT&CK techniques. "
        f"Timeline spans {len(merged_timeline)} events across all investigations."
    )

    return {
        "investigation_count": len(investigations),
        "investigation_ids": [inv["id"] for inv in investigations],
        "executive_summary": executive_summary,
        "overall_severity": overall_severity,
        "aggregated_iocs": aggregated_iocs,
        "aggregated_ioc_count": len(aggregated_iocs),
        "mitre_techniques": aggregated_techniques,
        "merged_timeline": merged_timeline,
        "recommendations": all_recommendations,
        "individual_summaries": individual_summaries,
        "errors": errors,
        "status": "success",
    }


@tool
def summarize_multiple(investigation_ids: str) -> dict[str, Any]:
    """Aggregate multiple investigations using map-reduce pattern.

    Summarizes each investigation individually (map phase), then merges
    the results into a unified synthesis (reduce phase). Useful for
    correlating related incidents from the same threat actor or campaign.

    Args:
        investigation_ids: Comma-separated investigation IDs
            (e.g. "inv_mock_001,inv_mock_002").
    """
    ids = [i.strip() for i in investigation_ids.split(",") if i.strip()]

    if not ids:
        return {"error": "No investigation IDs provided", "status": "failed"}

    investigations: list[dict[str, Any]] = []
    errors: list[str] = []
    for inv_id in ids:
        inv = _get_investigation(inv_id)
        if inv is None:
            errors.append(f"Investigation {inv_id} not found")
            continue
        investigations.append(inv)

    return build_multi_summary(investigations, errors=errors)


@tool
def format_agency_report(summary_json: str, format: str) -> dict[str, Any]:
    """Format a summary for a specific agency submission.

    Takes a summary (from summarize_investigation or summarize_multiple)
    and formats it according to agency-specific requirements.

    Args:
        summary_json: JSON string of the summary dict.
        format: Target agency format — one of: cisa, fbi_ic3, isac, generic.
    """
    try:
        summary = json.loads(summary_json)
    except (json.JSONDecodeError, TypeError):
        return {"error": "Invalid JSON in summary_json", "status": "failed"}

    valid_formats = {"cisa", "fbi_ic3", "isac", "generic"}
    if format not in valid_formats:
        return {
            "error": f"Invalid format '{format}'. Must be one of: {', '.join(sorted(valid_formats))}",
            "status": "failed",
        }

    exec_summary = summary.get("executive_summary", "No executive summary available.")
    iocs = summary.get("ioc_list") or summary.get("aggregated_iocs", [])
    techniques = summary.get("mitre_techniques", [])
    recommendations = summary.get("recommendations", [])

    now_iso = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

    if format == "cisa":
        sections = _format_cisa(exec_summary, iocs, techniques, recommendations, now_iso)
    elif format == "fbi_ic3":
        sections = _format_fbi_ic3(exec_summary, iocs, techniques, recommendations, now_iso)
    elif format == "isac":
        sections = _format_isac(exec_summary, iocs, techniques, recommendations, now_iso)
    else:
        sections = _format_generic(exec_summary, iocs, techniques, recommendations, now_iso)

    return {
        "format": format,
        "sections": sections,
        "generated_at": now_iso,
        "status": "success",
    }


# --------------------------------------------------------------------------- #
# Cover-communication drafting (EPIC-6 UC-6.2 part B)
# --------------------------------------------------------------------------- #
#
# Per-audience cover notes built from the exec/technical summaries. These are
# DRAFTS ONLY: nothing is sent here. Each draft is routed through the *draft*
# path of its MCP connector (email ``create_draft`` / Slack
# ``send_message_draft``) and is HITL-gated — an analyst must review and
# approve before any actual send. ``auto_send`` is always False.
_COVER_COMM_AUDIENCES: dict[str, dict[str, str]] = {
    "cisa_liaison": {
        "channel": "email",
        # Route through the Email MCP draft path — never a direct send.
        "mcp_draft_path": "email.create_draft",
        "recipient": "CISA agency liaison",
    },
    "leadership": {
        "channel": "slack",
        # Route through the Slack MCP draft path — never a direct send.
        "mcp_draft_path": "slack.send_message_draft",
        "recipient": "Leadership channel (#leadership)",
    },
}


def _draft_cisa_liaison_email(
    exec_summary: str,
    technical_summary: str,
    iocs: list[dict],
    techniques: list[str],
    recommendations: list[str],
    incident_ref: str,
    timestamp: str,
) -> dict[str, Any]:
    """Build a DRAFT cover email to a CISA liaison from the summaries."""
    ref = incident_ref or "(assign incident reference)"
    tech_line = ", ".join(techniques) if techniques else "None identified"
    rec_lines = "\n".join(f"  {i + 1}. {r}" for i, r in enumerate(recommendations)) or "  (none)"

    body = (
        f"Dear CISA Liaison,\n\n"
        f"We are sharing the following incident summary for coordination and, "
        f"where applicable, formal notification. This is a working draft pending "
        f"internal review and approval.\n\n"
        f"Incident reference: {ref}\n"
        f"Prepared: {timestamp}\n\n"
        f"EXECUTIVE SUMMARY\n{exec_summary}\n\n"
        f"TECHNICAL DETAIL\n{technical_summary}\n\n"
        f"MITRE ATT&CK techniques: {tech_line}\n"
        f"Indicators of compromise shared: {len(iocs)}\n\n"
        f"RECOMMENDED / PLANNED ACTIONS\n{rec_lines}\n\n"
        f"We will follow up with any formal filing required under applicable "
        f"reporting obligations. Please advise on preferred coordination steps.\n\n"
        f"Regards,\n[Reporting organization — analyst to complete]"
    )
    meta = _COVER_COMM_AUDIENCES["cisa_liaison"]
    return {
        "audience": "cisa_liaison",
        "channel": meta["channel"],
        "mcp_draft_path": meta["mcp_draft_path"],
        "to": meta["recipient"],
        "subject": f"[DRAFT] Incident coordination summary {ref}".strip(),
        "body": body,
        # Guardrails: this is a draft only and must pass HITL before any send.
        "send": False,
        "requires_approval": True,
    }


def _draft_leadership_slack(
    exec_summary: str,
    overall_severity: str,
    status: str,
    incident_ref: str,
    timestamp: str,
) -> dict[str, Any]:
    """Build a DRAFT Slack post to leadership from the executive summary."""
    ref = incident_ref or "(assign incident reference)"
    text = (
        f":rotating_light: *Incident update (DRAFT — pending approval)*\n"
        f"*Reference:* {ref}\n"
        f"*Severity:* {overall_severity}    *Status:* {status}\n"
        f"*Prepared:* {timestamp}\n\n"
        f"{exec_summary}\n\n"
        f"_This is a draft cover note for leadership. Review and approve before "
        f"posting._"
    )
    meta = _COVER_COMM_AUDIENCES["leadership"]
    return {
        "audience": "leadership",
        "channel": meta["channel"],
        "mcp_draft_path": meta["mcp_draft_path"],
        "to": meta["recipient"],
        "text": text,
        # Guardrails: this is a draft only and must pass HITL before any send.
        "send": False,
        "requires_approval": True,
    }


@tool
def draft_cover_communications(summary_json: str, incident_ref: str = "") -> dict[str, Any]:
    """Draft per-audience cover communications from an investigation summary.

    Builds DRAFT-ONLY cover notes from the executive / technical summaries
    already produced by ``summarize_investigation`` or ``summarize_multiple``:

    * an **email to a CISA liaison**, and
    * a **Slack post to leadership**.

    These are drafts only — nothing is sent. Each draft is routed through the
    *draft* path of its MCP connector (email ``create_draft`` / Slack
    ``send_message_draft``) and is HITL-gated: an analyst must review and
    approve before any send. Every draft carries ``send: false`` /
    ``requires_approval: true`` and the top-level ``auto_send`` is always
    ``False``.

    Args:
        summary_json: JSON string of a summary dict (from
            ``summarize_investigation`` or ``summarize_multiple``).
        incident_ref: Optional human-facing incident reference / case id to
            cite in the cover comms (e.g. "INC-2025-0421").
    """
    try:
        summary = json.loads(summary_json)
    except (json.JSONDecodeError, TypeError):
        return {"error": "Invalid JSON in summary_json", "status": "failed"}

    exec_summary = summary.get("executive_summary", "No executive summary available.")
    # ``technical_summary`` is present on single-investigation summaries; the
    # multi-investigation reduce output has none, so synthesize a compact one.
    technical_summary = summary.get("technical_summary")
    iocs = summary.get("ioc_list") or summary.get("aggregated_iocs", [])
    techniques = summary.get("mitre_techniques", [])
    recommendations = summary.get("recommendations", [])
    if not technical_summary:
        tech_line = ", ".join(techniques) if techniques else "None identified"
        technical_summary = (
            f"Aggregated {len(iocs)} indicator(s) of compromise across "
            f"{summary.get('investigation_count', 1)} investigation(s). "
            f"MITRE ATT&CK techniques: {tech_line}."
        )

    overall_severity = summary.get("overall_severity") or summary.get("severity", "unknown")
    # NB: the summary's ``status`` key is the *operation* status ("success"),
    # not the investigation lifecycle state — use an explicit label if present,
    # otherwise a neutral placeholder rather than leaking "success".
    status = summary.get("status_label", "under review")
    now_iso = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

    drafts = [
        _draft_cisa_liaison_email(
            exec_summary,
            technical_summary,
            iocs,
            techniques,
            recommendations,
            incident_ref,
            now_iso,
        ),
        _draft_leadership_slack(
            exec_summary,
            overall_severity,
            status,
            incident_ref,
            now_iso,
        ),
    ]

    return {
        "drafts": drafts,
        "draft_count": len(drafts),
        # Hard invariant surfaced to any caller/orchestrator: cover comms are
        # never auto-sent; they route through the HITL-gated MCP draft path.
        "auto_send": False,
        "generated_at": now_iso,
        "status": "success",
    }


# --------------------------------------------------------------------------- #
# Agency formatting helpers
# --------------------------------------------------------------------------- #


def _format_cisa(
    exec_summary: str,
    iocs: list[dict],
    techniques: list[str],
    recommendations: list[str],
    timestamp: str,
) -> dict[str, str]:
    """Format for CISA Incident Reporting."""
    ioc_lines = "\n".join(f"  - [{i.get('type', '?')}] {i.get('value', '?')}" for i in iocs)
    tech_lines = ", ".join(techniques) if techniques else "None identified"
    rec_lines = "\n".join(f"  {idx + 1}. {r}" for idx, r in enumerate(recommendations))

    return {
        "header": (f"CISA INCIDENT REPORT\nTLP: AMBER\nReport Date: {timestamp}\n{'=' * 60}"),
        "executive_summary": f"EXECUTIVE SUMMARY\n\n{exec_summary}",
        "affected_sectors": (
            "AFFECTED SECTORS\n\n"
            "  - Information Technology\n"
            "  - Financial Services\n"
            "(Adjust based on organization profile)"
        ),
        "technical_details": (
            f"TECHNICAL DETAILS\n\n"
            f"MITRE ATT&CK Techniques: {tech_lines}\n\n"
            f"Indicators of Compromise:\n{ioc_lines}"
        ),
        "critical_infrastructure_impact": (
            "CRITICAL INFRASTRUCTURE IMPACT\n\n"
            "Assessment pending. Evaluate against CISA Critical Infrastructure "
            "Sectors for applicability."
        ),
        "recommendations": f"RECOMMENDED ACTIONS\n\n{rec_lines}",
    }


def _format_fbi_ic3(
    exec_summary: str,
    iocs: list[dict],
    techniques: list[str],
    recommendations: list[str],
    timestamp: str,
) -> dict[str, str]:
    """Format for FBI IC3 submission."""
    ioc_lines = "\n".join(f"  - [{i.get('type', '?')}] {i.get('value', '?')}" for i in iocs)
    rec_lines = "\n".join(f"  {idx + 1}. {r}" for idx, r in enumerate(recommendations))

    return {
        "header": (
            f"FBI INTERNET CRIME COMPLAINT CENTER (IC3)\nSubmission Date: {timestamp}\n{'=' * 60}"
        ),
        "incident_description": f"INCIDENT DESCRIPTION\n\n{exec_summary}",
        "financial_impact": (
            "FINANCIAL IMPACT\n\n"
            "  Estimated loss: TBD (requires financial analysis)\n"
            "  Payment method: N/A\n"
            "  Recovery status: Pending"
        ),
        "suspect_information": (
            "SUSPECT INFORMATION\n\n"
            "  Attribution: Under investigation\n"
            "  Known aliases: TBD\n"
            "  Infrastructure used: See IOC list below"
        ),
        "digital_evidence": (f"DIGITAL EVIDENCE\n\nIndicators of Compromise:\n{ioc_lines}"),
        "recommendations": f"RECOMMENDED ACTIONS\n\n{rec_lines}",
    }


def _format_isac(
    exec_summary: str,
    iocs: list[dict],
    techniques: list[str],
    recommendations: list[str],
    timestamp: str,
) -> dict[str, str]:
    """Format for ISAC sharing."""
    ioc_lines = "\n".join(f"  - [{i.get('type', '?')}] {i.get('value', '?')}" for i in iocs)
    tech_lines = ", ".join(techniques) if techniques else "None identified"
    rec_lines = "\n".join(f"  {idx + 1}. {r}" for idx, r in enumerate(recommendations))

    return {
        "header": (
            f"ISAC THREAT INTELLIGENCE SHARING\nTLP: AMBER\nSharing Date: {timestamp}\n{'=' * 60}"
        ),
        "threat_summary": f"THREAT SUMMARY\n\n{exec_summary}",
        "sector_relevance": (
            "SECTOR RELEVANCE\n\n"
            "  This advisory is relevant to organizations in the financial "
            "services, healthcare, and technology sectors that may be targeted "
            "by similar techniques."
        ),
        "indicators": (
            f"INDICATORS OF COMPROMISE\n\n"
            f"Sharing Permissions: TLP:AMBER — share within your organization "
            f"and with clients on a need-to-know basis.\n\n{ioc_lines}"
        ),
        "mitre_mapping": (f"MITRE ATT&CK MAPPING\n\nTechniques: {tech_lines}"),
        "defensive_recommendations": f"DEFENSIVE RECOMMENDATIONS\n\n{rec_lines}",
    }


def _format_generic(
    exec_summary: str,
    iocs: list[dict],
    techniques: list[str],
    recommendations: list[str],
    timestamp: str,
) -> dict[str, str]:
    """Generic incident report format."""
    ioc_lines = "\n".join(f"  - [{i.get('type', '?')}] {i.get('value', '?')}" for i in iocs)
    tech_lines = ", ".join(techniques) if techniques else "None identified"
    rec_lines = "\n".join(f"  {idx + 1}. {r}" for idx, r in enumerate(recommendations))

    return {
        "header": (f"INCIDENT SUMMARY REPORT\nGenerated: {timestamp}\n{'=' * 60}"),
        "executive_summary": f"EXECUTIVE SUMMARY\n\n{exec_summary}",
        "technical_details": (
            f"TECHNICAL DETAILS\n\n"
            f"MITRE ATT&CK Techniques: {tech_lines}\n\n"
            f"Indicators of Compromise:\n{ioc_lines}"
        ),
        "recommendations": f"RECOMMENDATIONS\n\n{rec_lines}",
    }
