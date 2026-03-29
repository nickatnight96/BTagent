"""Report generation tools for the Report plugin.

Provides full report generation from investigation data using templates,
per-section generation, and template listing.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from langchain_core.tools import tool

_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"


# --------------------------------------------------------------------------- #
# Mock investigation data (shared with coordination plugin pattern)
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
            "198.51.100.23": {"reputation": "malicious", "country": "RU"},
            "malicious-domain.com": {"reputation": "malicious", "age_days": 7},
        },
    },
}


# --------------------------------------------------------------------------- #
# Template loading
# --------------------------------------------------------------------------- #


def _load_template(template_name: str) -> dict[str, Any] | None:
    """Load a report template from YAML.

    SEC-P3-001 FIX: Validate template_name to prevent path traversal.
    Only bare alphanumeric/underscore names are allowed; any path separator
    or '..' component is rejected before touching the filesystem.
    """
    import re

    if not re.match(r"^[a-zA-Z0-9_-]+$", template_name):
        return None
    yaml_path = (_TEMPLATES_DIR / f"{template_name}.yaml").resolve()
    # Belt-and-suspenders: ensure resolved path is inside templates dir
    if not str(yaml_path).startswith(str(_TEMPLATES_DIR.resolve())):
        return None
    if not yaml_path.exists():
        return None
    with yaml_path.open() as f:
        return yaml.safe_load(f)


def _get_investigation(investigation_id: str) -> dict[str, Any] | None:
    """Retrieve investigation data from mock store."""
    return _MOCK_INVESTIGATIONS.get(investigation_id)


# --------------------------------------------------------------------------- #
# Section generators
# --------------------------------------------------------------------------- #


def _gen_executive_summary(inv: dict[str, Any]) -> str:
    """Generate executive summary section."""
    timeline = inv.get("timeline", [])
    iocs = inv.get("iocs", [])
    severity = inv.get("severity", "medium")

    first_event = timeline[0]["timestamp"] if timeline else "Unknown"
    return (
        f"On {first_event}, a {severity}-severity security incident was identified "
        f"involving {inv.get('title', 'unknown activity')}. "
        f"The investigation identified {len(iocs)} indicators of compromise "
        f"and {len(inv.get('containment_actions', []))} containment actions were executed. "
        f"Current investigation status: {inv.get('status', 'unknown')}."
    )


def _gen_scope(inv: dict[str, Any]) -> str:
    """Generate scope and methodology section."""
    return (
        "## Scope and Methodology\n\n"
        "### Scope\n"
        "This investigation covered the analysis of security alerts, "
        "log data from SIEM and EDR platforms, threat intelligence enrichment "
        "of identified indicators, and containment action execution.\n\n"
        "### Methodology\n"
        "The investigation followed a structured incident response process:\n"
        "1. Alert triage and initial classification\n"
        "2. IOC extraction and enrichment against CTI sources\n"
        "3. Timeline reconstruction from available log data\n"
        "4. Containment action proposal and execution\n"
        "5. Impact assessment and reporting"
    )


def _gen_findings(inv: dict[str, Any]) -> str:
    """Generate findings section."""
    techniques = inv.get("mitre_techniques", [])
    enrichment = inv.get("enrichment", {})

    parts = ["## Findings\n"]

    if techniques:
        parts.append("### Attack Techniques")
        parts.append("The following MITRE ATT&CK techniques were identified:\n")
        for tech in techniques:
            parts.append(f"- **{tech}**")

    if enrichment:
        parts.append("\n### Threat Intelligence")
        for indicator, intel in enrichment.items():
            parts.append(f"- **{indicator}**: {intel}")

    return "\n".join(parts)


def _gen_iocs(inv: dict[str, Any]) -> str:
    """Generate IOC section."""
    iocs = inv.get("iocs", [])
    parts = [f"## Indicators of Compromise ({len(iocs)} total)\n"]

    by_type: dict[str, list[str]] = {}
    for ioc in iocs:
        ioc_type = ioc.get("type", "unknown")
        by_type.setdefault(ioc_type, []).append(ioc.get("value", ""))

    for ioc_type, values in sorted(by_type.items()):
        parts.append(f"### {ioc_type.upper()}")
        for val in values:
            parts.append(f"- {val}")
        parts.append("")

    return "\n".join(parts)


def _gen_timeline(inv: dict[str, Any]) -> str:
    """Generate timeline section."""
    timeline = inv.get("timeline", [])
    parts = [f"## Timeline ({len(timeline)} events)\n"]

    for event in timeline:
        parts.append(f"| {event.get('timestamp', 'Unknown')} | {event.get('description', '')} |")

    return "\n".join(parts)


def _gen_recommendations(inv: dict[str, Any]) -> str:
    """Generate recommendations section."""
    severity = inv.get("severity", "medium")
    techniques = inv.get("mitre_techniques", [])

    recs = ["## Recommendations\n", "### Immediate Actions"]
    recs.append("1. Verify all containment actions remain effective")
    recs.append("2. Reset credentials for all affected accounts")
    recs.append("3. Scan all endpoints for related indicators")

    recs.append("\n### Short-term (1-2 weeks)")
    if any(t.startswith("T1566") for t in techniques):
        recs.append("4. Deploy enhanced email filtering rules")
        recs.append("5. Conduct targeted phishing awareness training")
    recs.append("6. Review and update detection rules based on identified TTPs")

    recs.append("\n### Long-term (1-3 months)")
    recs.append("7. Implement network segmentation improvements")
    recs.append("8. Deploy multi-factor authentication for all remote access")
    recs.append("9. Conduct tabletop exercise based on this incident scenario")

    return "\n".join(recs)


def _gen_appendices(inv: dict[str, Any]) -> str:
    """Generate appendices section."""
    return (
        "## Appendices\n\n"
        "### Appendix A: Full IOC List\n"
        "See attached CSV export for complete IOC data.\n\n"
        "### Appendix B: Raw Query Results\n"
        "SIEM query results are archived in the investigation case file.\n\n"
        "### Appendix C: MITRE ATT&CK Navigator Layer\n"
        "An ATT&CK Navigator layer JSON is available for import."
    )


def _gen_data_affected(inv: dict[str, Any]) -> str:
    """Generate data affected section (for regulatory notification)."""
    return (
        "## Data Affected\n\n"
        "### Categories of Data\n"
        "- Email credentials\n"
        "- Internal email content\n"
        "- Financial department documents (assessment pending)\n\n"
        "### Number of Records\n"
        "Assessment in progress. Preliminary estimate: 1-50 individuals affected.\n\n"
        "### Sensitivity Classification\n"
        "Contains potentially sensitive financial and personal data."
    )


def _gen_sharing_guidance(inv: dict[str, Any]) -> str:
    """Generate IOC sharing guidance section."""
    return (
        "## Sharing Guidance\n\n"
        "- **TLP:AMBER** — Share within your organization and with clients "
        "who need this information to protect themselves.\n"
        "- IOCs may be shared with ISACs under TLP:AMBER restrictions.\n"
        "- Do not share raw investigation data externally."
    )


# Map section names to generators
_SECTION_GENERATORS: dict[str, Any] = {
    "executive_summary": _gen_executive_summary,
    "scope": _gen_scope,
    "methodology": _gen_scope,
    "findings": _gen_findings,
    "iocs": _gen_iocs,
    "timeline": _gen_timeline,
    "recommendations": _gen_recommendations,
    "appendices": _gen_appendices,
    "containment": lambda inv: (
        "## Containment Actions\n\n"
        + "\n".join(
            f"- {a.get('action_type', '?')}: {a.get('target', '?')}"
            for a in inv.get("containment_actions", [])
        )
    ),
    "data_affected": _gen_data_affected,
    "sharing_guidance": _gen_sharing_guidance,
}


# --------------------------------------------------------------------------- #
# Tool implementations
# --------------------------------------------------------------------------- #


@tool
def generate_report(investigation_id: str, template: str) -> dict[str, Any]:
    """Generate a full report from investigation data using a template.

    Loads the specified template, retrieves investigation data, and generates
    all sections defined in the template.

    Args:
        investigation_id: The investigation ID to generate a report for.
        template: Template name (incident_report, ioc_report,
            executive_briefing, regulatory_notification).
    """
    inv = _get_investigation(investigation_id)
    if inv is None:
        return {
            "error": f"Investigation {investigation_id} not found",
            "status": "failed",
        }

    tmpl = _load_template(template)
    if tmpl is None:
        return {
            "error": f"Template '{template}' not found",
            "status": "failed",
        }

    now_iso = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    sections: dict[str, str] = {}
    template_sections = tmpl.get("sections", [])

    for section_def in template_sections:
        section_name = section_def.get("name", "")
        generator = _SECTION_GENERATORS.get(section_name)
        if generator:
            sections[section_name] = generator(inv)
        else:
            sections[section_name] = f"[Section '{section_name}' — content pending]"

    return {
        "investigation_id": investigation_id,
        "template": template,
        "template_title": tmpl.get("title", template),
        "generated_at": now_iso,
        "sections": sections,
        "section_count": len(sections),
        "status": "success",
    }


@tool
def generate_section(investigation_id: str, section: str) -> dict[str, Any]:
    """Generate a single report section from investigation data.

    Useful for regenerating or customizing individual sections of a report.

    Args:
        investigation_id: The investigation ID to pull data from.
        section: Section name (executive_summary, findings, iocs, timeline,
            recommendations, scope, containment, appendices).
    """
    inv = _get_investigation(investigation_id)
    if inv is None:
        return {
            "error": f"Investigation {investigation_id} not found",
            "status": "failed",
        }

    generator = _SECTION_GENERATORS.get(section)
    if generator is None:
        available = sorted(_SECTION_GENERATORS.keys())
        return {
            "error": (f"Unknown section '{section}'. Available: {', '.join(available)}"),
            "status": "failed",
        }

    content = generator(inv)
    return {
        "investigation_id": investigation_id,
        "section": section,
        "content": content,
        "status": "success",
    }


@tool
def list_templates() -> dict[str, Any]:
    """Return available report templates with descriptions.

    Lists all YAML templates in the templates directory along with
    their title, description, and section list.
    """
    templates: list[dict[str, Any]] = []

    if _TEMPLATES_DIR.exists():
        for yaml_path in sorted(_TEMPLATES_DIR.glob("*.yaml")):
            with yaml_path.open() as f:
                tmpl = yaml.safe_load(f)
            if tmpl:
                templates.append(
                    {
                        "name": yaml_path.stem,
                        "title": tmpl.get("title", yaml_path.stem),
                        "description": tmpl.get("description", ""),
                        "sections": [s.get("name", "") for s in tmpl.get("sections", [])],
                    }
                )

    return {
        "templates": templates,
        "count": len(templates),
        "status": "success",
    }
