"""Severity scoring tool for the Triage plugin."""

from __future__ import annotations

import re
from typing import Any

from langchain_core.tools import tool

# --------------------------------------------------------------------------- #
# Scoring weights and keywords
# --------------------------------------------------------------------------- #

# Keywords that signal high asset criticality
_CRITICAL_ASSETS = [
    "domain controller",
    "active directory",
    "dc01",
    "exchange server",
    "vpn gateway",
    "firewall",
    "pam ",
    "privileged access",
    "jump server",
    "bastion",
    "certificate authority",
    "root ca",
    "hsm",
    "key vault",
    "production database",
    "prod db",
    "crown jewel",
    "scada",
    "ics ",
    "payment system",
    "pci",
    "pii database",
    "customer data",
]

# Keywords that signal sophisticated threat actors
_SOPHISTICATION_INDICATORS = [
    "apt",
    "advanced persistent",
    "zero-day",
    "0-day",
    "living off the land",
    "lotl",
    "fileless",
    "memory-only",
    "supply chain",
    "signed binary",
    "dll sideload",
    "cobalt strike",
    "covenant",
    "sliver",
    "brute ratel",
    "havoc",
    "mythic",
    "custom implant",
    "rootkit",
    "firmware",
    "uefi",
    "bootkit",
    "anti-forensic",
]

# Keywords that indicate wide blast radius
_BLAST_RADIUS_INDICATORS = [
    "all users",
    "entire domain",
    "organization-wide",
    "multiple hosts",
    "subnet",
    "broadcast",
    "mass email",
    "company-wide",
    "global policy",
    "gpo ",
    "group policy",
    "all endpoints",
    "entire fleet",
    "widespread",
    "multiple departments",
]

# Keywords that indicate time urgency
_TIME_URGENCY_INDICATORS = [
    "active",
    "in progress",
    "ongoing",
    "real-time",
    "currently executing",
    "encrypting",
    "spreading",
    "propagating",
    "countdown",
    "deadline",
    "ransom note",
    "exfiltrating now",
    "live session",
    "interactive",
]


def _score_dimension(text: str, indicators: list[str]) -> float:
    """Score a dimension 0.0-1.0 based on keyword presence."""
    text_lower = text.lower()
    matches = sum(1 for kw in indicators if kw in text_lower)
    if matches == 0:
        return 0.1
    if matches == 1:
        return 0.4
    if matches == 2:
        return 0.65
    if matches <= 4:
        return 0.8
    return 0.95


def _compute_overall_severity(scores: dict[str, float]) -> str:
    """Convert weighted dimension scores into a severity label."""
    # Weighted composite: time urgency and asset criticality matter most.
    weights = {
        "asset_criticality": 0.30,
        "threat_sophistication": 0.20,
        "blast_radius": 0.20,
        "time_sensitivity": 0.30,
    }
    weighted_score = sum(scores[dim] * weights[dim] for dim in weights)

    if weighted_score >= 0.75:
        return "critical"
    if weighted_score >= 0.55:
        return "high"
    if weighted_score >= 0.35:
        return "medium"
    if weighted_score >= 0.15:
        return "low"
    return "info"


def _build_justification(
    scores: dict[str, float],
    overall: str,
) -> list[str]:
    """Build human-readable justification lines for the severity rating."""
    justifications: list[str] = []

    labels = {
        "asset_criticality": "Asset Criticality",
        "threat_sophistication": "Threat Sophistication",
        "blast_radius": "Blast Radius",
        "time_sensitivity": "Time Sensitivity",
    }
    level_labels = {
        (0.0, 0.2): "minimal",
        (0.2, 0.45): "low",
        (0.45, 0.7): "moderate",
        (0.7, 0.85): "high",
        (0.85, 1.01): "very high",
    }

    for dim, score in scores.items():
        for (lo, hi), label in level_labels.items():
            if lo <= score < hi:
                justifications.append(f"{labels[dim]}: {label} ({score:.2f})")
                break

    return justifications


@tool
def severity_scorer(alert_details: str, org_context: str = "") -> dict[str, Any]:
    """Score the severity of a security alert across four dimensions.

    Evaluates alert severity by analyzing asset criticality, threat actor
    sophistication, blast radius, and time sensitivity. Optionally incorporates
    organizational context (e.g., which assets are crown jewels, current
    threat landscape) to refine the score.

    Args:
        alert_details: Full alert details including detection info, affected
            assets, and any analyst notes.
        org_context: Optional organizational context such as asset inventory
            priorities, current threat intelligence, or IR playbook notes.
    """
    combined_text = f"{alert_details}\n{org_context}"

    scores: dict[str, float] = {
        "asset_criticality": _score_dimension(combined_text, _CRITICAL_ASSETS),
        "threat_sophistication": _score_dimension(combined_text, _SOPHISTICATION_INDICATORS),
        "blast_radius": _score_dimension(combined_text, _BLAST_RADIUS_INDICATORS),
        "time_sensitivity": _score_dimension(combined_text, _TIME_URGENCY_INDICATORS),
    }

    overall = _compute_overall_severity(scores)
    justifications = _build_justification(scores, overall)

    # Extract any affected host/user counts from the text for context.
    host_count_match = re.search(r"(\d+)\s*(?:hosts?|endpoints?|machines?)", combined_text)
    user_count_match = re.search(r"(\d+)\s*(?:users?|accounts?)", combined_text)

    affected = {}
    if host_count_match:
        affected["hosts"] = int(host_count_match.group(1))
    if user_count_match:
        affected["users"] = int(user_count_match.group(1))

    return {
        "severity": overall,
        "scores": {k: round(v, 2) for k, v in scores.items()},
        "justification": justifications,
        "affected_scope": affected,
        "recommendation": _severity_recommendation(overall),
    }


def _severity_recommendation(severity: str) -> str:
    """Return a standard recommendation based on severity level."""
    recommendations = {
        "critical": (
            "IMMEDIATE ACTION REQUIRED. Escalate to incident commander. "
            "Consider emergency containment (host isolation, account lockout). "
            "Engage full IR team."
        ),
        "high": (
            "Urgent investigation required. Assign senior analyst. "
            "Prepare containment options. Notify SOC lead."
        ),
        "medium": (
            "Standard investigation. Assign to available analyst. "
            "Enrich IOCs and gather additional context before escalation."
        ),
        "low": (
            "Queue for review during normal operations. "
            "Consider as tuning candidate if pattern is recurring."
        ),
        "info": (
            "Log for awareness. No immediate action required. Review during weekly tuning sessions."
        ),
    }
    return recommendations.get(severity, "Investigate further.")
