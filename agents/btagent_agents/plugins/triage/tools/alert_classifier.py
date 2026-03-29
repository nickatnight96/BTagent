"""Alert classification tool for the Triage plugin."""

from __future__ import annotations

import re
from typing import Any

from langchain_core.tools import tool

# --------------------------------------------------------------------------- #
# IOC extraction patterns
# --------------------------------------------------------------------------- #
_IOC_PATTERNS: dict[str, re.Pattern[str]] = {
    "ip": re.compile(
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"(?:com|net|org|io|ru|cn|xyz|top|info|biz|co|uk|de|fr|gov|edu|mil"
        r"|onion|tk|ml|ga|cf|gq)\b",
        re.IGNORECASE,
    ),
    "url": re.compile(
        r"https?://[^\s<>\"')\]]+",
        re.IGNORECASE,
    ),
    "hash_sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
    "hash_sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
    "hash_md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
    "email": re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
}

# Keywords that drive category classification, ordered by priority.
_CATEGORY_KEYWORDS: dict[str, list[str]] = {
    "phishing": [
        "phish",
        "spearphish",
        "credential harvest",
        "bec ",
        "business email compromise",
        "suspicious email",
        "spoofed sender",
        "reply-to mismatch",
        "deceptive link",
    ],
    "malware": [
        "malware",
        "ransomware",
        "trojan",
        "dropper",
        "backdoor",
        "worm",
        "keylogger",
        "rootkit",
        "cryptominer",
        "miner",
        "cobalt strike",
        "meterpreter",
        "reverse shell",
    ],
    "c2_communication": [
        "c2",
        "command and control",
        "command-and-control",
        "beaconing",
        "beacon",
        "dns tunnel",
        "dns exfil",
        "known c2",
    ],
    "data_exfiltration": [
        "exfiltration",
        "data leak",
        "dlp",
        "data loss",
        "large upload",
        "unusual transfer",
        "bulk download",
    ],
    "unauthorized_access": [
        "brute force",
        "credential stuff",
        "privilege escalation",
        "unauthorized login",
        "failed login",
        "impossible travel",
        "password spray",
        "account compromise",
    ],
    "lateral_movement": [
        "lateral movement",
        "pass-the-hash",
        "pass the hash",
        "pth",
        "psexec",
        "wmiexec",
        "remote exec",
        "pivot",
    ],
    "reconnaissance": [
        "port scan",
        "enumeration",
        "vulnerability scan",
        "nmap",
        "directory brute",
        "recon",
        "fingerprint",
    ],
    "denial_of_service": [
        "ddos",
        "dos ",
        "denial of service",
        "flood",
        "volumetric",
        "syn flood",
        "amplification",
    ],
    "insider_threat": [
        "insider threat",
        "anomalous user",
        "data hoarding",
        "unusual access pattern",
        "terminated employee",
    ],
    "policy_violation": [
        "policy violation",
        "shadow it",
        "unapproved software",
        "compliance",
        "unauthorized software",
    ],
}

# MITRE ATT&CK technique hints keyed by category.
_MITRE_HINTS: dict[str, list[str]] = {
    "phishing": ["T1566.001", "T1566.002"],
    "malware": ["T1204.002", "T1059"],
    "c2_communication": ["T1071", "T1071.004"],
    "data_exfiltration": ["T1041", "T1048"],
    "unauthorized_access": ["T1110", "T1078"],
    "lateral_movement": ["T1021", "T1550.002"],
    "reconnaissance": ["T1595", "T1046"],
    "denial_of_service": ["T1498", "T1499"],
    "insider_threat": ["T1078"],
    "policy_violation": [],
}


def _extract_iocs(text: str) -> list[dict[str, str]]:
    """Extract IOCs from free-text alert data, deduplicating as we go."""
    seen: set[str] = set()
    iocs: list[dict[str, str]] = []

    for ioc_type, pattern in _IOC_PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group(0).strip().rstrip(".,;:")
            key = f"{ioc_type}:{value.lower()}"
            if key not in seen:
                seen.add(key)
                iocs.append({"type": ioc_type, "value": value})

    # Deduplicate: SHA-256 matches also match SHA-1 / MD5 length-wise.
    # Remove shorter hashes whose value is a substring of a longer one.
    sha256_values = {i["value"].lower() for i in iocs if i["type"] == "hash_sha256"}
    sha1_values = {i["value"].lower() for i in iocs if i["type"] == "hash_sha1"}

    deduped: list[dict[str, str]] = []
    for ioc in iocs:
        val_lower = ioc["value"].lower()
        if ioc["type"] == "hash_md5" and (val_lower in sha256_values or val_lower in sha1_values):
            continue
        if ioc["type"] == "hash_sha1" and any(val_lower in sha for sha in sha256_values):
            continue
        deduped.append(ioc)

    return deduped


def _classify_category(text: str) -> tuple[str, float]:
    """Return (category, confidence) based on keyword matching."""
    text_lower = text.lower()
    scores: dict[str, int] = {}

    for category, keywords in _CATEGORY_KEYWORDS.items():
        score = sum(1 for kw in keywords if kw in text_lower)
        if score > 0:
            scores[category] = score

    if not scores:
        return "unknown", 0.2

    best_category = max(scores, key=lambda k: scores[k])
    best_score = scores[best_category]
    total_possible = len(_CATEGORY_KEYWORDS[best_category])

    # Confidence: proportion of matched keywords, with a floor and ceiling.
    raw_confidence = min(best_score / max(total_possible, 1), 1.0)
    confidence = round(max(0.3, min(0.95, 0.3 + raw_confidence * 0.65)), 2)

    return best_category, confidence


def _infer_severity(category: str, iocs: list[dict[str, str]], text: str) -> str:
    """Heuristic initial severity based on category and IOC richness."""
    text_lower = text.lower()

    # Immediate critical indicators
    critical_signals = [
        "ransomware execut",
        "active breach",
        "data exfiltration in progress",
        "crown jewel",
        "domain admin compromised",
        "production down",
    ]
    if any(sig in text_lower for sig in critical_signals):
        return "critical"

    # Category-based baseline
    severity_map: dict[str, str] = {
        "malware": "high",
        "c2_communication": "high",
        "data_exfiltration": "high",
        "unauthorized_access": "medium",
        "lateral_movement": "high",
        "phishing": "medium",
        "reconnaissance": "low",
        "denial_of_service": "medium",
        "insider_threat": "medium",
        "policy_violation": "low",
        "unknown": "medium",
    }
    severity = severity_map.get(category, "medium")

    # Elevate if many IOCs are present (suggests real incident, not noise)
    if len(iocs) >= 8:
        upgrade = {"low": "medium", "medium": "high", "info": "low"}
        severity = upgrade.get(severity, severity)

    return severity


@tool
def alert_classifier(alert_text: str) -> dict[str, Any]:
    """Classify a security alert and extract indicators of compromise.

    Takes raw alert text from a SIEM, EDR, or other detection source and
    returns a structured classification including severity, category,
    confidence score, extracted IOCs, and suggested MITRE ATT&CK techniques.

    Args:
        alert_text: The raw alert text or JSON payload to classify.
    """
    category, confidence = _classify_category(alert_text)
    iocs = _extract_iocs(alert_text)
    severity = _infer_severity(category, iocs, alert_text)
    mitre_techniques = _MITRE_HINTS.get(category, [])

    return {
        "classification": {
            "category": category,
            "confidence": confidence,
            "severity": severity,
        },
        "iocs": iocs,
        "ioc_count": len(iocs),
        "mitre_techniques": mitre_techniques,
        "summary": (
            f"Alert classified as '{category}' with {severity} severity "
            f"(confidence: {confidence}). Found {len(iocs)} IOC(s)."
        ),
    }
