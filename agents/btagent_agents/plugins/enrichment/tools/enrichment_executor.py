"""IOC enrichment tools — query CTI sources and return combined results."""

from __future__ import annotations

import json
import hashlib
from datetime import datetime, timezone
from typing import Any

from langchain_core.tools import tool


# --------------------------------------------------------------------------- #
# Mock CTI source responses
# --------------------------------------------------------------------------- #

def _mock_virustotal(ioc_type: str, ioc_value: str) -> dict[str, Any]:
    """Simulated VirusTotal API response."""
    # Deterministic mock: hash the value to get consistent scores
    h = int(hashlib.md5(ioc_value.encode()).hexdigest()[:8], 16)
    malicious = h % 73
    total = 72
    malicious = min(malicious, total)

    return {
        "source": "virustotal",
        "verdict": "malicious" if malicious > 5 else "clean",
        "details": {
            "malicious_count": malicious,
            "total_engines": total,
            "detection_ratio": f"{malicious}/{total}",
            "last_analysis_date": "2026-03-25T12:00:00Z",
            "reputation_score": max(-100, -malicious * 3),
            "tags": ["trojan", "c2"] if malicious > 20 else [],
        },
    }


def _mock_shodan(ioc_type: str, ioc_value: str) -> dict[str, Any]:
    """Simulated Shodan API response for IPs and domains."""
    h = int(hashlib.md5(ioc_value.encode()).hexdigest()[:8], 16)
    open_ports = [22, 80, 443] if h % 3 == 0 else [80, 443, 8080, 8443]

    return {
        "source": "shodan",
        "verdict": "informational",
        "details": {
            "open_ports": open_ports,
            "os": "Linux" if h % 2 == 0 else "Windows Server 2019",
            "asn": f"AS{h % 65535}",
            "org": "Example Hosting LLC",
            "country": "US" if h % 3 == 0 else "RU",
            "last_update": "2026-03-24T08:30:00Z",
            "vulns": [f"CVE-2025-{h % 9999:04d}"] if h % 4 == 0 else [],
        },
    }


def _mock_greynoise(ioc_type: str, ioc_value: str) -> dict[str, Any]:
    """Simulated GreyNoise API response for IPs."""
    h = int(hashlib.md5(ioc_value.encode()).hexdigest()[:8], 16)
    is_noise = h % 5 == 0
    is_riot = h % 7 == 0

    classification = "benign" if is_riot else ("noise" if is_noise else "malicious")

    return {
        "source": "greynoise",
        "verdict": classification,
        "details": {
            "noise": is_noise,
            "riot": is_riot,
            "classification": classification,
            "name": "Known Scanner" if is_noise else "Unknown",
            "last_seen": "2026-03-25T10:00:00Z",
            "tags": ["scanner", "crawler"] if is_noise else [],
        },
    }


def _mock_abuseipdb(ioc_type: str, ioc_value: str) -> dict[str, Any]:
    """Simulated AbuseIPDB API response for IPs."""
    h = int(hashlib.md5(ioc_value.encode()).hexdigest()[:8], 16)
    abuse_score = h % 101

    return {
        "source": "abuseipdb",
        "verdict": "malicious" if abuse_score > 50 else "clean",
        "details": {
            "abuse_confidence_score": abuse_score,
            "total_reports": h % 500,
            "country_code": "US" if h % 3 == 0 else "CN",
            "isp": "Example ISP",
            "usage_type": "Data Center/Web Hosting",
            "is_tor": h % 20 == 0,
            "last_reported_at": "2026-03-24T15:00:00Z",
        },
    }


def _mock_urlhaus(ioc_type: str, ioc_value: str) -> dict[str, Any]:
    """Simulated URLhaus API response for URLs."""
    h = int(hashlib.md5(ioc_value.encode()).hexdigest()[:8], 16)
    is_listed = h % 3 == 0

    return {
        "source": "urlhaus",
        "verdict": "malicious" if is_listed else "clean",
        "details": {
            "url_status": "online" if is_listed else "not_listed",
            "threat": "malware_download" if is_listed else None,
            "tags": ["elf", "mirai"] if is_listed else [],
            "date_added": "2026-03-20T00:00:00Z" if is_listed else None,
        },
    }


# --------------------------------------------------------------------------- #
# Source selection logic
# --------------------------------------------------------------------------- #

_SOURCE_MAP: dict[str, list[str]] = {
    "ip": ["virustotal", "shodan", "greynoise", "abuseipdb"],
    "domain": ["virustotal", "shodan"],
    "hash_md5": ["virustotal"],
    "hash_sha1": ["virustotal"],
    "hash_sha256": ["virustotal"],
    "url": ["virustotal", "urlhaus"],
    "email": ["virustotal"],
}

_MOCK_FUNCTIONS: dict[str, Any] = {
    "virustotal": _mock_virustotal,
    "shodan": _mock_shodan,
    "greynoise": _mock_greynoise,
    "abuseipdb": _mock_abuseipdb,
    "urlhaus": _mock_urlhaus,
}

# MITRE technique mapping based on source verdicts
_MITRE_BY_IOC_TYPE: dict[str, list[str]] = {
    "ip": ["T1071", "T1071.001"],
    "domain": ["T1189", "T1566.002"],
    "hash_md5": ["T1204.002"],
    "hash_sha1": ["T1204.002"],
    "hash_sha256": ["T1204.002"],
    "url": ["T1566.002", "T1204.001"],
    "email": ["T1566.001"],
}


def _compute_initial_confidence(source_results: list[dict[str, Any]]) -> float:
    """Compute an initial confidence score from source verdicts."""
    if not source_results:
        return 0.0

    malicious_count = sum(
        1 for r in source_results if r.get("verdict") == "malicious"
    )
    clean_count = sum(
        1 for r in source_results if r.get("verdict") == "clean"
    )
    total = len(source_results)

    if malicious_count >= 3:
        return round(0.8 + (malicious_count / total) * 0.2, 2)
    if malicious_count >= 2:
        return round(0.6 + (malicious_count / total) * 0.2, 2)
    if malicious_count == 1 and clean_count == 0:
        return 0.6
    if malicious_count == 1:
        return round(0.4 + (1 - clean_count / total) * 0.2, 2)
    if clean_count == total:
        return 0.1
    return 0.3


def _build_summary(
    ioc_type: str,
    ioc_value: str,
    source_results: list[dict[str, Any]],
    confidence: float,
) -> str:
    """Build a human-readable enrichment summary."""
    verdicts = [f"{r['source']}={r['verdict']}" for r in source_results]
    verdict_str = ", ".join(verdicts)
    return (
        f"Enriched {ioc_type} '{ioc_value}' across {len(source_results)} source(s). "
        f"Verdicts: [{verdict_str}]. Confidence: {confidence}."
    )


# --------------------------------------------------------------------------- #
# Tool definitions
# --------------------------------------------------------------------------- #


@tool
def enrich_ioc(ioc_type: str, ioc_value: str) -> dict[str, Any]:
    """Enrich a single indicator of compromise against relevant CTI sources.

    Selects the appropriate threat intelligence sources based on the IOC type,
    queries each source, and returns a combined enrichment result with verdicts,
    confidence score, and MITRE ATT&CK technique suggestions.

    Args:
        ioc_type: Type of indicator — one of: ip, domain, hash_md5, hash_sha1,
            hash_sha256, url, email.
        ioc_value: The indicator value to enrich (e.g., "192.168.1.1",
            "evil.com", a SHA256 hash).
    """
    ioc_type_lower = ioc_type.lower().strip()
    ioc_value = ioc_value.strip()

    # Determine which sources to query
    sources = _SOURCE_MAP.get(ioc_type_lower, ["virustotal"])
    source_results: list[dict[str, Any]] = []

    for source_name in sources:
        mock_fn = _MOCK_FUNCTIONS.get(source_name)
        if mock_fn:
            result = mock_fn(ioc_type_lower, ioc_value)
            source_results.append(result)

    confidence = _compute_initial_confidence(source_results)

    # Determine MITRE techniques if any source flagged malicious
    mitre_techniques: list[str] = []
    malicious_count = sum(
        1 for r in source_results if r.get("verdict") == "malicious"
    )
    if malicious_count > 0:
        mitre_techniques = _MITRE_BY_IOC_TYPE.get(ioc_type_lower, [])

    summary = _build_summary(ioc_type_lower, ioc_value, source_results, confidence)

    return {
        "ioc_type": ioc_type_lower,
        "ioc_value": ioc_value,
        "sources_queried": sources,
        "source_results": source_results,
        "confidence": confidence,
        "mitre_techniques": mitre_techniques,
        "summary": summary,
        "enriched_at": datetime.now(timezone.utc).isoformat(),
    }


@tool
def bulk_enrich(iocs_json: str) -> dict[str, Any]:
    """Enrich multiple IOCs in bulk.

    Accepts a JSON string containing a list of IOC objects, each with 'type'
    and 'value' keys, and enriches all of them against relevant CTI sources.

    Args:
        iocs_json: JSON string of IOC list, e.g.:
            '[{"type": "ip", "value": "1.2.3.4"}, {"type": "domain", "value": "evil.com"}]'
    """
    try:
        iocs = json.loads(iocs_json)
    except json.JSONDecodeError as exc:
        return {
            "error": f"Invalid JSON: {exc}",
            "results": [],
            "total": 0,
            "enriched": 0,
        }

    if not isinstance(iocs, list):
        return {
            "error": "Expected a JSON array of IOC objects",
            "results": [],
            "total": 0,
            "enriched": 0,
        }

    results: list[dict[str, Any]] = []
    errors: list[str] = []

    for idx, ioc in enumerate(iocs):
        if not isinstance(ioc, dict):
            errors.append(f"Item {idx}: expected object, got {type(ioc).__name__}")
            continue

        ioc_type = ioc.get("type", "").strip()
        ioc_value = ioc.get("value", "").strip()

        if not ioc_type or not ioc_value:
            errors.append(f"Item {idx}: missing 'type' or 'value'")
            continue

        result = enrich_ioc.invoke({"ioc_type": ioc_type, "ioc_value": ioc_value})
        results.append(result)

    return {
        "results": results,
        "total": len(iocs),
        "enriched": len(results),
        "errors": errors,
        "enriched_at": datetime.now(timezone.utc).isoformat(),
    }
