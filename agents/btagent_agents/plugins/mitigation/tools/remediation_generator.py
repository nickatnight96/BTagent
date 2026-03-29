"""Remediation generation tools for the Mitigation plugin.

Provides audience-aware remediation checklists, platform-specific detection
content, and technical hardening recommendations mapped to NIST CSF / CIS Controls.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from langchain_core.tools import tool

# --------------------------------------------------------------------------- #
# Mock investigation data
# --------------------------------------------------------------------------- #

_MOCK_INVESTIGATIONS: dict[str, dict[str, Any]] = {
    "inv_mock_001": {
        "id": "inv_mock_001",
        "title": "Phishing Campaign Targeting Finance Department",
        "severity": "high",
        "status": "contained",
        "attack_vectors": ["phishing", "credential_harvest", "account_compromise"],
        "iocs": [
            {"type": "email", "value": "attacker@malicious-domain.com"},
            {"type": "domain", "value": "malicious-domain.com"},
            {"type": "ip", "value": "198.51.100.23"},
            {"type": "url", "value": "https://malicious-domain.com/harvest"},
            {"type": "hash_sha256", "value": "a" * 64},
        ],
        "mitre_techniques": ["T1566.002", "T1078", "T1114.002"],
        "affected_systems": ["MAIL-SRV01", "WKSTN-FIN-042"],
        "affected_accounts": ["jdoe@corp.com"],
        "containment_actions": [
            {"action_type": "disable_account", "target": "jdoe@corp.com"},
            {"action_type": "block_domain", "target": "malicious-domain.com"},
            {"action_type": "block_ip", "target": "198.51.100.23"},
        ],
    },
}


def _get_investigation(investigation_id: str) -> dict[str, Any] | None:
    """Retrieve investigation data from mock store."""
    return _MOCK_INVESTIGATIONS.get(investigation_id)


# --------------------------------------------------------------------------- #
# Remediation generators by audience
# --------------------------------------------------------------------------- #


def _remediation_executive(inv: dict[str, Any]) -> dict[str, Any]:
    """Generate executive-level remediation guidance."""
    severity = inv.get("severity", "medium")
    affected_count = len(inv.get("affected_accounts", []))

    return {
        "audience": "executive",
        "title": f"Executive Remediation Summary — {inv.get('title', 'Incident')}",
        "severity": severity,
        "business_impact": (
            f"A {severity}-severity incident was identified affecting "
            f"{affected_count} user account(s). Containment actions have been "
            f"executed. Business operations may experience temporary disruption "
            f"during remediation."
        ),
        "actions": [
            {
                "priority": "immediate",
                "action": "Approve credential reset for all affected accounts",
                "estimated_effort": "1-2 hours",
                "business_owner": "IT Security",
            },
            {
                "priority": "immediate",
                "action": "Notify affected department leadership",
                "estimated_effort": "30 minutes",
                "business_owner": "CISO",
            },
            {
                "priority": "short_term",
                "action": "Commission phishing awareness training for affected department",
                "estimated_effort": "1-2 weeks",
                "business_owner": "HR / Security Awareness",
            },
            {
                "priority": "short_term",
                "action": "Review email security controls and approve budget for improvements",
                "estimated_effort": "1 week",
                "business_owner": "IT Leadership",
            },
            {
                "priority": "long_term",
                "action": "Implement MFA for all external-facing applications",
                "estimated_effort": "2-4 weeks",
                "business_owner": "IT Infrastructure",
            },
        ],
        "resource_requirements": (
            "Estimated 40-80 hours of IT security team effort over 2-4 weeks. "
            "May require additional budget for email security gateway upgrade."
        ),
        "timeline": "Full remediation estimated at 2-4 weeks",
    }


def _remediation_technical(inv: dict[str, Any]) -> dict[str, Any]:
    """Generate technical remediation guidance."""
    iocs = inv.get("iocs", [])
    techniques = inv.get("mitre_techniques", [])
    affected_systems = inv.get("affected_systems", [])
    affected_accounts = inv.get("affected_accounts", [])

    ips = [i["value"] for i in iocs if i["type"] == "ip"]
    domains = [i["value"] for i in iocs if i["type"] == "domain"]
    hashes = [i["value"] for i in iocs if i["type"].startswith("hash_")]

    actions: list[dict[str, Any]] = []

    # Immediate: credential reset
    for account in affected_accounts:
        actions.append(
            {
                "priority": "immediate",
                "action": f"Reset credentials for {account}",
                "commands": [
                    f"Set-ADAccountPassword -Identity '{account.split('@')[0]}' -Reset",
                    f"Set-ADUser -Identity '{account.split('@')[0]}' -ChangePasswordAtLogon $true",
                ],
                "verification": f"Verify account lockout cleared: Get-ADUser '{account.split('@')[0]}' -Properties LockedOut",
            }
        )

    # Immediate: block IOCs
    if ips:
        actions.append(
            {
                "priority": "immediate",
                "action": "Block malicious IP addresses at firewall",
                "commands": [
                    "# Add to firewall block list:\n" + "\n".join(f"  block ip {ip}" for ip in ips),
                ],
                "verification": "Verify blocks: show access-list | include " + ips[0],
            }
        )

    if domains:
        actions.append(
            {
                "priority": "immediate",
                "action": "Block malicious domains at DNS/proxy",
                "commands": [
                    "# Add to DNS sinkhole / proxy block list:\n"
                    + "\n".join(f"  block domain {d}" for d in domains),
                ],
                "verification": "Verify DNS resolution fails: nslookup " + domains[0],
            }
        )

    if hashes:
        actions.append(
            {
                "priority": "immediate",
                "action": "Block file hashes in EDR policy",
                "commands": [
                    "# Add to EDR block list:\n" + "\n".join(f"  block hash {h}" for h in hashes),
                ],
                "verification": "Verify in EDR console that hashes are in deny list",
            }
        )

    # Short-term: system scanning
    for system in affected_systems:
        actions.append(
            {
                "priority": "short_term",
                "action": f"Full malware scan on {system}",
                "commands": [
                    f"# Initiate full scan via EDR:\n  Invoke-EDRScan -Target {system} -ScanType Full",
                ],
                "verification": f"Review scan results for {system} in EDR console",
            }
        )

    # Short-term: detection rules
    actions.append(
        {
            "priority": "short_term",
            "action": "Deploy updated detection rules for identified techniques",
            "commands": [
                "# See generate_detection_content tool for platform-specific rules",
            ],
            "verification": "Validate rules fire against test data in staging SIEM",
        }
    )

    # Long-term: hardening
    actions.append(
        {
            "priority": "long_term",
            "action": "Implement email authentication (SPF, DKIM, DMARC)",
            "commands": [
                '# Publish DMARC record: _dmarc.corp.com TXT "v=DMARC1; p=quarantine; rua=mailto:dmarc@corp.com"',
            ],
            "verification": "Verify DMARC record: dig TXT _dmarc.corp.com",
        }
    )

    return {
        "audience": "technical",
        "title": f"Technical Remediation Playbook — {inv.get('title', 'Incident')}",
        "severity": inv.get("severity", "medium"),
        "mitre_techniques": techniques,
        "affected_systems": affected_systems,
        "affected_accounts": affected_accounts,
        "actions": actions,
        "action_count": len(actions),
    }


def _remediation_compliance(inv: dict[str, Any]) -> dict[str, Any]:
    """Generate compliance-focused remediation guidance."""
    severity = inv.get("severity", "medium")
    affected_accounts = inv.get("affected_accounts", [])

    return {
        "audience": "compliance",
        "title": f"Compliance Remediation Guide — {inv.get('title', 'Incident')}",
        "severity": severity,
        "regulatory_considerations": [
            {
                "framework": "GDPR",
                "requirements": [
                    "Article 33: Notify supervisory authority within 72 hours of becoming aware of breach",
                    "Article 34: Notify affected individuals if high risk to rights and freedoms",
                    "Document all facts, effects, and remedial actions taken",
                ],
                "deadline": "72 hours from breach awareness",
            },
            {
                "framework": "HIPAA",
                "requirements": [
                    "Breach Notification Rule: Notify HHS within 60 days if >500 individuals affected",
                    "Notify affected individuals without unreasonable delay",
                    "Document risk assessment and notification decisions",
                ],
                "deadline": "60 days from discovery",
            },
        ],
        "actions": [
            {
                "priority": "immediate",
                "action": "Initiate breach assessment to determine notification requirements",
                "estimated_effort": "4-8 hours",
                "documentation_required": True,
            },
            {
                "priority": "immediate",
                "action": "Preserve all evidence and investigation logs",
                "estimated_effort": "2-4 hours",
                "documentation_required": True,
            },
            {
                "priority": "immediate",
                "action": "Engage legal counsel for regulatory notification guidance",
                "estimated_effort": "1-2 hours",
                "documentation_required": True,
            },
            {
                "priority": "short_term",
                "action": f"Prepare notification letters for {len(affected_accounts)} affected individual(s)",
                "estimated_effort": "1-2 days",
                "documentation_required": True,
            },
            {
                "priority": "short_term",
                "action": "Document complete incident timeline for regulatory submission",
                "estimated_effort": "1-2 days",
                "documentation_required": True,
            },
            {
                "priority": "long_term",
                "action": "Update incident response plan based on lessons learned",
                "estimated_effort": "1-2 weeks",
                "documentation_required": True,
            },
        ],
        "evidence_preservation": [
            "Investigation case files and analyst notes",
            "SIEM query results and raw log extracts",
            "IOC enrichment results and threat intelligence",
            "Containment action logs and approvals",
            "Email samples and header analysis",
        ],
    }


# --------------------------------------------------------------------------- #
# Detection content generators
# --------------------------------------------------------------------------- #


def _generate_splunk_rules(inv: dict[str, Any]) -> list[dict[str, str]]:
    """Generate Splunk SPL detection rules."""
    iocs = inv.get("iocs", [])
    rules: list[dict[str, str]] = []

    ips = [i["value"] for i in iocs if i["type"] == "ip"]
    domains = [i["value"] for i in iocs if i["type"] == "domain"]
    hashes = [i["value"] for i in iocs if i["type"].startswith("hash_")]

    if ips:
        ip_list = " OR ".join(f'"{ip}"' for ip in ips)
        rules.append(
            {
                "name": "IOC - Malicious IP Communication",
                "description": "Detect communication with known malicious IPs from this investigation",
                "language": "spl",
                "rule": (
                    f"index=* earliest=-24h\n"
                    f"(src_ip IN ({ip_list}) OR dest_ip IN ({ip_list}))\n"
                    f"| stats count min(_time) as first_seen max(_time) as last_seen "
                    f"by src_ip, dest_ip, action, sourcetype\n"
                    f"| where count > 0"
                ),
            }
        )

    if domains:
        domain_list = " OR ".join(f'"{d}"' for d in domains)
        rules.append(
            {
                "name": "IOC - Malicious Domain Resolution",
                "description": "Detect DNS queries for known malicious domains",
                "language": "spl",
                "rule": (
                    f"index=dns earliest=-24h\n"
                    f"query IN ({domain_list})\n"
                    f"| stats count by query, src_ip, answer\n"
                    f"| where count > 0"
                ),
            }
        )

    if hashes:
        hash_list = " OR ".join(f'"{h}"' for h in hashes)
        rules.append(
            {
                "name": "IOC - Malicious File Hash Detected",
                "description": "Detect execution of files with known malicious hashes",
                "language": "spl",
                "rule": (
                    f"index=endpoint earliest=-24h\n"
                    f"file_hash IN ({hash_list})\n"
                    f"| stats count by file_hash, file_name, host, user"
                ),
            }
        )

    # Add a technique-based rule
    techniques = inv.get("mitre_techniques", [])
    if "T1566.002" in techniques:
        rules.append(
            {
                "name": "TTP - Spearphishing Link Click",
                "description": "Detect email link clicks followed by credential entry on suspicious domains",
                "language": "spl",
                "rule": (
                    "index=proxy earliest=-24h action=allowed\n"
                    '| eval suspicious=if(match(url_domain, "(?i)(login|signin|verify|secure)"), 1, 0)\n'
                    "| where suspicious=1\n"
                    "| stats count by src_ip, url_domain, user"
                ),
            }
        )

    return rules


def _generate_elastic_rules(inv: dict[str, Any]) -> list[dict[str, str]]:
    """Generate Elastic KQL detection rules."""
    iocs = inv.get("iocs", [])
    rules: list[dict[str, str]] = []

    ips = [i["value"] for i in iocs if i["type"] == "ip"]
    domains = [i["value"] for i in iocs if i["type"] == "domain"]

    if ips:
        ip_clauses = " or ".join(f'source.ip: "{ip}" or destination.ip: "{ip}"' for ip in ips)
        rules.append(
            {
                "name": "IOC - Malicious IP Communication",
                "description": "Detect communication with known malicious IPs",
                "language": "kql",
                "rule": f"({ip_clauses})",
            }
        )

    if domains:
        domain_clauses = " or ".join(f'dns.question.name: "{d}"' for d in domains)
        rules.append(
            {
                "name": "IOC - Malicious Domain Resolution",
                "description": "Detect DNS queries for known malicious domains",
                "language": "kql",
                "rule": f"({domain_clauses})",
            }
        )

    techniques = inv.get("mitre_techniques", [])
    if "T1078" in techniques:
        rules.append(
            {
                "name": "TTP - Suspicious Account Usage",
                "description": "Detect anomalous authentication patterns for compromised accounts",
                "language": "kql",
                "rule": (
                    'event.category: "authentication" and event.outcome: "success" '
                    "and not source.ip: (10.0.0.0/8 or 172.16.0.0/12 or 192.168.0.0/16)"
                ),
            }
        )

    return rules


def _generate_sentinel_rules(inv: dict[str, Any]) -> list[dict[str, str]]:
    """Generate Microsoft Sentinel KQL detection rules."""
    iocs = inv.get("iocs", [])
    rules: list[dict[str, str]] = []

    ips = [i["value"] for i in iocs if i["type"] == "ip"]
    domains = [i["value"] for i in iocs if i["type"] == "domain"]

    if ips:
        ip_list = ", ".join(f'"{ip}"' for ip in ips)
        rules.append(
            {
                "name": "IOC - Malicious IP Communication",
                "description": "Detect communication with known malicious IPs (Sentinel)",
                "language": "kql",
                "rule": (
                    f"let malicious_ips = dynamic([{ip_list}]);\n"
                    f"CommonSecurityLog\n"
                    f"| where TimeGenerated > ago(24h)\n"
                    f"| where SourceIP in (malicious_ips) or DestinationIP in (malicious_ips)\n"
                    f"| summarize count() by SourceIP, DestinationIP, DeviceAction"
                ),
            }
        )

    if domains:
        domain_list = ", ".join(f'"{d}"' for d in domains)
        rules.append(
            {
                "name": "IOC - Malicious Domain Resolution",
                "description": "Detect DNS queries for known malicious domains (Sentinel)",
                "language": "kql",
                "rule": (
                    f"let malicious_domains = dynamic([{domain_list}]);\n"
                    f"DnsEvents\n"
                    f"| where TimeGenerated > ago(24h)\n"
                    f"| where Name in (malicious_domains)\n"
                    f"| summarize count() by Name, ClientIP, IPAddresses"
                ),
            }
        )

    return rules


# --------------------------------------------------------------------------- #
# Tool implementations
# --------------------------------------------------------------------------- #


@tool
def generate_remediation(investigation_id: str, audience: str) -> dict[str, Any]:
    """Generate a remediation checklist for a specific audience.

    Adapts tone, detail level, and content focus based on the target audience.

    Args:
        investigation_id: The investigation ID to generate remediation for.
        audience: Target audience — one of: executive, technical, compliance.
    """
    inv = _get_investigation(investigation_id)
    if inv is None:
        return {
            "error": f"Investigation {investigation_id} not found",
            "status": "failed",
        }

    valid_audiences = {"executive", "technical", "compliance"}
    if audience not in valid_audiences:
        return {
            "error": (
                f"Invalid audience '{audience}'. "
                f"Must be one of: {', '.join(sorted(valid_audiences))}"
            ),
            "status": "failed",
        }

    generators = {
        "executive": _remediation_executive,
        "technical": _remediation_technical,
        "compliance": _remediation_compliance,
    }

    result = generators[audience](inv)
    result["investigation_id"] = investigation_id
    result["generated_at"] = datetime.now(UTC).isoformat()
    result["status"] = "success"

    return result


@tool
def generate_detection_content(investigation_id: str, platform: str) -> dict[str, Any]:
    """Generate SIEM detection rules based on investigation findings.

    Creates platform-specific detection rules from IOCs and attack
    techniques identified during the investigation.

    Args:
        investigation_id: The investigation ID to generate rules for.
        platform: Target SIEM platform — one of: splunk, elastic, sentinel.
    """
    inv = _get_investigation(investigation_id)
    if inv is None:
        return {
            "error": f"Investigation {investigation_id} not found",
            "status": "failed",
        }

    valid_platforms = {"splunk", "elastic", "sentinel"}
    if platform not in valid_platforms:
        return {
            "error": (
                f"Invalid platform '{platform}'. "
                f"Must be one of: {', '.join(sorted(valid_platforms))}"
            ),
            "status": "failed",
        }

    generators = {
        "splunk": _generate_splunk_rules,
        "elastic": _generate_elastic_rules,
        "sentinel": _generate_sentinel_rules,
    }

    rules = generators[platform](inv)

    return {
        "investigation_id": investigation_id,
        "platform": platform,
        "rules": rules,
        "rule_count": len(rules),
        "generated_at": datetime.now(UTC).isoformat(),
        "status": "success",
    }


@tool
def generate_hardening_recommendations(
    investigation_id: str,
) -> dict[str, Any]:
    """Generate technical hardening recommendations based on attack vectors.

    Maps recommendations to NIST CSF functions and CIS Controls for
    framework alignment.

    Args:
        investigation_id: The investigation ID to base recommendations on.
    """
    inv = _get_investigation(investigation_id)
    if inv is None:
        return {
            "error": f"Investigation {investigation_id} not found",
            "status": "failed",
        }

    techniques = inv.get("mitre_techniques", [])
    attack_vectors = inv.get("attack_vectors", [])

    recommendations: list[dict[str, Any]] = []

    # Phishing-related hardening
    if "phishing" in attack_vectors or any(t.startswith("T1566") for t in techniques):
        recommendations.extend(
            [
                {
                    "category": "email_security",
                    "recommendation": "Deploy advanced email filtering with URL sandboxing",
                    "nist_csf": "PR.PT-4 (Communications and control networks are protected)",
                    "cis_control": "CIS 9.6 - Block Unnecessary File Types",
                    "priority": "high",
                    "complexity": "medium",
                },
                {
                    "category": "email_security",
                    "recommendation": "Implement DMARC with p=reject policy",
                    "nist_csf": "PR.PT-4",
                    "cis_control": "CIS 9.5 - Implement DMARC",
                    "priority": "high",
                    "complexity": "low",
                },
                {
                    "category": "awareness",
                    "recommendation": "Deploy simulated phishing exercises quarterly",
                    "nist_csf": "PR.AT-1 (All users are informed and trained)",
                    "cis_control": "CIS 14.1 - Establish Security Awareness Program",
                    "priority": "medium",
                    "complexity": "low",
                },
            ]
        )

    # Credential compromise hardening
    if "credential_harvest" in attack_vectors or "T1078" in techniques:
        recommendations.extend(
            [
                {
                    "category": "identity",
                    "recommendation": "Enforce MFA for all user accounts",
                    "nist_csf": "PR.AC-7 (Users, devices, other assets are authenticated)",
                    "cis_control": "CIS 6.3 - Require MFA for Externally-Exposed Applications",
                    "priority": "critical",
                    "complexity": "medium",
                },
                {
                    "category": "identity",
                    "recommendation": "Implement conditional access policies based on risk signals",
                    "nist_csf": "PR.AC-4 (Access permissions are managed)",
                    "cis_control": "CIS 6.8 - Define and Maintain Role-Based Access Control",
                    "priority": "high",
                    "complexity": "high",
                },
                {
                    "category": "monitoring",
                    "recommendation": "Deploy impossible-travel and anomalous-login detection",
                    "nist_csf": "DE.AE-1 (A baseline of network operations is established)",
                    "cis_control": "CIS 8.11 - Conduct Audit Log Reviews",
                    "priority": "high",
                    "complexity": "medium",
                },
            ]
        )

    # Account compromise hardening
    if "account_compromise" in attack_vectors or "T1114.002" in techniques:
        recommendations.extend(
            [
                {
                    "category": "email_security",
                    "recommendation": "Enable mailbox audit logging and forwarding rule alerts",
                    "nist_csf": "DE.CM-3 (Personnel activity is monitored)",
                    "cis_control": "CIS 8.2 - Collect Audit Logs",
                    "priority": "high",
                    "complexity": "low",
                },
                {
                    "category": "network",
                    "recommendation": "Implement network segmentation between user and server VLANs",
                    "nist_csf": "PR.AC-5 (Network integrity is protected)",
                    "cis_control": "CIS 12.2 - Establish and Maintain Network Segmentation",
                    "priority": "medium",
                    "complexity": "high",
                },
            ]
        )

    # General recommendations if no specific vectors matched
    if not recommendations:
        recommendations.extend(
            [
                {
                    "category": "general",
                    "recommendation": "Review and update endpoint protection configurations",
                    "nist_csf": "PR.PT-1 (Audit/log records are maintained)",
                    "cis_control": "CIS 10.1 - Deploy and Maintain Anti-Malware Software",
                    "priority": "medium",
                    "complexity": "low",
                },
                {
                    "category": "general",
                    "recommendation": "Conduct vulnerability assessment of affected systems",
                    "nist_csf": "ID.RA-1 (Asset vulnerabilities are identified)",
                    "cis_control": "CIS 7.1 - Establish and Maintain Vulnerability Management",
                    "priority": "medium",
                    "complexity": "medium",
                },
            ]
        )

    return {
        "investigation_id": investigation_id,
        "attack_vectors": attack_vectors,
        "mitre_techniques": techniques,
        "recommendations": recommendations,
        "recommendation_count": len(recommendations),
        "nist_csf_functions_covered": sorted(
            {r["nist_csf"].split("(")[0].strip().split(".")[0] for r in recommendations}
        ),
        "generated_at": datetime.now(UTC).isoformat(),
        "status": "success",
    }
