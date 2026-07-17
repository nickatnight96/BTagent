"""Recorded Wiz (CNAPP/CSPM) fixtures for mock-mode responses (#100 Tier-2).

Shapes mirror the Wiz GraphQL API surfaces the live connector will call:

- ``WIZ_FIXTURE_ISSUES`` — Wiz Issues (posture/toxic-combination findings):
  ``id``, ``severity``, ``status``, ``sourceRule`` (control name +
  category), ``entitySnapshot`` (the resource), ``createdAt``.
- ``WIZ_FIXTURE_VULNS`` — Wiz vulnerability findings:
  ``id``, ``name`` (CVE), ``severity``, ``cvssScore``, ``fixedVersion``,
  ``hasExploit``, ``vulnerableAsset`` (the resource).
- ``WIZ_FIXTURE_RESOURCES`` — cloud resource inventory keyed by resource id
  (type, cloud, region, public-exposure flag, tags).

The fixtures tell one coherent toxic-combination story on ``vm-web-01``:

* ``vm-web-01`` is **internet-exposed** (a HIGH posture issue) *and* carries a
  **critical, exploitable RCE** (CVE-2026-1337) — the exact
  exposed-plus-exploitable pair CNAPP exists to surface.
* An open S3 bucket (``s3-analytics-raw``) has a MEDIUM public-ACL issue.
* ``vm-batch-07`` is a clean, non-exposed comparison resource.

Join discipline: ``entitySnapshot.providerId`` / ``vulnerableAsset.providerId``
is the resource id on every surface — it ties issues ↔ vulns ↔ inventory.
"""

from __future__ import annotations

from typing import Any

# Severity ordering for the finding floor (Wiz's categorical scale).
WIZ_SEVERITY_ORDER: dict[str, int] = {
    "INFORMATIONAL": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}

EXPOSED_RESOURCE_ID = "arn:aws:ec2:us-east-1:123456789012:instance/i-0web01"


WIZ_FIXTURE_ISSUES: list[dict[str, Any]] = [
    {
        "id": "wiz-issue-0001",
        "severity": "HIGH",
        "status": "OPEN",
        "createdAt": "2026-07-10T06:00:00Z",
        "sourceRule": {
            "name": "Compute instance is publicly exposed to the internet",
            "category": "Network Exposure",
        },
        "entitySnapshot": {
            "providerId": EXPOSED_RESOURCE_ID,
            "name": "vm-web-01",
            "type": "VIRTUAL_MACHINE",
            "cloudPlatform": "AWS",
            "region": "us-east-1",
        },
    },
    {
        "id": "wiz-issue-0002",
        "severity": "MEDIUM",
        "status": "OPEN",
        "createdAt": "2026-07-09T18:30:00Z",
        "sourceRule": {
            "name": "Storage bucket allows public read access",
            "category": "Data Exposure",
        },
        "entitySnapshot": {
            "providerId": "arn:aws:s3:::s3-analytics-raw",
            "name": "s3-analytics-raw",
            "type": "BUCKET",
            "cloudPlatform": "AWS",
            "region": "us-east-1",
        },
    },
    {
        "id": "wiz-issue-0003",
        "severity": "LOW",
        "status": "RESOLVED",
        "createdAt": "2026-07-01T10:00:00Z",
        "sourceRule": {
            "name": "Instance missing recommended tags",
            "category": "Governance",
        },
        "entitySnapshot": {
            "providerId": "arn:aws:ec2:us-east-1:123456789012:instance/i-0batch07",
            "name": "vm-batch-07",
            "type": "VIRTUAL_MACHINE",
            "cloudPlatform": "AWS",
            "region": "us-east-1",
        },
    },
]


WIZ_FIXTURE_VULNS: list[dict[str, Any]] = [
    {
        "id": "wiz-vuln-0001",
        "name": "CVE-2026-1337",
        "severity": "CRITICAL",
        "cvssScore": 9.8,
        "fixedVersion": "2.19.1",
        "hasExploit": True,
        "detectedAt": "2026-07-10T06:05:00Z",
        "vulnerableAsset": {
            "providerId": EXPOSED_RESOURCE_ID,
            "name": "vm-web-01",
            "type": "VIRTUAL_MACHINE",
        },
    },
    {
        "id": "wiz-vuln-0002",
        "name": "CVE-2025-4521",
        "severity": "MEDIUM",
        "cvssScore": 5.4,
        "fixedVersion": "1.4.0",
        "hasExploit": False,
        "detectedAt": "2026-07-08T12:00:00Z",
        "vulnerableAsset": {
            "providerId": "arn:aws:ec2:us-east-1:123456789012:instance/i-0batch07",
            "name": "vm-batch-07",
            "type": "VIRTUAL_MACHINE",
        },
    },
]


WIZ_FIXTURE_RESOURCES: dict[str, dict[str, Any]] = {
    EXPOSED_RESOURCE_ID: {
        "providerId": EXPOSED_RESOURCE_ID,
        "name": "vm-web-01",
        "type": "VIRTUAL_MACHINE",
        "cloudPlatform": "AWS",
        "region": "us-east-1",
        "subscriptionId": "123456789012",
        "publiclyExposed": True,
        "tags": {"env": "prod", "team": "web"},
    },
    "arn:aws:s3:::s3-analytics-raw": {
        "providerId": "arn:aws:s3:::s3-analytics-raw",
        "name": "s3-analytics-raw",
        "type": "BUCKET",
        "cloudPlatform": "AWS",
        "region": "us-east-1",
        "subscriptionId": "123456789012",
        "publiclyExposed": True,
        "tags": {"env": "prod", "team": "analytics"},
    },
    "arn:aws:ec2:us-east-1:123456789012:instance/i-0batch07": {
        "providerId": "arn:aws:ec2:us-east-1:123456789012:instance/i-0batch07",
        "name": "vm-batch-07",
        "type": "VIRTUAL_MACHINE",
        "cloudPlatform": "AWS",
        "region": "us-east-1",
        "subscriptionId": "123456789012",
        "publiclyExposed": False,
        "tags": {"env": "prod", "team": "batch"},
    },
}
