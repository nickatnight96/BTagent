"""Recorded GCP Cloud Audit Logs + Security Command Center fixtures (#100 Tier-2).

Shapes mirror the GCP API surfaces the live connector will call:

- ``GCP_FIXTURE_AUDIT_ENTRIES`` — Cloud Audit Logs entries (Admin Activity /
  Data Access) with the ``protoPayload`` envelope (``methodName``,
  ``authenticationInfo.principalEmail``, ``requestMetadata.callerIp``,
  ``authorizationInfo`` grant/deny), ``resource``, ``severity``, ``timestamp``.
- ``GCP_FIXTURE_SCC_FINDINGS`` — Security Command Center findings
  (``category``, ``severity``, ``state``, ``resourceName``,
  ``sourceProperties``).

The fixtures tell one coherent service-account-key-abuse story in project
``acme-prod-1``:

* ``svc-deploy@acme-prod-1.iam.gserviceaccount.com`` — normally a CI deploy
  identity — is used from an unfamiliar IP (``45.146.53.12``) to grant itself
  ``roles/owner`` (``SetIamPolicy``), create a key on another service account
  (``CreateServiceAccountKey``), then disable audit logging
  (``UpdateSink``) — the privilege-escalation + persistence chain SCC also
  flags. One ``SetIamPolicy`` attempt is ``denied`` (authorization grant
  false) — the noise the principal summary surfaces.
* ``jvega@acme.com`` runs one benign ``storage.buckets.get`` from the
  corporate range — the clean comparison principal.

Join keys: ``protoPayload.authenticationInfo.principalEmail`` is the principal
on every audit surface; ``resourceName`` ties SCC findings to the project.
"""

from __future__ import annotations

from typing import Any

ATTACKER_IP = "45.146.53.12"
SERVICE_ACCOUNT = "svc-deploy@acme-prod-1.iam.gserviceaccount.com"


def _entry(
    *,
    timestamp: str,
    method: str,
    principal: str,
    caller_ip: str,
    resource_type: str,
    resource_name: str,
    granted: bool,
    severity: str = "NOTICE",
) -> dict[str, Any]:
    """Build one Cloud Audit Logs entry in the protoPayload envelope shape."""
    return {
        "timestamp": timestamp,
        "severity": severity,
        "resource": {
            "type": resource_type,
            "labels": {"project_id": "acme-prod-1"},
        },
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "methodName": method,
            "resourceName": resource_name,
            "authenticationInfo": {"principalEmail": principal},
            "requestMetadata": {"callerIp": caller_ip},
            "authorizationInfo": [{"permission": method, "granted": granted}],
        },
    }


GCP_FIXTURE_AUDIT_ENTRIES: list[dict[str, Any]] = [
    # --- service-account-key abuse chain from the attacker IP ---
    _entry(
        timestamp="2026-07-05T02:11:00Z",
        method="SetIamPolicy",
        principal=SERVICE_ACCOUNT,
        caller_ip=ATTACKER_IP,
        resource_type="project",
        resource_name="projects/acme-prod-1",
        granted=True,
        severity="NOTICE",
    ),
    _entry(
        timestamp="2026-07-05T02:11:20Z",
        method="SetIamPolicy",
        principal=SERVICE_ACCOUNT,
        caller_ip=ATTACKER_IP,
        resource_type="project",
        resource_name="projects/acme-prod-1",
        granted=False,  # a denied attempt — surfaces in the principal summary
        severity="ERROR",
    ),
    _entry(
        timestamp="2026-07-05T02:12:05Z",
        method="google.iam.admin.v1.CreateServiceAccountKey",
        principal=SERVICE_ACCOUNT,
        caller_ip=ATTACKER_IP,
        resource_type="service_account",
        resource_name=(
            "projects/acme-prod-1/serviceAccounts/svc-backup@acme-prod-1.iam.gserviceaccount.com"
        ),
        granted=True,
        severity="NOTICE",
    ),
    _entry(
        timestamp="2026-07-05T02:13:40Z",
        method="google.logging.v2.ConfigServiceV2.UpdateSink",
        principal=SERVICE_ACCOUNT,
        caller_ip=ATTACKER_IP,
        resource_type="logging_sink",
        resource_name="projects/acme-prod-1/sinks/_Default",
        granted=True,
        severity="WARNING",
    ),
    # --- clean comparison principal from the corporate range ---
    _entry(
        timestamp="2026-07-05T09:30:00Z",
        method="storage.buckets.get",
        principal="jvega@acme.com",
        caller_ip="203.0.113.44",
        resource_type="gcs_bucket",
        resource_name="projects/_/buckets/acme-prod-artifacts",
        granted=True,
        severity="INFO",
    ),
]


# Severity ordering for the SCC finding floor (mirrors GCP's categorical scale).
SCC_SEVERITY_ORDER: dict[str, int] = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


GCP_FIXTURE_SCC_FINDINGS: list[dict[str, Any]] = [
    {
        "name": "organizations/1234567890/sources/555/findings/f-priv-esc-001",
        "category": "Persistence: IAM Anomalous Grant",
        "severity": "HIGH",
        "state": "ACTIVE",
        "resourceName": "//cloudresourcemanager.googleapis.com/projects/acme-prod-1",
        "eventTime": "2026-07-05T02:11:05Z",
        "sourceProperties": {
            "principalEmail": SERVICE_ACCOUNT,
            "callerIp": ATTACKER_IP,
            "grantedRole": "roles/owner",
        },
    },
    {
        "name": "organizations/1234567890/sources/555/findings/f-key-002",
        "category": "Credential Access: Service Account Key Creation",
        "severity": "CRITICAL",
        "state": "ACTIVE",
        "resourceName": (
            "//iam.googleapis.com/projects/acme-prod-1/serviceAccounts/"
            "svc-backup@acme-prod-1.iam.gserviceaccount.com"
        ),
        "eventTime": "2026-07-05T02:12:10Z",
        "sourceProperties": {"principalEmail": SERVICE_ACCOUNT, "callerIp": ATTACKER_IP},
    },
    {
        "name": "organizations/1234567890/sources/555/findings/f-hygiene-003",
        "category": "Misconfiguration: Public Bucket ACL",
        "severity": "LOW",
        "state": "ACTIVE",
        "resourceName": "//storage.googleapis.com/acme-prod-old-logs",
        "eventTime": "2026-07-01T12:00:00Z",
        "sourceProperties": {"bucketName": "acme-prod-old-logs"},
    },
]
