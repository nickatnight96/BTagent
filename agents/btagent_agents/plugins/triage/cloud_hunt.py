"""Cloud control-plane hunt runner (cloud vertical, #117).

Ties the connector-independent cloud control-plane detectors in
:mod:`btagent_shared.hunt.cloud` (STS chaining, IAM persistence, cross-account
trust abuse, snapshot external share, CloudTrail tamper, shadow workloads,
overprivileged workload identity) to the Phase 6 hunt-findings pipeline,
mirroring the agentic runner. Like agentic, the cloud domain has **no live
control-plane connector wired yet** (CloudTrail / IAM / resource-event ingest is
deferred to #100), so the hunt runs over an in-memory observation bundle: a
caller-supplied one via :func:`run_cloud_hunt`, or the built-in deterministic
demo bundle via :func:`run_cloud_hunt_mock`.

Pure: no I/O, no network, no LLM. The detectors reference public taxonomies
(MITRE ATT&CK cloud matrix) and are detection signatures, not attack
generators — the demo bundle keeps the same property (synthetic, minimal).
"""

from __future__ import annotations

import logging

from btagent_shared.hunt.cloud import run_all_detections
from btagent_shared.types.cloud_hunt import (
    AgenticWorkload,
    AgenticWorkloadKind,
    CloudIdentity,
    CloudProvider,
    IdentityKind,
)
from btagent_shared.types.enums import Severity
from btagent_shared.types.hunt_finding import RecordFindingRequest
from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger("btagent.hunt.cloud")


class CloudHuntRunResult(BaseModel):
    """Outcome of one cloud control-plane hunt run — findings + a triage summary."""

    model_config = ConfigDict(extra="forbid")

    findings: list[RecordFindingRequest] = Field(default_factory=list)
    # The size of the observation bundle the detectors ran over.
    total_identities: int = 0
    total_workloads: int = 0
    total_cloudtrail_events: int = 0
    total_resource_events: int = 0
    counts_by_severity: dict[str, int] = Field(default_factory=dict)


def run_cloud_hunt(
    *,
    identities: list[CloudIdentity] | None = None,
    workloads: list[AgenticWorkload] | None = None,
    cloudtrail_events: list[dict] | None = None,
    resource_events: list[dict] | None = None,
    high_value_targets: set[str] | None = None,
    trusted_account_ids: set[str] | None = None,
) -> CloudHuntRunResult:
    """Run every connector-independent cloud detector over an observation bundle.

    Pure: no I/O. Composes the shared detectors and rolls their findings up with
    a severity breakdown for the triage inbox.
    """
    _identities = identities or []
    _workloads = workloads or []
    _ct_events = cloudtrail_events or []
    _res_events = resource_events or []

    findings = run_all_detections(
        identities=_identities,
        workloads=_workloads,
        cloudtrail_events=_ct_events,
        resource_events=_res_events,
        high_value_targets=high_value_targets,
        trusted_account_ids=trusted_account_ids,
    )

    counts_by_severity: dict[str, int] = {s.value: 0 for s in Severity}
    for f in findings:
        counts_by_severity[f.severity.value] = counts_by_severity.get(f.severity.value, 0) + 1

    return CloudHuntRunResult(
        findings=findings,
        total_identities=len(_identities),
        total_workloads=len(_workloads),
        total_cloudtrail_events=len(_ct_events),
        total_resource_events=len(_res_events),
        counts_by_severity=counts_by_severity,
    )


# --------------------------------------------------------------------------- #
# Mock-first demo bundle
# --------------------------------------------------------------------------- #
#
# Minimal, synthetic, deterministic observations that trip a representative set
# of detectors — cross-account trust abuse (identity), shadow workload + over-
# privileged identity (workload). The event-driven detectors (CloudTrail tamper,
# IAM persistence, snapshot external share) fire on the live path when those
# event streams are supplied. Used only in mock mode until control-plane
# connectors are wired (#100).

_DEMO_ORG = "org_01DEMOCLOUD"
_TRUSTED_ACCOUNT = "111111111111"
_EXTERNAL_ACCOUNT = "999999999999"
_GOVERNED_ROLE = f"arn:aws:iam::{_TRUSTED_ACCOUNT}:role/AgentRuntimeRole"
_SHADOW_IDENTITY = f"arn:aws:iam::{_TRUSTED_ACCOUNT}:role/RogueLambdaRole"

_DEMO_IDENTITIES: list[CloudIdentity] = [
    # Cross-account trust to an untrusted external account → trust-abuse finding.
    CloudIdentity(
        id="cid_demo_001",
        org_id=_DEMO_ORG,
        provider=CloudProvider.AWS,
        kind=IdentityKind.ROLE,
        arn_or_id=f"arn:aws:iam::{_TRUSTED_ACCOUNT}:role/CrossAccountBridge",
        display_name="Cross-account bridge role",
        can_be_assumed_by=[f"arn:aws:iam::{_EXTERNAL_ACCOUNT}:root"],
        has_cross_account_trust=True,
    ),
]

_DEMO_WORKLOADS: list[AgenticWorkload] = [
    # Untagged unmanaged Lambda with an overprivileged identity → shadow-workload
    # AND overprivileged-identity findings.
    AgenticWorkload(
        id="wl_demo_c001",
        org_id=_DEMO_ORG,
        provider=CloudProvider.AWS,
        kind=AgenticWorkloadKind.UNMANAGED,
        resource_id=f"arn:aws:lambda:us-east-1:{_TRUSTED_ACCOUNT}:function:rogue-agent-fn",
        display_name="Rogue Lambda agent",
        identity_ref=_SHADOW_IDENTITY,
        governance_tagged=False,
        is_shadow=True,
        has_overprivileged_identity=True,
        internet_reachable=True,
        last_activity=None,
        risk_score=0.9,
    ),
    # Properly governed workload — must NOT be flagged.
    AgenticWorkload(
        id="wl_demo_c002",
        org_id=_DEMO_ORG,
        provider=CloudProvider.AWS,
        kind=AgenticWorkloadKind.BEDROCK_AGENTCORE,
        resource_id=f"arn:aws:bedrock:us-east-1:{_TRUSTED_ACCOUNT}:agent/AGENT_OK",
        display_name="Governed Bedrock agent",
        identity_ref=_GOVERNED_ROLE,
        governance_tagged=True,
        is_shadow=False,
        has_overprivileged_identity=False,
        internet_reachable=False,
        last_activity=None,
        risk_score=0.0,
    ),
]


def run_cloud_hunt_mock() -> CloudHuntRunResult:
    """Run the cloud hunt over the built-in deterministic demo bundle.

    The mock-first entry point a backend ingest slice calls: the cloud domain
    has no live control-plane connector yet, so this stands in with a small
    synthetic bundle that trips a representative set of detectors. Deterministic,
    so it is safe in CI. ``trusted_account_ids`` intentionally excludes the demo
    external account so the cross-account-trust detector fires.
    """
    return run_cloud_hunt(
        identities=_DEMO_IDENTITIES,
        workloads=_DEMO_WORKLOADS,
        trusted_account_ids={_TRUSTED_ACCOUNT},
    )
