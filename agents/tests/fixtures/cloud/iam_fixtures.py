"""Fixture IAM inventory data for cloud hunt golden tests (#117).

All data is synthetic and deterministic.  No real AWS account IDs or ARNs.
Account IDs follow the pattern 11111NNNNNNN where N indicates the account role
in the attack scenario.
"""

from __future__ import annotations

from datetime import UTC, datetime, timezone

from btagent_shared.hunt.cloud import DnsRecord
from btagent_shared.types.cloud_hunt import (
    AgenticWorkload,
    AgenticWorkloadKind,
    CloudIdentity,
    CloudProvider,
    IdentityKind,
)

# ---------------------------------------------------------------------------
# Account / org constants used across fixtures
# ---------------------------------------------------------------------------

ORG_ID = "org_01FIXTURE"
TRUSTED_ACCOUNT = "111111111111"  # Primary prod account
SECOND_ACCOUNT = "222222222222"  # Approved DR account
EXTERNAL_ACCOUNT = "999999999999"  # External / untrusted attacker account

_NOW = datetime(2026, 6, 18, 12, 0, 0, tzinfo=UTC)

# ---------------------------------------------------------------------------
# STS chaining fixture
#
# Attack graph:
#   external_identity (999999999999)
#       → can assume → dev_role (low-priv dev role in prod account)
#           → can assume → cicd_role (CI/CD deploy role)
#               → can assume → admin_role (AdminAccess — high value target)
#
# Expected: detect_sts_chaining should find at least one path from
#   external_identity → admin_role (3 hops).
# ---------------------------------------------------------------------------

STS_CHAIN_IDENTITIES: list[CloudIdentity] = [
    CloudIdentity(
        id="id_001",
        org_id=ORG_ID,
        provider=CloudProvider.AWS,
        kind=IdentityKind.ROLE,
        arn_or_id=f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/AdminRole",
        display_name="Admin Role (AdminAccess)",
        trust_policy={
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/CICDDeployRole"},
                }
            ]
        },
        can_be_assumed_by=[f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/CICDDeployRole"],
        has_cross_account_trust=False,
        governance_tagged=True,
        last_activity=_NOW,
    ),
    CloudIdentity(
        id="id_002",
        org_id=ORG_ID,
        provider=CloudProvider.AWS,
        kind=IdentityKind.ROLE,
        arn_or_id=f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/CICDDeployRole",
        display_name="CI/CD Deploy Role",
        trust_policy={
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": [
                            f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/DevRole",
                            f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/AdminRole",
                        ]
                    },
                }
            ]
        },
        can_be_assumed_by=[
            f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/DevRole",
        ],
        has_cross_account_trust=False,
        governance_tagged=True,
        last_activity=_NOW,
    ),
    CloudIdentity(
        id="id_003",
        org_id=ORG_ID,
        provider=CloudProvider.AWS,
        kind=IdentityKind.ROLE,
        arn_or_id=f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/DevRole",
        display_name="Developer Role (low privilege)",
        trust_policy={
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": [
                            f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/CICDDeployRole",
                            # Trust relationship to external account — the vuln
                            f"arn:aws:iam::{EXTERNAL_ACCOUNT}:root",
                        ]
                    },
                }
            ]
        },
        can_be_assumed_by=[
            f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/CICDDeployRole",
            f"arn:aws:iam::{EXTERNAL_ACCOUNT}:root",  # external trustee!
        ],
        has_cross_account_trust=True,  # external account in trust
        governance_tagged=True,
        last_activity=_NOW,
    ),
    CloudIdentity(
        id="id_004",
        org_id=ORG_ID,
        provider=CloudProvider.AWS,
        kind=IdentityKind.USER,
        arn_or_id=f"arn:aws:iam::{EXTERNAL_ACCOUNT}:root",
        display_name="External attacker account root",
        trust_policy=None,
        can_be_assumed_by=[],
        has_cross_account_trust=False,
        governance_tagged=False,
        last_activity=_NOW,
    ),
]

# High-value targets for the STS chain test.
STS_HIGH_VALUE_TARGETS: set[str] = {
    f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/AdminRole",
}

# ---------------------------------------------------------------------------
# Cross-account trust abuse fixture
#
# ExternallyTrustedRole has a trust policy that includes an external account
# (EXTERNAL_ACCOUNT) that is not in the trusted list.
# ---------------------------------------------------------------------------

CROSS_ACCOUNT_IDENTITIES: list[CloudIdentity] = [
    CloudIdentity(
        id="id_010",
        org_id=ORG_ID,
        provider=CloudProvider.AWS,
        kind=IdentityKind.ROLE,
        arn_or_id=f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/ExternallyTrustedRole",
        display_name="Role with external trust (misconfigured)",
        trust_policy={
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": [
                            f"arn:aws:iam::{SECOND_ACCOUNT}:role/ApprovedCrossAccountRole",
                            f"arn:aws:iam::{EXTERNAL_ACCOUNT}:role/AttackerRole",
                        ]
                    },
                }
            ]
        },
        can_be_assumed_by=[
            f"arn:aws:iam::{SECOND_ACCOUNT}:role/ApprovedCrossAccountRole",
            f"arn:aws:iam::{EXTERNAL_ACCOUNT}:role/AttackerRole",
        ],
        has_cross_account_trust=True,
        governance_tagged=True,
        last_activity=_NOW,
    ),
    CloudIdentity(
        id="id_011",
        org_id=ORG_ID,
        provider=CloudProvider.AWS,
        kind=IdentityKind.ROLE,
        arn_or_id=f"arn:aws:iam::{SECOND_ACCOUNT}:role/ApprovedCrossAccountRole",
        display_name="Approved DR account role",
        trust_policy=None,
        can_be_assumed_by=[],
        has_cross_account_trust=False,
        governance_tagged=True,
        last_activity=_NOW,
    ),
]

CROSS_ACCOUNT_TRUSTED_IDS: set[str] = {TRUSTED_ACCOUNT, SECOND_ACCOUNT}

# ---------------------------------------------------------------------------
# IAM persistence events (CloudTrail-style fixture)
# ---------------------------------------------------------------------------

IAM_PERSISTENCE_EVENTS: list[dict] = [
    {
        "eventName": "CreateAccessKey",
        "eventTime": "2026-06-18T10:00:00Z",
        "awsRegion": "us-east-1",
        "userIdentity": {
            "arn": f"arn:aws:iam::{TRUSTED_ACCOUNT}:assumed-role/AttackerRole/session1"
        },
        "requestParameters": {
            "userName": "alice",
        },
    },
    {
        "eventName": "PutRolePolicy",
        "eventTime": "2026-06-18T10:05:00Z",
        "awsRegion": "us-east-1",
        "userIdentity": {
            "arn": f"arn:aws:iam::{TRUSTED_ACCOUNT}:assumed-role/AttackerRole/session1"
        },
        "requestParameters": {
            "roleName": "BackdoorRole",
            "policyName": "AdminAccess",
            "policyDocument": '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}',
        },
    },
    {
        "eventName": "UpdateAssumeRolePolicy",
        "eventTime": "2026-06-18T10:10:00Z",
        "awsRegion": "us-east-1",
        "userIdentity": {
            "arn": f"arn:aws:iam::{TRUSTED_ACCOUNT}:assumed-role/AttackerRole/session1"
        },
        "requestParameters": {
            "roleName": "ProdDeployRole",
            "policyDocument": (
                f'{{"Statement":[{{"Effect":"Allow","Principal":'
                f'{{"AWS":"arn:aws:iam::{EXTERNAL_ACCOUNT}:root"}},"Action":"sts:AssumeRole"}}]}}'
            ),
        },
    },
    # A benign GetCallerIdentity event (should NOT produce a finding).
    {
        "eventName": "GetCallerIdentity",
        "eventTime": "2026-06-18T10:00:01Z",
        "awsRegion": "us-east-1",
        "userIdentity": {"arn": f"arn:aws:iam::{TRUSTED_ACCOUNT}:user/alice"},
        "requestParameters": {},
    },
]

# ---------------------------------------------------------------------------
# CloudTrail tamper fixture
#
# Scenario: attacker logs in without MFA (GetSessionToken without MFA), then
# immediately disables CloudTrail to cover their tracks.
# ---------------------------------------------------------------------------

CLOUDTRAIL_TAMPER_EVENTS: list[dict] = [
    # Suspicious auth: GetSessionToken without MFA at T+0.
    {
        "eventName": "GetSessionToken",
        "eventTime": "2026-06-18T08:00:00Z",
        "awsRegion": "us-east-1",
        "userIdentity": {
            "arn": f"arn:aws:iam::{TRUSTED_ACCOUNT}:user/bob",
            "type": "IAMUser",
        },
        "additionalEventData": {"mfaAuthenticated": "false"},
        "requestParameters": {},
    },
    # CloudTrail stop: 15 minutes later.
    {
        "eventName": "StopLogging",
        "eventTime": "2026-06-18T08:15:00Z",
        "awsRegion": "us-east-1",
        "userIdentity": {
            "arn": f"arn:aws:iam::{TRUSTED_ACCOUNT}:assumed-role/AttackerRole/bob",
        },
        "requestParameters": {
            "trailARN": f"arn:aws:cloudtrail:us-east-1:{TRUSTED_ACCOUNT}:trail/management-events",
        },
    },
    # Second tamper: ConsoleLogin — should NOT pair with StopLogging (after, not before).
    {
        "eventName": "ConsoleLogin",
        "eventTime": "2026-06-18T09:00:00Z",
        "awsRegion": "us-east-1",
        "userIdentity": {"arn": f"arn:aws:iam::{TRUSTED_ACCOUNT}:user/carol"},
        "requestParameters": {},
    },
]

# ---------------------------------------------------------------------------
# Snapshot external share fixture
# ---------------------------------------------------------------------------

SNAPSHOT_SHARE_EVENTS: list[dict] = [
    {
        "eventName": "ModifySnapshotAttribute",
        "eventTime": "2026-06-18T11:00:00Z",
        "awsRegion": "us-east-1",
        "userIdentity": {
            "arn": f"arn:aws:iam::{TRUSTED_ACCOUNT}:assumed-role/AttackerRole/session2"
        },
        "requestParameters": {
            "snapshotId": "snap-0abc123def456",
            "attributeType": "createVolumePermission",
            "createVolumePermission": {
                "add": {
                    "items": [
                        {"userId": EXTERNAL_ACCOUNT},
                    ]
                }
            },
        },
    },
    # Public AMI share (critical).
    {
        "eventName": "ModifyImageAttribute",
        "eventTime": "2026-06-18T11:05:00Z",
        "awsRegion": "us-east-1",
        "userIdentity": {
            "arn": f"arn:aws:iam::{TRUSTED_ACCOUNT}:assumed-role/AttackerRole/session2"
        },
        "requestParameters": {
            "imageId": "ami-0def12345abc",
            "launchPermission": {
                "add": {
                    "items": [
                        {"group": "all"},
                    ]
                }
            },
        },
    },
    # Trusted cross-account share (should be reported but not critical).
    {
        "eventName": "ModifySnapshotAttribute",
        "eventTime": "2026-06-18T11:10:00Z",
        "awsRegion": "us-east-1",
        "userIdentity": {"arn": f"arn:aws:iam::{TRUSTED_ACCOUNT}:assumed-role/BackupRole/session3"},
        "requestParameters": {
            "snapshotId": "snap-0trusted111",
            "attributeType": "createVolumePermission",
            "createVolumePermission": {"add": {"items": [{"userId": SECOND_ACCOUNT}]}},
        },
    },
]

# ---------------------------------------------------------------------------
# Shadow agentic workload fixture
#
# Three Bedrock AgentCore agents:
#   - ManagedAgent: properly tagged (managed, not shadow)
#   - ShadowBedrockAgent: no governance tags (shadow)
#   - ShadowUnmanagedLambda: Lambda with LLM SDK calls, not AgentCore at all
# ---------------------------------------------------------------------------

AGENTIC_WORKLOAD_INVENTORY: list[AgenticWorkload] = [
    # Properly managed — should NOT be flagged.
    AgenticWorkload(
        id="wl_001",
        org_id=ORG_ID,
        provider=CloudProvider.AWS,
        kind=AgenticWorkloadKind.BEDROCK_AGENTCORE,
        resource_id=f"arn:aws:bedrock:us-east-1:{TRUSTED_ACCOUNT}:agent/AGENT001",
        display_name="Production Triage Agent",
        identity_ref=f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/BedrockAgentRole-Prod",
        governance_tagged=True,
        is_shadow=False,
        has_overprivileged_identity=False,
        internet_reachable=False,
        last_activity=_NOW,
        risk_score=0.0,
    ),
    # Shadow Bedrock agent — untagged, should be flagged.
    AgenticWorkload(
        id="wl_002",
        org_id=ORG_ID,
        provider=CloudProvider.AWS,
        kind=AgenticWorkloadKind.BEDROCK_AGENTCORE,
        resource_id=f"arn:aws:bedrock:us-east-1:{TRUSTED_ACCOUNT}:agent/AGENT002",
        display_name="Shadow Bedrock Agent (untagged)",
        identity_ref=f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/BedrockAgentRole-Shadow",
        governance_tagged=False,  # no governance tags
        is_shadow=True,
        has_overprivileged_identity=True,  # running as broad role
        internet_reachable=False,
        last_activity=None,  # never seen / data gap
        risk_score=0.8,
    ),
    # Shadow Lambda with unmanaged LLM calls — critical risk.
    AgenticWorkload(
        id="wl_003",
        org_id=ORG_ID,
        provider=CloudProvider.AWS,
        kind=AgenticWorkloadKind.UNMANAGED,
        resource_id=f"arn:aws:lambda:us-east-1:{TRUSTED_ACCOUNT}:function:rogue-llm-fn",
        display_name="Rogue Lambda with Bedrock SDK calls",
        identity_ref=f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/LambdaAdminRole",
        governance_tagged=False,
        is_shadow=True,
        has_overprivileged_identity=True,
        internet_reachable=True,  # public function URL
        last_activity=_NOW,
        risk_score=0.9,
    ),
    # Shadow Cloud Run MCP server (GCP).
    AgenticWorkload(
        id="wl_004",
        org_id=ORG_ID,
        provider=CloudProvider.GCP,
        kind=AgenticWorkloadKind.CLOUD_RUN_MCP,
        resource_id="projects/my-project/locations/us-central1/services/mcp-server-shadow",
        display_name="Untagged Cloud Run MCP server",
        identity_ref="shadow-mcp-sa@my-project.iam.gserviceaccount.com",
        governance_tagged=False,
        is_shadow=True,
        has_overprivileged_identity=False,
        internet_reachable=True,
        last_activity=_NOW,
        risk_score=0.6,
    ),
    # Managed GKE inference — should NOT be flagged.
    AgenticWorkload(
        id="wl_005",
        org_id=ORG_ID,
        provider=CloudProvider.GCP,
        kind=AgenticWorkloadKind.GKE_INFERENCE,
        resource_id="projects/my-project/zones/us-central1-a/clusters/inference-cluster",
        display_name="Managed GKE Inference",
        identity_ref="inference-sa@my-project.iam.gserviceaccount.com",
        governance_tagged=True,
        is_shadow=False,
        has_overprivileged_identity=False,
        internet_reachable=False,
        last_activity=_NOW,
        risk_score=0.0,
    ),
]

# ---------------------------------------------------------------------------
# Shadow / unmanaged Bedrock agent identities (#117 task E)
#
# ≥5 IAM execution roles behind shadow or unmanaged Bedrock agents — untagged
# (governance_tagged=False) agent-runtime roles that a Bedrock AgentCore or an
# unmanaged Lambda/ECS "agent" runs as.  These feed the shadow-workload +
# overprivileged-identity detectors and the shadow-Bedrock discovery tests.
# All synthetic; no real ARNs.
# ---------------------------------------------------------------------------

SHADOW_BEDROCK_IDENTITIES: list[CloudIdentity] = [
    # 1) Untagged Bedrock agent-runtime role, wildcard permissions.
    CloudIdentity(
        id="id_shadow_bedrock_001",
        org_id=ORG_ID,
        provider=CloudProvider.AWS,
        kind=IdentityKind.ROLE,
        arn_or_id=f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/BedrockAgentRuntime-Rogue1",
        display_name="Shadow Bedrock agent runtime (untagged, admin)",
        trust_policy={
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "bedrock.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ]
        },
        can_be_assumed_by=["bedrock.amazonaws.com"],
        has_cross_account_trust=False,
        governance_tagged=False,
        last_activity=None,
        enrichment={"shadow": True, "kind": "bedrock_agentcore", "overprivileged": True},
    ),
    # 2) Untagged Bedrock agent-runtime role, cross-account trust to attacker.
    CloudIdentity(
        id="id_shadow_bedrock_002",
        org_id=ORG_ID,
        provider=CloudProvider.AWS,
        kind=IdentityKind.ROLE,
        arn_or_id=f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/BedrockAgentRuntime-Rogue2",
        display_name="Shadow Bedrock agent runtime (external trust)",
        trust_policy={
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{EXTERNAL_ACCOUNT}:root"},
                    "Action": "sts:AssumeRole",
                }
            ]
        },
        can_be_assumed_by=[f"arn:aws:iam::{EXTERNAL_ACCOUNT}:root"],
        has_cross_account_trust=True,
        governance_tagged=False,
        last_activity=_NOW,
        enrichment={"shadow": True, "kind": "bedrock_agentcore"},
    ),
    # 3) Unmanaged Lambda "agent" role calling Bedrock without AgentCore.
    CloudIdentity(
        id="id_shadow_bedrock_003",
        org_id=ORG_ID,
        provider=CloudProvider.AWS,
        kind=IdentityKind.ROLE,
        arn_or_id=f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/UnmanagedBedrockLambda-3",
        display_name="Unmanaged Lambda agent (Bedrock SDK, untagged)",
        trust_policy=None,
        can_be_assumed_by=["lambda.amazonaws.com"],
        has_cross_account_trust=False,
        governance_tagged=False,
        last_activity=_NOW,
        enrichment={"shadow": True, "kind": "unmanaged", "overprivileged": True},
    ),
    # 4) Unmanaged ECS task role invoking Bedrock, untagged.
    CloudIdentity(
        id="id_shadow_bedrock_004",
        org_id=ORG_ID,
        provider=CloudProvider.AWS,
        kind=IdentityKind.ROLE,
        arn_or_id=f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/UnmanagedBedrockEcsTask-4",
        display_name="Unmanaged ECS task agent (Bedrock, untagged)",
        trust_policy=None,
        can_be_assumed_by=["ecs-tasks.amazonaws.com"],
        has_cross_account_trust=False,
        governance_tagged=False,
        last_activity=None,
        enrichment={"shadow": True, "kind": "unmanaged"},
    ),
    # 5) Untagged Bedrock agent-runtime role, machine service account style.
    CloudIdentity(
        id="id_shadow_bedrock_005",
        org_id=ORG_ID,
        provider=CloudProvider.AWS,
        kind=IdentityKind.SERVICE_ACCOUNT,
        arn_or_id=f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/BedrockAgentRuntime-Rogue5",
        display_name="Shadow Bedrock agent runtime (svc-account style, untagged)",
        trust_policy=None,
        can_be_assumed_by=["bedrock.amazonaws.com"],
        has_cross_account_trust=False,
        governance_tagged=False,
        last_activity=_NOW,
        enrichment={"shadow": True, "kind": "bedrock_agentcore"},
    ),
    # 6) Untagged Bedrock agent-runtime role, overprivileged + dormant.
    CloudIdentity(
        id="id_shadow_bedrock_006",
        org_id=ORG_ID,
        provider=CloudProvider.AWS,
        kind=IdentityKind.ROLE,
        arn_or_id=f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/BedrockAgentRuntime-Rogue6",
        display_name="Shadow Bedrock agent runtime (dormant, admin)",
        trust_policy=None,
        can_be_assumed_by=["bedrock.amazonaws.com"],
        has_cross_account_trust=False,
        governance_tagged=False,
        last_activity=None,
        enrichment={"shadow": True, "kind": "bedrock_agentcore", "overprivileged": True},
    ),
]

# Shadow / unmanaged Bedrock agent *workloads* running as the identities above —
# every one untagged (governance_tagged=False), so detect_shadow_workloads()
# emits ≥5 shadow findings.  Two carry an overprivileged identity flag.
SHADOW_BEDROCK_WORKLOADS: list[AgenticWorkload] = [
    AgenticWorkload(
        id="wl_shadow_bedrock_001",
        org_id=ORG_ID,
        provider=CloudProvider.AWS,
        kind=AgenticWorkloadKind.BEDROCK_AGENTCORE,
        resource_id=f"arn:aws:bedrock:us-east-1:{TRUSTED_ACCOUNT}:agent/ROGUE001",
        display_name="Shadow Bedrock agent 1",
        identity_ref=f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/BedrockAgentRuntime-Rogue1",
        governance_tagged=False,
        is_shadow=True,
        has_overprivileged_identity=True,
        internet_reachable=False,
        last_activity=None,
        risk_score=0.7,
    ),
    AgenticWorkload(
        id="wl_shadow_bedrock_002",
        org_id=ORG_ID,
        provider=CloudProvider.AWS,
        kind=AgenticWorkloadKind.BEDROCK_AGENTCORE,
        resource_id=f"arn:aws:bedrock:us-east-1:{TRUSTED_ACCOUNT}:agent/ROGUE002",
        display_name="Shadow Bedrock agent 2",
        identity_ref=f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/BedrockAgentRuntime-Rogue2",
        governance_tagged=False,
        is_shadow=True,
        has_overprivileged_identity=False,
        internet_reachable=True,
        last_activity=_NOW,
        risk_score=0.6,
    ),
    AgenticWorkload(
        id="wl_shadow_bedrock_003",
        org_id=ORG_ID,
        provider=CloudProvider.AWS,
        kind=AgenticWorkloadKind.UNMANAGED,
        resource_id=f"arn:aws:lambda:us-east-1:{TRUSTED_ACCOUNT}:function:unmanaged-bedrock-3",
        display_name="Unmanaged Bedrock Lambda 3",
        identity_ref=f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/UnmanagedBedrockLambda-3",
        governance_tagged=False,
        is_shadow=True,
        has_overprivileged_identity=True,
        internet_reachable=True,
        last_activity=_NOW,
        risk_score=0.9,
    ),
    AgenticWorkload(
        id="wl_shadow_bedrock_004",
        org_id=ORG_ID,
        provider=CloudProvider.AWS,
        kind=AgenticWorkloadKind.UNMANAGED,
        resource_id=f"arn:aws:ecs:us-east-1:{TRUSTED_ACCOUNT}:task-definition/unmanaged-bedrock-4",
        display_name="Unmanaged Bedrock ECS task 4",
        identity_ref=f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/UnmanagedBedrockEcsTask-4",
        governance_tagged=False,
        is_shadow=True,
        has_overprivileged_identity=False,
        internet_reachable=False,
        last_activity=None,
        risk_score=0.5,
    ),
    AgenticWorkload(
        id="wl_shadow_bedrock_005",
        org_id=ORG_ID,
        provider=CloudProvider.AWS,
        kind=AgenticWorkloadKind.BEDROCK_AGENTCORE,
        resource_id=f"arn:aws:bedrock:us-east-1:{TRUSTED_ACCOUNT}:agent/ROGUE005",
        display_name="Shadow Bedrock agent 5",
        identity_ref=f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/BedrockAgentRuntime-Rogue5",
        governance_tagged=False,
        is_shadow=True,
        has_overprivileged_identity=False,
        internet_reachable=False,
        last_activity=_NOW,
        risk_score=0.4,
    ),
    AgenticWorkload(
        id="wl_shadow_bedrock_006",
        org_id=ORG_ID,
        provider=CloudProvider.AWS,
        kind=AgenticWorkloadKind.BEDROCK_AGENTCORE,
        resource_id=f"arn:aws:bedrock:us-east-1:{TRUSTED_ACCOUNT}:agent/ROGUE006",
        display_name="Shadow Bedrock agent 6 (dormant)",
        identity_ref=f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/BedrockAgentRuntime-Rogue6",
        governance_tagged=False,
        is_shadow=True,
        has_overprivileged_identity=True,
        internet_reachable=False,
        last_activity=None,
        risk_score=0.7,
    ),
]

# Identities corresponding to the workload inventory (for privilege cross-ref).
AGENTIC_IDENTITY_INVENTORY: list[CloudIdentity] = [
    CloudIdentity(
        id="id_020",
        org_id=ORG_ID,
        provider=CloudProvider.AWS,
        kind=IdentityKind.ROLE,
        arn_or_id=f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/LambdaAdminRole",
        display_name="Lambda Admin Role (wildcard permissions)",
        trust_policy=None,
        can_be_assumed_by=[],
        has_cross_account_trust=False,
        governance_tagged=False,
        last_activity=_NOW,
    ),
    CloudIdentity(
        id="id_021",
        org_id=ORG_ID,
        provider=CloudProvider.AWS,
        kind=IdentityKind.ROLE,
        arn_or_id=f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/BedrockAgentRole-Shadow",
        display_name="Shadow Bedrock Agent Role",
        trust_policy=None,
        can_be_assumed_by=[],
        has_cross_account_trust=False,
        governance_tagged=False,
        last_activity=None,
    ),
]

# ---------------------------------------------------------------------------
# Shadow-MCP correlation fixture (#117 task B)
#
# Cloud Run service inventory + DNS records.  The correlation surfaces a Cloud
# Run MCP service fronted by an *unsanctioned* custom domain:
#   - mcp-shadow (kind CLOUD_RUN_MCP): default host mcp-shadow-xyz.a.run.app,
#     CNAMEd from mcp.evilcorp-shadow.io (NOT sanctioned)  → shadow-MCP finding
#   - mcp-governed (kind CLOUD_RUN_MCP): default host mcp-ok-abc.a.run.app,
#     fronted only by mcp.internal.company.com (sanctioned) → NO finding
#   - web-frontend (not an MCP server): CNAMEd from app.evilcorp-shadow.io →
#     NOT an MCP service, so NO finding (keys on Cloud Run MCP inventory)
# ---------------------------------------------------------------------------

MCP_SANCTIONED_SUFFIXES: list[str] = [
    ".run.app",
    ".internal",
    ".svc.cluster.local",
    "mcp.internal.company.com",
]

CLOUD_RUN_MCP_SERVICES: list[AgenticWorkload] = [
    # Shadow: untagged Cloud Run MCP server fronted by an external custom domain.
    AgenticWorkload(
        id="wl_run_mcp_shadow",
        org_id=ORG_ID,
        provider=CloudProvider.GCP,
        kind=AgenticWorkloadKind.CLOUD_RUN_MCP,
        resource_id="projects/my-project/locations/us-central1/services/mcp-shadow",
        display_name="Shadow Cloud Run MCP server",
        identity_ref="mcp-shadow-sa@my-project.iam.gserviceaccount.com",
        governance_tagged=False,
        is_shadow=True,
        has_overprivileged_identity=False,
        internet_reachable=True,
        last_activity=_NOW,
        risk_score=0.6,
        enrichment={
            "platform": "cloud_run",
            "service_url": "https://mcp-shadow-xyz.a.run.app",
            "resolved_ips": ["34.120.0.10"],
        },
    ),
    # Governed: tagged Cloud Run MCP server on an approved internal domain only.
    AgenticWorkload(
        id="wl_run_mcp_governed",
        org_id=ORG_ID,
        provider=CloudProvider.GCP,
        kind=AgenticWorkloadKind.CLOUD_RUN_MCP,
        resource_id="projects/my-project/locations/us-central1/services/mcp-governed",
        display_name="Governed Cloud Run MCP server",
        identity_ref="mcp-ok-sa@my-project.iam.gserviceaccount.com",
        governance_tagged=True,
        is_shadow=False,
        has_overprivileged_identity=False,
        internet_reachable=False,
        last_activity=_NOW,
        risk_score=0.0,
        enrichment={
            "platform": "cloud_run",
            "service_url": "https://mcp-ok-abc.a.run.app",
            "custom_domains": ["mcp.internal.company.com"],
        },
    ),
    # Not an MCP server — a plain web frontend Cloud Run service.
    AgenticWorkload(
        id="wl_run_web",
        org_id=ORG_ID,
        provider=CloudProvider.GCP,
        kind=AgenticWorkloadKind.UNMANAGED,
        resource_id="projects/my-project/locations/us-central1/services/web-frontend",
        display_name="Marketing web frontend",
        identity_ref="web-sa@my-project.iam.gserviceaccount.com",
        governance_tagged=True,
        is_shadow=False,
        has_overprivileged_identity=False,
        internet_reachable=True,
        last_activity=_NOW,
        risk_score=0.0,
        enrichment={
            "platform": "cloud_run",
            "service_url": "https://web-frontend-def.a.run.app",
        },
    ),
]

MCP_DNS_RECORDS: list[DnsRecord] = [
    # Unsanctioned custom domain CNAMEd to the shadow MCP service's default host.
    DnsRecord(
        name="mcp.evilcorp-shadow.io",
        record_type="CNAME",
        values=["mcp-shadow-xyz.a.run.app"],
    ),
    # Sanctioned internal domain fronting the governed MCP service (ignored).
    DnsRecord(
        name="mcp.internal.company.com",
        record_type="CNAME",
        values=["mcp-ok-abc.a.run.app"],
    ),
    # The shadow service's own default *.run.app host (sanctioned suffix → ignored).
    DnsRecord(
        name="mcp-shadow-xyz.a.run.app",
        record_type="A",
        values=["34.120.0.10"],
    ),
    # An unsanctioned domain fronting the *web frontend* (not an MCP service → no finding).
    DnsRecord(
        name="app.evilcorp-shadow.io",
        record_type="CNAME",
        values=["web-frontend-def.a.run.app"],
    ),
]

# ---------------------------------------------------------------------------
# Containment-proposal fixtures (#117 Phase C bullet 2 — IAM → IR)
#
# These drive the inert containment proposals seeded on promotion
# (``btagent_shared.hunt.cloud.build_cloud_containment_proposal``) and the
# accept path that runs them through the #106 containment execute service.
#
# The proposal maps CloudTrail persistence events to the containment verb that
# actually undoes them:
#   CreateAccessKey        → freeze_access_key   (long-lived credential)
#   PutUserPolicy/RolePolicy → detach_policy     (unexpected privilege grant)
#   UpdateAssumeRolePolicy → revoke_role         (trust-policy mutation)
# ---------------------------------------------------------------------------

# The actor throughout: a session on a role the attacker already controls.
CONTAINMENT_ACTOR_ARN = f"arn:aws:iam::{TRUSTED_ACCOUNT}:assumed-role/AttackerRole/session9"

# Principals an org would safelist: touching either is a self-inflicted outage.
BREAK_GLASS_ROLE_ARN = f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/BreakGlassIncidentRole"
ACCOUNT_ROOT_PRINCIPAL = f"arn:aws:iam::{TRUSTED_ACCOUNT}:root"

# Principals the proposal is expected to name, per verb.
CONTAINMENT_FREEZE_TARGET = f"arn:aws:iam::{TRUSTED_ACCOUNT}:user/svc-backup"
CONTAINMENT_DETACH_TARGET = f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/BackdoorRole"
CONTAINMENT_REVOKE_TARGET = f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/ProdDeployRole"

# One event per containable verb, plus two that must produce NO action.
IAM_CONTAINMENT_EVENTS: list[dict] = [
    # → freeze_access_key on arn:aws:iam::<acct>:user/svc-backup
    {
        "eventName": "CreateAccessKey",
        "eventTime": "2026-06-18T12:00:00Z",
        "awsRegion": "us-east-1",
        "userIdentity": {"arn": CONTAINMENT_ACTOR_ARN},
        "requestParameters": {"userName": "svc-backup"},
    },
    # → detach_policy on arn:aws:iam::<acct>:role/BackdoorRole
    {
        "eventName": "PutRolePolicy",
        "eventTime": "2026-06-18T12:01:00Z",
        "awsRegion": "us-east-1",
        "userIdentity": {"arn": CONTAINMENT_ACTOR_ARN},
        "requestParameters": {
            "roleName": "BackdoorRole",
            "policyName": "AdminAccess",
            "policyDocument": '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}',
        },
    },
    # → revoke_role on arn:aws:iam::<acct>:role/ProdDeployRole
    {
        "eventName": "UpdateAssumeRolePolicy",
        "eventTime": "2026-06-18T12:02:00Z",
        "awsRegion": "us-east-1",
        "userIdentity": {"arn": CONTAINMENT_ACTOR_ARN},
        "requestParameters": {
            "roleName": "ProdDeployRole",
            "policyDocument": (
                f'{{"Statement":[{{"Effect":"Allow","Principal":'
                f'{{"AWS":"arn:aws:iam::{EXTERNAL_ACCOUNT}:root"}},"Action":"sts:AssumeRole"}}]}}'
            ),
        },
    },
    # Detected as IAM persistence, but NOT containable by any of the three
    # verbs — the proposal must stay silent rather than propose theatre.
    {
        "eventName": "DeactivateMFADevice",
        "eventTime": "2026-06-18T12:03:00Z",
        "awsRegion": "us-east-1",
        "userIdentity": {"arn": CONTAINMENT_ACTOR_ARN},
        "requestParameters": {"userName": "dana"},
    },
    # Benign — no finding at all, therefore no action.
    {
        "eventName": "GetCallerIdentity",
        "eventTime": "2026-06-18T12:04:00Z",
        "awsRegion": "us-east-1",
        "userIdentity": {"arn": f"arn:aws:iam::{TRUSTED_ACCOUNT}:user/alice"},
        "requestParameters": {},
    },
]

# A single event whose containment target is the org's break-glass role. The
# proposal is still generated (the finding is real); the org never-touch
# safelist is what refuses it at execute time, with an audited denial.
SAFELISTED_CONTAINMENT_EVENTS: list[dict] = [
    {
        "eventName": "UpdateAssumeRolePolicy",
        "eventTime": "2026-06-18T12:10:00Z",
        "awsRegion": "us-east-1",
        "userIdentity": {"arn": CONTAINMENT_ACTOR_ARN},
        "requestParameters": {
            "roleName": "BreakGlassIncidentRole",
            "policyDocument": (
                f'{{"Statement":[{{"Effect":"Allow","Principal":'
                f'{{"AWS":"arn:aws:iam::{EXTERNAL_ACCOUNT}:root"}},"Action":"sts:AssumeRole"}}]}}'
            ),
        },
    },
]
