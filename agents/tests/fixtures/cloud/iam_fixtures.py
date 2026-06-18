"""Fixture IAM inventory data for cloud hunt golden tests (#117).

All data is synthetic and deterministic.  No real AWS account IDs or ARNs.
Account IDs follow the pattern 11111NNNNNNN where N indicates the account role
in the attack scenario.
"""

from __future__ import annotations

from datetime import UTC, datetime, timezone

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
