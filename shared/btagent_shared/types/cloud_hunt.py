"""Cloud Control-Plane Hunter schemas (Phase 6 #117 — connector-independent slice).

Defines the data contracts for:
- :class:`CloudIdentity` — IAM principals (roles, users, service accounts, workload
  identities) with trust-policy metadata enabling transitive STS closure analysis.
- :class:`AgenticWorkload` — AI agent workloads (Bedrock AgentCore, Vertex Agent Engine,
  Cloud Run MCP servers, GKE inference) classified as managed vs. shadow.

These types are the serialisation layer between:
  * :mod:`btagent_shared.hunt.cloud` (pure detection logic, no network)
  * Future CloudTrail/GuardDuty MCP connectors (deferred, blocked on #100)
  * The #119 HuntFinding triage queue

Design notes:
- Pydantic v2 with ``extra="forbid"`` — any undeclared field is a schema violation.
- StrEnum values are lowercase, consistent with the rest of btagent_shared.types.
- Zero heavy dependencies (no LangChain, no boto3, no network).
- No Alembic migration needed — these are in-flight models only.  If persistence is
  desired, see the "Live-wiring TODO" section in the PR description.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Cloud-provider and identity-kind enumerations
# ---------------------------------------------------------------------------


class CloudProvider(StrEnum):
    """Supported cloud provider identifiers."""

    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


class IdentityKind(StrEnum):
    """IAM principal classification.

    ``ROLE`` — AWS IAM Role / Azure Managed Identity (object, not a human).
    ``USER`` — AWS IAM User / GCP User Account / Azure Entra user.
    ``SERVICE_ACCOUNT`` — GCP Service Account; also used for AWS IAM Users that
        are clearly machine-scoped (detected by naming convention).
    ``WORKLOAD_IDENTITY`` — GCP Workload Identity / Azure Federated Credential;
        an identity that spans K8s ↔ cloud without a long-lived secret.
    """

    ROLE = "role"
    USER = "user"
    SERVICE_ACCOUNT = "service_account"
    WORKLOAD_IDENTITY = "workload_identity"


class AgenticWorkloadKind(StrEnum):
    """Managed vs. shadow classification of AI-agent workload types.

    ``BEDROCK_AGENTCORE`` — AWS Bedrock AgentCore agent; first-party managed.
    ``VERTEX_AGENT_ENGINE`` — Google Vertex AI Agent Engine; first-party managed.
    ``CLOUD_RUN_MCP`` — A Cloud Run service acting as an MCP server; may be
        managed (if governance-tagged) or shadow (if discovered without tags).
    ``GKE_INFERENCE`` — Inference workload on GKE; governance state depends on
        presence of required labels.
    ``UNMANAGED`` — A workload that cannot be classified into the above categories
        yet exhibits agent-like capabilities (e.g., a Lambda with LLM SDK calls
        or an ECS task calling Bedrock without Bedrock AgentCore).
    """

    BEDROCK_AGENTCORE = "bedrock_agentcore"
    VERTEX_AGENT_ENGINE = "vertex_agent_engine"
    CLOUD_RUN_MCP = "cloud_run_mcp"
    GKE_INFERENCE = "gke_inference"
    UNMANAGED = "unmanaged"


# ---------------------------------------------------------------------------
# CloudIdentity
# ---------------------------------------------------------------------------


class CloudIdentity(BaseModel):
    """An IAM principal from any cloud provider, with trust-policy metadata.

    The ``can_be_assumed_by`` list captures the *immediate* trust relationships
    declared in the principal's trust policy; transitive closure (multi-hop
    assume-role chains) is computed by
    :func:`btagent_shared.hunt.cloud.build_trust_graph`.

    ``trust_policy`` is stored verbatim (as parsed JSON-ish dict) so the
    graph builder can re-traverse it without re-fetching from the cloud API.
    Live fetching via CloudTrail/IAM connectors is deferred to #100.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="Unique identifier within the fixture/inventory batch.")
    org_id: str = Field(..., description="Tenant scope.")
    provider: CloudProvider
    kind: IdentityKind
    # For AWS this is the full ARN; for GCP the service-account email;
    # for Azure the object ID or UPN.
    arn_or_id: str = Field(..., min_length=1, max_length=512, description="Provider ARN / ID.")
    display_name: str = Field(default="", max_length=300)
    # Raw trust/delegation policy as a parsed dict.  May be None when the
    # identity has no assume-role trust (e.g. a user with no role assumption).
    trust_policy: dict[str, Any] | None = Field(
        default=None,
        description="IAM trust policy (AWS AssumeRolePolicyDocument / GCP binding conditions).",
    )
    # Immediate trustees — populated by the fixture loader or connector shim.
    # Format: ARN / ID strings matching other CloudIdentity.arn_or_id values
    # within the same inventory batch.
    can_be_assumed_by: list[str] = Field(
        default_factory=list,
        description="Principals that can directly assume/impersonate this identity.",
    )
    # Cross-account flag — True when any trustee is from a different account/project.
    has_cross_account_trust: bool = Field(default=False)
    # Governance state — None means "not yet evaluated".
    governance_tagged: bool | None = Field(
        default=None,
        description="True if all required governance tags are present.",
    )
    last_activity: datetime | None = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    # Free-form enrichment from connector / fixture.
    enrichment: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# AgenticWorkload
# ---------------------------------------------------------------------------


class AgenticWorkload(BaseModel):
    """An AI-agent workload inventory record.

    Classified as *managed* (governance-tagged + known kind) or *shadow*
    (untagged, unknown kind, or discovered outside sanctioned patterns).

    Shadow workloads are flagged with ``is_shadow = True`` and emitted into
    the #119 HuntFinding queue with distinct evidence fields so the downstream
    triage agent can route them to a governance workflow.  The governance
    workflow itself is out of scope for this slice (deferred).

    ``risk_score`` is in [0.0, 1.0]; a simple heuristic:
    - +0.4 for ``is_shadow``
    - +0.3 for excessive IAM permissions (``has_overprivileged_identity``)
    - +0.2 for internet-reachable ingress (``internet_reachable``)
    - +0.1 for absence of ``last_activity``
    The cloud detection logic in :mod:`btagent_shared.hunt.cloud` computes
    this deterministically from the above flags.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="Unique identifier within the fixture/inventory batch.")
    org_id: str = Field(..., description="Tenant scope.")
    provider: CloudProvider
    kind: AgenticWorkloadKind
    # Resource name / ARN / self-link.
    resource_id: str = Field(..., min_length=1, max_length=512)
    display_name: str = Field(default="", max_length=300)
    # The IAM identity this workload runs as.
    identity_ref: str = Field(
        ...,
        description="ARN/ID of the CloudIdentity this workload runs as.",
    )
    # Governance state.
    governance_tagged: bool = Field(
        default=False,
        description="True when all required governance labels/tags are present.",
    )
    # Shadow detection flags.
    is_shadow: bool = Field(
        default=False,
        description="True if the workload is untagged or outside sanctioned patterns.",
    )
    has_overprivileged_identity: bool = Field(
        default=False,
        description="True if the linked identity has broad/wildcard permissions.",
    )
    internet_reachable: bool = Field(
        default=False,
        description="True if the workload exposes a public ingress endpoint.",
    )
    last_activity: datetime | None = Field(
        default=None,
        description="Timestamp of last invocation; None = never observed or data unavailable.",
    )
    risk_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Composite risk in [0, 1] computed by cloud.score_workload_risk().",
    )
    # Free-form enrichment from connector / fixture.
    enrichment: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)
