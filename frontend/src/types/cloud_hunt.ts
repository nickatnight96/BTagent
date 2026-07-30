/**
 * Cloud Control-Plane Hunter TypeScript types (#117 Phase B).
 *
 * Mirrors the Python schemas in ``shared/btagent_shared/types/cloud_hunt.py``.
 * String-literal unions match the backend StrEnum values exactly (lowercase).
 *
 * These types are used by:
 *  - ``@/api/cloud``        — API wrapper pre-filtered to domain=cloud
 *  - ``@/stores/cloudStore`` — Zustand store for cloud hunt findings
 *  - ``@/components/cloud/CloudHuntsPage`` — the main page component
 */

// ---------------------------------------------------------------------------
// Enums (mirroring CloudProvider, IdentityKind, AgenticWorkloadKind)
// ---------------------------------------------------------------------------

export type CloudProvider = "aws" | "azure" | "gcp";

export type IdentityKind = "role" | "user" | "service_account" | "workload_identity";

export type AgenticWorkloadKind =
  | "bedrock_agentcore"
  | "vertex_agent_engine"
  | "cloud_run_mcp"
  | "gke_inference"
  | "unmanaged";

// ---------------------------------------------------------------------------
// CloudIdentity — IAM principal with trust-policy metadata
// ---------------------------------------------------------------------------

export interface CloudIdentity {
  id: string;
  org_id: string;
  provider: CloudProvider;
  kind: IdentityKind;
  /** Full ARN (AWS), service-account email (GCP), or object-ID/UPN (Azure). */
  arn_or_id: string;
  display_name: string;
  /** Raw trust / delegation policy; null when the identity has no assume-role trust. */
  trust_policy: Record<string, unknown> | null;
  /**
   * Principals that can directly assume / impersonate this identity.
   * Format: ARN/ID strings matching other ``CloudIdentity.arn_or_id`` values.
   */
  can_be_assumed_by: string[];
  has_cross_account_trust: boolean;
  governance_tagged: boolean | null;
  last_activity: string | null;
  created_at: string;
  enrichment: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// AgenticWorkload — AI-agent workload inventory record
// ---------------------------------------------------------------------------

export interface AgenticWorkload {
  id: string;
  org_id: string;
  provider: CloudProvider;
  kind: AgenticWorkloadKind;
  resource_id: string;
  display_name: string;
  identity_ref: string;
  governance_tagged: boolean;
  is_shadow: boolean;
  has_overprivileged_identity: boolean;
  internet_reachable: boolean;
  last_activity: string | null;
  risk_score: number;
  enrichment: Record<string, unknown>;
  created_at: string;
}

// ---------------------------------------------------------------------------
// Evidence shapes embedded in HuntFinding.evidence for domain=cloud findings
// ---------------------------------------------------------------------------

/**
 * Evidence fields on a cloud HuntFinding.
 *
 * These are extracted from ``HuntFinding.evidence`` (typed as
 * ``Record<string, unknown>``). All fields are optional because the backend
 * may not set every field for every finding.
 */
export interface CloudFindingEvidence {
  /** Cloud provider (aws / azure / gcp). */
  provider?: CloudProvider;
  /** Cloud account / project / subscription ID. */
  account_id?: string;
  /** IAM actor ARN/ID who performed the action. */
  actor_arn?: string;
  /** Target resource ARN/ID. */
  target_arn?: string;
  /**
   * STS assume-role chain trace from the Phase-A ``detect_sts_chaining``
   * detector. Real emitter writes ``path`` (with ``detection==="sts_chaining"``);
   * ``assume_chain`` is accepted as a legacy alias.
   */
  path?: string[];
  /** Legacy alias for ``path`` — older fixtures may still use this key. */
  assume_chain?: string[];
  /** Detection-type tag from the Phase-A emitters (e.g. ``"sts_chaining"``). */
  detection?: string;
  /** Raw trust policy extract (AWS AssumeRolePolicyDocument). */
  trust_policy?: Record<string, unknown>;
  /** Risk score in [0, 1] (only for shadow-workload findings). */
  risk_score?: number;
  /** True when this finding relates to a shadow (unmanaged) agentic workload. */
  shadow_workload?: boolean;
  /**
   * Workload kind from the real ``detect_shadow_workloads`` /
   * ``detect_overprivileged_workload_identity`` emitters (``evidence.kind``).
   * ``workload_kind`` is accepted as a legacy alias.
   */
  kind?: AgenticWorkloadKind;
  workload_kind?: AgenticWorkloadKind;
  /** MITRE technique family used for grouping in the tamper tab. */
  technique_family?: string;
}

// ---------------------------------------------------------------------------
// UI-only aggregated types
// ---------------------------------------------------------------------------

/**
 * One row in the control-plane event timeline.
 * Derived from a HuntFinding with domain=cloud.
 */
export interface CloudTimelineEntry {
  finding_id: string;
  created_at: string;
  provider: CloudProvider;
  account_id: string;
  actor: string;
  target: string;
  technique_ids: string[];
  title: string;
  severity: string;
}

/**
 * One row in the IAM role-graph view.
 * Derived from assume_chain / trust_policy evidence on cloud findings.
 */
export interface IAMRelationship {
  /** The role being assumed (target). */
  source_role: string;
  /** The principal that can assume ``source_role``. */
  trustee: string;
  /** Source finding that produced this relationship. */
  finding_id: string;
  /** Cross-account if trustee is in a different account than source_role. */
  is_cross_account: boolean;
}

/**
 * One cell in the agentic-workload inventory matrix.
 * Rows = provider, columns = workload kind.
 */
export interface WorkloadMatrixCell {
  provider: CloudProvider;
  kind: AgenticWorkloadKind;
  managed_count: number;
  shadow_count: number;
}

/** Active tab in the Cloud Hunts page. */
export type CloudTab = "timeline" | "iam" | "shadow_workloads" | "tamper";

/** Display labels for provider enum values. */
export const CLOUD_PROVIDER_LABELS: Record<CloudProvider, string> = {
  aws: "AWS",
  azure: "Azure",
  gcp: "GCP",
};

/** Display labels for workload kind enum values. */
export const WORKLOAD_KIND_LABELS: Record<AgenticWorkloadKind, string> = {
  bedrock_agentcore: "Bedrock AgentCore",
  vertex_agent_engine: "Vertex Agent Engine",
  cloud_run_mcp: "Cloud Run MCP",
  gke_inference: "GKE Inference",
  unmanaged: "Unmanaged",
};

/** All workload kinds in a stable column order for the matrix table. */
export const WORKLOAD_KINDS_ORDERED: AgenticWorkloadKind[] = [
  "bedrock_agentcore",
  "vertex_agent_engine",
  "cloud_run_mcp",
  "gke_inference",
  "unmanaged",
];

/** All cloud providers in a stable row order for the matrix table. */
export const CLOUD_PROVIDERS_ORDERED: CloudProvider[] = ["aws", "azure", "gcp"];

// ---------------------------------------------------------------------------
// Containment proposals (#117 Phase C bullet 2 — IAM/STS finding → IR)
// ---------------------------------------------------------------------------
//
// Mirrors ``CloudContainmentAction`` / ``CloudContainmentProposal`` in
// ``shared/btagent_shared/types/cloud_hunt.py``. The proposal is *inert data*
// hanging off an Investigation: nothing in it can dispatch. The only thing that
// can make it act is a human accepting it through
// ``POST /cloud/investigations/{id}/containment-proposal/accept``, which routes
// every action through the #106 containment execute service and inherits that
// path's ``containment:execute`` RBAC scope, its explicit approved-flag second
// gate, mock-by-default dispatch, the org never-touch principal safelist, and an
// audit row on every execute AND every denial.

/** The three cloud control-plane containment verbs this slice proposes. */
export type CloudContainmentActionType =
  | "revoke_role"
  | "freeze_access_key"
  | "detach_policy";

/**
 * Per-action lifecycle.
 *
 * ``proposed`` is inert. ``executed`` and ``denied`` are both written by the
 * #106 execute path — and ``denied`` always has a hash-chained audit row behind
 * it, which is why the UI renders it as a recorded guardrail outcome and never
 * as a failed request.
 */
export type CloudContainmentActionStatus = "proposed" | "executed" | "denied";

/** Lifecycle of the proposal attached to an investigation. */
export type CloudContainmentProposalStatus = "proposed" | "accepted" | "rejected";

/** One proposed containment action against one cloud IAM principal. */
export interface CloudContainmentAction {
  /** Stable within the proposal (``cca_1``, ``cca_2``, …) — names a partial accept. */
  id: string;
  action_type: CloudContainmentActionType;
  provider: CloudProvider;
  /** The principal acted on; the value screened against the org safelist. */
  target: string;
  /** Connector that would enforce it (``aws_iam`` / ``gcp_iam`` / ``azure_iam``). */
  connector: string;
  description: string;
  /** Action-shaped evidence detail: reason, event_name, policy_name, trustees, … */
  parameters: Record<string, unknown>;
  source_finding_ids: string[];
  status: CloudContainmentActionStatus;
  /** Set once the action has been through the #106 execute path. */
  outcome: string;
  audit_id: string | null;
  /** Verbatim server reason — the safelist refusal text arrives here. */
  message: string;
}

/** Inert containment proposals seeded on promotion of IAM/STS findings. */
export interface CloudContainmentProposal {
  actions: CloudContainmentAction[];
  rationale: string;
  status: CloudContainmentProposalStatus;
  decided_by: string | null;
  decided_at: string | null;
  decision_rationale: string;
}

/**
 * Accept/reject body — ``approved`` is the explicit HITL half of the gate.
 *
 * Optional here because that is the wire contract (the backend defaults it to
 * ``false``, so an omitted flag can never execute). Callers that *are* accepting
 * should require it locally rather than letting it default — see
 * ``@/api/cloudContainment``.
 */
export interface CloudContainmentDecisionRequest {
  approved?: boolean;
  rationale?: string;
  action_ids?: string[];
}

/** Display labels for the containment verbs. */
export const CLOUD_CONTAINMENT_ACTION_LABELS: Record<
  CloudContainmentActionType,
  string
> = {
  revoke_role: "Revoke role sessions",
  freeze_access_key: "Freeze access key",
  detach_policy: "Detach policy",
};
