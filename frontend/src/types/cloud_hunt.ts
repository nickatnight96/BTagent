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
   * Assume-chain: list of ARN/ID strings representing a transitive
   * assume-role path, e.g. [roleA, roleB, roleC].
   */
  assume_chain?: string[];
  /** Raw trust policy extract (AWS AssumeRolePolicyDocument). */
  trust_policy?: Record<string, unknown>;
  /** Risk score in [0, 1] (only for shadow-workload findings). */
  risk_score?: number;
  /** True when this finding relates to a shadow (unmanaged) agentic workload. */
  shadow_workload?: boolean;
  /** AgenticWorkloadKind when known. */
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
