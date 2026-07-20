/** Proactive threat-hunting domain types (Phase 6 #119).
 *
 * Mirrors the backend schemas in btagent_shared/types/hunt_finding.py and
 * the /api/v1/hunt routes.
 */

export type HuntDomain =
  | "sigma"
  | "behavioral"
  | "identity"
  | "cloud"
  | "cross_investigation"
  | "agentic";

export type HuntSource =
  | "hunt_pack"
  | "behavioral"
  | "identity"
  | "cloud"
  | "cross_investigation"
  | "agentic"
  | "manual";

export type HuntFindingState =
  | "new"
  | "clustered"
  | "triaged"
  | "suppressed"
  | "promoted"
  | "dismissed";

export type SuppressionState = "active" | "needs_reconfirm" | "expired" | "revoked";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface HuntEntity {
  kind: string;
  value: string;
}

export interface HuntObservable {
  type: string;
  value: string;
}

export interface SuppressionMatch {
  source?: HuntSource | null;
  domain?: HuntDomain | null;
  technique_ids: string[];
  entity_values: string[];
  observable_values: string[];
}

export interface HuntFinding {
  id: string;
  org_id: string;
  source: HuntSource;
  domain: HuntDomain;
  title: string;
  description: string;
  severity: Severity;
  confidence: number;
  technique_ids: string[];
  entities: HuntEntity[];
  observables: HuntObservable[];
  state: HuntFindingState;
  cluster_id: string | null;
  suppressed_by: string | null;
  investigation_id: string | null;
  evidence: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface HuntFindingCluster {
  id: string;
  org_id: string;
  signature: string;
  title: string;
  domain: HuntDomain;
  severity: Severity;
  technique_ids: string[];
  finding_count: number;
  state: HuntFindingState;
  representative_finding_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface SuppressionRule {
  id: string;
  org_id: string;
  name: string;
  reason: string;
  match: SuppressionMatch;
  state: SuppressionState;
  match_count: number;
  created_by: string | null;
  created_at: string;
  expires_at: string | null;
  reconfirm_at: string | null;
}

export interface HuntFindingClusterListResponse {
  clusters: HuntFindingCluster[];
  findings: HuntFinding[];
  total_clusters: number;
  total_findings: number;
}

export interface SuppressionListResponse {
  items: SuppressionRule[];
  total: number;
}

/** Response from POST /hunt/email/run — an email-hunt run summary. */
export interface EmailHuntRunResponse {
  window: { start: string; end: string };
  total_incidents: number;
  active_incident_count: number;
  findings_emitted: number;
  findings_created: number;
  counts_by_severity: Record<string, number>;
}

/** Response from POST /hunt/deception/run — a deception-hunt run summary. */
export interface DeceptionHuntRunResponse {
  total_incidents: number;
  active_intruder_count: number;
  findings_emitted: number;
  findings_created: number;
  counts_by_severity: Record<string, number>;
}

/** Response from POST /hunt/ndr/run — an NDR-hunt run summary. */
export interface NdrHuntRunResponse {
  total_hosts: number;
  campaign_count: number;
  findings_emitted: number;
  findings_created: number;
  counts_by_severity: Record<string, number>;
}

/** One vertical's slice of a combined all-hunts sweep. */
export interface VerticalRunSummary {
  findings_emitted: number;
  findings_created: number;
  counts_by_severity: Record<string, number>;
}

/** Response from POST /hunt/all/run — a combined sweep over every vertical. */
export interface AllHuntsRunResponse {
  verticals: Record<string, VerticalRunSummary>;
  total_findings_emitted: number;
  total_findings_created: number;
  counts_by_severity: Record<string, number>;
}

/** One findings-vertical entry from GET /hunt/verticals. */
export interface HuntVertical {
  name: string;
  domain: HuntDomain;
  source: HuntSource;
  run_route: string;
  windowed: boolean;
  schedule_enabled: boolean;
  scan_interval_hours: number;
}

/** Response from GET /hunt/verticals — the manual-runnable vertical catalog. */
export interface HuntVerticalListResponse {
  verticals: HuntVertical[];
}

export interface CreateSuppressionRequest {
  name: string;
  reason: string;
  match: SuppressionMatch;
  expires_in_hours?: number | null;
  reconfirm_in_hours?: number | null;
}

export interface PromoteFindingsResponse {
  investigation_id: string;
  promoted_finding_ids: string[];
}

export interface SuppressClusterRequest {
  name: string;
  reason: string;
  match?: SuppressionMatch | null;
  expires_in_hours?: number | null;
  reconfirm_in_hours?: number | null;
}

export interface PromoteClusterRequest {
  title?: string | null;
}
