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
  /** Detection-rule ids matched against evidence.rule_id (pack provenance). */
  rule_ids?: string[];
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

/** Response from POST /hunt/agentic/run — an agentic-misuse hunt run summary. */
export interface AgenticHuntRunResponse {
  total_events: number;
  total_identities: number;
  total_workloads: number;
  findings_emitted: number;
  findings_created: number;
  counts_by_severity: Record<string, number>;
}

/** Response from POST /hunt/cloud/run — a cloud control-plane hunt run summary. */
export interface CloudHuntRunResponse {
  total_identities: number;
  total_workloads: number;
  total_cloudtrail_events: number;
  total_resource_events: number;
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
  /** Whether the vertical has a cron at all (false = manual-only). */
  scheduled: boolean;
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

/** One chronically-hitting pack rule — advisory suppression candidate (#112). */
export interface NoisyRule {
  pack_id: string;
  pack_name: string;
  rule_id: string;
  rule_title: string;
  runs_observed: number;
  runs_hit: number;
  hit_rate: number;
  total_hits: number;
  avg_hits_per_run: number;
  last_hit_at: string | null;
}

/** One rule with a zero-hit record across the whole window (#112 Phase C). */
export interface UnderFiringRule {
  pack_id: string;
  pack_name: string;
  rule_id: string;
  rule_title: string;
  runs_observed: number;
  total_hits: number;
  first_observed_at: string | null;
  last_observed_at: string | null;
  days_silent: number;
  window_days: number;
}

/** Response from GET /hunt/under-firing. */
export interface UnderFiringReport {
  items: UnderFiringRule[];
  runs_analyzed: number;
  window_days: number;
  min_runs: number;
}

/**
 * One enabled rule that every sweep in the window skipped (#112).
 *
 * The E7 rules-per-sweep cap and per-run deadline stop the runner mid-list, so
 * these rules produced no `rule_stats` entry at all — they are invisible to
 * both hit-rate advisories, which is exactly why they get their own list. No
 * `rule_title`: the backend only has ids for rules that never built a result.
 */
export interface NeverRunRule {
  pack_id: string;
  pack_name: string;
  rule_id: string;
  runs_skipped: number;
  first_skipped_at: string | null;
  last_skipped_at: string | null;
  days_dark: number;
  window_days: number;
}

/** Response from GET /hunt/noise-baseline. */
export interface NoiseBaseline {
  items: NoisyRule[];
  runs_analyzed: number;
  min_runs: number;
  hit_rate_threshold: number;
  /** Mirror-image advisory: rules silent for the whole window (#112 Phase C). */
  under_firing?: UnderFiringRule[];
  under_firing_window_days?: number;
  /** Third direction: enabled rules no sweep in the window ever executed. */
  never_run?: NeverRunRule[];
  never_run_window_days?: number;
}

/** One hunt pack + this org's install/enable state (GET /hunt/packs). */
export interface HuntPackCatalogEntry {
  /** Install key — the builtin pack name the runner loads. */
  pack_id: string;
  /** The id this pack's runs carry in ``hunt_pack_runs.pack_id``. */
  manifest_pack_id: string;
  name: string;
  version: string;
  description: string;
  rule_count: number;
  /**
   * "builtin" (shipped), "installed" (imported corpus), or "custom"
   * (uploaded bundle — enabled by existence, managed in the custom-packs
   * panel, not toggleable through PUT /hunt/packs).
   */
  source: "builtin" | "installed" | "custom";
  enabled: boolean;
  /** True when an explicit org row exists (vs. resolved from the defaults). */
  installed: boolean;
  default_enabled: boolean;
  installed_at: string | null;
  updated_at: string | null;
  updated_by: string | null;
}

/** Response from GET /hunt/packs. */
export interface HuntPackCatalogResponse {
  items: HuntPackCatalogEntry[];
  total: number;
  default_packs: string[];
}

/**
 * Per-rule health relative to its noise baseline (#112 Phase B).
 * Mirrors ``btagent_shared.types.huntpack.HuntRuleState``.
 */
export type HuntRuleState =
  | "clean"
  | "firing_as_expected"
  | "over_firing"
  | "under_firing"
  | "errored";

/** One rule's rollup inside a pack run's ``rule_stats`` map. */
export interface HuntPackRunRuleStat {
  title: string;
  hits: number;
  errors: number;
  /** Transpiled query string per backend (``backend -> query``). */
  queries?: Record<string, string>;
}

/**
 * One scheduled / ad-hoc hunt-pack execution's history record (#112).
 * Mirrors ``btagent_shared.types.hunt_finding.HuntPackRun`` /
 * ``HuntPackRunRow``. ``status`` is ``running`` while in flight (resumable),
 * else a terminal ``completed`` / ``completed_with_errors`` / ``failed``.
 */
export interface HuntPackRun {
  id: string;
  org_id: string;
  run_id: string;
  pack_id: string;
  pack_name: string;
  pack_version: string;
  backends: string[];
  rule_stats: Record<string, HuntPackRunRuleStat>;
  hit_count: number;
  error_count: number;
  findings_created: number;
  status: string;
  error: string | null;
  /**
   * E7: the rules-per-sweep cap or the per-run deadline stopped this sweep
   * before every enabled rule ran. A truncated run still lands ``completed``,
   * so status alone cannot express it — without this flag a partial sweep is
   * indistinguishable from a full one, and "0 hits" reads as "nothing there"
   * rather than "we did not look".
   */
  truncated: boolean;
  /** Rule ids the run never got to (empty unless ``truncated``). */
  rules_not_run: string[];
  started_at: string;
  completed_at: string | null;
}

/** Response from GET /hunt/pack-runs. */
export interface HuntPackRunListResponse {
  items: HuntPackRun[];
  total: number;
}
