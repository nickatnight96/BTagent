/** Coverage Console types (#501).
 *
 * Mirrors the backend response models in
 * ``btagent_backend/services/coverage_console_service.py``, served by
 * ``GET /api/v1/coverage/console``.
 */

import type { ValidationVerdictKind } from "./validation";

/**
 * Heatmap band for one technique.
 *
 * Green = proven working recently, amber = overdue for re-validation, red =
 * never proven or proven silent. ``silent_gap`` outranks staleness server-side.
 */
export type CoverageStatus = "fresh" | "stale" | "never" | "silent_gap";

/** ``HuntRuleState`` subset the console reports — only the unhealthy ones. */
export type BrokenRuleState = "over_firing" | "under_firing" | "errored";

/** One technique cell: coverage + validation freshness. */
export interface TechniqueCoverageCell {
  technique_id: string;
  name?: string | null;
  tactic: string;
  last_validated?: string | null;
  last_verdict?: string | null;
  days_since_validated?: number | null;
  stale: boolean;
  has_detection: boolean;
  status: CoverageStatus;
}

/** One ATT&CK tactic column of the matrix, with its band tallies. */
export interface TacticColumn {
  tactic: string;
  techniques: TechniqueCoverageCell[];
  fresh: number;
  stale: number;
  never: number;
  silent_gap: number;
}

/** A deployed rule that is not doing its job (the #112 "dead 13%"). */
export interface BrokenRule {
  pack_id: string;
  pack_name: string;
  rule_id: string;
  rule_title: string;
  state: BrokenRuleState;
  runs_observed: number;
  runs_hit: number;
  hit_rate: number;
  total_hits: number;
  last_errors: number;
  last_run_at?: string | null;
}

/** A technique whose detection cannot be proven against current telemetry. */
export interface TelemetryGap {
  technique_id: string;
  name?: string | null;
  proposal_id: string;
  proposal_row_id: string;
  title: string;
  reason: "backends_errored" | "never_validated";
  unavailable_backends: string[];
  available_backends: string[];
  attack_data_sources: string[];
}

/** Validation verdicts tallied by kind across the org's run history. */
export type VerdictCounts = Record<ValidationVerdictKind, number> & { total: number };

/** One prioritised thing to do, deep-linked to the surface that does it. */
export interface NextBestAction {
  id: string;
  kind: "revalidate_technique" | "author_detection" | "tune_rule" | "review_draft";
  title: string;
  detail: string;
  /** 1 = most urgent. The list is already sorted by it. */
  priority: number;
  count: number;
  /** Frontend route this action hands off to. */
  link: string;
  technique_ids: string[];
  rule_ids: string[];
}

/** The headline numbers the console leads with. */
export interface CoverageSummary {
  total_techniques: number;
  with_detection: number;
  fresh: number;
  stale: number;
  never_validated: number;
  silent_gap: number;
  mitre_total_techniques: number;
  mapped_techniques: number;
  unmapped_techniques: number;
  broken_rules: number;
  telemetry_gaps: number;
  open_proposals: number;
  proposals_awaiting_review: number;
  prs_open: number;
}

/** Response from GET /coverage/console. */
export interface CoverageConsole {
  generated_at: string;
  stale_days: number;
  summary: CoverageSummary;
  tactics: TacticColumn[];
  techniques: TechniqueCoverageCell[];
  broken_rules: BrokenRule[];
  telemetry_gaps: TelemetryGap[];
  verdict_counts: VerdictCounts;
  next_best_actions: NextBestAction[];
}
