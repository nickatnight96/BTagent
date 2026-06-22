/**
 * Behavioral Hunter UI types (#114 Phase B).
 *
 * Mirrors the backend shapes in
 * ``shared/btagent_shared/types/behavioral.py`` — kept in sync manually;
 * the string literal unions match the backend StrEnum values exactly.
 */

export type EntityKind = "user" | "host" | "service_principal" | "ip";

export type ProfileType =
  | "cmdline_embedding"
  | "process_tree_pattern"
  | "identity_action_sequence"
  | "network_egress_profile";

export type IntentLabel = "benign" | "suspicious" | "malicious";

// --------------------------------------------------------------------------- //
// Domain models
// --------------------------------------------------------------------------- //

export interface BehavioralEntity {
  id: string;
  org_id: string;
  kind: EntityKind;
  canonical_id: string;
  first_seen: string;
  last_seen: string;
  enrichment: Record<string, unknown>;
}

export interface BehavioralProfile {
  id: string;
  org_id: string;
  entity_id: string;
  profile_type: ProfileType;
  centroid: number[] | null;
  frequency_map: Record<string, number>;
  pattern_count: number;
  sample_size: number;
  window_start: string;
  window_end: string;
  computed_at: string;
  updated_at: string;
}

export interface BehavioralOutlier {
  id: string;
  org_id: string;
  entity_id: string;
  profile_type: ProfileType;
  event_id: string;
  cosine_distance: number;
  frequency_rank: number;
  raw_event_excerpt: string;
  intent_label: IntentLabel | null;
  intent_rationale: string | null;
  promoted_to_finding_id: string | null;
  created_at: string;
}

// --------------------------------------------------------------------------- //
// Request / response payloads
// --------------------------------------------------------------------------- //

export interface SetIntentRequest {
  intent_label: IntentLabel;
  rationale: string;
}

export interface PromoteOutlierRequest {
  technique_ids: string[];
}

export interface PromoteOutlierResponse {
  finding_id: string;
}

export interface BehavioralOutlierListResponse {
  items: BehavioralOutlier[];
  total: number;
}

// --------------------------------------------------------------------------- //
// UI-only aggregated types
// --------------------------------------------------------------------------- //

/**
 * A per-entity drift summary derived client-side from the outlier list.
 *
 * Drift score = count × max_cosine_distance.  Rationale: ``count`` captures
 * how frequently the entity is anomalous (breadth); ``max_cosine_distance``
 * captures the worst single deviation (severity).  The product is a simple,
 * dimensionless scalar that ranks entities by both frequency and magnitude —
 * an entity with one extreme outlier (high distance, low count) ranks
 * similarly to one with many moderate outliers (lower distance, high count),
 * which matches analyst intuition.
 */
export interface EntityDriftSummary {
  entity_id: string;
  /** Most-recently-seen canonical_id for the entity (display name). */
  canonical_id: string;
  kind: EntityKind;
  /** Number of outlier records in the current page window. */
  outlier_count: number;
  max_cosine_distance: number;
  /**
   * Drift score = outlier_count × max_cosine_distance.
   * Pre-computed here so the dashboard can sort without a second pass.
   */
  drift_score: number;
  /** All outliers for this entity (used by the drilldown view). */
  outliers: BehavioralOutlier[];
}
