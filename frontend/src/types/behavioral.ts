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
  /** Pattern key the frequency floor matched on (``parent>child`` lineage). */
  event_pattern_key: string | null;
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
// "Why is this an outlier?" — explainability payloads
// --------------------------------------------------------------------------- //

/** Where a "this is what normal looks like" example came from. */
export type ExemplarSource = "entity_baseline" | "peer_baseline";

/**
 * One most-similar *normal* example shown beside an anomalous event.
 *
 * Carries only scores the backend computes: ``token_similarity`` (lexical token
 * overlap with the outlier's pattern key — per-event embeddings are not
 * retained, so baseline patterns cannot be ranked by cosine distance) for
 * entity exemplars, and ``centroid_distance`` (the pgvector cosine distance
 * between baseline centroids) for peer exemplars. Whichever does not apply is
 * ``null`` and the UI must say so rather than substitute a number.
 */
export interface BaselineExemplar {
  pattern_key: string;
  source: ExemplarSource;
  observation_count: number;
  frequency_rank: number;
  token_similarity: number | null;
  centroid_distance: number | null;
  entity_id: string | null;
  entity_canonical_id: string | null;
  profile_id: string | null;
}

/**
 * A contributing signal behind a detection — or an honest "unavailable".
 * ``available: false`` means the platform does not persist that signal per
 * outlier (e.g. the run-time detection thresholds); ``value`` is then null and
 * ``detail`` explains why.
 */
export interface ExplainSignal {
  key: string;
  label: string;
  value: string | null;
  detail: string;
  available: boolean;
}

/** The baseline window an outlier was scored against. */
export interface BaselineSummary {
  profile_id: string;
  profile_type: ProfileType;
  sample_size: number;
  pattern_count: number;
  has_centroid: boolean;
  window_start: string;
  window_end: string;
  computed_at: string;
}

/** Response of ``GET /behavioral/outliers/{id}/explain``. */
export interface OutlierExplanation {
  outlier: BehavioralOutlier;
  entity_id: string;
  entity_kind: EntityKind;
  entity_canonical_id: string;
  anomalous_event: string;
  event_pattern_key: string | null;
  baseline: BaselineSummary | null;
  exemplars: BaselineExemplar[];
  signals: ExplainSignal[];
  /** Anything that could not be produced (no baseline, no centroid, …). */
  notes: string[];
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
