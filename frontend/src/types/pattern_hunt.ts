/**
 * Pattern Hunt UI types (#120 Phase B).
 *
 * Mirrors the backend shapes in
 * ``shared/btagent_shared/types/pattern_hunt.py`` — kept in sync manually;
 * the string literal unions match the backend StrEnum values exactly.
 */

// --------------------------------------------------------------------------- //
// Enums (mirrored from Python StrEnum)
// --------------------------------------------------------------------------- //

export type WeakSignalKind =
  | "ioc"
  | "tld"
  | "cmdline_fragment"
  | "asset"
  | "asn"
  | "technique";

export type ProposalState = "proposed" | "accepted" | "dismissed" | "snoozed";

export type ProposalOutcome = "clean" | "hit";

// --------------------------------------------------------------------------- //
// Domain models
// --------------------------------------------------------------------------- //

/**
 * A single faint observable extracted from the closed-investigation corpus.
 * The UI uses this to show the source signal members inside a proposal card.
 */
export interface WeakSignal {
  id: string;
  kind: WeakSignalKind;
  value: string;
  ioc_type: string | null;
  first_seen: string;
  last_seen: string;
  investigation_refs: string[];
  distinct_investigation_count: number;
}

/**
 * A group of similar weak signals with its explainable rank.
 *
 * ``score`` is ``frequency × recency × cross-investigation diversity``;
 * ``rationale`` is the human-readable breakdown the UI surfaces in the
 * "why did this surface?" section.
 */
export interface WeakSignalCluster {
  id: string;
  members: WeakSignal[];
  score: number;
  rationale: string;
}

/**
 * A high-ranking cluster turned into a ready-to-run hunt proposal.
 *
 * ``hunt_input`` is the serialised ``HuntInput`` (adversaries / ttps / iocs /
 * scope) that Phase C will use to emit a ``HuntPlan``; Phase B just shows it
 * for context.
 */
export interface PatternHuntProposal {
  id: string;
  org_id: string;
  cluster_id: string;
  score: number;
  hunt_input: {
    adversaries: string[];
    ttps: string[];
    iocs: Array<{
      type: string;
      value: string;
      [key: string]: unknown;
    }>;
    scope?: {
      environments: string[];
      hosts: string[];
      date_from: string | null;
      date_to: string | null;
      backends: string[];
    };
  };
  rationale: string;
  /** Analyst triage notes accumulated across transitions (kept separate from
   * the generated `rationale` so that text stays pristine). */
  triage_rationale: string;
  state: ProposalState;
  outcome: ProposalOutcome | null;
  created_at: string;
  updated_at: string;
}

// --------------------------------------------------------------------------- //
// Request / response payloads
// --------------------------------------------------------------------------- //

export interface ActionRequest {
  rationale?: string;
}

export interface PatternHuntProposalListResponse {
  items: PatternHuntProposal[];
  total: number;
}

// --------------------------------------------------------------------------- //
// UI-only aggregated / derived types
// --------------------------------------------------------------------------- //

/**
 * A display-oriented summary of the hunt-input signal types for a proposal.
 * Derived client-side from ``hunt_input`` so the card can render chip groups.
 */
export interface ProposalSignalSummary {
  ttp_count: number;
  ioc_count: number;
  adversary_count: number;
}

/** Filter tab union — "all" is the catch-all; others match ProposalState. */
export type ProposalFilter = ProposalState | "all";

// --------------------------------------------------------------------------- //
// HuntPlan (#120 Phase C — compiled plan + execution)
// --------------------------------------------------------------------------- //

/** Compile lifecycle of the stored plan row (NOT the plan's execution state). */
export type HuntPlanRowStatus = "pending" | "ready" | "failed";

/**
 * ``GET /pattern/proposals/{id}/plan`` response — compile status plus the
 * serialised HuntPlan. ``plan`` is null until the compile finishes; after an
 * execution it additionally carries a ``last_run`` summary object.
 */
export interface ProposalHuntPlan {
  id: string;
  org_id: string;
  proposal_id: string;
  status: HuntPlanRowStatus;
  plan: {
    id: string;
    state: string;
    hypotheses: Array<{ ttp_id: string; ttp_name: string; priority: number }>;
    ttp_entries: Array<{
      ttp_id: string;
      ttp_name: string;
      queries: Record<string, { backend: string; query: string }>;
    }>;
    last_run?: {
      run_id: string;
      started_at: string;
      completed_at: string | null;
      findings_created: number;
      error_count: number;
      per_ttp: Record<string, { hits: number; errors: string[] }>;
    };
    [key: string]: unknown;
  } | null;
  error: string;
  created_at: string;
  updated_at: string;
}

/** ``POST /pattern/proposals/{id}/plan/execute`` response. */
export interface ExecutePlanResponse {
  plan: ProposalHuntPlan;
  queued: boolean;
  findings_created: number | null;
}
