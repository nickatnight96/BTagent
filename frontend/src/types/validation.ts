/** Detection-validation types (#118).
 *
 * Mirrors the backend response models in api/v1/validation.py.
 */

/** One persisted detection-validation run (list/summary view). */
export interface ValidationRunSummary {
  id: string;
  run_id: string;
  packs: string[];
  scenarios_run: number;
  total_techniques: number;
  detected_pct: number;
  gaps: string[];
  /** Emulation-path fields (#118). False / null for in-process replay runs. */
  emulated?: boolean;
  target_env?: string | null;
  generated_at: string;
  created_at: string;
}

/**
 * Where an emulation is aimed. Mirrors ``TargetEnv``.
 *
 * Only ``sandbox`` is approved — the server's allowlist refuses everything
 * else fail-closed with an audited denial, and no emulator is ever reached.
 * The other values exist here so the UI can *offer* them and let the operator
 * see the refusal, rather than the client quietly pre-filtering a control the
 * server is the authority on.
 */
export type TargetEnv = "sandbox" | "staging" | "production" | "unknown";

/** Which adversary-emulation engine drives the run. Mirrors ``Emulator``. */
export type Emulator = "atomic_red_team" | "caldera";

/** Outcome of scoring one emulated technique. Mirrors ``ValidationVerdict``. */
export type ValidationVerdictKind =
  | "validated"
  | "wrong_severity"
  | "late"
  | "silent_gap"
  | "errored";

/** Body for POST /validation/emulate. */
export interface EmulationRunRequest {
  technique_id: string;
  target_env: TargetEnv;
  emulator: Emulator;
}

/** Scored outcome of emulating one technique (subset the UI renders). */
export interface TechniqueVerdict {
  technique_id: string;
  verdict: ValidationVerdictKind;
  emulator: Emulator;
  expected_severity: string;
  observed_severity?: string | null;
  latency_seconds?: number | null;
  latency_sla_seconds: number;
  detail?: string;
}

/**
 * The audited 403 body when a non-sandbox target is refused.
 *
 * Carries ``audit_id`` so the refusal is traceable to a ledger row — the
 * whole point of the denial being audited rather than a bare rejection.
 */
export interface EmulationDenied {
  status: string;
  technique_id: string;
  target_env: string;
  reason: string;
  audit_id: string;
}

/** Per-technique coverage roll-up (POST response payload). */
export interface CoverageResult {
  technique_id: string;
  total_simulated: number;
  detected: number;
  missed: number;
  false_positives: number;
  rules_fired: string[];
  rules_expected_but_missed: string[];
}

/** Response from POST /validation/runs — a run summary plus full coverage. */
export interface ValidationRunResponse extends ValidationRunSummary {
  coverage_by_technique: CoverageResult[];
  /** Populated on the emulation path; empty for in-process replay runs. */
  verdicts?: TechniqueVerdict[];
}

/** Response from GET /validation/runs — the run history list. */
export interface ValidationRunListResponse {
  items: ValidationRunSummary[];
  total: number;
}
