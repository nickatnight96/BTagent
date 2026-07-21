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
  generated_at: string;
  created_at: string;
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
}

/** Response from GET /validation/runs — the run history list. */
export interface ValidationRunListResponse {
  items: ValidationRunSummary[];
  total: number;
}
