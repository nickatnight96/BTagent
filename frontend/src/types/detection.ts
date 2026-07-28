/** CTI → Detection proposal types (#113).
 *
 * Mirrors the backend response models in api/v1/cti_detection.py.
 */

export type ProposalState = "proposed" | "accepted" | "rejected" | "modified";

/** Detection-repo PR lifecycle for a composed proposal (#113 Phase C). */
export type PROutcome = "proposed" | "pr_opened" | "merged" | "rejected";

/** A persisted STIX → Sigma detection proposal. */
export interface DetectionProposal {
  id: string;
  org_id: string;
  proposal_id: string;
  source_stix_id: string;
  bundle_id: string | null;
  title: string;
  sigma_yaml: string;
  /** Analyst-edited "final" rule body (#113 Phase C). Null until edited. */
  final_sigma_yaml: string | null;
  technique_ids: string[];
  confidence: number;
  rationale: string;
  state: ProposalState;
  validation: Record<string, unknown> | null;
  validated_at: string | null;
  pr_url: string | null;
  pr_outcome: PROutcome;
  review_rationale: string;
  reviewed_by: string | null;
  reviewed_at: string | null;
  created_at: string;
  updated_at: string;
}

/** Response from GET /cti/proposals. */
export interface DetectionProposalListResponse {
  items: DetectionProposal[];
  total: number;
}

/** Response from POST /cti/proposals/compose-pr. */
export interface ComposePRResponse {
  pr_url: string;
  branch: string;
  commit: string;
  rule_count: number;
  row_ids: string[];
  is_mock: boolean;
}
