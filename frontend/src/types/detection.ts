/** CTI → Detection proposal types (#113).
 *
 * Mirrors the backend response models in api/v1/cti_detection.py.
 */

export type ProposalState = "proposed" | "accepted" | "rejected" | "modified";

/** A persisted STIX → Sigma detection proposal. */
export interface DetectionProposal {
  id: string;
  org_id: string;
  proposal_id: string;
  source_stix_id: string;
  bundle_id: string | null;
  title: string;
  sigma_yaml: string;
  technique_ids: string[];
  confidence: number;
  rationale: string;
  state: ProposalState;
  validation: Record<string, unknown> | null;
  validated_at: string | null;
  pr_url: string | null;
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
