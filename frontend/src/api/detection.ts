/** CTI → Detection proposal API client (#113). */

import api from "./client";
import type {
  ComposePRResponse,
  DetectionProposal,
  DetectionProposalListResponse,
  ProposalState,
} from "@/types/detection";

const BASE = "/v1/cti";

/** List detection proposals, optionally filtered by state, newest-first. */
export async function listProposals(params?: {
  state?: ProposalState;
  page?: number;
  page_size?: number;
}): Promise<DetectionProposalListResponse> {
  const search = new URLSearchParams();
  if (params?.state) search.set("state", params.state);
  if (params?.page) search.set("page", String(params.page));
  if (params?.page_size) search.set("page_size", String(params.page_size));
  const qs = search.toString();
  return api.get<DetectionProposalListResponse>(
    `${BASE}/proposals${qs ? `?${qs}` : ""}`,
  );
}

/** Accept a proposal with an optional review rationale. */
export async function acceptProposal(
  rowId: string,
  rationale = "",
): Promise<DetectionProposal> {
  return api.post<DetectionProposal>(`${BASE}/proposals/${rowId}/accept`, {
    rationale,
  });
}

/** Reject a proposal with an optional review rationale. */
export async function rejectProposal(
  rowId: string,
  rationale = "",
): Promise<DetectionProposal> {
  return api.post<DetectionProposal>(`${BASE}/proposals/${rowId}/reject`, {
    rationale,
  });
}

/**
 * Validate a proposal's Sigma rule against historical telemetry.
 * Returns the row with its `validation` verdict populated (mock connectors)
 * or unchanged (live path — the run is queued and lands asynchronously).
 */
export async function validateProposal(
  rowId: string,
  opts?: { backends?: string[]; lookback_hours?: number },
): Promise<DetectionProposal> {
  return api.post<DetectionProposal>(`${BASE}/proposals/${rowId}/validate`, {
    ...(opts?.backends ? { backends: opts.backends } : {}),
    ...(opts?.lookback_hours ? { lookback_hours: opts.lookback_hours } : {}),
  });
}

/**
 * Edit a proposal's Sigma rule (Engineer UI draft-edit path, #113 Phase C).
 * The edited body must parse as a Sigma rule; the row flips to `modified` and
 * the edited body ships instead of the generated draft. Returns the updated row.
 */
export async function editProposal(
  rowId: string,
  sigmaYaml: string,
  rationale = "",
): Promise<DetectionProposal> {
  return api.post<DetectionProposal>(`${BASE}/proposals/${rowId}/edit`, {
    sigma_yaml: sigmaYaml,
    rationale,
  });
}

/** Ship accepted proposals as one detection-repo pull request (HITL-gated). */
export async function composeDetectionPR(
  rowIds: string[],
  title?: string,
): Promise<ComposePRResponse> {
  return api.post<ComposePRResponse>(`${BASE}/proposals/compose-pr`, {
    row_ids: rowIds,
    ...(title ? { title } : {}),
  });
}

/** Summary of what the merge closed loop did (best-effort, may be empty). */
export interface ClosedLoop {
  hunt_pack?: Record<string, unknown>;
  validation_run?: Record<string, unknown>;
  [k: string]: unknown;
}

export interface PROutcomeResponse {
  proposal: DetectionProposal;
  closed_loop: ClosedLoop;
}

/**
 * Record what happened to a composed proposal's detection-repo PR.
 *
 * Only recordable once a PR is open, and only once — the server 409s on a
 * proposal that never shipped or is already terminal. Requires
 * `hunt:promote` (senior_analyst+): recording a merge *arms a live recurring
 * detection*, so it carries the same authority as composing the PR.
 *
 * On `merged` the closed loop fires server-side — the rule is auto-installed
 * as a hunt-pack entry and a sandbox detection-validation run is triggered.
 * Both are best-effort there, so the response reports what actually happened
 * rather than what was intended.
 */
export async function recordPROutcome(
  rowId: string,
  outcome: "merged" | "rejected",
): Promise<PROutcomeResponse> {
  return api.post<PROutcomeResponse>(`${BASE}/proposals/${rowId}/pr-outcome`, {
    outcome,
  });
}

/** A STIX indicator that could not be converted, with the reason. */
export interface SkippedIndicator {
  stix_id: string;
  pattern: string;
  reason: string;
}

/**
 * Upsert counts from a propose call.
 *
 * `unchanged` is the important one: re-importing a bundle never clobbers a
 * decision an analyst already made, so those rows are counted, not rewritten.
 */
export interface PersistedCounts {
  created: number;
  updated: number;
  unchanged: number;
}

export interface ProposeDetectionsResponse {
  proposals: DetectionProposal[];
  skipped: SkippedIndicator[];
  persisted: PersistedCounts | null;
}

/**
 * Turn a STIX 2.1 bundle into Sigma rule proposals, persisted for review.
 *
 * Requires `hunt:create` (analyst+). The server refuses TLP:RED bundles with
 * a 403 and rejects non-STIX input with a 422 — both are contentful answers
 * worth surfacing verbatim rather than collapsing into "import failed".
 *
 * Re-submitting the same bundle upserts rows that are still `proposed`;
 * anything an analyst has already decided keeps its decision.
 */
export async function proposeDetections(
  bundle: Record<string, unknown>,
  activeTlp = "green",
): Promise<ProposeDetectionsResponse> {
  return api.post<ProposeDetectionsResponse>(`${BASE}/propose-detections`, {
    stix_bundle: bundle,
    active_tlp: activeTlp,
  });
}

/**
 * Unstructured CTI report text → Sigma proposals (#113 back half).
 * The server extracts IOCs (defanged forms handled) into a synthetic STIX
 * bundle and runs the identical propose pipeline; 422 when no IOCs found.
 */
export async function proposeDetectionsFromReport(
  reportText: string,
  reportName = "",
  activeTlp = "green",
): Promise<ProposeDetectionsResponse> {
  return api.post<ProposeDetectionsResponse>(`${BASE}/propose-detections`, {
    report_text: reportText,
    report_name: reportName,
    active_tlp: activeTlp,
  });
}
