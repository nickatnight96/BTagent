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
