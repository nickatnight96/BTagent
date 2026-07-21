/** CTI → Detection proposal API client (#113). */

import api from "./client";
import type {
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
