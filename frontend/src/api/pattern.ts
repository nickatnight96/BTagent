/**
 * Pattern Hunt API client (#120 Phase B).
 *
 * Typed thin wrappers over ``/api/v1/pattern/*`` — mirrors the shape of
 * ``@/api/behavioral`` so the store layer stays symmetrical.
 */

import api from "./client";
import type {
  ActionRequest,
  ExecutePlanResponse,
  PatternHuntProposal,
  PatternHuntProposalListResponse,
  ProposalFilter,
  ProposalHuntPlan,
} from "@/types/pattern_hunt";

const BASE = "/v1/pattern";

// --------------------------------------------------------------------------- //
// Read
// --------------------------------------------------------------------------- //

/** Org-scoped, paginated proposal list (optionally filtered by state). */
export async function listProposals(params?: {
  state?: ProposalFilter | null;
  page?: number;
  page_size?: number;
}): Promise<PatternHuntProposalListResponse> {
  const search = new URLSearchParams();
  if (params?.state && params.state !== "all") {
    search.set("state", params.state);
  }
  if (params?.page) search.set("page", String(params.page));
  if (params?.page_size) search.set("page_size", String(params.page_size));
  const qs = search.toString();
  return api.get<PatternHuntProposalListResponse>(`${BASE}/proposals${qs ? `?${qs}` : ""}`);
}

// --------------------------------------------------------------------------- //
// Lifecycle mutations
// --------------------------------------------------------------------------- //

/**
 * Dismiss a proposal — down-weights similar future surfacing.
 * Requires ``hunt:triage`` permission.
 */
export async function dismissProposal(
  proposalId: string,
  body?: ActionRequest,
): Promise<PatternHuntProposal> {
  return api.post<PatternHuntProposal>(`${BASE}/proposals/${proposalId}/dismiss`, body ?? {});
}

/**
 * Snooze a proposal — reversibly down-weights similar future surfacing.
 * Requires ``hunt:triage`` permission.
 */
export async function snoozeProposal(
  proposalId: string,
  body?: ActionRequest,
): Promise<PatternHuntProposal> {
  return api.post<PatternHuntProposal>(`${BASE}/proposals/${proposalId}/snooze`, body ?? {});
}

/**
 * Accept a proposal — marks it as accepted so the analyst can kick off the
 * hunt. HuntPlan generation is deferred to Phase C.
 * Requires ``hunt:triage`` permission.
 */
export async function acceptProposal(
  proposalId: string,
  body?: ActionRequest,
): Promise<PatternHuntProposal> {
  return api.post<PatternHuntProposal>(`${BASE}/proposals/${proposalId}/accept`, body ?? {});
}

// --------------------------------------------------------------------------- //
// HuntPlan (#120 Phase C — compiled plan + execution)
// --------------------------------------------------------------------------- //

/**
 * Fetch the compiled HuntPlan (or its compile status) for a proposal.
 * 404s until the proposal has been accepted.
 */
export async function getProposalPlan(proposalId: string): Promise<ProposalHuntPlan> {
  return api.get<ProposalHuntPlan>(`${BASE}/proposals/${proposalId}/plan`);
}

/**
 * Execute the compiled plan — hits land in the hunt triage inbox. Inline
 * under mock connectors (``queued: false`` + counts); queued to the worker
 * on the live path (``queued: true``, poll ``getProposalPlan`` for
 * ``last_run``).
 */
export async function executeProposalPlan(proposalId: string): Promise<ExecutePlanResponse> {
  return api.post<ExecutePlanResponse>(`${BASE}/proposals/${proposalId}/plan/execute`, {});
}
