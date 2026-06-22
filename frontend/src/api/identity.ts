/**
 * Identity Hunt API client (#116 Phase B).
 *
 * Thin typed wrapper around the existing ``/api/v1/hunt/findings`` endpoint,
 * pre-filtered to ``domain=identity``.  No new backend endpoints are added in
 * this slice — the identity detectors emit standard ``HuntFinding``s into the
 * existing queue and this client simply constrains the query.
 *
 * TODO (Phase C): When ``GET /api/v1/identity/grants`` lands, add
 * ``listIdentityGrants(principalId?)`` here to power the live OAuth-grant
 * graph visualization.  The backend endpoint should return ``OAuthGrant[]``
 * (see ``shared/btagent_shared/types/identity_hunt.py``).
 */

import api from "./client";
import type {
  HuntFinding,
  HuntFindingClusterListResponse,
  PromoteFindingsResponse,
  SuppressionRule,
  CreateSuppressionRequest,
} from "@/types/hunt";

const HUNT_BASE = "/v1/hunt";

// --------------------------------------------------------------------------- //
// Read
// --------------------------------------------------------------------------- //

/**
 * List identity hunt findings, pre-filtered to ``domain=identity``.
 *
 * Mirrors the shape of ``listFindings`` in ``@/api/hunt`` but hard-codes the
 * domain filter so callers do not have to remember it.
 */
export async function listIdentityFindings(params?: {
  state?: "active" | "suppressed" | "promoted" | "all";
  page?: number;
  page_size?: number;
}): Promise<HuntFindingClusterListResponse> {
  const search = new URLSearchParams();
  search.set("domain", "identity");
  if (params?.state) search.set("state", params.state);
  if (params?.page) search.set("page", String(params.page));
  if (params?.page_size) search.set("page_size", String(params.page_size));
  return api.get<HuntFindingClusterListResponse>(
    `${HUNT_BASE}/findings?${search.toString()}`,
  );
}

/** Fetch a single identity finding by id. */
export async function getIdentityFinding(findingId: string): Promise<HuntFinding> {
  return api.get<HuntFinding>(`${HUNT_BASE}/findings/${findingId}`);
}

// --------------------------------------------------------------------------- //
// Triage mutations (delegate to existing hunt endpoints)
// --------------------------------------------------------------------------- //

/** Suppress an identity finding (creates a suppression rule and applies it). */
export async function suppressIdentityFinding(
  findingId: string,
  body: CreateSuppressionRequest,
): Promise<SuppressionRule> {
  return api.post<SuppressionRule>(`${HUNT_BASE}/findings/${findingId}/suppress`, body);
}

/** Promote one or more identity findings into a new investigation. */
export async function promoteIdentityFindings(
  findingIds: string[],
  title?: string,
): Promise<PromoteFindingsResponse> {
  return api.post<PromoteFindingsResponse>(`${HUNT_BASE}/findings/promote`, {
    finding_ids: findingIds,
    title: title ?? null,
  });
}
