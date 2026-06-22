/**
 * Cloud Control-Plane Hunter API client (#117 Phase B).
 *
 * Thin typed wrappers over the existing ``/api/v1/hunt`` endpoints,
 * pre-filtered to ``domain=cloud``.  No new backend endpoints are introduced
 * in Phase B — the same HuntFinding triage API is reused with a domain filter.
 *
 * Triage actions (suppress, promote) are inherited from the hunt API and
 * re-exported here so the cloud store does not need to import from
 * ``@/api/hunt`` directly.
 */

import api from "./client";
import {
  suppressFinding,
  promoteFindings,
} from "./hunt";
import type {
  HuntFinding,
  HuntFindingClusterListResponse,
  CreateSuppressionRequest,
  SuppressionRule,
  PromoteFindingsResponse,
} from "@/types/hunt";

// Re-export so cloud store imports stay in one place.
export type {
  HuntFinding,
  HuntFindingClusterListResponse,
  CreateSuppressionRequest,
  SuppressionRule,
  PromoteFindingsResponse,
};

const BASE = "/v1/hunt";

// ---------------------------------------------------------------------------
// Cloud-domain finding list (pre-filtered to domain=cloud)
// ---------------------------------------------------------------------------

export interface ListCloudFindingsParams {
  /** Server-side state filter (default: "active"). */
  state?: "active" | "suppressed" | "promoted" | "all";
  page?: number;
  page_size?: number;
}

/**
 * List hunt findings pre-filtered to ``domain=cloud``.
 *
 * The backend's ``/v1/hunt/findings`` endpoint accepts a ``domain`` query
 * parameter; this wrapper always sets it to ``cloud`` so consumers receive
 * only cloud control-plane findings.
 *
 * If the backend does not yet support the ``domain`` filter, the response
 * still works — the store layer applies a client-side filter as a fallback.
 */
export async function listCloudFindings(
  params?: ListCloudFindingsParams,
): Promise<HuntFindingClusterListResponse> {
  const search = new URLSearchParams();
  search.set("domain", "cloud");
  if (params?.state) search.set("state", params.state);
  if (params?.page) search.set("page", String(params.page));
  if (params?.page_size) search.set("page_size", String(params.page_size));
  return api.get<HuntFindingClusterListResponse>(
    `${BASE}/findings?${search.toString()}`,
  );
}

/**
 * Fetch a single cloud hunt finding by ID.
 *
 * The ``domain=cloud`` constraint is not applied here — the caller is expected
 * to know the finding's domain from context (e.g. by fetching from the cloud
 * store which already filters).
 */
export async function getCloudFinding(findingId: string): Promise<HuntFinding> {
  return api.get<HuntFinding>(`${BASE}/findings/${findingId}`);
}

// ---------------------------------------------------------------------------
// Triage / promote — delegates to the shared hunt API
// ---------------------------------------------------------------------------

export async function suppressCloudFinding(
  findingId: string,
  body: CreateSuppressionRequest,
): Promise<SuppressionRule> {
  return suppressFinding(findingId, body);
}

export async function promoteCloudFindings(
  findingIds: string[],
  title?: string,
): Promise<PromoteFindingsResponse> {
  return promoteFindings(findingIds, title);
}
