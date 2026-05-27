/** Hunt triage API client functions (Phase 6 #119). */

import api from "./client";
import type {
  CreateSuppressionRequest,
  HuntFinding,
  HuntFindingClusterListResponse,
  PromoteFindingsResponse,
  SuppressionListResponse,
  SuppressionRule,
} from "@/types/hunt";

const BASE = "/v1/hunt";

/** Clustered triage inbox. */
export async function listFindings(params?: {
  include_suppressed?: boolean;
  page?: number;
  page_size?: number;
}): Promise<HuntFindingClusterListResponse> {
  const search = new URLSearchParams();
  if (params?.include_suppressed) search.set("include_suppressed", "true");
  if (params?.page) search.set("page", String(params.page));
  if (params?.page_size) search.set("page_size", String(params.page_size));
  const qs = search.toString();
  return api.get<HuntFindingClusterListResponse>(
    `${BASE}/findings${qs ? `?${qs}` : ""}`,
  );
}

/** Fetch a single finding. */
export async function getFinding(findingId: string): Promise<HuntFinding> {
  return api.get<HuntFinding>(`${BASE}/findings/${findingId}`);
}

/** Create a suppression rule from a finding and apply it. */
export async function suppressFinding(
  findingId: string,
  body: CreateSuppressionRequest,
): Promise<SuppressionRule> {
  return api.post<SuppressionRule>(`${BASE}/findings/${findingId}/suppress`, body);
}

/** Promote one or more findings into a new investigation. */
export async function promoteFindings(
  findingIds: string[],
  title?: string,
): Promise<PromoteFindingsResponse> {
  return api.post<PromoteFindingsResponse>(`${BASE}/findings/promote`, {
    finding_ids: findingIds,
    title: title ?? null,
  });
}

/** List suppression rules. */
export async function listSuppressions(): Promise<SuppressionListResponse> {
  return api.get<SuppressionListResponse>(`${BASE}/suppressions`);
}

/** Create a standalone suppression rule. */
export async function createSuppression(
  body: CreateSuppressionRequest,
): Promise<SuppressionRule> {
  return api.post<SuppressionRule>(`${BASE}/suppressions`, body);
}
