/** Hunt triage API client functions (Phase 6 #119). */

import api from "./client";
import type {
  AgenticHuntRunResponse,
  AllHuntsRunResponse,
  CloudHuntRunResponse,
  CreateSuppressionRequest,
  DeceptionHuntRunResponse,
  EmailHuntRunResponse,
  HuntVerticalListResponse,
  NdrHuntRunResponse,
  HuntFinding,
  HuntFindingClusterListResponse,
  NoiseBaseline,
  PromoteClusterRequest,
  PromoteFindingsResponse,
  SuppressionListResponse,
  SuppressionRule,
  SuppressClusterRequest,
} from "@/types/hunt";

const BASE = "/v1/hunt";

/** Clustered triage inbox. */
export async function listFindings(params?: {
  include_suppressed?: boolean;
  /** Server-side cluster-state filter, applied BEFORE pagination (PR #202). */
  state?: "active" | "suppressed" | "promoted" | "all";
  page?: number;
  page_size?: number;
}): Promise<HuntFindingClusterListResponse> {
  const search = new URLSearchParams();
  if (params?.include_suppressed) search.set("include_suppressed", "true");
  if (params?.state) search.set("state", params.state);
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

/** Run an email hunt across the email connectors; findings land in the inbox. */
export async function runEmailHunt(
  body?: { lookback_hours?: number; start?: string; end?: string },
): Promise<EmailHuntRunResponse> {
  return api.post<EmailHuntRunResponse>(`${BASE}/email/run`, body ?? {});
}

/** Run a deception hunt over the Canary connector; findings land in the inbox. */
export async function runDeceptionHunt(): Promise<DeceptionHuntRunResponse> {
  return api.post<DeceptionHuntRunResponse>(`${BASE}/deception/run`, {});
}

/** Run an NDR hunt over the Vectra connector; findings land in the inbox. */
export async function runNdrHunt(): Promise<NdrHuntRunResponse> {
  return api.post<NdrHuntRunResponse>(`${BASE}/ndr/run`, {});
}

/** Run an agentic-misuse hunt; findings land in the inbox. */
export async function runAgenticHunt(): Promise<AgenticHuntRunResponse> {
  return api.post<AgenticHuntRunResponse>(`${BASE}/agentic/run`, {});
}

/** Run a cloud control-plane hunt; findings land in the inbox. */
export async function runCloudHunt(): Promise<CloudHuntRunResponse> {
  return api.post<CloudHuntRunResponse>(`${BASE}/cloud/run`, {});
}

/** Run every findings vertical (email + deception + NDR) in one sweep. */
export async function runAllHunts(): Promise<AllHuntsRunResponse> {
  return api.post<AllHuntsRunResponse>(`${BASE}/all/run`, {});
}

/** The manual-runnable findings-vertical catalog + their schedule status. */
export async function listHuntVerticals(): Promise<HuntVerticalListResponse> {
  return api.get<HuntVerticalListResponse>(`${BASE}/verticals`);
}

/** Bulk-suppress a cluster (one rule covering the cluster's pattern). */
export async function suppressCluster(
  clusterId: string,
  body: SuppressClusterRequest,
): Promise<SuppressionRule> {
  return api.post<SuppressionRule>(`${BASE}/clusters/${clusterId}/suppress`, body);
}

/** Escalate a cluster's eligible members into a single investigation. */
export async function promoteCluster(
  clusterId: string,
  body: PromoteClusterRequest,
): Promise<PromoteFindingsResponse> {
  return api.post<PromoteFindingsResponse>(
    `${BASE}/clusters/${clusterId}/promote`,
    body,
  );
}

/** Chronically-hitting pack rules — advisory suppression candidates (#112). */
export async function getNoiseBaseline(): Promise<NoiseBaseline> {
  return api.get<NoiseBaseline>(`${BASE}/noise-baseline`);
}
