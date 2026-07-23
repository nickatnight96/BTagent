/**
 * Agentic-AI Misuse Hunter API client (#121 Phase B).
 *
 * Thin typed wrapper over the existing ``/api/v1/hunt`` endpoints,
 * pre-filtered to ``domain=agentic`` — the same pattern api/cloud.ts uses
 * for #117. No new backend endpoints: the four Phase A detectors
 * (prompt_injection, shadow_agent_* , identity_*, llm_exfil) already land
 * their findings in the shared triage queue with ``evidence.detection``
 * as the per-detector discriminator.
 */

import api from "./client";
import type { HuntFindingClusterListResponse } from "@/types/hunt";

export type { HuntFinding, HuntFindingClusterListResponse } from "@/types/hunt";

const BASE = "/v1/hunt";

export interface ListAgenticFindingsParams {
  state?: "active" | "suppressed" | "promoted" | "all";
  page?: number;
  page_size?: number;
}

export async function listAgenticFindings(
  params?: ListAgenticFindingsParams,
): Promise<HuntFindingClusterListResponse> {
  const search = new URLSearchParams();
  search.set("domain", "agentic");
  if (params?.state) search.set("state", params.state);
  if (params?.page) search.set("page", String(params.page));
  if (params?.page_size) search.set("page_size", String(params.page_size));
  return api.get<HuntFindingClusterListResponse>(
    `${BASE}/findings?${search.toString()}`,
  );
}

// --- Shadow-agent governance (#121/#117 Phase C) --------------------------- //

export interface ShadowRegistryEntry {
  id: string;
  resource_key: string;
  kind: string;
  status: string;
  decided_by: string | null;
  rationale: string;
  source_finding_id: string | null;
  updated_at: string;
}

export interface ShadowRegistryListResponse {
  items: ShadowRegistryEntry[];
  total: number;
}

/** Register (sanction) or sunset (decommission) a shadow-agent finding. */
export async function governFinding(
  findingId: string,
  action: "register" | "sunset",
  rationale = "",
): Promise<ShadowRegistryEntry> {
  return api.post<ShadowRegistryEntry>(
    `${BASE}/findings/${findingId}/govern`,
    { action, rationale },
  );
}

export async function listGovernance(): Promise<ShadowRegistryListResponse> {
  return api.get<ShadowRegistryListResponse>(`${BASE}/governance?page_size=200`);
}
