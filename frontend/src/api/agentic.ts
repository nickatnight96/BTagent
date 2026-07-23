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
