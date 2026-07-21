/** Detection-validation API client (#118). */

import api from "./client";
import type {
  ValidationRunListResponse,
  ValidationRunResponse,
} from "@/types/validation";

const BASE = "/v1/validation";

/** Trigger a detection-validation run; returns the persisted coverage report. */
export async function runValidation(): Promise<ValidationRunResponse> {
  return api.post<ValidationRunResponse>(`${BASE}/runs`, {});
}

/** List persisted detection-validation runs, newest-first. */
export async function listValidationRuns(params?: {
  limit?: number;
  offset?: number;
}): Promise<ValidationRunListResponse> {
  const search = new URLSearchParams();
  if (params?.limit) search.set("limit", String(params.limit));
  if (params?.offset) search.set("offset", String(params.offset));
  const qs = search.toString();
  return api.get<ValidationRunListResponse>(`${BASE}/runs${qs ? `?${qs}` : ""}`);
}
