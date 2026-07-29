/** Coverage Console API client (#501). */

import api from "./client";
import type { CoverageConsole } from "@/types/coverage";

const BASE = "/v1/coverage";

/**
 * The whole detection-engineering picture for the caller's org in one request.
 *
 * Deliberately a single call: the console's panels are four views of the same
 * moment, and stitching them client-side from four endpoints would let them
 * disagree (a technique fresh in one panel and stale in another) while the
 * page is still loading.
 */
export async function getCoverageConsole(params?: {
  staleDays?: number;
  lookbackRuns?: number;
}): Promise<CoverageConsole> {
  const search = new URLSearchParams();
  if (params?.staleDays) search.set("stale_days", String(params.staleDays));
  if (params?.lookbackRuns) search.set("lookback_runs", String(params.lookbackRuns));
  const qs = search.toString();
  return api.get<CoverageConsole>(`${BASE}/console${qs ? `?${qs}` : ""}`);
}
