/** Shift-handover API client (EPIC-5 UC-5.1). */

import api from "./client";
import type { HandoverSummary } from "@/types/handover";

/** Fetch the org's shift-handover summary (default window 8h). */
export async function getHandoverSummary(windowHours?: number): Promise<HandoverSummary> {
  const qs = windowHours ? `?window_hours=${windowHours}` : "";
  return api.get<HandoverSummary>(`/v1/handover${qs}`);
}
