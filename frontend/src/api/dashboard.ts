/** Dashboard-layout preference API client (EPIC-5 role-tuned views, #108). */

import api from "./client";
import type { DashboardLayout, DashboardLayoutResponse } from "@/types/dashboard";

/** The caller's PunchList layout — their saved one, else their role default. */
export async function getDashboardLayout(): Promise<DashboardLayoutResponse> {
  return api.get<DashboardLayoutResponse>("/v1/config/dashboard-layout");
}

/** Save the caller's PunchList layout. */
export async function putDashboardLayout(
  layout: DashboardLayout,
): Promise<DashboardLayoutResponse> {
  return api.put<DashboardLayoutResponse>("/v1/config/dashboard-layout", layout);
}

/** Drop the saved layout, reverting to the role default. */
export async function resetDashboardLayout(): Promise<DashboardLayoutResponse> {
  return api.delete<DashboardLayoutResponse>("/v1/config/dashboard-layout");
}
