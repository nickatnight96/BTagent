/** Role-tuned PunchList layout preference (EPIC-5, #108). */

/** PunchList section keys the frontend knows how to render. */
export type DashboardSection = "handover" | "investigations";

/** A user's PunchList arrangement (mirrors backend DashboardLayout). */
export interface DashboardLayout {
  /** Ordered visible sections; omitting "handover" hides the shift card. */
  sections: DashboardSection[];
  /** Status-pill value preselected on load; "" = All. */
  default_status_filter: string;
}

export interface DashboardLayoutResponse {
  layout: DashboardLayout;
  /** "user" when the caller saved a customization; "role_default" otherwise. */
  source: "user" | "role_default" | string;
  role: string;
}
