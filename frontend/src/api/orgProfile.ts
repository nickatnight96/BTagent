/** Organisation-profile client (#418 / GH #393). */

import api from "./client";

/** IR team configuration (shifts, escalation paths, on-call). */
export interface IRTeam {
  shifts: Array<Record<string, unknown>>;
  escalation_paths: Array<Record<string, unknown>>;
  on_call: Record<string, unknown>;
}

/**
 * The org profile injected into agent prompts. Mirrors the backend
 * `OrgProfile` pydantic model (`services/org_profile.py`).
 */
export interface OrgProfile {
  industry: string;
  compliance: string[];
  tech_stack: Record<string, unknown>;
  critical_assets: Array<Record<string, unknown>>;
  ir_team: IRTeam;
}

export interface OrgProfileResponse {
  profile: OrgProfile;
}

/** An empty profile — used before load and as the shape default. */
export function emptyOrgProfile(): OrgProfile {
  return {
    industry: "",
    compliance: [],
    tech_stack: {},
    critical_assets: [],
    ir_team: { shifts: [], escalation_paths: [], on_call: {} },
  };
}

/** Read the caller's org profile (org-scoped server-side). */
export async function getOrgProfile(): Promise<OrgProfileResponse> {
  return api.get<OrgProfileResponse>("/v1/config/org-profile");
}

/**
 * Upsert the caller's org profile (admin only, org-scoped). The whole profile
 * is sent — the backend replaces the stored row wholesale.
 */
export async function updateOrgProfile(profile: OrgProfile): Promise<OrgProfileResponse> {
  return api.put<OrgProfileResponse>("/v1/config/org-profile", profile);
}
