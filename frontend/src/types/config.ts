/**
 * Mirrors `TLP` in shared/btagent_shared/types/config.py — the values the API
 * accepts and returns, not display text.
 *
 * These members used to hold presentation strings ("AMBER+STRICT", "CLEAR"),
 * with one caller lowercasing on the way out. That worked for exactly three of
 * the five levels: "AMBER+STRICT".toLowerCase() is "amber+strict" and "CLEAR"
 * is "clear", neither of which the Pydantic `TLP` field accepts — so creating
 * an investigation at TLP:AMBER+STRICT or TLP:CLEAR 422'd.
 *
 * Display text lives in the `label` of each option list. `WHITE` keeps the
 * backend's member name (TLP 1.0) and is labelled "TLP:CLEAR" (TLP 2.0) at the
 * points where a human reads it.
 */
export enum TLP {
  RED = "red",
  AMBER_STRICT = "amber_strict",
  AMBER = "amber",
  GREEN = "green",
  WHITE = "white",
}

export enum Severity {
  CRITICAL = "critical",
  HIGH = "high",
  MEDIUM = "medium",
  LOW = "low",
  INFO = "info",
}

/**
 * Mirrors `InvestigationStatus` in shared/btagent_shared/types/enums.py.
 *
 * These are the raw values stored in `investigations.status`. The list filter
 * sends the selected value to `GET /investigations?status=`, which does an
 * exact string compare — so a value invented here that the backend never
 * writes matches nothing, silently. This enum previously carried `running`,
 * `awaiting_hitl`, `completed` and `stopped`, none of which the API has ever
 * sent, while missing seven statuses that it does.
 *
 * `backend/tests/test_shared_enum_ts_parity.py` now parses this declaration
 * and fails if it drifts from the Python enum again.
 */
export enum InvestigationStatus {
  PENDING = "pending",
  TRIAGING = "triaging",
  INVESTIGATING = "investigating",
  PAUSED = "paused",
  PAUSED_HITL = "paused_hitl",
  CONTAINED = "contained",
  REMEDIATED = "remediated",
  CLOSED = "closed",
  FAILED = "failed",
  CANCELLED = "cancelled",
  ARCHIVED = "archived",
}

/**
 * Mirrors `UserRole` in shared/btagent_shared/types/enums.py:
 * analyst < senior_analyst < incident_commander < admin.
 *
 * `viewer` was a member here but exists nowhere in the backend — no RBAC
 * registry entry, no enum member, nothing that issues it. It is kept below as
 * a raw ROLE_RANK key instead, because an SSO `role_map` can still hand us an
 * unrecognised role string and that has to rank below analyst.
 */
export enum UserRole {
  ADMIN = "admin",
  INCIDENT_COMMANDER = "incident_commander",
  SENIOR_ANALYST = "senior_analyst",
  ANALYST = "analyst",
}

// Role ranks mirroring backend ROLE_HIERARCHY (auth/rbac.py). A permission
// gated at role R is held by every role of equal-or-higher rank — checking
// role-equality on the frontend (F10) wrongly excluded incident_commander
// from senior_analyst-gated surfaces like the TAXII panel.
//
// "viewer" is not a backend role (see UserRole above); it is listed explicitly
// so a deployment whose SSO emits it gets a defined below-analyst rank rather
// than the undefined lookup that `roleAtLeast` also denies, but silently.
const ROLE_RANK: Record<string, number> = {
  viewer: -1,
  [UserRole.ANALYST]: 0,
  [UserRole.SENIOR_ANALYST]: 1,
  [UserRole.INCIDENT_COMMANDER]: 2,
  [UserRole.ADMIN]: 3,
};

/** True when `role` ranks at or above `minimum` in the RBAC hierarchy. */
export function roleAtLeast(role: string | null | undefined, minimum: UserRole): boolean {
  if (!role) return false;
  const have = ROLE_RANK[role];
  const need = ROLE_RANK[minimum];
  return have !== undefined && need !== undefined && have >= need;
}

export interface User {
  id: string;
  username: string;
  role: UserRole;
}

export const SEVERITY_COLORS: Record<Severity, string> = {
  [Severity.CRITICAL]: "bg-red-500/20 text-red-400 border-red-500/30",
  [Severity.HIGH]: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  [Severity.MEDIUM]: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  [Severity.LOW]: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  [Severity.INFO]: "bg-gray-500/20 text-gray-400 border-gray-500/30",
};

// STATUS_COLORS used to live here: a second, unreferenced colour map keyed by
// the same stale vocabulary. Nothing in the app imported it — `StatusBadge` is
// the single status-rendering surface — so it is deleted rather than carried
// forward as a second thing to keep in sync.
