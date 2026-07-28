/** Detection-validation API client (#118). */

import api from "./client";
import { ApiError } from "./client";
import type {
  EmulationDenied,
  EmulationRunRequest,
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

/**
 * Trigger a sandbox-gated adversary-emulation run of one ATT&CK technique.
 *
 * Requires ``validation:emulate`` (incident_commander) — the same tier as
 * executing containment, because in live mode the emulators fire real
 * techniques. A non-sandbox ``target_env`` is refused server-side with an
 * audited 403 before any emulator is reached.
 */
export async function runEmulation(
  body: EmulationRunRequest,
): Promise<ValidationRunResponse> {
  return api.post<ValidationRunResponse>(`${BASE}/emulate`, body);
}

/**
 * Extract the audited-denial body from a refused emulation, or ``null``.
 *
 * A denial is a *documented outcome* of this endpoint, not a failure: the
 * server records a ledger row and returns the reason plus its ``audit_id``.
 * Collapsing that into a generic "request failed" would throw away the only
 * pointer the operator has to the audit trail.
 */
export function emulationDenial(e: unknown): EmulationDenied | null {
  if (!(e instanceof ApiError) || e.status !== 403) return null;
  const detail = (e.body as { detail?: unknown } | null)?.detail;
  if (!detail || typeof detail !== "object") return null;
  const d = detail as Partial<EmulationDenied>;
  // `audit_id` is the field that makes this a *denial* rather than a plain
  // RBAC 403 (which has a string detail and no ledger row).
  if (typeof d.audit_id !== "string" || !d.audit_id) return null;
  return {
    status: d.status ?? "denied",
    technique_id: d.technique_id ?? "",
    target_env: d.target_env ?? "",
    reason: d.reason ?? "Emulation refused.",
    audit_id: d.audit_id,
  };
}
