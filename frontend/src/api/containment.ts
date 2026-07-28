import api, { ApiError } from "./client";
import type { MitigationAction } from "./mitigation";
import type { ResponseAction } from "./response-plan";

// Approve→execute→record loop (EPIC-3 #106). These endpoints are double-gated:
// the caller must hold `containment:execute` (incident_commander+) AND the
// action must already be approved. Every call writes a hash-chain audit row.

export interface ExecutionResult {
  executed: boolean;
  outcome: "success" | "failure" | "denied";
  tool: string;
  target: string;
  audit_id: string;
  approver_id: string;
  change_ref: string | null;
  tool_response: Record<string, unknown>;
}

/** Execute one APPROVED response-plan tactical step through the connector layer. */
export async function executeResponseAction(
  action: ResponseAction,
): Promise<ExecutionResult> {
  return api.post<ExecutionResult>("/v1/containment/execute/response-action", {
    action_id: action.id,
    action_type: action.action_type,
    connector: action.connector,
    target: action.target,
    description: action.description,
    approved: true,
  });
}

/**
 * The audited 403 a refused containment returns.
 *
 * A refusal is a documented outcome here, not a transport failure: the server
 * writes a hash-chained DENIED row *before* answering, and hands back the
 * reason plus its ``audit_id``. The commonest cause is the org never-block
 * safelist, which is why the reason is worth showing verbatim — it tells the
 * operator to go look at the safelist rather than retry.
 */
export interface ExecutionDenied {
  message: string;
  outcome: string;
  target: string | null;
  tool: string | null;
  audit_id: string | null;
  approver_id: string | null;
}

/** Pull the audited denial out of a refused execution, or ``null``. */
export function executionDenial(e: unknown): ExecutionDenied | null {
  if (!(e instanceof ApiError) || e.status !== 403) return null;
  const detail = (e.body as { detail?: unknown } | null)?.detail;
  if (!detail || typeof detail !== "object") return null;
  const d = detail as Partial<ExecutionDenied>;
  // `audit_id` is what separates an audited containment refusal from a plain
  // RBAC 403, which carries a string detail and leaves no ledger row.
  if (typeof d.audit_id !== "string" || !d.audit_id) return null;
  return {
    message: d.message ?? "Execution refused",
    outcome: d.outcome ?? "denied",
    target: d.target ?? null,
    tool: d.tool ?? null,
    audit_id: d.audit_id,
    approver_id: d.approver_id ?? null,
  };
}

/**
 * Execute one APPROVED bulk-block step (UC-3.3) through the connector layer.
 *
 * Same double-gate as the response-action path: `containment:execute` plus an
 * explicit prior approval on the request. The org never-block safelist is
 * consulted *before* any dispatch, so a safelisted IOC comes back as an
 * audited 403 and nothing runs.
 */
export async function executeBulkBlock(
  action: MitigationAction,
): Promise<ExecutionResult> {
  return api.post<ExecutionResult>("/v1/containment/execute/bulk-block", {
    action_id: action.id,
    ioc_type: action.ioc_type,
    ioc_value: action.ioc_value,
    tool: action.tool,
    policy_object: action.policy_object,
    rollback: action.rollback,
    approved: true,
  });
}

// --------------------------------------------------------------------------
// Never-block safelist (org-scoped extension of the code-level baseline).
// Reads and writes all require `containment:execute`, same as executing.
// --------------------------------------------------------------------------

export type SafelistEntryType = "ip" | "domain";

export interface SafelistEntry {
  id: string;
  org_id: string;
  entry_type: SafelistEntryType;
  value: string;
  reason: string;
  created_by: string | null;
}

/** This org's never-block entries (newest first). 403 for non-commanders. */
export async function listSafelistEntries(): Promise<SafelistEntry[]> {
  return api.get<SafelistEntry[]>("/v1/containment/safelist");
}

/** Add a never-block entry. Re-adding an existing pair is a no-op server-side. */
export async function addSafelistEntry(input: {
  entryType: SafelistEntryType;
  value: string;
  reason: string;
}): Promise<SafelistEntry> {
  return api.post<SafelistEntry>("/v1/containment/safelist", {
    entry_type: input.entryType,
    value: input.value,
    reason: input.reason,
  });
}

/**
 * Remove a never-block entry (204). Only drops an *org* row — the universal
 * baseline lives in code, so this can never take an org below the shared floor.
 */
export async function removeSafelistEntry(entryId: string): Promise<void> {
  await api.delete<void>(`/v1/containment/safelist/${encodeURIComponent(entryId)}`);
}
