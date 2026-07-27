import api from "./client";
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
