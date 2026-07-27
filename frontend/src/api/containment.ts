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
