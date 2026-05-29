import api from "./client";
import type { Severity } from "./triage";

export type ResponseCategory = "contain" | "investigate" | "document";

export type ResponseActionType =
  | "isolate_host"
  | "block_ip"
  | "block_domain"
  | "disable_account"
  | "kill_process"
  | "forensic_snapshot"
  | "pull_logs"
  | "open_ticket"
  | "notify";

export interface ResponseAction {
  id: string;
  category: ResponseCategory;
  action_type: ResponseActionType;
  target: string;
  connector: string;
  description: string;
  destructive: boolean;
  requires_approval: boolean;
  rollback: string | null;
}

export interface ResponsePlan {
  strategic_goal: string;
  rationale: string;
  tactical_steps: ResponseAction[];
  estimated_containment_minutes: number | null;
}

export interface ResponsePlanOutput {
  plan: ResponsePlan;
  mock_mode: boolean;
}

export type TypedIntent =
  | "suspicious_login"
  | "malware_detected"
  | "data_exfil_suspected"
  | "c2_beaconing"
  | "privilege_escalation"
  | "lateral_movement"
  | "reconnaissance"
  | "phishing"
  | "policy_violation"
  | "benign"
  | "unknown";

export interface ResponsePlanRequest {
  typed_intent: TypedIntent;
  severity?: Severity;
  entities?: Record<string, string[]>;
}

export async function generateResponsePlan(
  req: ResponsePlanRequest,
): Promise<ResponsePlanOutput> {
  return api.post<ResponsePlanOutput>("/v1/response-plan", req);
}
