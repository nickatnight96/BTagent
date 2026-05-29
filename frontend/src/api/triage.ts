import api from "./client";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface NextStep {
  action: string;
  rationale: string;
}

export interface TriageResult {
  typed_intent: string;
  proposed_severity: Severity;
  disposition: string;
  confidence: number;
  explanation: string;
  next_steps: NextStep[];
  evidence: string[];
  severity_escalated: boolean;
}

export interface TriageRequest {
  title: string;
  description?: string;
  source?: string;
  severity?: Severity;
  entities?: Record<string, string[]>;
}

export async function triageAlert(req: TriageRequest): Promise<TriageResult> {
  return api.post<TriageResult>("/v1/triage", req);
}
