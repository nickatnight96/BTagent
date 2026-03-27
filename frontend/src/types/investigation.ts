import { InvestigationStatus, Severity, TLP } from "./config";

export interface IOC {
  id: string;
  type: "ip" | "domain" | "hash_md5" | "hash_sha1" | "hash_sha256" | "url" | "email" | "cve" | "file_path" | "other";
  value: string;
  source: string;
  confidence: number;
  tags: string[];
  first_seen: string;
  context?: string;
}

export interface TimelineEntry {
  id: string;
  timestamp: string;
  event_type: string;
  source: string;
  description: string;
  severity: Severity;
  raw_data?: Record<string, unknown>;
  ioc_refs: string[];
}

export interface ContainmentAction {
  id: string;
  action_type: "isolate_host" | "block_ip" | "disable_account" | "quarantine_file" | "block_domain" | "custom";
  target: string;
  reason: string;
  status: "pending" | "approved" | "executed" | "failed" | "rolled_back";
  requires_approval: boolean;
  approved_by?: string;
  executed_at?: string;
  rollback_steps?: string[];
}

export interface Investigation {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  tlp: TLP;
  status: InvestigationStatus;
  assigned_to?: string;
  created_by: string;
  created_at: string;
  updated_at: string;
  template?: string;
  iocs: IOC[];
  timeline: TimelineEntry[];
  containment_actions: ContainmentAction[];
  cost_usd: number;
  token_count: number;
  tags: string[];
}

export interface CreateInvestigationRequest {
  title: string;
  description: string;
  severity: Severity;
  tlp: TLP;
  template?: string;
}

export interface ChatMessage {
  id: string;
  role: "user" | "assistant" | "system";
  content: string;
  timestamp: string;
  tool_calls?: ToolCallInfo[];
  is_streaming?: boolean;
}

export interface ToolCallInfo {
  id: string;
  name: string;
  arguments: Record<string, unknown>;
  result?: string;
  status: "pending" | "running" | "completed" | "error";
  duration_ms?: number;
}

export interface HITLCheckpoint {
  id: string;
  investigation_id: string;
  action: ContainmentAction;
  prompt: string;
  timestamp: string;
  timeout_seconds: number;
}
