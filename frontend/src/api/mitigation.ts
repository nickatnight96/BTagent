import api from "./client";

export type IOCType =
  | "ip"
  | "domain"
  | "url"
  | "hash_md5"
  | "hash_sha1"
  | "hash_sha256"
  | "email"
  | "file_path"
  | "registry_key"
  | "cve"
  | "user_agent"
  | "mutex"
  | "process_name"
  | "other";

export type MitigationDecision =
  | "block"
  | "skip_allowlisted"
  | "skip_invalid"
  | "skip_unsupported"
  | "skip_duplicate";

export interface IOCRef {
  type: IOCType;
  value: string;
}

export interface MitigationAction {
  id: string;
  ioc_type: IOCType;
  ioc_value: string;
  decision: MitigationDecision;
  tool: string;
  policy_object: string;
  policy_preview: string;
  description: string;
  destructive: boolean;
  requires_approval: boolean;
  rollback: string | null;
  reason: string;
}

export interface MitigationPlan {
  summary: string;
  actions: MitigationAction[];
  block_count: number;
  skip_count: number;
  tools: string[];
}

export interface MitigationOutput {
  plan: MitigationPlan;
  mock_mode: boolean;
}

export interface MitigationRequest {
  iocs: IOCRef[];
  extra_allowlist?: string[];
}

export async function planBulkMitigation(
  req: MitigationRequest,
): Promise<MitigationOutput> {
  return api.post<MitigationOutput>("/v1/mitigation", req);
}
