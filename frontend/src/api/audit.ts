import api from "./client";

export interface AuditEntry {
  id: string;
  seq: number;
  timestamp: string;
  actor: string;
  category: string;
  action: string;
  resource: string;
  outcome: string;
  prev_hash: string;
  hash: string;
}

export interface AuditEntryList {
  items: AuditEntry[];
  limit: number;
  offset: number;
}

export interface ChainVerify {
  valid: boolean;
  errors: string[];
}

export async function listAuditEntries(params?: {
  actor?: string;
  category?: string;
  limit?: number;
  offset?: number;
}): Promise<AuditEntryList> {
  const q = new URLSearchParams();
  if (params?.actor) q.set("actor", params.actor);
  if (params?.category) q.set("category", params.category);
  if (params?.limit) q.set("limit", String(params.limit));
  if (params?.offset) q.set("offset", String(params.offset));
  const qs = q.toString();
  return api.get<AuditEntryList>(`/v1/audit/entries${qs ? `?${qs}` : ""}`);
}

export async function verifyAuditChain(): Promise<ChainVerify> {
  return api.get<ChainVerify>("/v1/audit/verify");
}

/** Returns the export endpoint URL (the browser downloads via a link/fetch). */
export function auditExportUrl(): string {
  return "/api/v1/audit/export";
}
