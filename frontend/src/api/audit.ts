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
  /** UC-7.1: narrow to one audited object (matched against `resource`). */
  incidentId?: string;
  limit?: number;
  offset?: number;
}): Promise<AuditEntryList> {
  const q = new URLSearchParams();
  if (params?.actor) q.set("actor", params.actor);
  if (params?.category) q.set("category", params.category);
  if (params?.incidentId) q.set("incident_id", params.incidentId);
  if (params?.limit) q.set("limit", String(params.limit));
  if (params?.offset) q.set("offset", String(params.offset));
  const qs = q.toString();
  return api.get<AuditEntryList>(`/v1/audit/entries${qs ? `?${qs}` : ""}`);
}

export async function verifyAuditChain(): Promise<ChainVerify> {
  return api.get<ChainVerify>("/v1/audit/verify");
}

export interface LineageNode {
  id: string;
  seq: number;
  timestamp: string;
  actor: string;
  category: string;
  action: string;
  resource: string;
  outcome: string;
  prev_hash: string;
  sequence: number;
}

export interface LineageEdge {
  source: string;
  target: string;
  kind: string;
}

export interface LineageGraph {
  nodes: LineageNode[];
  edges: LineageEdge[];
  intact: boolean;
  broken_at: string | null;
}

export async function getAuditLineage(
  upToHash?: string,
): Promise<LineageGraph> {
  const qs = upToHash ? `?up_to_hash=${encodeURIComponent(upToHash)}` : "";
  return api.get<LineageGraph>(`/v1/audit/lineage${qs}`);
}

/**
 * Returns the export endpoint URL (the browser downloads via a link/fetch).
 *
 * With `incidentId` the CSV is scoped to that object's evidence package
 * (UC-7.1). The id is URL-encoded — it lands in a query string, and the
 * server additionally sanitizes it before echoing it in the attachment
 * filename.
 */
export function auditExportUrl(incidentId?: string): string {
  const base = "/api/v1/audit/export";
  return incidentId
    ? `${base}?incident_id=${encodeURIComponent(incidentId)}`
    : base;
}
