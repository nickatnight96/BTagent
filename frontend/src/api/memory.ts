import api from "./client";

/** The four fact kinds the agent-memory store accepts (#482). */
export const MEMORY_KINDS = ["entity_note", "decision", "learning", "observation"] as const;
export type MemoryKind = (typeof MEMORY_KINDS)[number];

/**
 * One org-scoped long-term memory (`GET /memory` row).
 *
 * These are the compact structured facts the agent recalls at investigation
 * start and records at close — the store #484 built. Recall is TLP-filtered
 * server-side: rows above the API clearance (AMBER_STRICT) never arrive here.
 */
export interface AgentMemory {
  id: string;
  kind: string;
  subject: string;
  content: string;
  source: string;
  confidence: number | null;
  tlp_level: string;
  created_at: string | null;
  updated_at: string | null;
}

export interface MemoryListResponse {
  items: AgentMemory[];
  total: number;
}

/** Recall recency-ranked memories, optionally narrowed by subject / kind. */
export async function recallMemories(params?: {
  subject?: string;
  kind?: MemoryKind;
  limit?: number;
}): Promise<MemoryListResponse> {
  const sp = new URLSearchParams();
  if (params?.subject) sp.set("subject", params.subject);
  if (params?.kind) sp.set("kind", params.kind);
  if (params?.limit) sp.set("limit", String(params.limit));
  const q = sp.toString();
  return api.get<MemoryListResponse>(`/v1/memory${q ? `?${q}` : ""}`);
}

export interface RecordMemoryRequest {
  kind: MemoryKind;
  subject: string;
  content: string;
  source?: string;
  confidence?: number;
  tlp_level?: string;
}

/**
 * Record (upsert by org+kind+subject) a memory. Senior analyst+
 * (`memory:write`) — authoring a fact shapes what every future investigation
 * in the org recalls, which is why the bar is above plain analyst.
 */
export async function recordMemory(body: RecordMemoryRequest): Promise<AgentMemory> {
  return api.post<AgentMemory>("/v1/memory", body);
}
