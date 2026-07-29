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

/** Which ranking answered a recall: pgvector similarity, or recency/exact. */
export type MemoryRecallMode = "semantic" | "recency";

export interface MemoryListResponse {
  items: AgentMemory[];
  total: number;
  /**
   * The mode the server ranked by. `semantic` means a `query` was sent and
   * the embedding path answered; `recency` is the ordinary most-recent-first
   * listing. Surfaced in the UI because "no results" means different things
   * in each mode — an empty semantic answer is "nothing similar", an empty
   * recency answer is "nothing recorded".
   */
  mode?: MemoryRecallMode;
}

/**
 * Recall memories, optionally narrowed by subject / kind.
 *
 * Passing `query` switches the server to SEMANTIC recall (pgvector cosine
 * similarity over the same org- and TLP-filtered rows) instead of recency
 * ranking. The server degrades to recency when pgvector or an embedding
 * provider is unavailable, so the response's `mode` is what the caller asked
 * for — treat it as the mode label, not a promise about the internal path.
 */
export async function recallMemories(params?: {
  subject?: string;
  kind?: MemoryKind;
  query?: string;
  limit?: number;
}): Promise<MemoryListResponse> {
  const sp = new URLSearchParams();
  if (params?.subject) sp.set("subject", params.subject);
  if (params?.kind) sp.set("kind", params.kind);
  if (params?.query) sp.set("query", params.query);
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

/**
 * Forget a memory — the correction primitive an overwrite cannot replace.
 *
 * A remembered fact is recalled into EVERY future investigation for the org,
 * so a wrong one has to be removable, not merely outvoted. Senior analyst+
 * (`memory:write`), and a SOFT delete server-side: the row is stamped
 * superseded (dropped from all recall) but retained, and the deletion is
 * written to the audit ledger. 404 covers unknown ids and other tenants'
 * rows alike — the API never confirms a memory it won't let you touch.
 */
export async function forgetMemory(id: string): Promise<void> {
  return api.delete<void>(`/v1/memory/${encodeURIComponent(id)}`);
}
