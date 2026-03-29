/** Knowledge base domain types for the BTagent frontend. */

/** Source types for knowledge documents */
export type KnowledgeSourceType =
  | "investigation_report"
  | "runbook"
  | "threat_profile"
  | "agency_profile"
  | "enrichment_data"
  | "playbook_log"
  | "conversation";

/** A document stored in the knowledge base */
export interface KnowledgeDocument {
  id: string;
  title: string;
  source_type: KnowledgeSourceType;
  token_count?: number;
  metadata?: Record<string, unknown>;
  created_at?: string | null;
  updated_at?: string | null;
}

/** Document with content and chunk count */
export interface KnowledgeDocumentDetail extends KnowledgeDocument {
  content: string;
  chunk_count: number;
}

/** A single search result from hybrid search */
export interface KnowledgeSearchResult {
  chunk_content: string;
  document_title: string;
  source_type: string;
  relevance_score: number;
  metadata: Record<string, unknown>;
  document_id: string;
  chunk_id: string;
}

/** Query response from the knowledge API */
export interface KnowledgeQueryResponse {
  query: string;
  results: KnowledgeSearchResult[];
  total_results: number;
}

/** Paginated document list response */
export interface KnowledgeDocumentListResponse {
  items: KnowledgeDocument[];
  total: number;
  page: number;
  page_size: number;
}

/** Ingest request body */
export interface KnowledgeIngestRequest {
  title: string;
  content: string;
  source_type: string;
  metadata?: Record<string, unknown>;
}

/** Ingest response */
export interface KnowledgeIngestResponse {
  id: string;
  title: string;
  source_type: string;
  token_count: number;
  message: string;
}

/** Source type display configuration */
export const SOURCE_TYPE_CONFIG: Record<
  KnowledgeSourceType,
  { label: string; color: string }
> = {
  investigation_report: { label: "Investigation Report", color: "blue" },
  runbook: { label: "Runbook", color: "green" },
  threat_profile: { label: "Threat Profile", color: "red" },
  agency_profile: { label: "Agency Profile", color: "purple" },
  enrichment_data: { label: "Enrichment Data", color: "yellow" },
  playbook_log: { label: "Playbook Log", color: "orange" },
  conversation: { label: "Conversation", color: "slate" },
};
