/** Knowledge base API client functions. */

import api from "./client";
import type {
  KnowledgeDocumentDetail,
  KnowledgeDocumentListResponse,
  KnowledgeIngestRequest,
  KnowledgeIngestResponse,
  KnowledgeQueryResponse,
} from "@/types/knowledge";

const BASE = "/v1/knowledge";

/** Ingest a document into the knowledge base. */
export async function ingestDocument(
  body: KnowledgeIngestRequest,
): Promise<KnowledgeIngestResponse> {
  return api.post<KnowledgeIngestResponse>(`${BASE}/ingest`, body);
}

/** Hybrid search (vector + keyword) the knowledge base. */
export async function queryKnowledge(
  query: string,
  topK: number = 5,
  sourceTypeFilter?: string,
): Promise<KnowledgeQueryResponse> {
  return api.post<KnowledgeQueryResponse>(`${BASE}/query`, {
    query,
    top_k: topK,
    source_type_filter: sourceTypeFilter ?? null,
  });
}

/** Keyword-only search (GET endpoint). */
export async function searchKnowledge(
  q: string,
  topK: number = 5,
  sourceType?: string,
): Promise<KnowledgeQueryResponse> {
  const params = new URLSearchParams({ q, top_k: String(topK) });
  if (sourceType) params.set("source_type", sourceType);
  return api.get<KnowledgeQueryResponse>(`${BASE}/search?${params}`);
}

/** List documents with optional filter and pagination. */
export async function listDocuments(params?: {
  source_type?: string;
  page?: number;
  page_size?: number;
}): Promise<KnowledgeDocumentListResponse> {
  const search = new URLSearchParams();
  if (params?.source_type) search.set("source_type", params.source_type);
  if (params?.page) search.set("page", String(params.page));
  if (params?.page_size) search.set("page_size", String(params.page_size));
  const qs = search.toString();
  return api.get<KnowledgeDocumentListResponse>(
    `${BASE}/documents${qs ? `?${qs}` : ""}`,
  );
}

/** Get document detail with content and chunk count. */
export async function getDocument(
  documentId: string,
): Promise<KnowledgeDocumentDetail> {
  return api.get<KnowledgeDocumentDetail>(`${BASE}/documents/${documentId}`);
}

/** Delete a document and its chunks. */
export async function deleteDocument(documentId: string): Promise<void> {
  return api.delete(`${BASE}/documents/${documentId}`);
}
